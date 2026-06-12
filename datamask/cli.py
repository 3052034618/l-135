# -*- coding: utf-8 -*-
"""
命令行入口 - 数据要素样本脱敏工具
五个命令: scan, mask, preview, report, rules
"""
import os
import sys
import io
import json
from pathlib import Path
from typing import List, Optional

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

import click
from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from .config import MaskConfig
from .processor import DataProcessor, get_output_path
from .fileio import (
    get_supported_files, read_file, SUPPORTED_FORMATS,
    UnsupportedFormatError, FileReadError,
)
from .report import ReportGenerator, RISK_LEVELS
from .detector import SENSITIVE_TYPES

colorama_init()

TYPE_LABELS = {
    "PHONE": "手机号",
    "ID_CARD": "身份证号",
    "ADDRESS": "地址",
    "NAME": "姓名",
    "COMPANY": "企业名称",
    "EMAIL": "电子邮箱",
    "BANK_CARD": "银行卡号",
    "UNKNOWN": "未知",
}

STRATEGY_LABELS = {
    "retain": "保留位数",
    "replace": "替换字符",
    "random": "随机映射",
}


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def _print_banner():
    banner = r"""
  ____        _          __  __           _    
 |  _ \  __ _| |_ __ _  |  \/  | __ _ ___| | __
 | | | |/ _` | __/ _` | | |\/| |/ _` / __| |/ /
 | |_| | (_| | || (_| | | |  | | (_| \__ \   < 
 |____/ \__,_|\__\__,_| |_|  |_|\__,_|___/_|\_\
                                                
"""
    click.echo(_c(banner, Fore.CYAN))
    click.echo(_c("  数据要素样本脱敏工具 - 演示样本上架前处理  v1.0.0", Fore.CYAN))
    click.echo()


def _load_config(config_path: Optional[str]) -> MaskConfig:
    try:
        return MaskConfig.load(config_path)
    except ValueError as e:
        click.echo(_c(f"❌ 配置加载失败: {e}", Fore.RED), err=True)
        sys.exit(1)


def _parse_strategy_overrides(strategy_opts: List[str]) -> dict:
    overrides = {}
    if not strategy_opts:
        return overrides
    for opt in strategy_opts:
        if "=" not in opt:
            click.echo(_c(f"⚠️  忽略无效策略参数: {opt} (格式应为 TYPE=strategy)", Fore.YELLOW), err=True)
            continue
        sens_type, strategy = opt.split("=", 1)
        sens_type = sens_type.strip().upper()
        strategy = strategy.strip().lower()
        if strategy not in STRATEGY_LABELS:
            click.echo(_c(f"⚠️  无效策略 '{strategy}'，支持: retain|replace|random", Fore.YELLOW), err=True)
            continue
        overrides[sens_type] = strategy
    return overrides


def _print_unknown_format_hint(file_stat, filepath):
    if file_stat.unknown_format_fields:
        click.echo()
        click.echo(_c(f"⚠️  发现 {len(file_stat.unknown_format_fields)} 个无法识别格式的字段", Fore.YELLOW))
        click.echo(_c("   请在配置文件的 field_overrides 中手动指定脱敏规则：", Fore.YELLOW))
        for item in file_stat.unknown_format_fields:
            field = item["field"]
            example = str(item["value"])[:40]
            click.echo(_c(f"   • 字段 '{field}': 示例值='{example}'", Fore.YELLOW))
            click.echo(_c(f"     建议: 在field_overrides中添加 \"{field}\" 配置脱敏策略", Fore.LIGHTBLACK_EX))


def _print_extra_outputs(extra: dict):
    if not extra:
        return
    mapping = [
        ("task_summary", "任务清单摘要 (Markdown)"),
        ("task_summary_md", "任务清单摘要 (Markdown)"),
        ("task_summary_json", "任务清单摘要 (JSON)"),
        ("md_report", "检查报告 (Markdown)"),
        ("report_md", "检查报告 (Markdown)"),
        ("json_report", "检查报告 (JSON)"),
        ("report_json", "检查报告 (JSON)"),
        ("audit_detail", "审计明细表 (Markdown)"),
        ("audit_detail_md", "审计明细表 (Markdown)"),
        ("rule_draft", "规则草稿文件"),
    ]
    rows = []
    seen_paths = set()
    for key, label in mapping:
        path = extra.get(key)
        if not path:
            continue
        if not isinstance(path, str) or not os.path.exists(path):
            continue
        if path in seen_paths:
            continue
        seen_paths.add(path)
        rows.append([_c(label, Fore.LIGHTYELLOW_EX), _c(path, Fore.LIGHTBLUE_EX)])
    if rows:
        click.echo()
        click.echo(_c("📦 产出物清单:", Fore.LIGHTGREEN_EX))
        click.echo(tabulate(rows, headers=["类型", "路径"], tablefmt="simple", stralign="left"))


@click.group()
@click.version_option(version="1.0.0", prog_name="datamask")
def cli():
    """数据要素样本脱敏命令行工具

    供数据运营人员在上架前处理演示样本，支持扫描识别、脱敏处理、
    预览对比和生成报告四种操作。

    \b
    支持格式: CSV (.csv), JSON (.json), Excel (.xlsx/.xls)
    识别类型: 手机号、身份证号、地址、姓名、企业名称、邮箱、银行卡
    脱敏策略: 保留位数(retain)、替换字符(replace)、随机映射(random)
    """
    pass


@cli.command("scan")
@click.option("-i", "--input", "input_path", required=True, type=click.Path(),
              help="输入文件或文件夹路径")
@click.option("-c", "--config", "config_path", default=None, type=click.Path(),
              help="自定义规则配置文件 (JSON)")
@click.option("-r", "--recursive/--no-recursive", default=True,
              help="递归扫描子文件夹 (默认开启)")
@click.option("--min-confidence", type=float, default=None,
              help="最小识别置信度阈值 (0-1, 默认0.6)")
@click.option("-w", "--whitelist", multiple=True,
              help="白名单字段，可多次指定，扫描时跳过")
@click.option("--json-output", is_flag=True, default=False,
              help="以JSON格式输出扫描结果")
@click.option("--strict-draft", is_flag=True, default=False,
              help="严格草稿模式：仅处理草稿中 AUTO_OK 或手工配置的字段，SKIP/NEED_MANUAL 即使被自动识别也跳过")
def scan_cmd(input_path, config_path, recursive, min_confidence, whitelist, json_output, strict_draft):
    """扫描识别文件中的敏感内容

    扫描输入文件或文件夹，识别其中的手机号、证件号、地址、姓名、企业名称等敏感内容，
    输出识别统计和详细结果。
    """
    _print_banner()
    config = _load_config(config_path)
    strategy_overrides = {}
    processor = DataProcessor(config, strategy_overrides, list(whitelist), min_confidence, strict_draft=strict_draft)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件: {input_path}", Fore.YELLOW))
        click.echo(_c(f"   支持格式: {', '.join(SUPPORTED_FORMATS.keys())}", Fore.LIGHTBLACK_EX))
        sys.exit(0)

    click.echo(_c(f"🔍 扫描模式: 识别敏感内容", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)}")
    click.echo(f"   配置: {_c(config.source_file or '默认', Fore.CYAN)}")
    click.echo(f"   文件数: {_c(str(len(files)), Fore.CYAN)}")
    if whitelist:
        click.echo(f"   白名单字段: {_c(', '.join(whitelist), Fore.LIGHTBLACK_EX)}")
    click.echo()

    all_results = {}
    scan_data_list = []

    for fpath in files:
        click.echo(_c(f"─── {os.path.basename(fpath)} ───", Fore.LIGHTCYAN_EX))
        try:
            data, field_types, stat = processor.scan_file(fpath)
            scan_data_list.append((fpath, data, field_types, stat))

            click.echo(f"   格式: {stat.format}  记录数: {stat.total_records}  字段数: {stat.total_fields}")
            click.echo(f"   含敏感记录: {_c(str(stat.records_with_sensitive), Fore.RED)} / {stat.total_records}")

            if field_types:
                click.echo()
                click.echo("   识别字段:")
                table = []
                for fname, stype in field_types.items():
                    count = stat.sensitive_fields.get(fname, 0)
                    table.append([
                        _c(fname, Fore.CYAN),
                        _c(TYPE_LABELS.get(stype, stype), Fore.YELLOW),
                        str(count),
                    ])
                click.echo(tabulate(table, headers=["字段名", "敏感类型", "命中数"],
                                    tablefmt="simple", stralign="left"))

            if stat.sens_type_counts:
                click.echo()
                click.echo("   敏感类型分布:")
                type_table = []
                for stype, cnt in stat.sens_type_counts.most_common():
                    type_table.append([_c(TYPE_LABELS.get(stype, stype), Fore.MAGENTA), str(cnt)])
                click.echo(tabulate(type_table, headers=["类型", "数量"],
                                    tablefmt="simple", stralign="left"))

            _print_unknown_format_hint(stat, fpath)

            all_results[fpath] = {
                "filepath": fpath,
                "format": stat.format,
                "total_records": stat.total_records,
                "records_with_sensitive": stat.records_with_sensitive,
                "field_types": field_types,
                "sens_type_counts": dict(stat.sens_type_counts),
                "unknown_fields": stat.unknown_format_fields,
            }

        except UnsupportedFormatError as e:
            click.echo(_c(f"   ⚠️  跳过: {e}", Fore.YELLOW))
        except FileReadError as e:
            click.echo(_c(f"   ❌ 读取失败: {e.reason}", Fore.RED))
        except Exception as e:
            click.echo(_c(f"   ❌ 处理错误: {e}", Fore.RED))
        click.echo()

    total_files = len(files)
    total_records = sum(s.total_records for _, _, _, s in scan_data_list)
    total_sens = sum(s.records_with_sensitive for _, _, _, s in scan_data_list)
    click.echo(_c("=" * 60, Fore.CYAN))
    click.echo(_c(f"📊 扫描完成", Fore.GREEN))
    click.echo(f"   文件: {total_files}  记录: {total_records}  含敏感: {_c(str(total_sens), Fore.RED)}")

    if json_output:
        click.echo()
        click.echo(_c("--- JSON OUTPUT ---", Fore.LIGHTBLACK_EX))
        click.echo(json.dumps(all_results, ensure_ascii=False, indent=2))


@cli.command("mask")
@click.option("-i", "--input", "input_path", required=True, type=click.Path(),
              help="输入文件或文件夹路径")
@click.option("-o", "--output", "output_dir", required=True, type=click.Path(),
              help="脱敏后文件输出目录")
@click.option("-c", "--config", "config_path", default=None, type=click.Path(),
              help="自定义规则配置文件 (JSON)")
@click.option("-r", "--recursive/--no-recursive", default=True,
              help="递归处理子文件夹 (默认开启)")
@click.option("-s", "--strategy", "strategy_opts", multiple=True,
              help="命令行覆写策略，格式: TYPE=retain|replace|random (如: PHONE=random)")
@click.option("--min-confidence", type=float, default=None,
              help="最小识别置信度阈值 (0-1)")
@click.option("-w", "--whitelist", multiple=True,
              help="白名单字段，跳过脱敏处理，可多次指定")
@click.option("--dry-run", is_flag=True, default=False,
              help="仅处理不写入文件，用于预检查")
@click.option("--no-report", is_flag=True, default=False,
              help="不生成报告文件")
@click.option("--strict-draft", is_flag=True, default=False,
              help="严格草稿模式：仅处理草稿中 AUTO_OK 或手工配置的字段")
def mask_cmd(input_path, output_dir, config_path, recursive, strategy_opts,
             min_confidence, whitelist, dry_run, no_report, strict_draft):
    """按规则脱敏处理文件并输出到指定目录

    批量处理输入文件，按保留位数、替换字符或随机映射方式脱敏敏感内容，
    输出脱敏后的文件到指定目录，自动生成处理检查报告。
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence, strict_draft=strict_draft)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    out_abs = os.path.abspath(output_dir)
    if not dry_run:
        os.makedirs(out_abs, exist_ok=True)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件: {input_path}", Fore.YELLOW))
        click.echo(_c(f"   支持格式: {', '.join(SUPPORTED_FORMATS.keys())}", Fore.LIGHTBLACK_EX))
        sys.exit(0)

    click.echo(_c(f"🛡️  脱敏模式: {'[试运行] ' if dry_run else ''}处理敏感内容", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)}")
    click.echo(f"   输出: {_c(output_dir, Fore.CYAN)} {'(不写入)' if dry_run else ''}")
    click.echo(f"   配置: {_c(config.source_file or '默认', Fore.CYAN)}")
    if overrides:
        click.echo(f"   策略覆写: {_c(json.dumps(overrides, ensure_ascii=False), Fore.YELLOW)}")
    click.echo(f"   文件数: {_c(str(len(files)), Fore.CYAN)}")
    if whitelist:
        click.echo(f"   白名单字段: {_c(', '.join(whitelist), Fore.LIGHTBLACK_EX)}")
    click.echo()

    report_formats = tuple() if no_report else ("markdown", "json")

    report = processor.process_folder(
        folder=input_abs,
        output_dir=out_abs,
        operation="mask",
        recursive=recursive,
        dry_run=dry_run,
        report_formats=report_formats,
    )

    for fstat in report.files:
        fname = os.path.basename(fstat.filepath)
        if fstat.errors:
            click.echo(_c(f"❌ {fname}: {fstat.errors[0][:80]}", Fore.RED))
        else:
            pct = (fstat.records_with_sensitive / fstat.total_records * 100) if fstat.total_records else 0
            click.echo(_c(f"✅ {fname}", Fore.GREEN)
                       + _c(f"  记录:{fstat.total_records}", Fore.CYAN)
                       + _c(f"  敏感:{fstat.records_with_sensitive}({pct:.0f}%)", Fore.MAGENTA)
                       + _c(f"  脱敏单元格:{fstat.masked_cells}", Fore.YELLOW))
            _print_unknown_format_hint(fstat, fstat.filepath)

    click.echo()
    click.echo(_c("=" * 60, Fore.CYAN))
    click.echo(_c(f"🏁 处理完成 ({report.duration:.2f}秒)", Fore.GREEN))
    click.echo(f"   文件: 成功{report.success_files} 失败{report.failed_files} 跳过{report.skipped_files}")
    agg = report.aggregate
    click.echo(f"   记录总数: {agg.get('total_records', 0)}")
    click.echo(f"   脱敏单元格: {_c(str(agg.get('total_masked_cells', 0)), Fore.CYAN)}")
    if agg.get("unknown_format_count", 0):
        click.echo(_c(f"   ⚠️  未识别格式字段: {agg['unknown_format_count']}", Fore.YELLOW))
    if agg.get("low_confidence_count", 0):
        click.echo(_c(f"   ⚠️  低置信度项目: {agg['low_confidence_count']}", Fore.YELLOW))

    if not dry_run:
        _print_extra_outputs(getattr(report, "extra_outputs", None) or {})

    if report.failed_files or report.total_errors:
        sys.exit(2)


@cli.command("preview")
@click.option("-i", "--input", "input_path", required=True, type=click.Path(),
              help="输入文件或文件夹路径")
@click.option("-c", "--config", "config_path", default=None, type=click.Path(),
              help="自定义规则配置文件 (JSON)")
@click.option("-r", "--recursive/--no-recursive", default=True,
              help="递归处理子文件夹")
@click.option("-s", "--strategy", "strategy_opts", multiple=True,
              help="命令行覆写策略，格式: TYPE=strategy")
@click.option("--min-confidence", type=float, default=None,
              help="最小识别置信度阈值")
@click.option("-w", "--whitelist", multiple=True, help="白名单字段")
@click.option("-n", "--rows", type=int, default=5, show_default=True,
              help="rows 模式下每个文件预览的行数")
@click.option("--mode", "preview_mode",
              type=click.Choice(["rows", "by-type"]),
              default="rows", show_default=True,
              help="预览模式: rows=前N行逐列对比; by-type=按敏感类型汇总抽样")
@click.option("--per-type", "per_type", type=int, default=5, show_default=True,
              help="by-type 模式下每种敏感类型最多抽样条数")
@click.option("--strict-draft", is_flag=True, default=False,
              help="严格草稿模式：仅处理草稿中 AUTO_OK 或手工配置的字段")
def preview_cmd(input_path, config_path, recursive, strategy_opts,
                min_confidence, whitelist, rows, preview_mode, per_type, strict_draft):
    """展示脱敏前后的对比预览

    两种预览模式：
    • rows 模式：对前 N 行数据逐列展示原始值和脱敏值对比
    • by-type 模式：按敏感类型汇总抽样，每类最多 N 条原值/脱敏值对照，
      适合正式上架前按类型确认效果
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence, strict_draft=strict_draft)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件", Fore.YELLOW))
        sys.exit(0)

    mode_label = f"前{rows}行逐列对比" if preview_mode == "rows" else f"按敏感类型汇总抽样 (每类最多{per_type}条)"
    click.echo(_c(f"👀 预览模式: {mode_label}", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)}")
    click.echo()

    if preview_mode == "by-type":
        global_samples: dict = {}

    for fpath in files:
        click.echo(_c(f"{'=' * 70}", Fore.LIGHTCYAN_EX))
        click.echo(_c(f"📄 {os.path.basename(fpath)}", Fore.LIGHTCYAN_EX))
        try:
            data, field_types, stat = processor.scan_file(fpath)
            if not data.records:
                click.echo(_c("   (空文件)", Fore.LIGHTBLACK_EX))
                continue

            if preview_mode == "rows":
                diff_rows = processor.preview_diff(data, field_types, rows)

                display_fields = []
                for f in data.fields:
                    if f in field_types or f in whitelist:
                        display_fields.append(f)
                if not display_fields:
                    display_fields = data.fields[:5]

                for diff_row in diff_rows:
                    row_num = diff_row["__row__"]
                    click.echo()
                    click.echo(_c(f"   ── 第 {row_num} 行 ──", Fore.LIGHTBLACK_EX))
                    table = []
                    for fname in display_fields:
                        info = diff_row.get(fname, {})
                        orig = str(info.get("original", ""))[:30]
                        masked = str(info.get("masked", ""))[:30]
                        changed = info.get("changed", False)
                        rule = info.get("rule", "")
                        stype = TYPE_LABELS.get(field_types.get(fname, ""),
                                                field_types.get(fname, ""))
                        mark = _c(" ⚑", Fore.MAGENTA) if changed else ""
                        stype_col = _c(stype, Fore.LIGHTMAGENTA_EX) if stype else ""
                        orig_col = _c(orig, Fore.RED) if changed else orig
                        masked_col = _c(masked, Fore.GREEN) if changed else masked
                        rule_col = _c(rule or "", Fore.LIGHTBLACK_EX)
                        table.append([fname, stype_col, orig_col, masked_col, rule_col])
                    click.echo(tabulate(
                        table,
                        headers=["字段", "类型", "原始", "脱敏后", "规则"],
                        tablefmt="simple", stralign="left"
                    ))
                _print_unknown_format_hint(stat, fpath)
            else:
                samples = processor.sample_by_sens_type(data, field_types, per_type=per_type)
                if preview_mode == "by-type" and samples:
                    for stype, entries in samples.items():
                        if stype not in global_samples:
                            global_samples[stype] = []
                        for e in entries[:per_type]:
                            e2 = dict(e)
                            e2["source_file"] = os.path.basename(fpath)
                            global_samples[stype].append(e2)

                if not samples:
                    click.echo(_c("   未发现敏感数据", Fore.LIGHTBLACK_EX))
                else:
                    for stype, entries in samples.items():
                        label = TYPE_LABELS.get(stype, stype)
                        click.echo()
                        click.echo(_c(f"   ▣ {label} ({stype}) 共 {len(entries)} 条样例", Fore.MAGENTA))
                        table = []
                        for idx, e in enumerate(entries[:per_type], 1):
                            orig = str(e.get("original", ""))[:35]
                            masked = str(e.get("masked", ""))[:35]
                            rule = str(e.get("rule", ""))
                            table.append([
                                str(idx),
                                e.get("field", ""),
                                _c(orig, Fore.RED),
                                _c(masked, Fore.GREEN),
                                _c(rule, Fore.LIGHTBLACK_EX),
                            ])
                        click.echo(tabulate(
                            table,
                            headers=["#", "字段", "原始", "脱敏后", "规则"],
                            tablefmt="simple", stralign="left"
                        ))
                    _print_unknown_format_hint(stat, fpath)

        except UnsupportedFormatError as e:
            click.echo(_c(f"   ⚠️  跳过: {e}", Fore.YELLOW))
        except FileReadError as e:
            click.echo(_c(f"   ❌ 读取失败: {e.reason}", Fore.RED))
        except Exception as e:
            click.echo(_c(f"   ❌ 处理错误: {e}", Fore.RED))
        click.echo()

    if preview_mode == "by-type" and global_samples and len(files) > 1:
        click.echo(_c("═" * 70, Fore.LIGHTYELLOW_EX))
        click.echo(_c(f"📊 跨文件按敏感类型汇总抽样 (每类最多 {per_type} 条)", Fore.LIGHTYELLOW_EX))
        for stype, entries in sorted(global_samples.items(), key=lambda x: -len(x[1])):
            label = TYPE_LABELS.get(stype, stype)
            deduped = []
            seen_keys = set()
            for e in entries:
                k = (e.get("original"), e.get("masked"))
                if k in seen_keys:
                    continue
                seen_keys.add(k)
                deduped.append(e)
                if len(deduped) >= per_type:
                    break
            click.echo()
            click.echo(_c(f"   ▣ {label} ({stype}) 展示 {len(deduped)} 条", Fore.MAGENTA))
            table = []
            for idx, e in enumerate(deduped, 1):
                orig = str(e.get("original", ""))[:35]
                masked = str(e.get("masked", ""))[:35]
                rule = str(e.get("rule", ""))
                table.append([
                    str(idx),
                    _c(str(e.get("source_file", "")), Fore.CYAN),
                    e.get("field", ""),
                    _c(orig, Fore.RED),
                    _c(masked, Fore.GREEN),
                    _c(rule, Fore.LIGHTBLACK_EX),
                ])
            click.echo(tabulate(
                table,
                headers=["#", "文件", "字段", "原始", "脱敏后", "规则"],
                tablefmt="simple", stralign="left"
            ))


@cli.command("report")
@click.option("-i", "--input", "input_path", required=True, type=click.Path(),
              help="输入文件或文件夹路径")
@click.option("-o", "--output", "output_dir", required=True, type=click.Path(),
              help="报告输出目录")
@click.option("-c", "--config", "config_path", default=None, type=click.Path(),
              help="自定义规则配置文件 (JSON)")
@click.option("-r", "--recursive/--no-recursive", default=True,
              help="递归处理子文件夹")
@click.option("-s", "--strategy", "strategy_opts", multiple=True,
              help="命令行覆写策略，格式: TYPE=strategy")
@click.option("--min-confidence", type=float, default=None,
              help="最小识别置信度阈值")
@click.option("-w", "--whitelist", multiple=True, help="白名单字段")
@click.option("--format", "report_format",
              type=click.Choice(["all", "markdown", "json", "both"]),
              default="both", show_default=True, help="报告输出格式")
@click.option("--strict-draft", is_flag=True, default=False,
              help="严格草稿模式：仅处理草稿中 AUTO_OK 或手工配置的字段")
def report_cmd(input_path, output_dir, config_path, recursive, strategy_opts,
               min_confidence, whitelist, report_format, strict_draft):
    """生成完整的处理检查报告（不写入脱敏文件）

    对输入数据执行完整扫描检查，生成包含处理数量、敏感类型分布、
    风险项清单和问题建议的 Markdown 和 JSON 检查报告。
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence, strict_draft=strict_draft)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    out_abs = os.path.abspath(output_dir)
    os.makedirs(out_abs, exist_ok=True)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件", Fore.YELLOW))
        sys.exit(0)

    click.echo(_c(f"📋 报告模式: 生成脱敏处理检查报告", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)}")
    click.echo(f"   输出: {_c(output_dir, Fore.CYAN)}")
    click.echo(f"   文件数: {_c(str(len(files)), Fore.CYAN)}")
    click.echo()

    formats = []
    if report_format in ("markdown", "all", "both"):
        formats.append("markdown")
    if report_format in ("json", "all", "both"):
        formats.append("json")

    report = processor.process_folder(
        folder=input_abs,
        output_dir=out_abs,
        operation="report",
        recursive=recursive,
        dry_run=True,
        report_formats=tuple(formats),
    )

    agg = report.aggregate
    click.echo(_c("─" * 50, Fore.CYAN))
    click.echo(_c("📊 报告摘要", Fore.LIGHTGREEN_EX))
    click.echo(f"   处理文件: 成功{report.success_files} 失败{report.failed_files} 跳过{report.skipped_files}")
    click.echo(f"   处理记录: {agg.get('total_records', 0)}")
    click.echo(f"   含敏感记录: {agg.get('records_with_sensitive', 0)}")
    click.echo(f"   脱敏单元格: {agg.get('total_masked_cells', 0)}")
    click.echo()

    if agg.get("sensitive_type_counts"):
        click.echo(_c("敏感类型统计:", Fore.LIGHTMAGENTA_EX))
        for t, c in sorted(agg["sensitive_type_counts"].items(), key=lambda x: -x[1]):
            click.echo(f"   {TYPE_LABELS.get(t, t):<8}: {_c(str(c), Fore.YELLOW)}")
        click.echo()

    if agg.get("unknown_format_count", 0):
        click.echo(_c(f"⚠️  未识别格式字段: {agg['unknown_format_count']}", Fore.YELLOW))
        click.echo(_c("   建议: 在配置文件 field_overrides 中为这些字段手动指定规则", Fore.LIGHTBLACK_EX))
        for fstat in report.files:
            for item in fstat.unknown_format_fields[:5]:
                click.echo(_c(
                    f"   • 文件[{os.path.basename(fstat.filepath)}] "
                    f"字段='{item['field']}' 示例='{str(item['value'])[:30]}'",
                    Fore.LIGHTYELLOW_EX
                ))
        click.echo()

    if report.total_errors:
        click.echo(_c("❌ 错误清单:", Fore.RED))
        for e in report.total_errors[:10]:
            click.echo(_c(f"   - {e[:100]}", Fore.RED))

    click.echo(_c("=" * 60, Fore.CYAN))
    _print_extra_outputs(getattr(report, "extra_outputs", None) or {})


@cli.group("rules")
def rules_cmd():
    """规则模板与草稿管理

    提供规则模板导出、基于现有数据生成可编辑规则草稿等功能，
    方便运营人员先确认字段含义再执行 scan/preview/mask。
    """
    pass


@rules_cmd.command("export")
@click.option("-o", "--output", "output_path", required=True, type=click.Path(),
              help="模板输出路径 (JSON文件)")
@click.option("--with-comments/--no-comments", default=True, show_default=True,
              help="是否在模板中附带详细说明和示例字段 (# 开头的注释字段)")
def rules_export_cmd(output_path, with_comments):
    """导出默认规则模板 (含说明和示例)

    导出一份可编辑的规则模板，包含各敏感类型的默认脱敏策略、
    字段级覆写示例、白名单字段和说明注释。运营人员可以在此基础上修改后
    作为其他命令的 -c 配置文件使用。
    """
    _print_banner()
    config = MaskConfig.load(None)
    out_abs = os.path.abspath(output_path)
    try:
        config.export_template(out_abs, with_comments=with_comments)
    except OSError as e:
        click.echo(_c(f"❌ 写入失败: {e}", Fore.RED), err=True)
        sys.exit(1)
    click.echo(_c("📤 规则模板已导出:", Fore.LIGHTGREEN_EX))
    click.echo(_c(f"   📄 {out_abs}", Fore.LIGHTBLUE_EX))
    if with_comments:
        click.echo()
        click.echo(_c("💡 编辑提示:", Fore.LIGHTYELLOW_EX))
        click.echo(_c("   • # 开头的字段是说明注释，不影响实际运行", Fore.LIGHTBLACK_EX))
        click.echo(_c("   • field_overrides 中按示例填写需要强制指定规则的字段", Fore.LIGHTBLACK_EX))
        click.echo(_c("   • 编辑完成后用 -c <文件> 传入其他命令使用", Fore.LIGHTBLACK_EX))


@rules_cmd.command("draft")
@click.option("-i", "--input", "input_path", required=True, type=click.Path(),
              help="输入文件或文件夹，用于扫描并生成草稿")
@click.option("-o", "--output", "output_path", required=True, type=click.Path(),
              help="草稿输出路径 (JSON文件)")
@click.option("-c", "--config", "config_path", default=None, type=click.Path(),
              help="基础规则配置（可选，草稿会在此基础上补充字段建议）")
@click.option("-r", "--recursive/--no-recursive", default=True,
              help="递归扫描子文件夹 (默认开启)")
@click.option("--min-confidence", type=float, default=None,
              help="最小识别置信度阈值")
@click.option("-w", "--whitelist", multiple=True, help="白名单字段")
def rules_draft_cmd(input_path, output_path, config_path, recursive, min_confidence, whitelist):
    """基于数据扫描结果生成可编辑的规则草稿

    扫描输入文件（或文件夹），按系统识别结果生成一份规则草稿：
    • 自动识别的字段标注 status=AUTO_OK，可直接使用
    • 疑似敏感但不确定的字段标注 status=NEED_MANUAL，需运营人工补 sens_type
    • 非敏感字段标注 status=SKIP_NON_SENSITIVE，不会被处理

    草稿用文本编辑器修改确认后，作为其他命令的 -c 配置文件传入即可。
    """
    _print_banner()
    config = _load_config(config_path)
    strategy_overrides = {}
    processor = DataProcessor(config, strategy_overrides, list(whitelist), min_confidence)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件: {input_path}", Fore.YELLOW))
        click.echo(_c(f"   支持格式: {', '.join(SUPPORTED_FORMATS.keys())}", Fore.LIGHTBLACK_EX))
        sys.exit(0)

    click.echo(_c("📝 草稿生成模式: 基于扫描结果生成规则", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)} (共{len(files)}个文件)")
    click.echo(f"   输出: {_c(output_path, Fore.CYAN)}")
    click.echo()

    all_scans = []
    all_field_types: dict = {}
    for fpath in files:
        fname = os.path.basename(fpath)
        click.echo(_c(f"   🔍 扫描 {fname} ...", Fore.LIGHTCYAN_EX))
        try:
            data, field_types, stat = processor.scan_file(fpath)
            all_scans.append((fpath, data, field_types, stat))
            for k, v in field_types.items():
                all_field_types[k] = v
            pct = (stat.records_with_sensitive / stat.total_records * 100) if stat.total_records else 0
            click.echo(_c(f"      ✅ 记录{stat.total_records} 敏感{stat.records_with_sensitive}({pct:.0f}%)",
                          Fore.LIGHTBLACK_EX))
        except UnsupportedFormatError as e:
            click.echo(_c(f"      ⚠️  跳过: {e}", Fore.YELLOW))
        except FileReadError as e:
            click.echo(_c(f"      ❌ 读取失败: {e.reason}", Fore.RED))
        except Exception as e:
            click.echo(_c(f"      ❌ 错误: {e}", Fore.RED))

    click.echo()
    if not all_scans:
        click.echo(_c("❌ 没有成功扫描到任何文件，草稿未生成", Fore.RED), err=True)
        sys.exit(1)

    draft = processor.build_rule_draft(
        scans=all_scans,
        base_config=config,
        source_path=input_abs,
    )

    out_abs = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
    try:
        with open(out_abs, "w", encoding="utf-8") as f:
            json.dump(draft, f, ensure_ascii=False, indent=2)
    except OSError as e:
        click.echo(_c(f"❌ 写入草稿失败: {e}", Fore.RED), err=True)
        sys.exit(1)

    stats = {"AUTO_OK": 0, "NEED_MANUAL": 0, "SKIP_NON_SENSITIVE": 0}
    for entry in draft.get("field_overrides", {}).values():
        s = entry.get("status", "CUSTOM")
        if s in stats:
            stats[s] += 1

    click.echo(_c("=" * 50, Fore.CYAN))
    click.echo(_c("✅ 规则草稿已生成:", Fore.LIGHTGREEN_EX))
    click.echo(_c(f"   📄 {out_abs}", Fore.LIGHTBLUE_EX))
    click.echo()
    click.echo(_c("📊 字段状态统计:", Fore.LIGHTMAGENTA_EX))
    click.echo(f"   自动识别 (AUTO_OK)        : {_c(str(stats['AUTO_OK']), Fore.GREEN)} 个")
    click.echo(f"   需人工补充 (NEED_MANUAL)  : {_c(str(stats['NEED_MANUAL']), Fore.YELLOW)} 个")
    click.echo(f"   非敏感 (SKIP_NON_SENSITIVE): {_c(str(stats['SKIP_NON_SENSITIVE']), Fore.LIGHTBLACK_EX)} 个")
    click.echo()
    click.echo(_c("💡 下一步建议:", Fore.LIGHTYELLOW_EX))
    click.echo(_c("   1. 打开草稿，查找 status=NEED_MANUAL 的字段补充 sens_type", Fore.LIGHTBLACK_EX))
    click.echo(_c("   2. 根据业务需要修改各字段的 strategy / keep_start / keep_end 等", Fore.LIGHTBLACK_EX))
    click.echo(_c("   3. 确认无误后： python main.py preview -i 输入 -c 草稿 --mode by-type", Fore.LIGHTBLACK_EX))
    click.echo(_c("   4. 最终执行： python main.py mask -i 输入 -o 输出 -c 草稿", Fore.LIGHTBLACK_EX))


@rules_cmd.command("validate")
@click.option("-c", "--config", "config_path", required=True, type=click.Path(),
              help="待校验的规则配置/草稿文件 (JSON)")
@click.option("--json-output", is_flag=True, default=False,
              help="以JSON格式输出校验结果")
def rules_validate_cmd(config_path, json_output):
    """校验规则配置/草稿的合法性

    检查内容：
    • sens_type 是否为标准类型
    • strategy 策略是否合法、参数是否完整
    • 白名单与字段规则是否冲突
    • 草稿中需要人工补充的字段

    输出分类：
    ✅ 可直接使用 / ⚠️ 有警告 / ❌ 有错误 / ⏭️  已跳过 / 📝 待人工补充
    """
    _print_banner()
    config = _load_config(config_path)
    result = config.validate()

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        if not result["valid"]:
            sys.exit(1)
        return

    stats = result["stats"]
    click.echo(_c("🔍 规则校验", Fore.GREEN))
    click.echo(f"   配置文件: {_c(config_path, Fore.CYAN)}")
    click.echo()

    overall_status = _c("✅ 通过", Fore.GREEN) if result["valid"] else _c("❌ 存在错误", Fore.RED)
    click.echo(_c("─" * 50, Fore.CYAN))
    click.echo(f"   整体结论: {overall_status}")
    click.echo()

    click.echo(_c("📊 统计概览:", Fore.LIGHTMAGENTA_EX))
    click.echo(f"   类型规则 (type_rules)    : {stats['type_rules_ok']}/{stats['type_rules_total']} 有效")
    click.echo(f"   字段规则总数              : {stats['field_overrides_total']}")
    click.echo(f"   ✅ 可直接使用              : {_c(str(stats['fields_ok']), Fore.GREEN)}")
    click.echo(f"   ⚠️  有警告                  : {_c(str(stats['fields_warning']), Fore.YELLOW)}")
    if stats['fields_error']:
        click.echo(f"   ❌ 有错误                  : {_c(str(stats['fields_error']), Fore.RED)}")
    click.echo(f"   ⏭️  已跳过 (SKIP)           : {_c(str(stats['fields_skipped']), Fore.LIGHTBLACK_EX)}")
    click.echo(f"   📝 待人工补充 (NEED_MANUAL): {_c(str(stats['fields_need_manual']), Fore.LIGHTYELLOW_EX)}")
    click.echo(f"   白名单字段                : {stats['whitelist_count']}")
    if stats['whitelist_conflicts']:
        click.echo(f"   ⚠️  白名单冲突              : {_c(str(stats['whitelist_conflicts']), Fore.YELLOW)}")
    click.echo()

    field_status = result["field_status"]
    if field_status:
        click.echo(_c("📋 字段状态明细:", Fore.LIGHTMAGENTA_EX))
        rows = []
        status_colors = {
            "OK": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SKIPPED": Fore.LIGHTBLACK_EX,
            "NEED_MANUAL": Fore.LIGHTYELLOW_EX,
        }
        status_labels = {
            "OK": "✅ 可用",
            "WARNING": "⚠️  警告",
            "ERROR": "❌ 错误",
            "SKIPPED": "⏭️  跳过",
            "NEED_MANUAL": "📝 待补充",
        }
        meta = config.draft_field_meta
        for fname in sorted(field_status.keys()):
            st = field_status[fname]
            stype = ""
            if fname in config.field_overrides:
                stype = config.field_overrides[fname].get("sens_type", "")
            elif fname in meta:
                stype = str(meta[fname].get("detected_type") or "")
            label = status_labels.get(st, st)
            color = status_colors.get(st, Fore.WHITE)
            rows.append([
                _c(label, color),
                fname,
                stype or "-",
            ])
        click.echo(tabulate(rows, headers=["状态", "字段名", "敏感类型"],
                            tablefmt="simple", stralign="left"))
        click.echo()

    issues = result["issues"]
    if issues:
        click.echo(_c("🔔 问题清单:", Fore.LIGHTMAGENTA_EX))
        level_order = ["error", "warning", "info"]
        level_labels = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}
        level_colors = {"error": Fore.RED, "warning": Fore.YELLOW, "info": Fore.LIGHTBLACK_EX}
        for level in level_order:
            level_issues = [i for i in issues if i["level"] == level]
            if not level_issues:
                continue
            for iss in level_issues[:20]:
                icon = level_labels.get(level, "")
                color = level_colors.get(level, Fore.WHITE)
                msg = iss["message"]
                field = iss.get("field", "")
                category = iss.get("category", "")
                prefix = f"   {icon} [{category}] {field}" if field else f"   {icon} [{category}]"
                click.echo(_c(prefix, color))
                click.echo(_c(f"      {msg}", Fore.LIGHTBLACK_EX))
            if len(level_issues) > 20:
                click.echo(_c(f"   ... 还有 {len(level_issues) - 20} 条同级别问题", Fore.LIGHTBLACK_EX))
        click.echo()

    click.echo(_c("💡 操作建议:", Fore.LIGHTYELLOW_EX))
    if not result["valid"]:
        click.echo(_c("   存在错误项，请先修复 ❌ 标记的字段后再使用", Fore.LIGHTBLACK_EX))
    elif stats["fields_need_manual"] > 0:
        click.echo(_c("   有字段需要人工确认，请补充 NEED_MANUAL 字段的 sens_type", Fore.LIGHTBLACK_EX))
    else:
        click.echo(_c("   配置校验通过，可直接用于 scan/preview/mask/report", Fore.LIGHTBLACK_EX))
    click.echo()

    if not result["valid"]:
        sys.exit(1)


def main():
    try:
        cli(standalone_mode=True)
    except KeyboardInterrupt:
        click.echo()
        click.echo(_c("⏹️  操作已取消", Fore.YELLOW))
        sys.exit(130)
    except Exception as e:
        click.echo(_c(f"\n💥 未处理异常: {e}", Fore.RED), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
