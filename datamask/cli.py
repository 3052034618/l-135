# -*- coding: utf-8 -*-
"""
命令行入口 - 数据要素样本脱敏工具
四个命令: scan, mask, preview, report
"""
import os
import sys
import json
from pathlib import Path
from typing import List, Optional

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
def scan_cmd(input_path, config_path, recursive, min_confidence, whitelist, json_output):
    """扫描识别文件中的敏感内容

    扫描输入文件或文件夹，识别其中的手机号、证件号、地址、姓名、企业名称等敏感内容，
    输出识别统计和详细结果。
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
def mask_cmd(input_path, output_dir, config_path, recursive, strategy_opts,
             min_confidence, whitelist, dry_run, no_report):
    """按规则脱敏处理文件并输出到指定目录

    批量处理输入文件，按保留位数、替换字符或随机映射方式脱敏敏感内容，
    输出脱敏后的文件到指定目录，自动生成处理检查报告。
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence)

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

    if not dry_run and not no_report:
        report_dir = os.path.join(out_abs, "_reports")
        task_id = report.task_id
        click.echo()
        click.echo(_c("📋 报告已生成:", Fore.LIGHTGREEN_EX))
        click.echo(_c(f"   Markdown: {os.path.join(report_dir, f'report_{task_id}.md')}", Fore.LIGHTBLUE_EX))
        click.echo(_c(f"   JSON:     {os.path.join(report_dir, f'report_{task_id}.json')}", Fore.LIGHTBLUE_EX))

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
              help="每个文件预览的行数")
def preview_cmd(input_path, config_path, recursive, strategy_opts,
                min_confidence, whitelist, rows):
    """展示脱敏前后的对比预览

    对前N行数据展示原始值和脱敏后值的逐列对比，方便在正式脱敏前确认效果。
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence)

    input_abs = os.path.abspath(input_path)
    if not os.path.exists(input_abs):
        click.echo(_c(f"❌ 输入路径不存在: {input_path}", Fore.RED), err=True)
        sys.exit(1)

    files = get_supported_files(input_path, recursive)
    if not files:
        click.echo(_c(f"⚠️  未找到支持的文件", Fore.YELLOW))
        sys.exit(0)

    click.echo(_c(f"👀 预览模式: 脱敏前后对比 (前{rows}行)", Fore.GREEN))
    click.echo(f"   输入: {_c(input_path, Fore.CYAN)}")
    click.echo()

    for fpath in files:
        click.echo(_c(f"{'=' * 70}", Fore.LIGHTCYAN_EX))
        click.echo(_c(f"📄 {os.path.basename(fpath)}", Fore.LIGHTCYAN_EX))
        try:
            data, field_types, stat = processor.scan_file(fpath)
            if not data.records:
                click.echo(_c("   (空文件)", Fore.LIGHTBLACK_EX))
                continue

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

        except UnsupportedFormatError as e:
            click.echo(_c(f"   ⚠️  跳过: {e}", Fore.YELLOW))
        except FileReadError as e:
            click.echo(_c(f"   ❌ 读取失败: {e.reason}", Fore.RED))
        except Exception as e:
            click.echo(_c(f"   ❌ 处理错误: {e}", Fore.RED))
        click.echo()


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
def report_cmd(input_path, output_dir, config_path, recursive, strategy_opts,
               min_confidence, whitelist, report_format):
    """生成完整的处理检查报告（不写入脱敏文件）

    对输入数据执行完整扫描检查，生成包含处理数量、敏感类型分布、
    风险项清单和问题建议的 Markdown 和 JSON 检查报告。
    """
    _print_banner()
    config = _load_config(config_path)
    overrides = _parse_strategy_overrides(strategy_opts)
    processor = DataProcessor(config, overrides, list(whitelist), min_confidence)

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

    report = processor.process_folder(
        folder=input_abs,
        output_dir=out_abs,
        operation="scan",
        recursive=recursive,
        dry_run=True,
        report_formats=(),
    )

    task_id = report.task_id
    formats = []
    if report_format in ("markdown", "all", "both"):
        formats.append("markdown")
    if report_format in ("json", "all", "both"):
        formats.append("json")

    report_paths = []
    if "markdown" in formats:
        p = os.path.join(out_abs, f"scan_report_{task_id}.md")
        ReportGenerator.generate_markdown(report, p)
        report_paths.append(p)
    if "json" in formats:
        p = os.path.join(out_abs, f"scan_report_{task_id}.json")
        ReportGenerator.generate_json(report, p)
        report_paths.append(p)

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
    click.echo(_c("✅ 报告已生成:", Fore.GREEN))
    for p in report_paths:
        click.echo(_c(f"   📄 {p}", Fore.LIGHTBLUE_EX))


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
