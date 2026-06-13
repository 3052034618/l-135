# -*- coding: utf-8 -*-
"""
主处理流程 - 协调检测、脱敏、报告
"""
import os
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable, Set

from .detector import (
    detect_record, detect_value, detect_value_best, SensitiveMatch, DetectorResult,
    SENSITIVE_TYPES,
)
from .masker import MaskEngine, MaskResult
from .fileio import (
    read_file, write_file, get_supported_files,
    DataFile, UnsupportedFormatError, FileReadError, FileWriteError,
    SUPPORTED_FORMATS,
)
from .config import MaskConfig
from .report import ProcessReport, FileProcessStat, ReportGenerator


TYPE_LABELS = {
    "PHONE": "手机号",
    "ID_CARD": "身份证号",
    "BANK_CARD": "银行卡号",
    "NAME": "姓名",
    "EMAIL": "电子邮箱",
    "COMPANY": "企业名称",
    "ADDRESS": "地址",
    "FIELD": "自定义字段",
}


def get_output_path(input_path: str, input_root: str, output_dir: str,
                    suffix: str = "_masked") -> str:
    input_path = os.path.abspath(input_path)
    input_root = os.path.abspath(input_root)
    if os.path.isfile(input_root):
        input_root = os.path.dirname(input_root)
    rel = os.path.relpath(input_path, input_root)
    base, ext = os.path.splitext(rel)
    return os.path.join(os.path.abspath(output_dir), f"{base}{suffix}{ext}")


class DataProcessor:
    """数据处理器"""

    def __init__(self, config: MaskConfig,
                 strategy_overrides: Optional[Dict[str, str]] = None,
                 extra_whitelist: Optional[List[str]] = None,
                 min_confidence: Optional[float] = None,
                 strict_draft: bool = False):
        self.config = config
        self.min_conf = min_confidence if min_confidence is not None else config.min_confidence
        self.whitelist = list(config.whitelist_fields)
        if extra_whitelist:
            self.whitelist.extend(extra_whitelist)
        self.engine = config.build_mask_engine(strategy_overrides)
        self.strict_draft = strict_draft

    def _infer_field_types_across_file(
        self, data: DataFile, stat: FileProcessStat
    ) -> Dict[str, str]:
        """跨整文件推断每个字段的敏感类型（仅做投票推断，不做统计计数）"""
        field_votes: Dict[str, Counter] = {}
        field_low_conf: Dict[str, List[Dict[str, Any]]] = {}
        unknown_fields: Dict[str, Counter] = {}

        sample_size = min(len(data.records), 200)
        for idx in range(sample_size):
            record = data.records[idx]
            for field_name, value in record.items():
                if field_name in self.whitelist:
                    continue
                best = detect_value_best(value, field_name, self.min_conf)
                if best:
                    field_votes.setdefault(field_name, Counter())[best.sens_type] += 1
                    if best.confidence < 0.8 and best.confidence >= self.min_conf:
                        field_low_conf.setdefault(field_name, []).append({
                            "row": idx,
                            "value": str(value)[:100],
                            "confidence": best.confidence,
                            "sens_type": best.sens_type,
                        })
                elif value and str(value).strip():
                    unknown_fields.setdefault(field_name, Counter())["non_empty"] += 1

        final_types: Dict[str, str] = {}
        for field_name, votes in field_votes.items():
            best_type, _best_count = votes.most_common(1)[0]
            final_types[field_name] = best_type
            if field_name in field_low_conf:
                stat.low_confidence_items.extend([
                    {"field": field_name, **item} for item in field_low_conf[field_name][:5]
                ])

        for field_name, cnt in unknown_fields.items():
            if field_name in final_types:
                continue
            sample_val = ""
            for r in data.records[:5]:
                v = r.get(field_name)
                if v and str(v).strip():
                    sample_val = str(v)[:60]
                    break
            non_empty_pct = cnt["non_empty"] / max(sample_size, 1)
            if non_empty_pct >= 0.3 and sample_val:
                stat.unknown_format_fields.append({
                    "field": field_name,
                    "non_empty_ratio": round(non_empty_pct, 2),
                    "value": sample_val,
                    "suggestion": "无法自动识别该字段内容格式，请在field_overrides中手动指定脱敏规则",
                })

        return final_types

    def _resolve_confirmed_field_types(
        self, inferred_types: Dict[str, str], data: DataFile
    ) -> Dict[str, str]:
        """应用配置覆盖，得到最终确认的字段类型

        规则：
        1. config.field_overrides 中有 sens_type 的字段 → 手工确认，优先级最高
        2. 自动推断的字段 → 保留，除非被草稿跳过
        3. strict_draft 模式下：草稿中 status=SKIP_NON_SENSITIVE / NEED_MANUAL 的字段，
           即使被自动识别也移除（只保留 AUTO_OK 和 手工配置）
        4. 白名单字段始终不包含
        """
        confirmed: Dict[str, str] = {}
        for fname, stype in inferred_types.items():
            if fname in self.whitelist:
                continue
            confirmed[fname] = stype

        for fname, rule in self.config.field_overrides.items():
            if fname in self.whitelist:
                continue
            stype = rule.get("sens_type")
            if stype:
                confirmed[fname] = stype

        if self.strict_draft and self.config.draft_source:
            meta = self.config.draft_field_meta
            to_remove = []
            for fname in list(confirmed.keys()):
                if fname in self.config.field_overrides:
                    continue
                if fname in meta:
                    status = meta[fname].get("status", "AUTO_OK")
                    if status in ("SKIP_NON_SENSITIVE", "NEED_MANUAL"):
                        to_remove.append(fname)
                elif fname in self.config.skipped_fields:
                    to_remove.append(fname)
            for fname in to_remove:
                confirmed.pop(fname, None)

        return confirmed

    def _adjust_stats_for_confirmed_fields(
        self, data: DataFile, stat: FileProcessStat,
        confirmed_types: Dict[str, str],
    ) -> None:
        """根据确认后的字段类型，调整统计数据

        - 已手工配置的字段：如果 detect 没命中，按非空记录数补命中
        - strict_draft 模式下：被排除的字段，从统计中减去
        - 从 unknown_format_fields 中移除已确认 + 已跳过的字段
        """
        confirmed_set = set(confirmed_types.keys())

        skipped_set = set()
        if self.config.draft_field_meta:
            for fname, meta in self.config.draft_field_meta.items():
                if meta.get("status") == "SKIP_NON_SENSITIVE":
                    skipped_set.add(fname)
        skipped_set.update(self.config.skipped_fields)

        stat.unknown_format_fields = [
            item for item in stat.unknown_format_fields
            if item["field"] not in confirmed_set and item["field"] not in skipped_set
        ]

        for fname, stype in confirmed_types.items():
            if fname in self.config.field_overrides:
                non_empty = 0
                for rec in data.records:
                    v = rec.get(fname)
                    if v is not None and str(v).strip():
                        non_empty += 1
                current = stat.sensitive_fields.get(fname, 0)
                if non_empty > current:
                    delta = non_empty - current
                    stat.sensitive_fields[fname] = non_empty
                    stat.sens_type_counts[stype] += delta

        if self.strict_draft and self.config.draft_source:
            removed_sens: Counter = Counter()
            removed_fields: Counter = Counter()
            removed_records = 0

            inferred_only = set()
            for fname in list(stat.sensitive_fields.keys()):
                if fname not in confirmed_types and fname not in self.whitelist:
                    inferred_only.add(fname)

            for fname in inferred_only:
                cnt = stat.sensitive_fields.pop(fname, 0)
                if cnt <= 0:
                    continue
                removed_fields[fname] = cnt
                for st in list(stat.sens_type_counts.keys()):
                    pass

            original_sens = dict(stat.sens_type_counts)
            stat.sens_type_counts = Counter()
            for fname, stype in confirmed_types.items():
                cnt = stat.sensitive_fields.get(fname, 0)
                if cnt > 0:
                    stat.sens_type_counts[stype] += cnt

            records_with_sensitive = 0
            for rec in data.records:
                has_sens = False
                for fname in confirmed_types:
                    v = rec.get(fname)
                    if v is None or not str(v).strip():
                        continue
                    if fname in self.config.field_overrides:
                        has_sens = True
                        break
                    best = detect_value_best(v, fname, self.min_conf)
                    if best and best.sens_type == confirmed_types.get(fname):
                        has_sens = True
                        break
                if has_sens:
                    records_with_sensitive += 1
            stat.records_with_sensitive = records_with_sensitive

    def scan_file(self, filepath: str,
                  progress_cb: Optional[Callable] = None) -> Tuple[DataFile, Dict[str, str], FileProcessStat]:
        """扫描单个文件 - 类型推断（抽样）+ 全量精确计数（每字段最佳命中）+ 配置覆盖合并"""
        stat = FileProcessStat(filepath=filepath)
        data = read_file(filepath)
        stat.format = data.format
        stat.total_records = data.total_records
        stat.total_fields = len(data.fields)

        inferred_types = self._infer_field_types_across_file(data, stat)

        for idx, record in enumerate(data.records):
            result = detect_record(record, self.whitelist, self.min_conf)
            if result.has_sensitive:
                stat.records_with_sensitive += 1
                for match in result.matches:
                    stat.sens_type_counts[match.sens_type] += 1
                    if match.field_name:
                        stat.sensitive_fields[match.field_name] += 1
            if progress_cb:
                progress_cb("scan", filepath, idx, data.total_records)

        confirmed_types = self._resolve_confirmed_field_types(inferred_types, data)
        self._adjust_stats_for_confirmed_fields(data, stat, confirmed_types)

        return data, confirmed_types, stat

    def mask_file(self, data: DataFile, field_sens_types: Dict[str, str],
                  stat: FileProcessStat,
                  progress_cb: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """对文件进行脱敏，返回脱敏后的记录"""
        masked_records: List[Dict[str, Any]] = []
        for idx, record in enumerate(data.records):
            details = self.engine.mask_record_with_details(
                record, field_sens_types, self.whitelist
            )
            masked_row = {}
            for field, mr in details.items():
                masked_row[field] = mr.masked
                if mr.changed:
                    stat.masked_cells += 1
                    strategy = "default_retain"
                    if mr.rule_used and mr.rule_used.startswith("type:"):
                        t = mr.rule_used.split(":", 1)[1]
                        if t in self.engine.rules:
                            strategy = self.engine.rules[t].strategy
                    elif mr.rule_used and mr.rule_used.startswith("field:"):
                        fname = mr.rule_used.split(":", 1)[1]
                        if fname in self.engine.field_overrides:
                            strategy = self.engine.field_overrides[fname].strategy
                    stat.mask_strategy_counts[strategy] += 1
                if mr.rule_used == "whitelist_skip":
                    stat.whitelist_skipped_cells += 1
                    stat.mask_strategy_counts["whitelist_skip"] += 1
                if mr.risk_level:
                    stat.risk_level_counts[mr.risk_level] += 1
            masked_records.append(masked_row)
            if progress_cb:
                progress_cb("mask", data.filepath, idx, data.total_records)
        return masked_records

    def preview_diff(self, data: DataFile, field_sens_types: Dict[str, str],
                     max_rows: int = 5) -> List[Dict[str, Any]]:
        """生成脱敏前后对比预览数据"""
        diff_rows = []
        for idx, record in enumerate(data.records[:max_rows]):
            details = self.engine.mask_record_with_details(
                record, field_sens_types, self.whitelist
            )
            row = {"__row__": idx + 1}
            for field, mr in details.items():
                row[field] = {
                    "original": mr.original,
                    "masked": mr.masked,
                    "changed": mr.changed,
                    "rule": mr.rule_used,
                    "risk": mr.risk_level,
                }
            diff_rows.append(row)
        return diff_rows

    def sample_by_sens_type(
        self, data: DataFile, field_sens_types: Dict[str, str],
        per_type: int = 5,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """按敏感类型汇总抽样，每类最多取 per_type 条原值/脱敏值对比

        Returns:
            { "PHONE": [{"field":xxx, "original":..., "masked":..., "row":1}, ...],
              "NAME":  [...], ... }
        """
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        seen: Dict[Tuple[str, str], int] = {}

        field_to_type: Dict[str, str] = {}
        for fname, stype in field_sens_types.items():
            field_to_type[fname] = stype
        for fname, rule in self.engine.field_overrides.items():
            if fname not in field_to_type:
                field_to_type[fname] = rule.sens_type or "OVERRIDE"

        for idx, record in enumerate(data.records):
            details = self.engine.mask_record_with_details(
                record, field_sens_types, self.whitelist
            )
            for field, mr in details.items():
                if not mr.changed:
                    continue
                stype = field_to_type.get(field, "UNKNOWN")
                bucket = buckets.setdefault(stype, [])
                if len(bucket) >= per_type:
                    continue
                key = (stype, str(mr.original))
                if seen.get(key, 0) >= 1:
                    continue
                seen[key] = seen.get(key, 0) + 1
                bucket.append({
                    "field": field,
                    "row": idx + 1,
                    "original": mr.original,
                    "masked": mr.masked,
                    "rule": mr.rule_used,
                    "risk": mr.risk_level,
                })
        return buckets

    def _build_field_audit(
        self, data: DataFile, field_types: Dict[str, str], stat: FileProcessStat
    ) -> List[Dict[str, Any]]:
        """构建字段级审计明细列表

        Returns:
            [{
                "field": "name",
                "sens_type": "NAME",
                "strategy": "retain",
                "hit_count": 100,
                "masked_count": 100,
                "sample_original": "张三",
                "sample_masked": "张*",
                "source": "auto" / "manual" / "unknown" / "whitelist",
                "status": "CONFIRMED" / "AUTO_OK" / "NEED_MANUAL" / "SKIPPED" / "WHITELIST",
            }, ...]
        """
        audit: List[Dict[str, Any]] = []
        seen_fields: Set[str] = set()

        details_map: Dict[str, Any] = {}
        sample_record = None
        for rec in data.records:
            if rec:
                sample_record = rec
                break

        if sample_record:
            details = self.engine.mask_record_with_details(
                sample_record, field_types, self.whitelist
            )
            details_map = details

        all_fields = set(data.fields)

        manual_fields = set(self.config.field_overrides.keys())
        skip_fields = set(self.config.skipped_fields)
        meta = self.config.draft_field_meta

        for fname in data.fields:
            if fname in seen_fields:
                continue
            seen_fields.add(fname)

            if fname in self.whitelist:
                audit.append({
                    "field": fname,
                    "sens_type": "-",
                    "strategy": "-",
                    "hit_count": 0,
                    "masked_count": 0,
                    "sample_original": self._first_sample(data, fname),
                    "sample_masked": self._first_sample(data, fname),
                    "source": "whitelist",
                    "status": "WHITELIST",
                })
                continue

            field_meta = meta.get(fname, {})
            meta_status = field_meta.get("status", "")

            if (fname in skip_fields or meta_status == "SKIP_NON_SENSITIVE") and fname not in self.config.field_overrides:
                audit.append({
                    "field": fname,
                    "sens_type": "-",
                    "strategy": "-",
                    "hit_count": 0,
                    "masked_count": 0,
                    "sample_original": self._first_sample(data, fname),
                    "sample_masked": self._first_sample(data, fname),
                    "source": "skip",
                    "status": "SKIPPED",
                })
                continue

            stype = field_types.get(fname, "")
            hit_count = stat.sensitive_fields.get(fname, 0)
            masked_count = hit_count
            strategy = "-"
            sample_orig = self._first_sample(data, fname)
            sample_masked = sample_orig

            detail = details_map.get(fname)
            if detail and detail.changed:
                sample_orig = str(detail.original) if detail.original is not None else ""
                sample_masked = str(detail.masked) if detail.masked is not None else ""
                rule_used = detail.rule_used or ""
                if rule_used and rule_used.startswith("field:"):
                    rule_name = rule_used[len("field:"):]
                    type_rule = self.engine.rules.get(stype)
                    if type_rule:
                        strategy = type_rule.strategy
                    else:
                        strategy = rule_name
                else:
                    strategy = rule_used
            elif stype:
                rule = self.engine.rules.get(stype)
                if rule:
                    strategy = rule.strategy

            if fname in self.config.field_overrides:
                field_rule = self.config.field_overrides[fname]
                if "strategy" in field_rule:
                    strategy = field_rule["strategy"]
                elif stype:
                    type_rule = self.engine.rules.get(stype)
                    if type_rule:
                        strategy = type_rule.strategy

            has_manual_config = False
            if fname in self.config.field_overrides:
                field_rule = self.config.field_overrides[fname]
                draft_meta = self.config.draft_field_meta.get(fname, {})
                draft_status = draft_meta.get("status", "")

                if draft_status == "CONFIRMED_MANUAL":
                    has_manual_config = True
                elif draft_status == "NEED_MANUAL":
                    has_manual_config = True
                elif draft_status == "AUTO_OK":
                    if "strategy" in field_rule:
                        has_manual_config = True
                    elif "sens_type" in field_rule and "detected_type" in draft_meta and field_rule["sens_type"] != draft_meta["detected_type"]:
                        has_manual_config = True
                elif not draft_status:
                    has_manual_config = True

            if has_manual_config or meta_status == "CONFIRMED_MANUAL":
                source = "manual"
                status = "CONFIRMED"
            elif meta_status == "AUTO_OK":
                source = "auto"
                status = "AUTO_OK"
            elif meta_status == "SKIP_NON_SENSITIVE":
                source = "skip"
                status = "SKIPPED"
            elif meta_status == "NEED_MANUAL":
                source = "unknown"
                status = "NEED_MANUAL"
            elif stype:
                source = "auto"
                status = "AUTO_OK"
            else:
                source = "unknown"
                status = "UNKNOWN"

            if status == "SKIPPED" and not stype:
                audit.append({
                    "field": fname,
                    "sens_type": "-",
                    "strategy": "-",
                    "hit_count": 0,
                    "masked_count": 0,
                    "sample_original": sample_orig,
                    "sample_masked": sample_orig,
                    "source": "skip",
                    "status": "SKIPPED",
                })
                continue

            audit.append({
                "field": fname,
                "sens_type": stype or "-",
                "strategy": strategy,
                "hit_count": hit_count,
                "masked_count": masked_count,
                "sample_original": sample_orig,
                "sample_masked": sample_masked,
                "source": source,
                "status": status,
            })

        return audit

    def _first_sample(self, data: DataFile, field: str) -> str:
        """取字段的第一个非空样本值"""
        for rec in data.records:
            v = rec.get(field)
            if v is not None and str(v).strip():
                return str(v)[:80]
        return ""

    def _build_approval_package(self, report: ProcessReport, output_dir: str) -> str:
        """构建审批包目录，包含脱敏文件、报告、审计明细、配置、校验结果和总清单

        目录结构:
            _approval_<task_id>/
            ├── README.md                  # 总清单
            ├── config/
            │   ├── rules_config.yaml      # 使用的规则配置/草稿
            │   └── validation_result.md   # 规则校验结果
            ├── data/                      # 脱敏后的输出文件
            └── reports/
                ├── report.md              # 主报告
                ├── report.json
                ├── audit_detail.md        # 审计明细
                ├── audit_detail.csv
                └── summary.md             # 任务清单
        """
        import shutil

        task_id = report.task_id
        pkg_root = os.path.join(output_dir, f"_approval_{task_id}")
        os.makedirs(pkg_root, exist_ok=True)

        data_dir = os.path.join(pkg_root, "data")
        reports_dir = os.path.join(pkg_root, "reports")
        config_dir = os.path.join(pkg_root, "config")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(config_dir, exist_ok=True)

        extra = report.extra_outputs or {}

        copied_files = []

        for fstat in report.files:
            if fstat.output_path and os.path.exists(fstat.output_path):
                dst = os.path.join(data_dir, os.path.basename(fstat.output_path))
                shutil.copy2(fstat.output_path, dst)
                copied_files.append(("data", os.path.basename(fstat.output_path), fstat.output_path))

        report_files_map = {
            "report.md": extra.get("md_report", ""),
            "report.json": extra.get("json_report", ""),
            "audit_detail.md": extra.get("audit_detail", ""),
            "audit_detail.csv": extra.get("audit_detail_csv", ""),
            "summary.md": extra.get("task_summary", ""),
        }
        for dst_name, src_path in report_files_map.items():
            if src_path and os.path.exists(src_path):
                dst = os.path.join(reports_dir, dst_name)
                shutil.copy2(src_path, dst)
                copied_files.append(("reports", dst_name, src_path))

        config_src = self.config.source_file
        if config_src and os.path.exists(config_src):
            dst = os.path.join(config_dir, "rules_config.yaml")
            shutil.copy2(config_src, dst)
            copied_files.append(("config", "rules_config.yaml", config_src))

        validation_path = os.path.join(config_dir, "validation_result.md")
        try:
            vr = self.config.validate()
            lines = []
            lines.append("# 规则配置校验结果\n")
            lines.append(f"- **校验时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"- **配置文件**: `{config_src or '内置默认'}`")
            lines.append(f"- **整体结论**: {'✅ 通过' if vr['valid'] else '❌ 未通过'}\n")

            stats = vr["stats"]
            lines.append("## 📊 统计概览\n")
            lines.append("| 指标 | 数值 |")
            lines.append("|-----|------|")
            lines.append(f"| 类型规则 | {stats.get('type_rules_ok', 0)}/{stats.get('type_rules_total', 0)} 有效 |")
            lines.append(f"| 字段规则 - 可用 | {stats.get('fields_ok', 0)} |")
            lines.append(f"| 字段规则 - 警告 | {stats.get('fields_warning', 0)} |")
            lines.append(f"| 字段规则 - 错误 | {stats.get('fields_error', 0)} |")
            lines.append(f"| 字段规则 - 已跳过 | {stats.get('fields_skipped', 0)} |")
            lines.append(f"| 字段规则 - 待人工补充 | {stats.get('fields_need_manual', 0)} |")
            lines.append(f"| 白名单字段 | {stats.get('whitelist_count', 0)} |")
            lines.append(f"| 白名单冲突 | {stats.get('whitelist_conflicts', 0)} |\n")

            issues = vr.get("issues", [])
            if issues:
                lines.append("## 🔔 问题清单\n")
                level_map = {"error": "❌ 错误", "warning": "⚠️ 警告", "info": "ℹ️ 提示"}
                for issue in issues:
                    level = issue.get("level", "info")
                    cat = issue.get("category", "")
                    field = issue.get("field", "")
                    msg = issue.get("message", "")
                    label = level_map.get(level, level)
                    lines.append(f"### {label} [{cat}] `{field}`\n")
                    lines.append(f"{msg}\n")

            with open(validation_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            copied_files.append(("config", "validation_result.md", validation_path))
        except Exception as e:
            with open(validation_path, "w", encoding="utf-8") as f:
                f.write(f"# 规则校验结果\n\n校验失败: {e}\n")
            copied_files.append(("config", "validation_result.md", validation_path))

        readme_path = os.path.join(pkg_root, "README.md")
        lines = []
        lines.append("# 数据脱敏审批包\n")
        lines.append(f"- **任务ID**: `{task_id}`")
        lines.append(f"- **操作类型**: `{report.operation}`")
        lines.append(f"- **生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.started_at))}")
        lines.append(f"- **耗时**: {report.duration:.2f}秒")
        lines.append(f"- **配置文件**: `{config_src or '内置默认'}`")
        lines.append(f"- **输出目录**: `{output_dir}`\n")

        agg = report.aggregate or {}
        lines.append("## 📊 总体统计\n")
        lines.append("| 指标 | 数值 |")
        lines.append("|-----|------|")
        lines.append(f"| 处理文件数 | {report.total_files} |")
        lines.append(f"| 成功 | {report.success_files} |")
        lines.append(f"| 失败 | {report.failed_files} |")
        lines.append(f"| 处理记录数 | {agg.get('total_records', 0)} |")
        lines.append(f"| 含敏感记录数 | {agg.get('records_with_sensitive', 0)} |")
        lines.append(f"| 脱敏单元格总数 | {agg.get('total_masked_cells', 0)} |\n")

        lines.append("## 📁 文件清单\n")
        lines.append("### 脱敏数据 (data/)\n")
        data_files = [name for category, name, _ in copied_files if category == "data"]
        if data_files:
            for name in sorted(data_files):
                lines.append(f"- `data/{name}`")
        else:
            lines.append("_（无输出数据文件）_")
        lines.append("")

        lines.append("### 检查报告 (reports/)\n")
        report_files = [name for category, name, _ in copied_files if category == "reports"]
        for name in sorted(report_files):
            lines.append(f"- `reports/{name}`")
        lines.append("")

        lines.append("### 规则配置 (config/)\n")
        config_files = [name for category, name, _ in copied_files if category == "config"]
        for name in sorted(config_files):
            lines.append(f"- `config/{name}`")
        lines.append("")

        lines.append("## 📝 使用说明\n")
        lines.append(
            "1. 打开 `data/` 目录，抽样检查各脱敏文件效果是否符合要求；\n"
            "2. 查看 `reports/report.md` 了解整体脱敏统计和风险项；\n"
            "3. 查看 `reports/audit_detail.md` 或 `.csv` 逐字段核对处理口径；\n"
            "4. 查看 `config/validation_result.md` 确认规则校验状态；\n"
            "5. 全部确认无误后，将本目录整体压缩提交上架审批。\n"
        )
        lines.append("---\n")
        lines.append(f"*审批包生成于 {time.strftime('%Y-%m-%d %H:%M:%S')} by DataMask Tool*")

        with open(readme_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        review_path = os.path.join(pkg_root, "REVIEW.md")
        review_lines = []
        review_lines.append("# 🎯 运营复核首页\n")
        review_lines.append(f"> 任务ID: `{task_id}` | 操作: `{report.operation}` | 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.started_at))}\n")

        all_audit = []
        for fstat in report.files:
            if fstat.field_audit:
                for a in fstat.field_audit:
                    a2 = dict(a)
                    a2["file"] = os.path.basename(fstat.filepath)
                    all_audit.append(a2)

        status_counts: Dict[str, int] = {}
        sens_type_counts: Dict[str, int] = {}
        manual_fields = []
        need_manual_fields = []
        skipped_fields = []
        auto_fields = []

        status_label_map = {
            "CONFIRMED": "✅ 手工确认",
            "AUTO_OK": "🤖 自动识别",
            "NEED_MANUAL": "⚠️ 待补充",
            "SKIPPED": "⏭️ 已跳过",
            "WHITELIST": "📋 白名单",
            "UNKNOWN": "❓ 未识别",
        }

        for a in all_audit:
            status = a.get("status", "UNKNOWN")
            stype = a.get("sens_type", "-")
            status_counts[status] = status_counts.get(status, 0) + 1
            if stype and stype != "-":
                sens_type_counts[stype] = sens_type_counts.get(stype, 0) + 1

            if status == "CONFIRMED":
                manual_fields.append(a)
            elif status == "NEED_MANUAL":
                need_manual_fields.append(a)
            elif status == "SKIPPED":
                skipped_fields.append(a)
            elif status == "AUTO_OK":
                auto_fields.append(a)

        review_lines.append("## 📊 快速概览\n")
        review_lines.append("| 状态 | 字段数 | 说明 |")
        review_lines.append("|-----|-------|------|")
        for status in ["CONFIRMED", "AUTO_OK", "NEED_MANUAL", "SKIPPED", "WHITELIST", "UNKNOWN"]:
            count = status_counts.get(status, 0)
            if count > 0 or status in ("CONFIRMED", "NEED_MANUAL"):
                review_lines.append(f"| {status_label_map.get(status, status)} | {count} | |")
        review_lines.append("")

        review_lines.append("## 📁 处理文件清单\n")
        for fstat in report.files:
            review_lines.append(f"### `{os.path.basename(fstat.filepath)}`")
            review_lines.append(f"- 记录数: {fstat.total_records} | 含敏感记录: {fstat.records_with_sensitive} | 脱敏单元格: {fstat.masked_cells}")
            file_audit = [a for a in all_audit if a["file"] == os.path.basename(fstat.filepath)]
            file_sens = [a for a in file_audit if a.get("sens_type") and a.get("sens_type") != "-"]
            if file_sens:
                sens_list = ", ".join([f"{TYPE_LABELS.get(a['sens_type'], a['sens_type'])}({a['hit_count']})" for a in file_sens])
                review_lines.append(f"- 敏感类型: {sens_list}")
            review_lines.append("")

        if manual_fields:
            review_lines.append("## ✅ 人工确认字段\n")
            review_lines.append("> 以下字段已通过手工配置规则，请复核处理口径是否正确：\n")
            review_lines.append("| 文件 | 字段 | 敏感类型 | 脱敏策略 | 命中数 | 说明 |")
            review_lines.append("|-----|------|---------|---------|-------|------|")
            manual_fields.sort(key=lambda x: (x["file"], x["field"]))
            for a in manual_fields:
                stype = a.get("sens_type", "-")
                stype_label = TYPE_LABELS.get(stype, stype) if stype != "-" else "-"
                review_lines.append(
                    f"| `{a['file']}` | `{a['field']}` | {stype_label} | {a.get('strategy', '-')} | {a.get('hit_count', 0)} | 人工确认 |"
                )
            review_lines.append("")

        if need_manual_fields:
            review_lines.append("## ⚠️ 待补充规则字段\n")
            review_lines.append("> 以下字段无法自动识别，请补充配置后再提交审批：\n")
            review_lines.append("| 文件 | 字段 | 样本值 | 建议 |")
            review_lines.append("|-----|------|-------|------|")
            need_manual_fields.sort(key=lambda x: (x["file"], x["field"]))
            for a in need_manual_fields:
                sample = str(a.get("sample_original", ""))[:30]
                review_lines.append(f"| `{a['file']}` | `{a['field']}` | `{sample}` | 请补充 sens_type 和 strategy |")
            review_lines.append("")

        if auto_fields:
            review_lines.append("## 🤖 自动识别字段\n")
            review_lines.append("> 以下字段由系统自动识别，可抽样检查：\n")
            review_lines.append("| 文件 | 字段 | 敏感类型 | 脱敏策略 | 命中数 |")
            review_lines.append("|-----|------|---------|---------|-------|")
            auto_fields.sort(key=lambda x: (x["file"], x["field"]))
            for a in auto_fields:
                stype = a.get("sens_type", "-")
                stype_label = TYPE_LABELS.get(stype, stype) if stype != "-" else "-"
                review_lines.append(
                    f"| `{a['file']}` | `{a['field']}` | {stype_label} | {a.get('strategy', '-')} | {a.get('hit_count', 0)} |"
                )
            review_lines.append("")

        if skipped_fields:
            review_lines.append("## ⏭️ 已跳过字段\n")
            review_lines.append("| 文件 | 字段 | 原因 |")
            review_lines.append("|-----|------|------|")
            skipped_fields.sort(key=lambda x: (x["file"], x["field"]))
            for a in skipped_fields:
                review_lines.append(f"| `{a['file']}` | `{a['field']}` | 非敏感字段，跳过处理 |")
            review_lines.append("")

        if sens_type_counts:
            review_lines.append("## 📈 按敏感类型统计\n")
            review_lines.append("| 敏感类型 | 字段数 |")
            review_lines.append("|---------|-------|")
            for stype, count in sorted(sens_type_counts.items(), key=lambda x: -x[1]):
                stype_label = TYPE_LABELS.get(stype, stype)
                review_lines.append(f"| {stype_label} ({stype}) | {count} |")
            review_lines.append("")

        review_lines.append("## ✅ 复核检查清单\n")
        review_lines.append("- [ ] 所有 **人工确认字段** 的脱敏策略和敏感类型是否正确？")
        review_lines.append("- [ ] **待补充字段** 是否已全部配置规则？")
        review_lines.append("- [ ] 抽样检查脱敏后的数据是否符合预期？")
        review_lines.append("- [ ] 已跳过字段是否确实为非敏感信息？")
        review_lines.append("- [ ] 主报告统计数据是否与实际一致？\n")

        review_lines.append("---\n")
        review_lines.append(f"*生成于 {time.strftime('%Y-%m-%d %H:%M:%S')} by DataMask Tool*")

        with open(review_path, "w", encoding="utf-8") as f:
            f.write("\n".join(review_lines))

        return pkg_root

    def build_rule_draft(
        self,
        filepath: Optional[str] = None,
        include_comments: bool = True,
        scans: Optional[List[Tuple[str, Any, Dict[str, str], Any]]] = None,
        base_config: Optional[Any] = None,
        source_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """基于文件扫描生成可编辑的规则草稿（兼容单文件与多文件两种调用方式）

        方式一（单文件）：传 filepath，内部执行 scan_file 后生成草稿
        方式二（多文件）：传 scans = [(fpath, data, field_types, stat), ...]，
                  由 cli 先扫描再统一合并草稿（推荐批量场景）
        """
        if scans is None:
            if not filepath:
                raise ValueError("build_rule_draft 需要 filepath 或 scans 之一")
            data, field_types, stat = self.scan_file(filepath)
            scans = [(filepath, data, field_types, stat)]

        type_rules_json: Dict[str, Any] = {}
        for stype, rule in self.engine.rules.items():
            entry = {
                "strategy": rule.strategy,
                "mask_char": rule.mask_char,
                "keep_start": rule.keep_start,
                "keep_end": rule.keep_end,
            }
            if include_comments:
                from .detector import SENSITIVE_TYPES
                entry["#类型说明"] = SENSITIVE_TYPES.get(stype, stype)
                if rule.strategy == "retain":
                    entry["#策略说明"] = f"保留前{rule.keep_start}位、后{rule.keep_end}位，中间用'{rule.mask_char}'打码"
                elif rule.strategy == "replace":
                    entry["#策略说明"] = f"全部用'{rule.mask_char}'替换"
                elif rule.strategy == "random":
                    entry["#策略说明"] = "映射为同格式的随机值，同值同映射确保一致性"
            type_rules_json[stype] = entry

        merged_field_types: Dict[str, str] = {}
        merged_samples: Dict[str, str] = {}
        merged_unknowns: Dict[str, Dict[str, Any]] = {}
        file_field_sources: Dict[str, List[str]] = {}
        total_records = 0
        total_fields_set: Set[str] = set()

        for (fpath, data, field_types, stat) in scans:
            total_records += data.total_records
            for fname in data.fields:
                total_fields_set.add(fname)
                file_field_sources.setdefault(fname, []).append(os.path.basename(fpath))
                if fname not in merged_samples:
                    for r in data.records[:3]:
                        v = r.get(fname)
                        if v and str(v).strip():
                            merged_samples[fname] = str(v)[:50]
                            break
            for fname, st in field_types.items():
                if fname not in merged_field_types:
                    merged_field_types[fname] = st
            for unk in (stat.unknown_format_fields or []):
                key = unk["field"]
                if key not in merged_unknowns:
                    merged_unknowns[key] = unk

        whitelist = list(self.whitelist)
        if base_config and getattr(base_config, "whitelist_fields", None):
            for w in base_config.whitelist_fields:
                if w not in whitelist:
                    whitelist.append(w)

        field_overrides_json: Dict[str, Any] = {}
        all_fields = sorted(total_fields_set)
        for fname in all_fields:
            if fname in whitelist:
                continue
            stype = merged_field_types.get(fname)
            sample_val = merged_samples.get(fname, "")
            sources = file_field_sources.get(fname, [])

            entry: Dict[str, Any] = {}
            if stype:
                entry["detected_type"] = stype
                entry["status"] = "AUTO_OK"
                if include_comments:
                    from .detector import SENSITIVE_TYPES
                    entry["#识别说明"] = f"自动识别为{SENSITIVE_TYPES.get(stype, stype)}，按该类型规则脱敏"
            else:
                unk = merged_unknowns.get(fname)
                if unk:
                    entry["detected_type"] = None
                    entry["status"] = "NEED_MANUAL"
                    entry["suggestion"] = unk.get("suggestion", "请检查字段含义后补充 sens_type 和 strategy")
                    if include_comments:
                        entry["#提示"] = "该字段无法自动识别，请手工配置sens_type和strategy后再处理"
                else:
                    entry["detected_type"] = None
                    entry["status"] = "SKIP_NON_SENSITIVE"
                    if include_comments:
                        entry["#说明"] = "未识别为敏感内容，默认保持原值不变"
            if include_comments:
                entry["#示例值"] = sample_val or "(空)"
                if len(sources) > 1:
                    entry["#出现文件"] = sources

            field_overrides_json[fname] = entry

        src = source_path or filepath or (scans[0][0] if scans else "")
        draft = {
            "#规则草稿说明": (
                "此文件由 rules draft 自动生成，供数据运营同事在脱敏前审核确认：\n"
                "  1) 检查 field_overrides 中每个字段的 detected_type 是否正确；\n"
                "  2) 标记 NEED_MANUAL 的字段请补充 sens_type 和 strategy 或加入 whitelist_fields；\n"
                "  3) 标记 AUTO_OK 的字段如无需修改可保留原样；\n"
                "  4) 确认无误后通过 -c 传此文件给 scan/preview/mask 使用。"
            ),
            "source_path": src,
            "total_files": len(scans),
            "total_records": total_records,
            "unique_fields": len(total_fields_set),
            "type_rules": type_rules_json,
            "field_overrides": field_overrides_json,
            "whitelist_fields": whitelist,
            "min_confidence": self.min_conf,
        }
        return draft

    def process_folder(
        self, folder: str, output_dir: str,
        operation: str = "mask",
        recursive: bool = True,
        dry_run: bool = False,
        report_formats: Tuple[str, ...] = ("markdown", "json"),
        progress_cb: Optional[Callable] = None,
        approval_package: bool = False,
    ) -> ProcessReport:
        """处理整个文件夹"""
        output_dir = os.path.abspath(output_dir)
        report = ReportGenerator.start_report(
            operation=operation, output_dir=output_dir,
            config_used=self.config.source_file or "内置默认"
        )

        input_root = folder
        folder_path = Path(folder)
        if folder_path.is_file():
            input_root = str(folder_path.parent)
            files = [str(folder_path)]
        else:
            files = get_supported_files(folder, recursive)

        report.total_files = len(files)

        for filepath in files:
            file_stat = FileProcessStat(filepath=filepath)
            try:
                data, field_types, scan_stat = self.scan_file(filepath, progress_cb)
                file_stat = scan_stat
                file_stat.format = data.format

                file_stat.field_audit = self._build_field_audit(data, field_types, file_stat)

                if operation == "scan":
                    file_stat.output_status = "SCAN_OK"
                    report.files.append(file_stat)
                    report.success_files += 1
                    continue

                masked_records = self.mask_file(data, field_types, file_stat, progress_cb)

                if operation == "preview":
                    file_stat.output_status = "PREVIEW_OK"
                    report.files.append(file_stat)
                    report.success_files += 1
                    continue

                if not dry_run and operation == "mask":
                    out_path = get_output_path(filepath, input_root, output_dir)
                    out_data = DataFile(
                        filepath=out_path,
                        records=masked_records,
                        fields=data.fields,
                        format=data.format,
                        total_records=len(masked_records),
                    )
                    write_file(out_path, out_data)
                    file_stat.output_path = out_path
                    file_stat.output_status = "MASK_OK"
                else:
                    file_stat.output_status = "DRY_OK" if operation == "mask" else "PREVIEW_OK"

                need_manual = [u["field"] for u in file_stat.unknown_format_fields]
                if need_manual:
                    file_stat.output_messages.append(f"需人工补规则字段: {', '.join(need_manual)}")

                report.files.append(file_stat)
                report.success_files += 1

            except UnsupportedFormatError as e:
                file_stat.errors.append(f"格式不支持: {e}")
                file_stat.output_status = "SKIP_FORMAT"
                report.files.append(file_stat)
                report.skipped_files += 1
            except FileReadError as e:
                file_stat.errors.append(f"读取失败: {e.reason}")
                file_stat.output_status = "FAIL_READ"
                report.files.append(file_stat)
                report.failed_files += 1
            except FileWriteError as e:
                file_stat.errors.append(f"写入失败: {e.reason}")
                file_stat.output_status = "FAIL_WRITE"
                report.files.append(file_stat)
                report.failed_files += 1
            except Exception as e:
                tb = traceback.format_exc(limit=2)
                file_stat.errors.append(f"未知错误: {e}\n{tb}")
                file_stat.output_status = "FAIL_UNKNOWN"
                report.files.append(file_stat)
                report.failed_files += 1

        ReportGenerator.finalize_report(report)

        report_dir = None
        task_stamp = report.task_id
        md_report_path = ""
        json_report_path = ""
        summary_path = ""

        if operation == "mask" and not dry_run and report_formats:
            report_dir = os.path.join(output_dir, "_reports")
            if "markdown" in report_formats:
                md_report_path = os.path.join(report_dir, f"report_{task_stamp}.md")
                ReportGenerator.generate_markdown(report, md_report_path)
            if "json" in report_formats:
                json_report_path = os.path.join(report_dir, f"report_{task_stamp}.json")
                ReportGenerator.generate_json(report, json_report_path)
            summary_path = os.path.join(report_dir, f"summary_{task_stamp}.md")
            ReportGenerator.generate_task_summary(
                report, summary_path,
                md_report=md_report_path, json_report=json_report_path,
            )
        elif operation == "report" or operation == "scan":
            report_dir = os.path.join(output_dir, "_reports") if output_dir else None
            if report_dir and report_formats:
                if "markdown" in report_formats:
                    md_report_path = os.path.join(report_dir, f"report_{task_stamp}.md")
                    ReportGenerator.generate_markdown(report, md_report_path)
                if "json" in report_formats:
                    json_report_path = os.path.join(report_dir, f"report_{task_stamp}.json")
                    ReportGenerator.generate_json(report, json_report_path)
                summary_path = os.path.join(report_dir, f"summary_{task_stamp}.md")
                ReportGenerator.generate_task_summary(
                    report, summary_path,
                    md_report=md_report_path, json_report=json_report_path,
                )

        audit_detail_path = ""
        audit_detail_csv_path = ""
        if report_dir:
            audit_detail_path = os.path.join(report_dir, f"audit_detail_{task_stamp}.md")
            ReportGenerator.generate_audit_detail(report, audit_detail_path)
            audit_detail_csv_path = os.path.join(report_dir, f"audit_detail_{task_stamp}.csv")
            ReportGenerator.generate_audit_detail_csv(report, audit_detail_csv_path)

        report.extra_outputs = {
            "report_dir": report_dir,
            "md_report": md_report_path,
            "json_report": json_report_path,
            "task_summary": summary_path,
            "audit_detail": audit_detail_path,
            "audit_detail_csv": audit_detail_csv_path,
            "task_id": task_stamp,
        }

        if approval_package and output_dir:
            pkg_path = self._build_approval_package(report, output_dir)
            report.extra_outputs["approval_package"] = pkg_path

        return report
