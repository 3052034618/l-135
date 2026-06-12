# -*- coding: utf-8 -*-
"""
主处理流程 - 协调检测、脱敏、报告
"""
import os
import traceback
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable

from .detector import (
    detect_record, detect_value, SensitiveMatch, DetectorResult,
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
                 min_confidence: Optional[float] = None):
        self.config = config
        self.min_conf = min_confidence if min_confidence is not None else config.min_confidence
        self.whitelist = list(config.whitelist_fields)
        if extra_whitelist:
            self.whitelist.extend(extra_whitelist)
        self.engine = config.build_mask_engine(strategy_overrides)

    def _infer_field_types_across_file(
        self, data: DataFile, stat: FileProcessStat
    ) -> Dict[str, str]:
        """跨整文件推断每个字段的敏感类型"""
        field_votes: Dict[str, Counter] = {}
        field_low_conf: Dict[str, List[Dict[str, Any]]] = {}
        unknown_fields: Dict[str, Counter] = {}

        sample_size = min(len(data.records), 200)
        for idx in range(sample_size):
            record = data.records[idx]
            for field_name, value in record.items():
                if field_name in self.whitelist:
                    continue
                matches = detect_value(value, field_name, self.min_conf)
                if matches:
                    for m in matches:
                        field_votes.setdefault(field_name, Counter())[m.sens_type] += 1
                        if m.confidence < 0.8 and m.confidence >= self.min_conf:
                            field_low_conf.setdefault(field_name, []).append({
                                "row": idx,
                                "value": str(value)[:100],
                                "confidence": m.confidence,
                                "sens_type": m.sens_type,
                            })
                elif value and str(value).strip():
                    unknown_fields.setdefault(field_name, Counter())["non_empty"] += 1

        final_types: Dict[str, str] = {}
        for field_name, votes in field_votes.items():
            best_type, best_count = votes.most_common(1)[0]
            final_types[field_name] = best_type
            stat.sensitive_fields[field_name] += best_count
            stat.sens_type_counts[best_type] += best_count
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

    def scan_file(self, filepath: str,
                  progress_cb: Optional[Callable] = None) -> Tuple[DataFile, Dict[str, str], FileProcessStat]:
        """扫描单个文件 - 返回数据、字段敏感类型映射、统计"""
        stat = FileProcessStat(filepath=filepath)
        data = read_file(filepath)
        stat.format = data.format
        stat.total_records = data.total_records
        stat.total_fields = len(data.fields)

        field_sens_types = self._infer_field_types_across_file(data, stat)

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

        return data, field_sens_types, stat

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

    def process_folder(
        self, folder: str, output_dir: str,
        operation: str = "mask",
        recursive: bool = True,
        dry_run: bool = False,
        report_formats: Tuple[str, ...] = ("markdown", "json"),
        progress_cb: Optional[Callable] = None,
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

                if operation == "scan":
                    report.files.append(file_stat)
                    report.success_files += 1
                    continue

                masked_records = self.mask_file(data, field_types, file_stat, progress_cb)

                if operation == "preview":
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

                report.files.append(file_stat)
                report.success_files += 1

            except UnsupportedFormatError as e:
                file_stat.errors.append(f"格式不支持: {e}")
                report.files.append(file_stat)
                report.skipped_files += 1
            except FileReadError as e:
                file_stat.errors.append(f"读取失败: {e.reason}")
                report.files.append(file_stat)
                report.failed_files += 1
            except FileWriteError as e:
                file_stat.errors.append(f"写入失败: {e.reason}")
                report.files.append(file_stat)
                report.failed_files += 1
            except Exception as e:
                tb = traceback.format_exc(limit=2)
                file_stat.errors.append(f"未知错误: {e}\n{tb}")
                report.files.append(file_stat)
                report.failed_files += 1

        ReportGenerator.finalize_report(report)

        if operation == "mask" and not dry_run and report_formats:
            report_dir = os.path.join(output_dir, "_reports")
            task_stamp = report.task_id
            if "markdown" in report_formats:
                ReportGenerator.generate_markdown(
                    report, os.path.join(report_dir, f"report_{task_stamp}.md")
                )
            if "json" in report_formats:
                ReportGenerator.generate_json(
                    report, os.path.join(report_dir, f"report_{task_stamp}.json")
                )

        return report
