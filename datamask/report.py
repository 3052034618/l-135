# -*- coding: utf-8 -*-
"""
报告生成与处理统计
"""
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
from pathlib import Path


RISK_LEVELS = {
    "high_safe": {"label": "高安全", "color": "green", "weight": 0},
    "normal": {"label": "普通", "color": "yellow", "weight": 1},
    "low_mask": {"label": "低脱敏(风险)", "color": "red", "weight": 2},
    "unknown": {"label": "未知格式(风险)", "color": "red", "weight": 3},
    "whitelist_skip": {"label": "白名单跳过", "color": "gray", "weight": -1},
}


@dataclass
class FileProcessStat:
    """单个文件处理统计"""
    filepath: str
    format: str = ""
    total_records: int = 0
    total_fields: int = 0
    records_with_sensitive: int = 0
    sensitive_fields: Counter = field(default_factory=Counter)
    sens_type_counts: Counter = field(default_factory=Counter)
    mask_strategy_counts: Counter = field(default_factory=Counter)
    risk_level_counts: Counter = field(default_factory=Counter)
    masked_cells: int = 0
    whitelist_skipped_cells: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    low_confidence_items: List[Dict[str, Any]] = field(default_factory=list)
    unknown_format_fields: List[Dict[str, Any]] = field(default_factory=list)
    output_path: str = ""
    output_status: str = ""
    output_messages: List[str] = field(default_factory=list)


@dataclass
class ProcessReport:
    """整体处理报告"""
    task_id: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    duration: float = 0.0
    operation: str = ""
    total_files: int = 0
    success_files: int = 0
    failed_files: int = 0
    skipped_files: int = 0
    output_dir: str = ""
    config_used: str = ""
    files: List[FileProcessStat] = field(default_factory=list)
    aggregate: Dict[str, Any] = field(default_factory=dict)
    extra_outputs: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_records(self) -> int:
        return sum(f.total_records for f in self.files)

    @property
    def total_masked_cells(self) -> int:
        return sum(f.masked_cells for f in self.files)

    @property
    def total_errors(self) -> List[str]:
        errors = []
        for f in self.files:
            for e in f.errors:
                errors.append(f"[{os.path.basename(f.filepath)}] {e}")
        return errors

    @property
    def total_warnings(self) -> List[str]:
        warns = []
        for f in self.files:
            for w in f.warnings:
                warns.append(f"[{os.path.basename(f.filepath)}] {w}")
        return warns


class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def start_report(operation: str, output_dir: str, config_used: str = "") -> ProcessReport:
        import uuid
        return ProcessReport(
            task_id=uuid.uuid4().hex[:12],
            started_at=time.time(),
            operation=operation,
            output_dir=output_dir,
            config_used=config_used,
        )

    @staticmethod
    def finalize_report(report: ProcessReport) -> ProcessReport:
        report.finished_at = time.time()
        report.duration = report.finished_at - report.started_at

        total_sens = Counter()
        total_fields = Counter()
        total_strategies = Counter()
        total_risks = Counter()
        total_masked = 0
        total_sens_records = 0

        for f in report.files:
            total_sens.update(f.sens_type_counts)
            total_fields.update(f.sensitive_fields)
            total_strategies.update(f.mask_strategy_counts)
            total_risks.update(f.risk_level_counts)
            total_masked += f.masked_cells
            total_sens_records += f.records_with_sensitive

        report.aggregate = {
            "total_records": report.total_records,
            "total_masked_cells": report.total_masked_cells,
            "records_with_sensitive": total_sens_records,
            "sensitive_type_counts": dict(total_sens),
            "sensitive_field_counts": dict(total_fields),
            "strategy_counts": dict(total_strategies),
            "risk_level_counts": dict(total_risks),
            "errors": report.total_errors,
            "warnings": report.total_warnings,
            "unknown_format_count": sum(
                len(f.unknown_format_fields) for f in report.files
            ),
            "low_confidence_count": sum(
                len(f.low_confidence_items) for f in report.files
            ),
        }
        return report

    @staticmethod
    def generate_markdown(report: ProcessReport, output_path: str) -> str:
        lines = []
        lines.append("# 数据脱敏处理检查报告\n")
        lines.append(f"**任务ID**: `{report.task_id}`")
        lines.append(f"**操作类型**: `{report.operation}`")
        lines.append(f"**开始时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.started_at))}")
        lines.append(f"**结束时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.finished_at))}")
        lines.append(f"**处理时长**: {report.duration:.2f}秒")
        lines.append(f"**输出目录**: `{report.output_dir}`")
        lines.append(f"**配置文件**: `{report.config_used}`\n")

        lines.append("## 一、总体统计\n")
        agg = report.aggregate
        lines.append(f"- **处理文件总数**: {report.total_files}")
        lines.append(f"- **成功**: {report.success_files}  **失败**: {report.failed_files}  **跳过**: {report.skipped_files}")
        lines.append(f"- **处理记录总数**: {agg.get('total_records', 0)}")
        lines.append(f"- **含敏感数据记录数**: {agg.get('records_with_sensitive', 0)}")
        lines.append(f"- **脱敏单元格总数**: {agg.get('total_masked_cells', 0)}")
        lines.append(f"- **低置信度告警**: {agg.get('low_confidence_count', 0)}")
        lines.append(f"- **未知格式字段**: {agg.get('unknown_format_count', 0)}\n")

        lines.append("### 1.1 敏感类型分布\n")
        lines.append("| 敏感类型 | 数量 |")
        lines.append("|---------|------|")
        type_labels = {
            "PHONE": "手机号", "ID_CARD": "身份证号", "ADDRESS": "地址",
            "NAME": "姓名", "COMPANY": "企业名称", "EMAIL": "电子邮箱",
            "BANK_CARD": "银行卡号", "UNKNOWN": "未知类型"
        }
        for t, c in sorted(agg.get("sensitive_type_counts", {}).items(), key=lambda x: -x[1]):
            lines.append(f"| {type_labels.get(t, t)} | {c} |")
        lines.append("")

        lines.append("### 1.2 风险级别分布\n")
        lines.append("| 风险级别 | 数量 | 说明 |")
        lines.append("|---------|------|------|")
        for r, c in sorted(agg.get("risk_level_counts", {}).items(), key=lambda x: -x[1]):
            info = RISK_LEVELS.get(r, {"label": r, "color": "gray", "weight": 1})
            lines.append(f"| {info['label']} | {c} | `{r}` |")
        lines.append("")

        lines.append("### 1.3 脱敏策略使用情况\n")
        lines.append("| 策略 | 数量 |")
        lines.append("|-----|------|")
        strat_labels = {"retain": "保留位数", "replace": "替换字符", "random": "随机映射",
                        "default_retain": "默认保留", "whitelist_skip": "白名单跳过"}
        for s, c in sorted(agg.get("strategy_counts", {}).items(), key=lambda x: -x[1]):
            lines.append(f"| {strat_labels.get(s, s)} | {c} |")
        lines.append("")

        lines.append("## 二、各文件明细\n")
        for idx, fstat in enumerate(report.files, 1):
            lines.append(f"### {idx}. {os.path.basename(fstat.filepath)}\n")
            lines.append(f"- **完整路径**: `{fstat.filepath}`")
            lines.append(f"- **格式**: {fstat.format}")
            lines.append(f"- **记录数**: {fstat.total_records}")
            lines.append(f"- **字段数**: {fstat.total_fields}")
            lines.append(f"- **含敏感记录**: {fstat.records_with_sensitive}")
            lines.append(f"- **脱敏单元格**: {fstat.masked_cells}")
            lines.append(f"- **白名单跳过单元格**: {fstat.whitelist_skipped_cells}")

            if fstat.sensitive_fields:
                lines.append("\n**涉及敏感字段**:")
                lines.append("| 字段名 | 命中次数 | 主要敏感类型 |")
                lines.append("|-------|---------|------------|")
                for field_name, cnt in fstat.sensitive_fields.most_common(10):
                    primary_type = ""
                    lines.append(f"| `{field_name}` | {cnt} | {primary_type} |")

            if fstat.low_confidence_items:
                lines.append(f"\n**低置信度项 ({len(fstat.low_confidence_items)} 项):**")
                for item in fstat.low_confidence_items[:10]:
                    lines.append(f"- 字段 `{item.get('field', '?')}`: 置信度 {item.get('confidence', 0):.2f}, 值 `{str(item.get('value', ''))[:40]}`")
                if len(fstat.low_confidence_items) > 10:
                    lines.append(f"- ... 其余 {len(fstat.low_confidence_items) - 10} 项")

            if fstat.unknown_format_fields:
                lines.append(f"\n**⚠️ 未识别格式字段 ({len(fstat.unknown_format_fields)} 项):**")
                lines.append("| 字段名 | 示例值 | 建议 |")
                lines.append("|-------|-------|------|")
                for item in fstat.unknown_format_fields[:10]:
                    example = str(item.get("value", ""))[:30]
                    lines.append(f"| `{item.get('field', '?')}` | `{example}` | 请在field_overrides中手动指定 |")

            if fstat.errors:
                lines.append(f"\n**❌ 错误 ({len(fstat.errors)} 项):**")
                for e in fstat.errors[:10]:
                    lines.append(f"- {e}")

            if fstat.warnings:
                lines.append(f"\n**⚠️ 警告 ({len(fstat.warnings)} 项):**")
                for w in fstat.warnings[:10]:
                    lines.append(f"- {w}")

            lines.append("")

        if report.total_errors or report.total_warnings:
            lines.append("## 三、风险与问题汇总\n")
            if report.total_errors:
                lines.append("### 错误清单")
                for e in report.total_errors:
                    lines.append(f"- ❌ {e}")
                lines.append("")
            if report.total_warnings:
                lines.append("### 警告清单")
                for w in report.total_warnings:
                    lines.append(f"- ⚠️ {w}")
                lines.append("")

        lines.append("---\n")
        lines.append(f"*报告生成于 {time.strftime('%Y-%m-%d %H:%M:%S')} by DataMask Tool*\n")

        content = "\n".join(lines)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path

    @staticmethod
    def generate_json(report: ProcessReport, output_path: str) -> str:
        def _stat_to_dict(s: FileProcessStat) -> Dict[str, Any]:
            return {
                "filepath": s.filepath,
                "format": s.format,
                "total_records": s.total_records,
                "total_fields": s.total_fields,
                "records_with_sensitive": s.records_with_sensitive,
                "sensitive_fields": dict(s.sensitive_fields),
                "sens_type_counts": dict(s.sens_type_counts),
                "mask_strategy_counts": dict(s.mask_strategy_counts),
                "risk_level_counts": dict(s.risk_level_counts),
                "masked_cells": s.masked_cells,
                "whitelist_skipped_cells": s.whitelist_skipped_cells,
                "errors": s.errors,
                "warnings": s.warnings,
                "low_confidence_items": s.low_confidence_items,
                "unknown_format_fields": s.unknown_format_fields,
            }

        data = {
            "task_id": report.task_id,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "duration": report.duration,
            "operation": report.operation,
            "total_files": report.total_files,
            "success_files": report.success_files,
            "failed_files": report.failed_files,
            "skipped_files": report.skipped_files,
            "output_dir": report.output_dir,
            "config_used": report.config_used,
            "files": [_stat_to_dict(f) for f in report.files],
            "aggregate": report.aggregate,
        }
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return output_path

    @staticmethod
    def generate_task_summary(report: ProcessReport, output_path: str,
                              md_report: str = "", json_report: str = "") -> str:
        """生成可直接发给运营同事复核的任务清单摘要"""
        lines = []
        lines.append("# 数据脱敏处理 - 任务复核清单\n")
        lines.append(f"- **任务ID**: `{report.task_id}`")
        lines.append(f"- **操作类型**: `{report.operation}`")
        lines.append(f"- **执行时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.started_at))}")
        lines.append(f"- **耗时**: {report.duration:.2f}秒")
        lines.append(f"- **配置文件**: `{report.config_used}`")
        lines.append(f"- **输出目录**: `{report.output_dir}`\n")

        lines.append("## 📊 总体概览\n")
        lines.append("| 指标 | 数值 |")
        lines.append("|-----|------|")
        agg = report.aggregate or {}
        lines.append(f"| 待处理文件总数 | {report.total_files} |")
        lines.append(f"| ✅ 处理成功 | {report.success_files} |")
        lines.append(f"| ❌ 处理失败 | {report.failed_files} |")
        lines.append(f"| ⏭️  跳过(格式不支持) | {report.skipped_files} |")
        lines.append(f"| 处理记录总数 | {agg.get('total_records', 0)} |")
        lines.append(f"| 含敏感记录数 | {agg.get('records_with_sensitive', 0)} |")
        lines.append(f"| 脱敏单元格总数 | {agg.get('total_masked_cells', 0)} |")
        lines.append(f"| ⚠️  待人工补规则字段 | {agg.get('unknown_format_count', 0)} |")
        lines.append(f"| ⚠️  低置信度识别项 | {agg.get('low_confidence_count', 0)} |\n")

        lines.append("## 📁 处理明细\n")
        success_files = [f for f in report.files if not f.errors]
        fail_files = [f for f in report.files if f.errors]
        need_manual = [(f, u) for f in report.files for u in f.unknown_format_fields]

        lines.append("### ✅ 处理成功文件\n")
        if success_files:
            lines.append("| # | 源文件 | 格式 | 记录 | 敏感 | 脱敏单元格 | 输出文件 | 状态 |")
            lines.append("|---|-------|------|------|------|----------|---------|------|")
            for i, f in enumerate(success_files, 1):
                base_in = os.path.basename(f.filepath)
                base_out = os.path.basename(f.output_path) if f.output_path else "(未生成)"
                status = f.output_status or "OK"
                lines.append(
                    f"| {i} | `{base_in}` | {f.format} | {f.total_records} | "
                    f"{f.records_with_sensitive} | {f.masked_cells} | `{base_out}` | {status} |"
                )
            lines.append("")
            for f in success_files:
                if f.output_path:
                    lines.append(f"- `{f.filepath}` → `{f.output_path}`")
            lines.append("")
        else:
            lines.append("_暂无成功文件_\n")

        if need_manual:
            lines.append("### ⚠️  需要人工补规则的字段\n")
            lines.append("| 文件 | 字段名 | 示例值 | 建议操作 |")
            lines.append("|-----|-------|-------|---------|")
            seen_key = set()
            for f, u in need_manual:
                key = (os.path.basename(f.filepath), u.get("field"))
                if key in seen_key:
                    continue
                seen_key.add(key)
                example = str(u.get("value", ""))[:40]
                suggestion = u.get("suggestion", "在field_overrides中配置sens_type和strategy，或加入whitelist")
                lines.append(
                    f"| `{os.path.basename(f.filepath)}` | `{u.get('field')}` | `{example}` | {suggestion} |"
                )
            lines.append("")

        if fail_files:
            lines.append("### ❌ 处理失败/跳过文件\n")
            lines.append("| # | 文件 | 状态 | 错误信息 |")
            lines.append("|---|-----|------|---------|")
            for i, f in enumerate(fail_files, 1):
                base = os.path.basename(f.filepath)
                status = f.output_status or "FAIL"
                err = "；".join(f.errors)[:120]
                lines.append(f"| {i} | `{base}` | {status} | {err} |")
            lines.append("")

        lines.append("## 📄 关联报告\n")
        if md_report:
            lines.append(f"- 详细检查报告(Markdown): `{md_report}`")
        if json_report:
            lines.append(f"- 详细检查报告(JSON): `{json_report}`")
        lines.append(f"- 规则配置来源: `{report.config_used}`\n")

        lines.append("## 📝 复核说明\n")
        lines.append(
            "请数据运营同事完成以下复核:\n"
            "1. 抽样打开输出文件，确认各敏感字段打码效果符合上架要求；\n"
            "2. 检查「待人工补规则的字段」清单，如为敏感信息请补充规则后重跑；\n"
            "3. 检查「处理失败/跳过文件」清单，修复后重新提交处理；\n"
            "4. 全部确认无误后，将输出目录下的文件提交上架流程。\n"
        )
        lines.append("---\n")
        lines.append(f"*清单生成于 {time.strftime('%Y-%m-%d %H:%M:%S')} by DataMask Tool*")

        content = "\n".join(lines)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
