# -*- coding: utf-8 -*-
"""
配置加载与管理
"""
import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Any, Optional
from .masker import MaskRule, MaskEngine


@dataclass
class MaskConfig:
    """脱敏配置"""
    type_rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    field_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    whitelist_fields: List[str] = field(default_factory=list)
    min_confidence: float = 0.6
    source_file: Optional[str] = None
    draft_source: Optional[str] = None
    skipped_fields: List[str] = field(default_factory=list)
    draft_field_meta: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, filepath: Optional[str] = None) -> "MaskConfig":
        if filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                raw_field_overrides = data.get("field_overrides", {}) or {}
                cleaned_field_overrides: Dict[str, Dict[str, Any]] = {}
                skipped: List[str] = []
                field_meta: Dict[str, Dict[str, Any]] = {}

                for fname, entry in raw_field_overrides.items():
                    if not isinstance(entry, dict):
                        continue
                    status = entry.get("status", "CUSTOM")
                    has_explicit = "sens_type" in entry or "strategy" in entry
                    meta = {"status": status}
                    for k in ("detected_type", "suggestion", "#说明", "#提示", "#识别说明", "#示例值"):
                        if k in entry:
                            meta[k] = entry[k]
                    field_meta[fname] = meta

                    if status == "SKIP_NON_SENSITIVE" and not has_explicit:
                        skipped.append(fname)
                        continue
                    if status == "NEED_MANUAL" and not has_explicit:
                        continue

                    effective: Dict[str, Any] = {}
                    if "sens_type" in entry:
                        effective["sens_type"] = entry["sens_type"]
                    elif "detected_type" in entry and entry["detected_type"]:
                        effective["sens_type"] = entry["detected_type"]

                    for k in ("strategy", "mask_char", "keep_start", "keep_end",
                              "mapping_scope", "custom_pattern"):
                        if k in entry:
                            effective[k] = entry[k]

                    if effective:
                        cleaned_field_overrides[fname] = effective
                    elif has_explicit:
                        cleaned_field_overrides[fname] = {"sens_type": effective.get("sens_type", "FIELD")}

                cfg = cls(
                    type_rules=data.get("type_rules", {}),
                    field_overrides=cleaned_field_overrides,
                    whitelist_fields=list(data.get("whitelist_fields", []) or []),
                    min_confidence=float(data.get("min_confidence", 0.6)),
                    source_file=filepath,
                    draft_source=filepath if bool(field_meta) else None,
                    skipped_fields=skipped,
                    draft_field_meta=field_meta,
                )
                return cfg
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                raise ValueError(f"配置文件解析失败 '{filepath}': {e}")

        default_path = Path(__file__).parent / "rules" / "default_rules.json"
        if default_path.exists():
            with open(str(default_path), "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(
                type_rules=data.get("type_rules", {}),
                field_overrides=data.get("field_overrides", {}),
                whitelist_fields=list(data.get("whitelist_fields", []) or []),
                min_confidence=float(data.get("min_confidence", 0.6)),
                source_file=str(default_path)
            )
        return cls()

    def export_template(self, filepath: str, with_comments: bool = True) -> None:
        """导出一份带详细说明和示例的可编辑规则模板"""
        import copy
        base_type_rules: Dict[str, Any] = {}
        defaults = {
            "PHONE": ("手机号", "retain", 3, 4, "*"),
            "ID_CARD": ("身份证号", "retain", 6, 4, "*"),
            "NAME": ("姓名", "retain", 1, 0, "*"),
            "COMPANY": ("企业名称", "retain", 2, 4, "*"),
            "ADDRESS": ("地址", "retain", 6, 3, "*"),
            "EMAIL": ("电子邮箱", "retain", 2, 4, "*"),
            "BANK_CARD": ("银行卡号", "retain", 4, 4, "*"),
        }
        for stype, (label, strat, ks, ke, mc) in defaults.items():
            entry: Dict[str, Any] = {"strategy": strat, "keep_start": ks, "keep_end": ke, "mask_char": mc}
            if with_comments:
                entry["#类型说明"] = label
                if strat == "retain":
                    entry["#策略说明"] = f"保留前{ks}位、后{ke}位，中间用'{mc}'打码"
            base_type_rules[stype] = entry

        sample_overrides: Dict[str, Any] = {}
        if with_comments:
            sample_overrides = {
                "示例_手机号列": {
                    "#使用场景": "当字段名无法被自动识别（如 field_01），通过指定 sens_type 强制按手机号策略处理",
                    "sens_type": "PHONE",
                    "#可选_覆盖策略": "如不写，则使用 type_rules 中 PHONE 的策略",
                },
                "示例_特殊备注": {
                    "#使用场景": "对某个字段单独指定脱敏策略",
                    "sens_type": "COMPANY",
                    "strategy": "replace",
                    "mask_char": "#",
                },
            }

        data: Dict[str, Any] = {
            "version": "1.0",
            "#模板说明": (
                "数据脱敏规则模板\n"
                "  - type_rules: 每种敏感类型的全局策略（一般无需改动）\n"
                "  - field_overrides: 单字段级别的定制规则，不写则由系统自动识别\n"
                "    • status: AUTO_OK(自动识别) / NEED_MANUAL(需要人工补充sens_type) / SKIP_NON_SENSITIVE(跳过)\n"
                "    • 如需强制脱敏某字段，请至少填写 sens_type；想自定义策略再加 strategy/keep_start 等\n"
                "  - whitelist_fields: 绝对跳过不处理的字段名列表\n"
                "  - min_confidence: 识别的置信度阈值，值越高越严格（建议 0.5~0.75）"
            ),
            "type_rules": base_type_rules,
            "field_overrides": sample_overrides,
            "whitelist_fields": ["示例_白名单字段1", "id", "create_time"],
            "min_confidence": 0.6,
        }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def save(self, filepath: str) -> None:
        data = {
            "version": "1.0",
            "type_rules": self.type_rules,
            "field_overrides": self.field_overrides,
            "whitelist_fields": self.whitelist_fields,
            "min_confidence": self.min_confidence,
        }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def build_mask_engine(self, cli_overrides: Optional[Dict[str, Any]] = None) -> MaskEngine:
        rules: Dict[str, MaskRule] = {}
        merged_type_rules: Dict[str, Dict[str, Any]] = {}
        for k, v in self.type_rules.items():
            merged_type_rules[k] = {kk: vv for kk, vv in v.items() if not kk.startswith("#")}

        for sens_type, rule_dict in merged_type_rules.items():
            rules[sens_type] = MaskRule(
                sens_type=sens_type,
                strategy=rule_dict.get("strategy", "retain"),
                mask_char=rule_dict.get("mask_char", "*"),
                keep_start=int(rule_dict.get("keep_start", 3)),
                keep_end=int(rule_dict.get("keep_end", 4)),
                mapping_scope=rule_dict.get("mapping_scope", "global"),
                custom_pattern=rule_dict.get("custom_pattern"),
            )

        if cli_overrides:
            for sens_type, strategy in cli_overrides.items():
                if sens_type in rules:
                    if isinstance(strategy, str):
                        rules[sens_type].strategy = strategy
                    elif isinstance(strategy, dict):
                        for k, v in strategy.items():
                            if hasattr(rules[sens_type], k):
                                setattr(rules[sens_type], k, v)

        field_rules: Dict[str, MaskRule] = {}
        for fname, rule_dict in self.field_overrides.items():
            clean = {k: v for k, v in rule_dict.items() if not str(k).startswith("#")}
            sens_type = str(clean.get("sens_type", "FIELD"))
            strategy = clean.get("strategy")
            base_type_cfg = merged_type_rules.get(sens_type, {}) if sens_type in merged_type_rules else {}

            def _pick(key: str, default: Any) -> Any:
                if key in clean:
                    return clean[key]
                if strategy is None and key == "strategy" and base_type_cfg:
                    return base_type_cfg.get("strategy", "retain")
                if strategy is None:
                    return default
                if base_type_cfg and key in base_type_cfg:
                    return base_type_cfg[key]
                return default

            field_rules[fname] = MaskRule(
                sens_type=sens_type,
                strategy=strategy or (base_type_cfg.get("strategy", "retain") if base_type_cfg else "retain"),
                mask_char=str(_pick("mask_char", "*")),
                keep_start=int(_pick("keep_start", 3)),
                keep_end=int(_pick("keep_end", 4)),
                mapping_scope=str(_pick("mapping_scope", "global")),
                custom_pattern=clean.get("custom_pattern"),
            )

        return MaskEngine(rules=rules, field_overrides=field_rules)

    def validate(self) -> Dict[str, Any]:
        """校验配置的合法性，返回校验结果

        Returns:
            {
                "valid": bool,               # 是否整体通过（无 error 级问题）
                "issues": [...],             # 问题清单
                "stats": {                   # 统计
                    "type_rules_total": int,
                    "type_rules_ok": int,
                    "field_overrides_total": int,
                    "fields_ok": int,
                    "fields_warning": int,
                    "fields_error": int,
                    "fields_skipped": int,
                    "fields_need_manual": int,
                    "whitelist_count": int,
                    "whitelist_conflicts": int,
                },
                "field_status": {fname: status, ...},
            }
        """
        from .detector import SENSITIVE_TYPES

        issues: List[Dict[str, Any]] = []
        field_status: Dict[str, str] = {}
        valid_sens_types = set(SENSITIVE_TYPES.keys())
        valid_strategies = {"retain", "replace", "random"}

        type_rules_ok = 0
        for stype, rule in self.type_rules.items():
            clean = {k: v for k, v in rule.items() if not str(k).startswith("#")}
            has_issue = False
            if stype not in valid_sens_types:
                issues.append({
                    "level": "warning",
                    "field": f"type_rules.{stype}",
                    "category": "sens_type",
                    "message": f"敏感类型 '{stype}' 不在标准类型列表中",
                })
                has_issue = True
            strategy = clean.get("strategy", "retain")
            if strategy not in valid_strategies:
                issues.append({
                    "level": "error",
                    "field": f"type_rules.{stype}",
                    "category": "strategy",
                    "message": f"策略 '{strategy}' 不合法，支持: retain/replace/random",
                })
                has_issue = True
            if strategy == "retain":
                ks = clean.get("keep_start", 3)
                ke = clean.get("keep_end", 4)
                try:
                    int(ks); int(ke)
                except (TypeError, ValueError):
                    issues.append({
                        "level": "error",
                        "field": f"type_rules.{stype}",
                        "category": "params",
                        "message": "retain 策略要求 keep_start/keep_end 为整数",
                    })
                    has_issue = True
            if not has_issue:
                type_rules_ok += 1

        whitelist_set = set(self.whitelist_fields)

        fields_ok = 0
        fields_warning = 0
        fields_error = 0
        fields_skipped = 0
        fields_need_manual = 0
        whitelist_conflicts = 0

        for fname in self.skipped_fields:
            field_status[fname] = "SKIPPED"
            fields_skipped += 1
            if fname in whitelist_set:
                whitelist_conflicts += 1
                issues.append({
                    "level": "info",
                    "field": fname,
                    "category": "conflict",
                    "message": "字段同时在白名单和跳过列表中（不冲突，仅提示）",
                })

        for fname, meta in self.draft_field_meta.items():
            if fname in field_status:
                continue
            status = meta.get("status", "CUSTOM")
            if status == "NEED_MANUAL":
                field_status[fname] = "NEED_MANUAL"
                fields_need_manual += 1
                issues.append({
                    "level": "warning",
                    "field": fname,
                    "category": "manual",
                    "message": meta.get("#提示") or meta.get("suggestion") or "该字段需要人工补充 sens_type 后才能使用",
                })

        for fname, rule in self.field_overrides.items():
            level = "ok"
            stype = rule.get("sens_type")
            strategy = rule.get("strategy")
            has_error = False
            has_warning = False

            if not stype:
                issues.append({
                    "level": "error",
                    "field": fname,
                    "category": "sens_type",
                    "message": "缺少 sens_type 配置",
                })
                has_error = True
            elif stype not in valid_sens_types and stype != "FIELD":
                issues.append({
                    "level": "warning",
                    "field": fname,
                    "category": "sens_type",
                    "message": f"sens_type '{stype}' 不在标准类型列表中",
                })
                has_warning = True

            if strategy and strategy not in valid_strategies:
                issues.append({
                    "level": "error",
                    "field": fname,
                    "category": "strategy",
                    "message": f"策略 '{strategy}' 不合法",
                })
                has_error = True

            if strategy == "retain":
                ks = rule.get("keep_start")
                ke = rule.get("keep_end")
                if ks is not None:
                    try:
                        int(ks)
                    except (TypeError, ValueError):
                        issues.append({
                            "level": "error",
                            "field": fname,
                            "category": "params",
                            "message": "keep_start 必须为整数",
                        })
                        has_error = True
                if ke is not None:
                    try:
                        int(ke)
                    except (TypeError, ValueError):
                        issues.append({
                            "level": "error",
                            "field": fname,
                            "category": "params",
                            "message": "keep_end 必须为整数",
                        })
                        has_error = True

            if fname in whitelist_set:
                whitelist_conflicts += 1
                issues.append({
                    "level": "warning",
                    "field": fname,
                    "category": "conflict",
                    "message": "字段同时在白名单和 field_overrides 中，白名单优先级更高将跳过处理",
                })
                has_warning = True

            if has_error:
                field_status[fname] = "ERROR"
                fields_error += 1
            elif has_warning:
                field_status[fname] = "WARNING"
                fields_warning += 1
            else:
                field_status[fname] = "OK"
                fields_ok += 1

        valid = not any(i["level"] == "error" for i in issues)

        stats = {
            "type_rules_total": len(self.type_rules),
            "type_rules_ok": type_rules_ok,
            "field_overrides_total": len(self.field_overrides) + len(self.skipped_fields) + fields_need_manual,
            "fields_ok": fields_ok,
            "fields_warning": fields_warning,
            "fields_error": fields_error,
            "fields_skipped": fields_skipped,
            "fields_need_manual": fields_need_manual,
            "whitelist_count": len(self.whitelist_fields),
            "whitelist_conflicts": whitelist_conflicts,
        }

        return {
            "valid": valid,
            "issues": issues,
            "stats": stats,
            "field_status": field_status,
        }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
