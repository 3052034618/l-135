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

    @classmethod
    def load(cls, filepath: Optional[str] = None) -> "MaskConfig":
        if filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cfg = cls(
                    type_rules=data.get("type_rules", {}),
                    field_overrides=data.get("field_overrides", {}),
                    whitelist_fields=data.get("whitelist_fields", []),
                    min_confidence=float(data.get("min_confidence", 0.6)),
                    source_file=filepath
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
                whitelist_fields=data.get("whitelist_fields", []),
                min_confidence=float(data.get("min_confidence", 0.6)),
                source_file=str(default_path)
            )
        return cls()

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
        for sens_type, rule_dict in self.type_rules.items():
            rules[sens_type] = MaskRule(
                sens_type=sens_type,
                strategy=rule_dict.get("strategy", "retain"),
                mask_char=rule_dict.get("mask_char", "*"),
                keep_start=int(rule_dict.get("keep_start", 3)),
                keep_end=int(rule_dict.get("keep_end", 4)),
                mapping_scope=rule_dict.get("mapping_scope", "global"),
                custom_pattern=rule_dict.get("custom_pattern"),
            )

        field_rules: Dict[str, MaskRule] = {}
        for fname, rule_dict in self.field_overrides.items():
            field_rules[fname] = MaskRule(
                sens_type=rule_dict.get("sens_type", "FIELD"),
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

        return MaskEngine(rules=rules, field_overrides=field_rules)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
