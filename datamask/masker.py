# -*- coding: utf-8 -*-
"""
脱敏策略模块
支持三种策略：保留位数、替换字符、随机映射
"""
import hashlib
import random
import re
import string
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from faker import Faker


DEFAULT_MASK_CHAR = "*"


@dataclass
class MaskRule:
    """脱敏规则配置"""
    sens_type: str
    strategy: str = "retain"
    mask_char: str = DEFAULT_MASK_CHAR
    keep_start: int = 3
    keep_end: int = 4
    mapping_scope: str = "global"
    custom_pattern: Optional[str] = None


@dataclass
class MaskResult:
    """脱敏结果"""
    original: Any
    masked: Any
    changed: bool
    rule_used: Optional[str]
    risk_level: str = "normal"


class RandomMapper:
    """随机映射器 - 保证相同输入得到相同输出"""

    def __init__(self, locale: str = "zh_CN"):
        self._cache: Dict[str, Dict[str, str]] = {}
        self._faker = Faker(locale)
        self._name_chars = "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
        self._company_prefixes = ["金诚", "宏达", "瑞华", "安泰", "恒信", "盛隆", "盈科", "明达", "鑫源", "国丰"]
        self._company_suffixes = ["科技有限公司", "贸易有限公司", "实业有限公司", "咨询有限公司", "服务有限公司"]
        self._street_prefixes = ["中山", "人民", "解放", "建设", "和平", "胜利", "朝阳", "长江", "黄河", "珠江"]
        self._street_suffixes = ["路", "街", "大道", "巷", "道"]

    def _hash_key(self, scope: str, key: str) -> str:
        raw = f"{scope}||{key}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _get_or_create(self, scope: str, key: str, generator: Callable[[str], str]) -> str:
        hkey = self._hash_key(scope, key)
        cache = self._cache.setdefault(scope, {})
        if hkey not in cache:
            cache[hkey] = generator(key)
        return cache[hkey]

    def map_phone(self, original: str, scope: str = "phone") -> str:
        def gen(_):
            prefix = random.choice(["138", "139", "150", "151", "152", "158", "159", "186", "187", "188"])
            suffix = "".join(random.choices(string.digits, k=8))
            return prefix + suffix
        return self._get_or_create(scope, original, gen)

    def map_id_card(self, original: str, scope: str = "idcard") -> str:
        def gen(_):
            region = "".join(random.choices(string.digits, k=6))
            year = str(random.randint(1960, 2005))
            month = f"{random.randint(1, 12):02d}"
            day = f"{random.randint(1, 28):02d}"
            seq = "".join(random.choices(string.digits, k=3))
            check = random.choice(string.digits + "X")
            return region + year + month + day + seq + check
        return self._get_or_create(scope, original, gen)

    def map_name(self, original: str, scope: str = "name") -> str:
        def gen(_):
            surname = random.choice(self._name_chars[:20])
            given_len = random.choice([1, 2])
            given = "".join(random.choices(self._name_chars, k=given_len))
            return surname + given
        return self._get_or_create(scope, original, gen)

    def map_company(self, original: str, scope: str = "company") -> str:
        def gen(_):
            prefix = random.choice(self._company_prefixes)
            suffix = random.choice(self._company_suffixes)
            return prefix + suffix
        return self._get_or_create(scope, original, gen)

    def map_address(self, original: str, scope: str = "address") -> str:
        def gen(_):
            province = random.choice(PROVINCES)
            city = random.choice(["市", "自治州"])
            street_p = random.choice(self._street_prefixes)
            street_s = random.choice(self._street_suffixes)
            num = random.randint(1, 999)
            return f"{province}{random.choice(['A', 'B', 'C'])}{city}{street_p}{street_s}{num}号"
        return self._get_or_create(scope, original, gen)

    def map_email(self, original: str, scope: str = "email") -> str:
        def gen(_):
            name_len = random.randint(5, 10)
            name = "".join(random.choices(string.ascii_lowercase, k=name_len))
            domain = random.choice(["example.com", "test.com", "demo.cn", "sample.org"])
            return f"{name}@{domain}"
        return self._get_or_create(scope, original, gen)

    def map_bank_card(self, original: str, scope: str = "bankcard") -> str:
        def gen(_):
            prefix = random.choice(["6222", "6228", "6216", "6217", "6205"])
            length = len(original) if original else 19
            rest_len = max(length - len(prefix), 0)
            rest = "".join(random.choices(string.digits, k=rest_len))
            return prefix + rest
        return self._get_or_create(scope, original, gen)

    def map_generic(self, original: str, scope: str = "generic") -> str:
        def gen(orig):
            if not orig:
                return ""
            length = len(orig)
            masked = []
            for ch in orig:
                if '\u4e00' <= ch <= '\u9fff':
                    masked.append(random.choice(self._name_chars))
                elif ch.isdigit():
                    masked.append(random.choice(string.digits))
                elif ch.isalpha():
                    case = random.choice([string.ascii_lowercase, string.ascii_uppercase])
                    masked.append(random.choice(case))
                else:
                    masked.append(ch)
            return "".join(masked)
        return self._get_or_create(scope, original, gen)


PROVINCES = [
    "北京市", "天津市", "河北省", "山西省", "内蒙古自治区",
    "辽宁省", "吉林省", "黑龙江省", "上海市", "江苏省",
    "浙江省", "安徽省", "福建省", "江西省", "山东省",
    "河南省", "湖北省", "湖南省", "广东省", "广西壮族自治区",
    "海南省", "重庆市", "四川省", "贵州省", "云南省",
    "西藏自治区", "陕西省", "甘肃省", "青海省", "宁夏回族自治区",
    "新疆维吾尔自治区",
]


def mask_retain(value: str, keep_start: int = 3, keep_end: int = 4,
                mask_char: str = DEFAULT_MASK_CHAR) -> str:
    """按保留位数脱敏 - 保留首尾若干字符"""
    if not isinstance(value, str) or not value:
        return value
    n = len(value)
    ks = max(0, keep_start)
    ke = max(0, keep_end)
    if n <= ks + ke:
        half = n // 2
        start_keep = max(1, half - 1) if n > 2 else 1
        end_keep = max(0, n - start_keep - max(1, n // 3))
        if start_keep + end_keep >= n:
            end_keep = max(0, n - start_keep - 1)
        middle_len = n - start_keep - end_keep
        end_part = value[n - end_keep:] if end_keep > 0 else ""
        return value[:start_keep] + mask_char * middle_len + end_part
    end_part = value[n - ke:] if ke > 0 else ""
    return value[:ks] + mask_char * (n - ks - ke) + end_part


def mask_replace(value: str, mask_char: str = DEFAULT_MASK_CHAR,
                 pattern: Optional[str] = None) -> str:
    """按替换字符脱敏 - 全量或按模式替换"""
    if not isinstance(value, str) or not value:
        return value
    if pattern:
        try:
            return re.sub(pattern, lambda m: mask_char * len(m.group(0)), value)
        except re.error:
            pass
    return mask_char * len(value)


class MaskEngine:
    """脱敏引擎"""

    def __init__(self, rules: Optional[Dict[str, MaskRule]] = None,
                 field_overrides: Optional[Dict[str, MaskRule]] = None):
        self.rules = rules or {}
        self.field_overrides = field_overrides or {}
        self.mapper = RandomMapper()
        self._init_default_rules()

    def _init_default_rules(self):
        defaults = {
            "PHONE": MaskRule("PHONE", "retain", "*", 3, 4),
            "ID_CARD": MaskRule("ID_CARD", "retain", "*", 6, 4),
            "NAME": MaskRule("NAME", "retain", "*", 1, 0),
            "COMPANY": MaskRule("COMPANY", "retain", "*", 2, 4),
            "ADDRESS": MaskRule("ADDRESS", "retain", "*", 6, 3),
            "EMAIL": MaskRule("EMAIL", "retain", "*", 2, 4),
            "BANK_CARD": MaskRule("BANK_CARD", "retain", "*", 4, 4),
        }
        for k, v in defaults.items():
            if k not in self.rules:
                self.rules[k] = v

    def set_rule(self, rule: MaskRule):
        self.rules[rule.sens_type] = rule

    def set_field_rule(self, field_name: str, rule: MaskRule):
        self.field_overrides[field_name] = rule

    def _apply_strategy(self, value: str, rule: MaskRule) -> str:
        if not isinstance(value, str):
            return value
        if rule.strategy == "retain":
            return mask_retain(value, rule.keep_start, rule.keep_end, rule.mask_char)
        elif rule.strategy == "replace":
            return mask_replace(value, rule.mask_char, rule.custom_pattern)
        elif rule.strategy == "random":
            return self._random_map(value, rule.sens_type, rule.mapping_scope)
        else:
            return mask_retain(value, rule.keep_start, rule.keep_end, rule.mask_char)

    def _random_map(self, value: str, sens_type: str, scope: str) -> str:
        if sens_type == "PHONE":
            return self.mapper.map_phone(value, f"{scope}:phone")
        elif sens_type == "ID_CARD":
            return self.mapper.map_id_card(value, f"{scope}:idcard")
        elif sens_type == "NAME":
            return self.mapper.map_name(value, f"{scope}:name")
        elif sens_type == "COMPANY":
            return self.mapper.map_company(value, f"{scope}:company")
        elif sens_type == "ADDRESS":
            return self.mapper.map_address(value, f"{scope}:address")
        elif sens_type == "EMAIL":
            return self.mapper.map_email(value, f"{scope}:email")
        elif sens_type == "BANK_CARD":
            return self.mapper.map_bank_card(value, f"{scope}:bankcard")
        else:
            return self.mapper.map_generic(value, f"{scope}:generic")

    def mask_value(self, value: Any, sens_type: Optional[str] = None,
                   field_name: str = "") -> MaskResult:
        """对单个值脱敏"""
        if value is None or (isinstance(value, str) and not value.strip()):
            return MaskResult(original=value, masked=value, changed=False, rule_used=None)

        str_val = str(value)

        rule = None
        rule_source = None
        if field_name and field_name in self.field_overrides:
            rule = self.field_overrides[field_name]
            rule_source = f"field:{field_name}"
        elif sens_type and sens_type in self.rules:
            rule = self.rules[sens_type]
            rule_source = f"type:{sens_type}"

        if not rule:
            default_rule = MaskRule("UNKNOWN", "retain", "*", 2, 2)
            masked = mask_retain(str_val, default_rule.keep_start, default_rule.keep_end)
            return MaskResult(
                original=value,
                masked=masked,
                changed=(str_val != masked),
                rule_used="default_retain",
                risk_level="unknown"
            )

        masked = self._apply_strategy(str_val, rule)
        risk = "normal"
        if rule.strategy == "retain" and (rule.keep_start + rule.keep_end) >= len(str_val):
            risk = "low_mask"
        if rule.strategy == "random":
            risk = "high_safe"

        return MaskResult(
            original=value,
            masked=masked,
            changed=(str_val != str(masked)),
            rule_used=rule_source,
            risk_level=risk
        )

    def mask_record(self, record: Dict[str, Any],
                    field_sens_types: Dict[str, str],
                    whitelist: List[str] = None) -> Dict[str, Any]:
        """对一条记录脱敏"""
        whitelist = whitelist or []
        result = {}
        for field, value in record.items():
            if field in whitelist:
                result[field] = value
                continue
            sens_type = field_sens_types.get(field)
            mr = self.mask_value(value, sens_type, field)
            result[field] = mr.masked
        return result

    def mask_record_with_details(self, record: Dict[str, Any],
                                 field_sens_types: Dict[str, str],
                                 whitelist: List[str] = None) -> Dict[str, MaskResult]:
        """脱敏并返回详细结果"""
        whitelist = whitelist or []
        details = {}
        for field, value in record.items():
            if field in whitelist:
                details[field] = MaskResult(
                    original=value, masked=value, changed=False, rule_used="whitelist_skip"
                )
                continue
            sens_type = field_sens_types.get(field)
            details[field] = self.mask_value(value, sens_type, field)
        return details
