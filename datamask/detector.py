# -*- coding: utf-8 -*-
"""
敏感内容识别引擎
识别类型：手机号、身份证号、地址、姓名、企业名称
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class SensitiveMatch:
    """敏感匹配结果"""
    field_name: str
    value: str
    sens_type: str
    confidence: float
    start: int = 0
    end: int = 0


@dataclass
class DetectorResult:
    """检测结果"""
    has_sensitive: bool
    matches: List[SensitiveMatch] = field(default_factory=list)
    field_types: Dict[str, str] = field(default_factory=dict)


SENSITIVE_TYPES = {
    "PHONE": "手机号",
    "ID_CARD": "身份证号",
    "ADDRESS": "地址",
    "NAME": "姓名",
    "COMPANY": "企业名称",
    "EMAIL": "电子邮箱",
    "BANK_CARD": "银行卡号",
}


PHONE_PATTERN = re.compile(
    r'(?<!\d)(1[3-9]\d{9})(?!\d)'
)

ID_CARD_PATTERN = re.compile(
    r'(?<!\d)([1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)'
)

EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
)

BANK_CARD_PATTERN = re.compile(
    r'(?<!\d)(\d{16,19})(?!\d)'
)

PROVINCE_KEYWORDS = [
    "北京", "上海", "天津", "重庆",
    "河北", "山西", "辽宁", "吉林", "黑龙江",
    "江苏", "浙江", "安徽", "福建", "江西", "山东",
    "河南", "湖北", "湖南", "广东", "海南",
    "四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾",
    "内蒙古", "广西", "西藏", "宁夏", "新疆",
    "香港", "澳门",
]

CITY_SUFFIXES = ["市", "地区", "自治州", "盟", "特别行政区"]
DISTRICT_SUFFIXES = ["区", "县", "旗", "市"]
STREET_KEYWORDS = ["路", "街", "道", "巷", "号", "栋", "楼", "单元", "室"]

COMPANY_SUFFIXES = [
    "有限公司", "股份有限公司", "有限责任公司",
    "集团", "公司", "厂", "商店", "商行", "经营部",
    "合作社", "协会", "研究院", "研究所", "中心",
    "工作室", "事务所", "银行", "酒店", "宾馆",
]

COMMON_SURNAMES = [
    "王", "李", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴",
    "徐", "孙", "胡", "朱", "高", "林", "何", "郭", "马", "罗",
    "梁", "宋", "郑", "谢", "韩", "唐", "冯", "于", "董", "萧",
    "程", "曹", "袁", "邓", "许", "傅", "沈", "曾", "彭", "吕",
    "苏", "卢", "蒋", "蔡", "贾", "丁", "魏", "薛", "叶", "阎",
    "余", "潘", "杜", "戴", "夏", "钟", "汪", "田", "任", "姜",
    "范", "方", "石", "姚", "谭", "廖", "邹", "熊", "金", "陆",
    "郝", "孔", "白", "崔", "康", "毛", "邱", "秦", "江", "史",
    "顾", "侯", "邵", "孟", "龙", "万", "段", "雷", "钱", "汤",
]

COMPOUND_SURNAMES = [
    "欧阳", "太史", "端木", "上官", "司马", "东方", "独孤", "南宫",
    "万俟", "闻人", "夏侯", "诸葛", "尉迟", "公羊", "赫连", "澹台",
    "皇甫", "宗政", "濮阳", "公冶", "太叔", "申屠", "公孙", "慕容",
    "仲孙", "钟离", "长孙", "宇文", "司徒", "鲜于", "司空", "闾丘",
    "子车", "亓官", "司寇", "巫马", "公西", "颛孙", "壤驷", "公良",
    "漆雕", "乐正", "宰父", "谷梁", "拓跋", "夹谷", "轩辕", "令狐",
    "段干", "百里", "呼延", "东郭", "南门", "羊舌", "微生", "公户",
]

FIELD_NAME_HINTS: Dict[str, List[str]] = {
    "PHONE": ["phone", "mobile", "tel", "手机", "电话", "联系电话", "联系方式"],
    "ID_CARD": ["id", "idcard", "identity", "身份证", "证件号", "证件号码", "身份"],
    "ADDRESS": ["address", "addr", "地址", "住址", "居住地址", "通讯地址"],
    "NAME": ["name", "姓名", "名字", "客户名", "用户名", "user_name", "username"],
    "COMPANY": ["company", "enterprise", "corp", "企业", "公司", "单位", "机构名称"],
    "EMAIL": ["email", "mail", "邮箱", "电子邮件"],
    "BANK_CARD": ["bank", "card", "银行卡", "卡号", "账号", "账户"],
}


def detect_by_field_name(field_name: str) -> Optional[str]:
    """根据字段名判断敏感类型"""
    name_lower = field_name.lower().strip()
    for sens_type, keywords in FIELD_NAME_HINTS.items():
        for kw in keywords:
            if kw.lower() in name_lower:
                return sens_type
    return None


def detect_phone(value: str) -> List[SensitiveMatch]:
    """检测手机号"""
    matches = []
    if not isinstance(value, str):
        return matches
    for m in PHONE_PATTERN.finditer(value):
        matches.append(SensitiveMatch(
            field_name="",
            value=m.group(1),
            sens_type="PHONE",
            confidence=0.95,
            start=m.start(1),
            end=m.end(1)
        ))
    return matches


def detect_id_card(value: str) -> List[SensitiveMatch]:
    """检测身份证号"""
    matches = []
    if not isinstance(value, str):
        return matches
    for m in ID_CARD_PATTERN.finditer(value):
        id_str = m.group(1)
        if validate_id_card_checksum(id_str):
            conf = 0.99
        else:
            conf = 0.85
        matches.append(SensitiveMatch(
            field_name="",
            value=id_str,
            sens_type="ID_CARD",
            confidence=conf,
            start=m.start(1),
            end=m.end(1)
        ))
    return matches


def validate_id_card_checksum(id_str: str) -> bool:
    """校验身份证校验码"""
    if len(id_str) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    try:
        total = sum(int(id_str[i]) * weights[i] for i in range(17))
        expected = check_codes[total % 11]
        return id_str[17].upper() == expected
    except (ValueError, IndexError):
        return False


def detect_email(value: str) -> List[SensitiveMatch]:
    """检测邮箱"""
    matches = []
    if not isinstance(value, str):
        return matches
    for m in EMAIL_PATTERN.finditer(value):
        matches.append(SensitiveMatch(
            field_name="",
            value=m.group(0),
            sens_type="EMAIL",
            confidence=0.98,
            start=m.start(),
            end=m.end()
        ))
    return matches


def detect_bank_card(value: str) -> List[SensitiveMatch]:
    """检测银行卡号"""
    matches = []
    if not isinstance(value, str):
        return matches
    for m in BANK_CARD_PATTERN.finditer(value):
        card_num = m.group(1)
        conf = 0.75
        if luhn_check(card_num):
            conf = 0.90
        matches.append(SensitiveMatch(
            field_name="",
            value=card_num,
            sens_type="BANK_CARD",
            confidence=conf,
            start=m.start(1),
            end=m.end(1)
        ))
    return matches


def luhn_check(num_str: str) -> bool:
    """Luhn算法校验银行卡号"""
    try:
        digits = [int(d) for d in num_str]
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except (ValueError, TypeError):
        return False


def detect_address(value: str) -> List[SensitiveMatch]:
    """检测地址"""
    matches = []
    if not isinstance(value, str) or len(value) < 5:
        return matches

    has_province = any(p in value for p in PROVINCE_KEYWORDS)
    has_city_suffix = any(s in value for s in CITY_SUFFIXES)
    has_district = any(s in value for s in DISTRICT_SUFFIXES)
    has_street = any(k in value for k in STREET_KEYWORDS)
    has_number = bool(re.search(r'\d+号|\d+栋|\d+单元|\d+室', value))

    score = 0
    if has_province:
        score += 0.4
    if has_city_suffix:
        score += 0.2
    if has_district:
        score += 0.15
    if has_street:
        score += 0.15
    if has_number:
        score += 0.1

    if score >= 0.5:
        matches.append(SensitiveMatch(
            field_name="",
            value=value,
            sens_type="ADDRESS",
            confidence=min(score, 0.98),
            start=0,
            end=len(value)
        ))
    return matches


def detect_company(value: str) -> List[SensitiveMatch]:
    """检测企业名称"""
    matches = []
    if not isinstance(value, str) or len(value) < 4:
        return matches

    has_suffix = any(s in value for s in COMPANY_SUFFIXES)
    has_location = any(p in value for p in PROVINCE_KEYWORDS) or any(s in value for s in CITY_SUFFIXES)
    is_not_sentence = (len(value) <= 30 and value.count("，") == 0 and value.count("。") == 0)

    score = 0
    if has_suffix:
        score += 0.6
    if has_location:
        score += 0.2
    if is_not_sentence:
        score += 0.15

    if score >= 0.6:
        matches.append(SensitiveMatch(
            field_name="",
            value=value,
            sens_type="COMPANY",
            confidence=min(score, 0.95),
            start=0,
            end=len(value)
        ))
    return matches


def detect_name(value: str) -> List[SensitiveMatch]:
    """检测姓名"""
    matches = []
    if not isinstance(value, str):
        return matches
    stripped = value.strip()
    if len(stripped) < 2 or len(stripped) > 6:
        return matches
    if not re.match(r'^[\u4e00-\u9fa5]+$', stripped):
        return matches

    starts_with_compound = any(stripped.startswith(s) for s in COMPOUND_SURNAMES)
    starts_with_surname = any(stripped.startswith(s) for s in COMMON_SURNAMES)

    if starts_with_compound:
        if len(stripped) >= 3:
            matches.append(SensitiveMatch(
                field_name="",
                value=stripped,
                sens_type="NAME",
                confidence=0.85,
                start=0,
                end=len(stripped)
            ))
    elif starts_with_surname and len(stripped) <= 4:
        matches.append(SensitiveMatch(
            field_name="",
            value=stripped,
            sens_type="NAME",
            confidence=0.75,
            start=0,
            end=len(stripped)
        ))
    return matches


ALL_DETECTORS = [
    detect_phone,
    detect_id_card,
    detect_email,
    detect_bank_card,
    detect_address,
    detect_company,
    detect_name,
]


def detect_value(value: Any, field_name: str = "",
                 min_confidence: float = 0.6) -> List[SensitiveMatch]:
    """检测单个值中的所有敏感内容"""
    if value is None:
        return []
    str_val = str(value).strip()
    if not str_val:
        return []

    all_matches: List[SensitiveMatch] = []
    type_hint = detect_by_field_name(field_name) if field_name else None

    for detector in ALL_DETECTORS:
        try:
            found = detector(str_val)
            for fm in found:
                fm.field_name = field_name
                if type_hint and fm.sens_type == type_hint:
                    fm.confidence = min(fm.confidence + 0.05, 1.0)
                if fm.confidence >= min_confidence:
                    all_matches.append(fm)
        except Exception:
            continue

    all_matches.sort(key=lambda m: -m.confidence)
    return all_matches


def detect_record(record: Dict[str, Any], whitelist: List[str] = None,
                  min_confidence: float = 0.6) -> DetectorResult:
    """检测一条记录中的所有字段"""
    whitelist = whitelist or []
    matches: List[SensitiveMatch] = []
    field_types: Dict[str, str] = {}

    for field_name, value in record.items():
        if field_name in whitelist:
            continue
        field_matches = detect_value(value, field_name, min_confidence)
        if field_matches:
            best = field_matches[0]
            matches.extend(field_matches)
            if field_name and best.confidence >= min_confidence:
                field_types[field_name] = best.sens_type

    return DetectorResult(
        has_sensitive=len(matches) > 0,
        matches=matches,
        field_types=field_types
    )
