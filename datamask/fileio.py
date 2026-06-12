# -*- coding: utf-8 -*-
"""
文件读写层
支持：CSV、JSON、Excel (.xlsx/.xls)
"""
import os
import json
import csv
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Iterator

SUPPORTED_FORMATS = {
    ".csv": "CSV",
    ".json": "JSON",
    ".xlsx": "Excel",
    ".xls": "Excel",
}


class UnsupportedFormatError(Exception):
    """不支持的文件格式异常"""

    def __init__(self, filepath: str, detail: str = ""):
        self.filepath = filepath
        self.ext = Path(filepath).suffix.lower()
        msg = f"无法识别的文件格式: '{filepath}'"
        if self.ext:
            msg += f" (扩展名: {self.ext})"
        else:
            msg += " (无扩展名)"
        msg += f"\n支持的格式: {', '.join(SUPPORTED_FORMATS.keys())}"
        if detail:
            msg += f"\n详细信息: {detail}"
        super().__init__(msg)


class FileReadError(Exception):
    """文件读取异常"""

    def __init__(self, filepath: str, reason: str):
        self.filepath = filepath
        self.reason = reason
        super().__init__(f"读取文件失败 '{filepath}': {reason}")


class FileWriteError(Exception):
    """文件写入异常"""

    def __init__(self, filepath: str, reason: str):
        self.filepath = filepath
        self.reason = reason
        super().__init__(f"写入文件失败 '{filepath}': {reason}")


@dataclass
class DataFile:
    """数据文件包装"""
    filepath: str
    records: List[Dict[str, Any]] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    format: str = ""
    total_records: int = 0

    def __post_init__(self):
        if not self.format:
            ext = Path(self.filepath).suffix.lower()
            self.format = SUPPORTED_FORMATS.get(ext, "")


def is_supported_format(filepath: str) -> bool:
    ext = Path(filepath).suffix.lower()
    return ext in SUPPORTED_FORMATS


def get_supported_files(folder: str, recursive: bool = True) -> List[str]:
    folder_path = Path(folder)
    if not folder_path.exists():
        return []
    if folder_path.is_file():
        if is_supported_format(str(folder_path)):
            return [str(folder_path)]
        return []

    pattern = "**/*" if recursive else "*"
    files = []
    for p in folder_path.glob(pattern):
        if p.is_file() and is_supported_format(str(p)):
            files.append(str(p))
    return sorted(files)


def read_csv(filepath: str, encoding: str = "utf-8-sig") -> Tuple[List[str], List[Dict[str, Any]]]:
    try:
        with open(filepath, "r", encoding=encoding, newline="") as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                reader = csv.DictReader(f, dialect=dialect)
            except (csv.Error, Exception):
                reader = csv.DictReader(f)
            records = list(reader)
        if not records:
            return [], []
        fields = list(records[0].keys())
        return fields, records
    except UnicodeDecodeError as e:
        raise FileReadError(filepath, f"编码错误(尝试{encoding}): {e}. 请确认文件编码")
    except csv.Error as e:
        raise FileReadError(filepath, f"CSV解析错误: {e}")
    except Exception as e:
        raise FileReadError(filepath, str(e))


def write_csv(filepath: str, fields: List[str], records: List[Dict[str, Any]],
              encoding: str = "utf-8-sig") -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    try:
        with open(filepath, "w", encoding=encoding, newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
    except Exception as e:
        raise FileWriteError(filepath, str(e))


def read_json(filepath: str, encoding: str = "utf-8") -> Tuple[List[str], List[Dict[str, Any]]]:
    try:
        with open(filepath, "r", encoding=encoding) as f:
            data = json.load(f)
    except UnicodeDecodeError as e:
        raise FileReadError(filepath, f"编码错误(尝试{encoding}): {e}")
    except json.JSONDecodeError as e:
        raise FileReadError(filepath, f"JSON解析错误: 第{e.lineno}行, 第{e.colno}列 - {e.msg}")
    except Exception as e:
        raise FileReadError(filepath, str(e))

    if isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        if "data" in data and isinstance(data["data"], list):
            records = [r for r in data["data"] if isinstance(r, dict)]
        elif "records" in data and isinstance(data["records"], list):
            records = [r for r in data["records"] if isinstance(r, dict)]
        elif "items" in data and isinstance(data["items"], list):
            records = [r for r in data["items"] if isinstance(r, dict)]
        else:
            records = [data]
    else:
        raise FileReadError(filepath, f"JSON根节点类型不支持: {type(data).__name__}, 需要list或dict")

    if not records:
        return [], []

    all_keys = set()
    for r in records:
        all_keys.update(r.keys())
    fields = sorted(all_keys)

    ordered_fields = list(records[0].keys())
    for k in ordered_fields:
        if k in all_keys:
            all_keys.discard(k)
    fields = ordered_fields + [k for k in fields if k in all_keys]

    return fields, records


def write_json(filepath: str, fields: List[str], records: List[Dict[str, Any]],
               encoding: str = "utf-8", pretty: bool = True) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    try:
        with open(filepath, "w", encoding=encoding) as f:
            if pretty:
                json.dump(records, f, ensure_ascii=False, indent=2)
            else:
                json.dump(records, f, ensure_ascii=False)
    except Exception as e:
        raise FileWriteError(filepath, str(e))


def read_excel(filepath: str) -> Tuple[List[str], List[Dict[str, Any]]]:
    try:
        import pandas as pd
    except ImportError:
        raise FileReadError(filepath, "缺少 pandas 依赖。请运行: pip install pandas openpyxl")

    try:
        df = pd.read_excel(filepath, dtype=str, keep_default_na=False)
    except ImportError as e:
        if "openpyxl" in str(e).lower() or "xlrd" in str(e).lower():
            raise FileReadError(filepath, "缺少 openpyxl 依赖。请运行: pip install openpyxl")
        raise
    except Exception as e:
        raise FileReadError(filepath, f"Excel解析错误: {e}")

    df = df.fillna("")
    fields = [str(c) for c in df.columns]
    records = df.to_dict("records")
    normalized = []
    for rec in records:
        norm = {}
        for k, v in rec.items():
            key = str(k)
            if v is None:
                norm[key] = ""
            elif isinstance(v, float) and v == int(v):
                norm[key] = str(int(v))
            else:
                norm[key] = str(v)
        normalized.append(norm)
    return fields, normalized


def write_excel(filepath: str, fields: List[str], records: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    try:
        import pandas as pd
    except ImportError:
        raise FileWriteError(filepath, "缺少 pandas 依赖。请运行: pip install pandas openpyxl")
    try:
        df = pd.DataFrame(records, columns=fields)
        df.to_excel(filepath, index=False, engine="openpyxl")
    except Exception as e:
        raise FileWriteError(filepath, str(e))


def read_file(filepath: str) -> DataFile:
    ext = Path(filepath).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise UnsupportedFormatError(filepath)

    fmt = SUPPORTED_FORMATS[ext]
    if fmt == "CSV":
        fields, records = read_csv(filepath)
    elif fmt == "JSON":
        fields, records = read_json(filepath)
    elif fmt == "Excel":
        fields, records = read_excel(filepath)
    else:
        raise UnsupportedFormatError(filepath, f"内部错误: 未实现格式 {fmt}")

    return DataFile(
        filepath=filepath,
        records=records,
        fields=fields,
        format=fmt,
        total_records=len(records)
    )


def write_file(filepath: str, data: DataFile) -> None:
    ext = Path(filepath).suffix.lower()
    target_fmt = SUPPORTED_FORMATS.get(ext)
    if not target_fmt:
        raise UnsupportedFormatError(filepath)

    fields = data.fields or []
    records = data.records or []

    if target_fmt == "CSV":
        write_csv(filepath, fields, records)
    elif target_fmt == "JSON":
        write_json(filepath, fields, records)
    elif target_fmt == "Excel":
        write_excel(filepath, fields, records)
