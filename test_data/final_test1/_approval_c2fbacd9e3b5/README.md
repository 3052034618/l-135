# 数据脱敏审批包

- **任务ID**: `c2fbacd9e3b5`
- **操作类型**: `mask`
- **生成时间**: 2026-06-13 08:41:52
- **耗时**: 0.00秒
- **配置文件**: `test_data\mixed_draft.yaml`
- **输出目录**: `D:\trae-bz\TraeProjects\135\test_data\final_test1`

## 📊 总体统计

| 指标 | 数值 |
|-----|------|
| 处理文件数 | 1 |
| 成功 | 1 |
| 失败 | 0 |
| 处理记录数 | 3 |
| 含敏感记录数 | 3 |
| 脱敏单元格总数 | 12 |

## 📁 文件清单

### 脱敏数据 (data/)

- `data/employees_masked.json`

### 检查报告 (reports/)

- `reports/audit_detail.csv`
- `reports/audit_detail.md`
- `reports/report.json`
- `reports/report.md`
- `reports/summary.md`

### 规则配置 (config/)

- `config/rules_config.yaml`
- `config/validation_result.md`

## 📝 使用说明

1. 打开 `data/` 目录，抽样检查各脱敏文件效果是否符合要求；
2. 查看 `reports/report.md` 了解整体脱敏统计和风险项；
3. 查看 `reports/audit_detail.md` 或 `.csv` 逐字段核对处理口径；
4. 查看 `config/validation_result.md` 确认规则校验状态；
5. 全部确认无误后，将本目录整体压缩提交上架审批。

---

*审批包生成于 2026-06-13 08:41:52 by DataMask Tool*