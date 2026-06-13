# 数据脱敏处理 - 任务复核清单

- **任务ID**: `6f1440ece320`
- **操作类型**: `report`
- **执行时间**: 2026-06-13 08:41:52
- **耗时**: 0.00秒
- **配置文件**: `test_data\field_strategy_test.yaml`
- **输出目录**: `D:\trae-bz\TraeProjects\135\test_data\final_test2`

## 📊 总体概览

| 指标 | 数值 |
|-----|------|
| 待处理文件总数 | 1 |
| ✅ 处理成功 | 1 |
| ❌ 处理失败 | 0 |
| ⏭️  跳过(格式不支持) | 0 |
| 处理记录总数 | 3 |
| 含敏感记录数 | 3 |
| 脱敏单元格总数 | 12 |
| ⚠️  待人工补规则字段 | 3 |
| ⚠️  低置信度识别项 | 0 |

## 📁 处理明细

### ✅ 处理成功文件

| # | 源文件 | 格式 | 记录 | 敏感 | 脱敏单元格 | 输出文件 | 状态 |
|---|-------|------|------|------|----------|---------|------|
| 1 | `employees.json` | JSON | 3 | 3 | 12 | `(未生成)` | PREVIEW_OK |


### ⚠️  需要人工补规则的字段

| 文件 | 字段名 | 示例值 | 建议操作 |
|-----|-------|-------|---------|
| `employees.json` | `emp_no` | `E1001` | 无法自动识别该字段内容格式，请在field_overrides中手动指定脱敏规则 |
| `employees.json` | `备注` | `VIP客户，优先处理` | 无法自动识别该字段内容格式，请在field_overrides中手动指定脱敏规则 |
| `employees.json` | `unknown_col` | `随机字符串ABC123` | 无法自动识别该字段内容格式，请在field_overrides中手动指定脱敏规则 |

## 📄 关联报告

- 详细检查报告(Markdown): `D:\trae-bz\TraeProjects\135\test_data\final_test2\_reports\report_6f1440ece320.md`
- 详细检查报告(JSON): `D:\trae-bz\TraeProjects\135\test_data\final_test2\_reports\report_6f1440ece320.json`
- 规则配置来源: `test_data\field_strategy_test.yaml`

## 📝 复核说明

请数据运营同事完成以下复核:
1. 抽样打开输出文件，确认各敏感字段打码效果符合上架要求；
2. 检查「待人工补规则的字段」清单，如为敏感信息请补充规则后重跑；
3. 检查「处理失败/跳过文件」清单，修复后重新提交处理；
4. 全部确认无误后，将输出目录下的文件提交上架流程。

---

*清单生成于 2026-06-13 08:41:52 by DataMask Tool*