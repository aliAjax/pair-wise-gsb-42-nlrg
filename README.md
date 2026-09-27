# 金融犯罪调查与制裁筛查系统

标准库实现的交易筛查、可疑线索、案件调查、实体合并、冻结和监管报告原型，数据保存到 SQLite。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8208`，默认数据库 `financial_crime.db`。可用 `--db`、`--host`、`--port` 修改。

## 主要接口

请求头 `X-User`、`X-Role`。角色有 `analyst`、`investigator`、`supervisor`、`director`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/cases/{id}`
- `POST /api/entities`、`POST /api/entities/alias`、`POST /api/entities/merge`
- `POST /api/customers`
- `POST /api/watchlist`：新增或版本化更新名单（更正/停用都保留旧版快照和生效时间；可用 `entry_id` 改名同一条目）
- `POST /api/transactions`：筛查、命中时存档命中的名单版本，并生成指纹去重后的线索
- `GET /api/watchlist/history`：名单历史回看（当前态 + 全部版本快照）
- `GET /api/watchlist/reviews?status=pending|done`：名单变更后自动生成的待复核队列（同一版本只生成一次）
- `POST /api/watchlist/reviews/resolve`：复核处理，记录处理人、结论（`confirmed`/`false_positive`/`escalate`）、说明和时间
- `POST /api/alerts/triage`：误报关闭或形成案件
- `POST /api/cases/update`、`POST /api/cases/report`；`GET /api/cases/{id}` 案件详情含 `screening_hits`，可展开相关交易采用过的名单版本及复核记录
- `POST /api/entities/freeze`、`POST /api/entities/unfreeze`

名单历史、筛查存档与页面分开实现：`watchlist_history.py` 管理 `watchlist_versions`，`screening_archive.py` 管理 `screening_archive` 与 `watchlist_reviews`，页面在 `static/watchlist.html`（`/watchlist.html`）。记录均持久化到 SQLite，服务重启后仍可追查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖制裁命中到监管报告、冻结即时阻断、实体合并迁移、线索降噪、案件保密和版本冲突，以及名单版本留存、筛查命中存档、变更待复核去重、复核结论和重启追查。

## 局限

名称筛查使用归一化和序列相似度，不替代专业名单供应商；冻结仅影响本系统内后续交易；金额与风险规则是演示规则；身份依赖请求头，没有密钥管理、数字签名或真实监管报送通道。
