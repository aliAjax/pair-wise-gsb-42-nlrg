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
- `GET /api/watchlist/{id}/history`：名单条目的全部历史版本（旧版内容、变化类型、生效时间、操作人）
- `GET /api/transactions/{id}`：单笔交易的筛查追溯，含采用过的名单版本与复核记录
- `POST /api/entities`、`POST /api/entities/alias`、`POST /api/entities/merge`
- `POST /api/customers`
- `POST /api/watchlist`：新增或版本化更新名单（可传 `entry_id` 按 ID 更正；`active=false` 为停用）。
  更正、停用、重新启用都会生成新版本并保留旧版快照；之前命中该条目的交易自动进入待复核队列，
  同一（交易，条目，新版本）只入队一次，返回 `enqueued_reviews`。
- `POST /api/transactions`：筛查并生成指纹去重后的线索；命中时把命中条目的当时版本快照存入筛查存档（`screen_archive`）。
- `POST /api/alerts/triage`：误报关闭或形成案件
- `POST /api/watchlist/review`：复核名单变化（`review_id`、`conclusion` 为 `confirmed`/`false_positive`/`escalated`、
  可选 `note`），记录处理人、结论、处理时间并追加一条复筛存档；`escalated` 会生成去重后的新线索。
- `POST /api/cases/update`、`POST /api/cases/report`
- `POST /api/entities/freeze`、`POST /api/entities/unfreeze`

## 名单历史、筛查存档与复核

三部分分开实现，互不耦合，且都落在 SQLite，重启服务后仍可追查：

- **名单历史**：`watchlist_versions` 表与 `WatchlistHistory` 类，保存每个版本的名称、国家、生效状态、
  变化类型（created/corrected/deactivated/reactivated）、生效时间与操作人；当前 `watchlist` 表只保留最新版。
- **筛查存档**：`screening_archives` 表与 `ScreeningArchive` 类，交易初次命中时快照条目版本（关联
  `watchlist_version_id`，并冗余名称/版本/相似度），复核复筛时再追加 `kind='rescreen'` 的记录。
  `GET /api/cases/{id}` 的每笔涉案交易会展开这些存档，页面上可在案件详情或交易列表中查看。
- **复核队列**：`watchlist_reviews` 表与 `ListReviewQueue` 类。名单变更后用
  `INSERT OR IGNORE ... UNIQUE(transaction_id, watchlist_entry_id, to_version)` 保证同一版本对同一交易只生成一次
  待复核；`GET /api/state` 返回 `watchlist_reviews` 与 `pending_review_txn_ids`。

页面（`static/index.html` 加独立的 `static/app.js`）只负责展示这三块：复核队列、名单与历史版本、
案件/交易中的名单版本展开。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖制裁命中到监管报告、冻结即时阻断、实体合并迁移、线索降噪、案件保密和版本冲突。

## 局限

名称筛查使用归一化和序列相似度，不替代专业名单供应商；冻结仅影响本系统内后续交易；金额与风险规则是演示规则；身份依赖请求头，没有密钥管理、数字签名或真实监管报送通道。
