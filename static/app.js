// 金融犯罪调查页面：名单历史、筛查存档、复核队列三块分开实现，仅负责展示与调用接口。
const $ = (sel) => document.querySelector(sel);

function identity() {
  return {
    user: localStorage.getItem("fc_user") || "sup1",
    role: localStorage.getItem("fc_role") || "supervisor",
  };
}

async function api(method, path, body) {
  const id = identity();
  const opts = { method, headers: { "X-User": id.user, "X-Role": id.role } };
  if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("请求失败 " + res.status));
  return data;
}

const esc = (v) => String(v == null ? "" : v).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const CHANGE_LABEL = { created: "新建", corrected: "更正", deactivated: "停用", reactivated: "重新启用" };
const CONCLUSION_LABEL = { confirmed: "维持命中", false_positive: "误报放行", escalated: "升级线索" };

async function loadState() {
  try {
    const d = await api("GET", "/api/state");
    if (d.access_limited) {
      ["cases", "txns", "watchlist", "reviews"].forEach((id) => {
        $("#" + id + " tbody").innerHTML =
          '<tr><td colspan="8">当前角色仅能看到有限数据</td></tr>';
      });
      return;
    }
    renderCases(d.cases);
    renderTransactions(d.transactions, new Set(d.pending_review_txn_ids));
    renderWatchlist(d.watchlist);
    renderReviews(d.watchlist_reviews);
    $("#timeline").innerHTML = d.timeline
      .slice(0, 20)
      .map((x) => `<li>${esc(x.created_at)} ${esc(x.action)} ${esc(x.details)}</li>`)
      .join("");
  } catch (err) {
    alert(err.message);
  }
}

function renderCases(rows) {
  $("#cases tbody").innerHTML = rows
    .map((r) => `<tr>
      <td><a href="#" data-case="${r.id}" class="case-link">${esc(r.case_no)}</a></td>
      <td>${esc(r.status)}</td><td>${r.risk_score}</td>
      <td>${esc(r.assignee || "")}</td><td>${esc(r.report_ref || "")}</td>
    </tr>`)
    .join("");
  document.querySelectorAll(".case-link").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); openCase(a.dataset.case); })
  );
}

function renderTransactions(rows, pendingIds) {
  $("#txns tbody").innerHTML = rows
    .map((r) => `<tr>
      <td>${esc(r.txn_ref)} ${pendingIds.has(r.id) ? '<span class="badge">待复核</span>' : ""}</td>
      <td>${r.amount}</td><td>${esc(r.currency)}</td>
      <td>${esc(r.status)}</td><td>${esc(r.reason)}</td>
      <td><a href="#" data-txn="${r.id}" class="trace-link">筛查存档</a></td>
    </tr>`)
    .join("");
  document.querySelectorAll(".trace-link").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); openTrace(a.dataset.txn); })
  );
}

function renderWatchlist(rows) {
  $("#watchlist tbody").innerHTML = rows
    .map((r) => `<tr>
      <td>${r.id}</td><td>${esc(r.list_name)}</td><td>${esc(r.name)}</td>
      <td>${r.version}</td>
      <td>${r.active ? "生效中" : '<span class="off">已停用</span>'}</td>
      <td>${esc(r.updated_at)}</td>
      <td><a href="#" data-entry="${r.id}" class="history-link">历史版本</a>
          <div class="versions" id="versions-${r.id}"></div></td>
    </tr>`)
    .join("");
  document.querySelectorAll(".history-link").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); toggleHistory(a.dataset.entry); })
  );
}

async function toggleHistory(entryId) {
  const box = $("#versions-" + entryId);
  if (box.dataset.open) { box.innerHTML = ""; box.removeAttribute("data-open"); return; }
  const data = await api("GET", "/api/watchlist/" + entryId + "/history");
  box.dataset.open = "1";
  box.innerHTML = `<table class="sub"><thead><tr>
    <th>版本</th><th>类型</th><th>名称</th><th>国家</th><th>状态</th><th>生效时间</th><th>操作人</th>
  </tr></thead><tbody>${data.versions.map((v) => `<tr>
    <td>v${v.version}</td>
    <td>${esc(CHANGE_LABEL[v.change_type] || v.change_type)}</td>
    <td>${esc(v.name)}</td>
    <td>${esc(v.countries)}</td>
    <td>${v.active ? "生效" : "停用"}</td>
    <td>${esc(v.effective_at)}</td>
    <td>${esc(v.changed_by)}</td>
  </tr>`).join("")}</tbody></table>`;
}

function renderReviews(rows) {
  $("#reviews tbody").innerHTML = rows
    .map((r) => `<tr${r.status === "pending" ? ' class="pending"' : ""}>
      <td>${r.id}</td><td>${esc(r.txn_ref)}</td>
      <td>${esc(r.list_name || "")} / ${esc(r.entry_name || "")}</td>
      <td>v${r.from_version} → v${r.to_version}</td>
      <td>${esc(CHANGE_LABEL[r.trigger_change] || r.trigger_change)}</td>
      <td>${r.status === "pending" ? "待复核" : esc(CONCLUSION_LABEL[r.conclusion] || r.conclusion)}</td>
      <td>${esc(r.handled_by || "")}${r.handled_at ? "<br>" + esc(r.handled_at) : ""}</td>
      <td>${r.status === "pending"
        ? `<button data-review="${r.id}" data-conclusion="confirmed">维持命中</button>
           <button data-review="${r.id}" data-conclusion="false_positive">误报放行</button>
           <button data-review="${r.id}" data-conclusion="escalated">升级线索</button>`
        : esc(r.note || "")}</td>
    </tr>`)
    .join("");
  document.querySelectorAll("#reviews button[data-review]").forEach((btn) =>
    btn.addEventListener("click", () => completeReview(btn.dataset.review, btn.dataset.conclusion))
  );
}

async function completeReview(reviewId, conclusion) {
  const note = prompt("复核备注（可留空）：", "") || "";
  await api("POST", "/api/watchlist/review", { review_id: Number(reviewId), conclusion, note });
  loadState();
}

function archiveRows(archives) {
  if (!archives || !archives.length) return "<em>无名单命中存档</em>";
  return `<table class="sub"><thead><tr>
    <th>类型</th><th>名单</th><th>命中名称</th><th>版本</th>
    <th>相似度</th><th>版本生效时间</th><th>版本来源</th><th>筛查时间</th>
  </tr></thead><tbody>${archives.map((a) => `<tr>
    <td>${a.kind === "initial" ? "初次筛查" : "变化复筛"}</td>
    <td>${esc(a.list_name || "")}</td><td>${esc(a.entry_name || "（无命中）")}</td>
    <td>${a.entry_version ? "v" + a.entry_version : "-"}</td>
    <td>${a.score.toFixed(2)}</td>
    <td>${esc(a.version_effective_at || "-")}</td>
    <td>${esc(CHANGE_LABEL[a.version_change_type] || a.version_change_type || "-")}</td>
    <td>${esc(a.screened_at)}</td>
  </tr>`).join("")}</tbody></table>`;
}

function reviewRows(reviews) {
  if (!reviews || !reviews.length) return "";
  return `<div class="block-title">名单变化复核</div>
  <table class="sub"><thead><tr>
    <th>v旧→v新</th><th>触发</th><th>状态</th><th>结论</th><th>处理人</th><th>时间</th><th>备注</th>
  </tr></thead><tbody>${reviews.map((r) => `<tr>
    <td>v${r.from_version}→v${r.to_version}</td>
    <td>${esc(CHANGE_LABEL[r.trigger_change] || r.trigger_change)}</td>
    <td>${r.status === "pending" ? "待复核" : "已复核"}</td>
    <td>${esc(CONCLUSION_LABEL[r.conclusion] || r.conclusion || "")}</td>
    <td>${esc(r.handled_by || "")}</td><td>${esc(r.handled_at || "")}</td>
    <td>${esc(r.note || "")}</td>
  </tr>`).join("")}</tbody></table>`;
}

async function openCase(caseId) {
  const data = await api("GET", "/api/cases/" + caseId);
  const c = data.case;
  const body = `<div class="block-title">案件 ${esc(c.case_no)}（${esc(c.status)}，调查员 ${esc(c.assignee || "")}）</div>
    <div class="block-title">调查记录</div>
    <ul>${data.notes.map((n) => `<li>${esc(n.created_at)} ${esc(n.actor)}：${esc(n.note)}</li>`).join("") || "<em>暂无</em>"}</ul>
    <div class="block-title">涉案交易与名单版本</div>
    ${data.transactions.map((t) => `<div class="txn-block">
      <strong>${esc(t.txn_ref)}</strong> ${esc(t.status)} ${esc(t.reason)}
      ${archiveRows(t.screening_archives)}
      ${reviewRows(t.watchlist_reviews)}
    </div>`).join("") || "<em>无交易</em>"}`;
  openPanel("案件详情", body);
}

async function openTrace(txnId) {
  const t = await api("GET", "/api/transactions/" + txnId);
  openPanel("交易筛查追溯 " + esc(t.txn_ref),
    `<div class="block-title">采用过的名单版本</div>${archiveRows(t.screening_archives)}${reviewRows(t.watchlist_reviews)}`);
}

function openPanel(title, bodyHtml) {
  $("#panel-title").textContent = title;
  $("#panel-body").innerHTML = bodyHtml;
  $("#panel").classList.add("show");
}

function bindChrome() {
  const id = identity();
  $("#user").value = id.user;
  $("#role").value = id.role;
  $("#save-id").addEventListener("click", () => {
    localStorage.setItem("fc_user", $("#user").value.trim());
    localStorage.setItem("fc_role", $("#role").value);
    loadState();
  });
  $("#refresh").addEventListener("click", loadState);
  $("#panel-close").addEventListener("click", () => $("#panel").classList.remove("show"));
}

bindChrome();
loadState();
