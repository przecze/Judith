// The dashboard secret arrives in the URL fragment (never sent to a server)
// and is kept in localStorage for this origin only. All agent-controlled
// text is rendered with textContent, never as HTML.
"use strict";

const KEY = "cfkey-secret";
(function takeSecretFromFragment() {
  const m = location.hash.match(/k=([0-9a-f]+)/);
  if (m) {
    try { localStorage.setItem(KEY, m[1]); } catch (_) {}
    history.replaceState(null, "", location.pathname);
  }
})();
function secret() {
  try { return localStorage.getItem(KEY) || ""; } catch (_) { return ""; }
}

async function api(method, path) {
  const res = await fetch(path, { method, headers: { Authorization: "Bearer " + secret() } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k === "onclick") e.addEventListener("click", v);
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function fmtDuration(ms) {
  if (ms <= 0) return "0s";
  const s = Math.round(ms / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}
function fmtTTL(ns) { return fmtDuration(ns / 1e6); }
function fmtTime(t) { return new Date(t).toLocaleTimeString(); }
function requester(p) {
  if (!p || !p.pid) return "unknown process";
  return (p.chain && p.chain.length ? p.chain.join(" ← ") : "pid " + p.pid);
}

async function act(button, method, path) {
  button.disabled = true;
  try { await api(method, path); } catch (e) { alert(e.message); }
  refresh();
}

function pendingCard(r) {
  return el("div", { class: "card pending" },
    el("div", { class: "summary" }, ...r.grant.summary.map(s => el("div", null, s))),
    el("div", { class: "reason" }, "Reason: ", el("em", null, r.grant.reason)),
    el("div", { class: "meta" },
      el("div", null, "Valid for ", fmtTTL(r.grant.ttl), " after approval"),
      el("div", null, "Requested by ", requester(r.peer), " at ", fmtTime(r.created)),
      r.peer && r.peer.cwd ? el("div", null, "Working directory: ", r.peer.cwd) : null),
    el("details", null, el("summary", null, "Exact token policies"),
      el("pre", null, JSON.stringify(r.grant.policies, null, 2))),
    el("div", { class: "actions" },
      el("button", { class: "approve", onclick: e => act(e.target, "POST", `/api/requests/${r.id}/approve`) }, "Approve"),
      el("button", { class: "danger", onclick: e => act(e.target, "POST", `/api/requests/${r.id}/deny`) }, "Deny")));
}

function activeCard(r, now) {
  return el("div", { class: "card" },
    el("div", { class: "summary" }, ...r.grant.summary.map(s => el("div", null, s))),
    el("div", { class: "reason" }, "Reason: ", el("em", null, r.grant.reason)),
    el("div", { class: "meta" },
      el("div", null, "Expires in ", fmtDuration(new Date(r.expires_on) - now), " (", fmtTime(r.expires_on), ")"),
      el("div", null, "Requested by ", requester(r.peer)),
      el("div", null, "Token ID ", r.token_id)),
    el("div", { class: "actions" },
      el("button", { class: "danger", onclick: e => act(e.target, "POST", `/api/keys/${r.id}/revoke`) }, "Revoke")));
}

function historyRow(r) {
  return el("tr", null,
    el("td", null, fmtTime(r.created)),
    el("td", null, el("span", { class: "badge " + r.status }, r.status.replace("_", " "))),
    el("td", null, (r.grant.summary || []).join("; ") || (r.spec.permissions || []).join(", ")),
    el("td", null, r.grant.reason || r.spec.reason || ""),
    el("td", null, requester(r.peer)),
    el("td", null, r.error || ""));
}

function render(state) {
  const now = new Date(state.now);
  const s = state.session;
  document.getElementById("session").textContent =
    `Session ${s.id} · ends in ${fmtDuration(new Date(s.expires) - now)}` +
    (s.session_token ? " · session token self-destructs on exit" : " · using master token directly") +
    ` · max key TTL ${s.max_ttl}`;
  document.getElementById("stop").hidden = false;

  const pending = state.requests.filter(r => r.status === "pending");
  const active = state.requests.filter(r => r.status === "issued");
  document.getElementById("pending").replaceChildren(
    ...(pending.length ? pending.map(pendingCard) : [el("p", { class: "empty" }, "Nothing waiting for approval.")]));
  document.getElementById("active").replaceChildren(
    ...(active.length ? active.map(r => activeCard(r, now)) : [el("p", { class: "empty" }, "No live keys.")]));
  document.getElementById("history").replaceChildren(...state.requests.map(historyRow));
  document.getElementById("pending-count").textContent = pending.length ? `(${pending.length})` : "";
  document.getElementById("active-count").textContent = active.length ? `(${active.length})` : "";
  document.title = pending.length ? `(${pending.length}) cfkey – approval needed` : "cfkey";
}

let lastPendingIDs = "";
async function refresh() {
  const msg = document.getElementById("message");
  try {
    const state = await api("GET", "/api/state");
    msg.hidden = true;
    // Keep open <details> and button state stable: only re-render pending
    // cards when the set of pending requests changes.
    const ids = state.requests.filter(r => r.status === "pending").map(r => r.id).join(",");
    if (ids !== lastPendingIDs || !document.querySelector("#pending details[open]")) {
      lastPendingIDs = ids;
      render(state);
    } else {
      const pendingEl = document.getElementById("pending");
      const keep = Array.from(pendingEl.children);
      render(state);
      pendingEl.replaceChildren(...keep);
    }
  } catch (e) {
    msg.textContent = e.message.includes("unauthorized")
      ? "Not signed in. Open the dashboard link printed in the terminal where `cfkey serve` runs."
      : "Lost connection to cfkey: " + e.message + " (the session may have ended).";
    msg.hidden = false;
  }
}

document.getElementById("stop").addEventListener("click", async e => {
  if (!confirm("End the session? All live keys will be revoked and the session token deleted.")) return;
  await act(e.target, "POST", "/api/stop");
});

refresh();
setInterval(refresh, 1500);
