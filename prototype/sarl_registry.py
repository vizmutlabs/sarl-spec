"""
SARL Registry — Secure Agent Reachability Layer
Minimal prototype: pre-contact reachability filtering, nothing else.

Usage
-----
uvicorn sarl_registry:app --reload

Quickstart (httpie):
  http POST :8000/register agent_id=alice endpoint=https://alice.example tags:='["private"]' credential=s3cr3t
  http POST :8000/register agent_id=bob   endpoint=https://bob.example  tags:='["public"]'  credential=b0bkey
  http POST :8000/policy   requester=private target=public allow:=true
  http GET  ':8000/resolve?target=bob&requester_id=alice&credential=s3cr3t'
"""

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="SARL Registry", version="0.1.0")

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_agents: dict[str, dict] = {}  # agent_id → {endpoint, tags, credential}
_policies: list[dict] = []     # ordered list of {requester, target, allow}
_audit_log: list[dict] = []    # resolve attempt records


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    agent_id: str
    endpoint: str
    tags: list[str] = []
    credential: str  # mock auth — compared verbatim at resolve time


class PolicyRule(BaseModel):
    requester: str   # agent_id  OR  a tag label
    target: str      # agent_id  OR  a tag label
    allow: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _selector_matches(selector: str, agent_id: str, tags: list[str]) -> bool:
    """True when a policy selector matches an agent by id or by tag."""
    return selector == agent_id or selector in tags


def _is_reachable(
    req_id: str, req_tags: list[str],
    tgt_id: str, tgt_tags: list[str],
) -> bool:
    """
    Walk the ordered policy list; first matching rule wins.
    Default (no match) = DENY.
    """
    for rule in _policies:
        req_match = _selector_matches(rule["requester"], req_id, req_tags)
        tgt_match = _selector_matches(rule["target"], tgt_id, tgt_tags)
        if req_match and tgt_match:
            return rule["allow"]
    return False  # closed-world default


# ---------------------------------------------------------------------------
# Endpoints — register / delete agent
# ---------------------------------------------------------------------------
@app.post("/register", status_code=201)
def register(body: RegisterRequest):
    if body.agent_id in _agents:
        raise HTTPException(409, f"agent '{body.agent_id}' is already registered")
    _agents[body.agent_id] = {
        "endpoint":   body.endpoint,
        "tags":       body.tags,
        "credential": body.credential,
    }
    return {"registered": body.agent_id, "tags": body.tags}


@app.delete("/agents/{agent_id}")
def delete_agent(agent_id: str):
    if agent_id not in _agents:
        raise HTTPException(404, f"agent '{agent_id}' not found")
    del _agents[agent_id]
    return {"deleted": agent_id}


# ---------------------------------------------------------------------------
# Endpoints — policy
# ---------------------------------------------------------------------------
@app.post("/policy", status_code=201)
def add_policy(rule: PolicyRule):
    _policies.append(rule.model_dump())
    return {
        "policy_index": len(_policies) - 1,
        "rule":         rule.model_dump(),
        "total_rules":  len(_policies),
    }


@app.delete("/policies/{index}")
def delete_policy(index: int):
    if index < 0 or index >= len(_policies):
        raise HTTPException(404, f"policy index {index} not found")
    removed = _policies.pop(index)
    return {"deleted_index": index, "rule": removed}


# ---------------------------------------------------------------------------
# Endpoints — reset
# ---------------------------------------------------------------------------
@app.delete("/reset")
def reset_all():
    _agents.clear()
    _policies.clear()
    _audit_log.clear()
    return {"reset": True}


# ---------------------------------------------------------------------------
# Endpoints — resolve (with audit logging)
# ---------------------------------------------------------------------------
@app.get("/resolve")
def resolve(
    target:       str = Query(..., description="agent_id of the target agent"),
    requester_id: str = Query(..., description="agent_id of the requesting agent"),
    credential:   str = Query(..., description="requester's registered credential"),
):
    """
    Resolve a target's endpoint — only if:
    1. The requester is registered and the credential matches  (mock auth)
    2. At least one policy permits requester → target          (reachability filter)
    """
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _deny(reason: str, status: int, detail: str):
        _audit_log.append({"ts": ts, "requester": requester_id,
                           "target": target, "result": "DENIED", "reason": reason})
        raise HTTPException(status, detail)

    requester = _agents.get(requester_id)
    if requester is None:
        _deny("requester not registered", 404, f"requester '{requester_id}' not registered")
    if requester["credential"] != credential:
        _deny("credential mismatch", 401, "credential mismatch")

    target_agent = _agents.get(target)
    if target_agent is None:
        _deny("target not registered", 404, f"target '{target}' not registered")

    if not _is_reachable(requester_id, requester["tags"], target, target_agent["tags"]):
        _deny("policy deny", 403,
              f"reachability policy denies '{requester_id}' \u2192 '{target}'")

    _audit_log.append({"ts": ts, "requester": requester_id,
                       "target": target, "result": "ALLOWED", "reason": ""})
    return {
        "agent_id": target,
        "endpoint": target_agent["endpoint"],
        "tags":     target_agent["tags"],
    }


# ---------------------------------------------------------------------------
# State inspection (used by the UI only)
# ---------------------------------------------------------------------------
@app.get("/_state/agents", include_in_schema=False)
def state_agents():
    return [{"id": k, **{f: v for f, v in a.items() if f != "credential"}}
            for k, a in _agents.items()]


@app.get("/_state/policies", include_in_schema=False)
def state_policies():
    return _policies


@app.get("/_state/audit", include_in_schema=False)
def state_audit():
    return list(reversed(_audit_log))  # newest first


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui():
    return HTMLResponse("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SARL Registry</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0;
         max-width: 1200px; margin: 0 auto; padding: 2rem; }

  h1   { font-size: 1.4rem; letter-spacing: .05em; color: #a78bfa; margin: 0 0 .15rem; }
  p.sub { color: #64748b; font-size: .85rem; margin: 0 0 1.25rem; }

  /* Explanation panel */
  .explain-panel {
    background: #1a1e2e; border: 1px solid #2a2f4a;
    border-left: 3px solid #6366f1; border-radius: 8px;
    padding: .9rem 1.2rem; margin-bottom: 1.25rem;
    font-size: .85rem; color: #94a3b8; line-height: 1.65;
  }
  .explain-panel strong { color: #c4b5fd; }

  /* Toolbar */
  .toolbar { display: flex; gap: .6rem; margin-bottom: 1.25rem; }
  .toolbar button { width: auto; margin: 0; padding: .48rem 1.1rem; font-size: .84rem; }
  .btn-demo  { background: #14532d !important; }
  .btn-demo:hover  { background: #166534 !important; }
  .btn-reset { background: #7f1d1d !important; }
  .btn-reset:hover { background: #991b1b !important; }

  /* Demo step panel */
  .demo-panel {
    background: #0d1f0d; border: 1px solid #14532d; border-radius: 8px;
    padding: .8rem 1.1rem; margin-bottom: 1.25rem;
    font-size: .85rem; color: #86efac; line-height: 1.5;
    display: none;
  }
  .demo-panel .step-lbl { font-weight: 700; color: #4ade80; }
  .demo-panel .step-res {
    font-family: monospace; font-size: .78rem; color: #a7f3d0;
    margin-top: .45rem; white-space: pre-wrap; word-break: break-all;
  }

  /* Cards */
  .flow { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
  .card { background: #1e2130; border: 1px solid #2d3148; border-radius: 10px;
          padding: 1.25rem 1.5rem; flex: 1; min-width: 260px; }
  .card h2 { font-size: .95rem; text-transform: uppercase; letter-spacing: .08em;
             color: #818cf8; margin: 0 0 1rem; display:flex; align-items:center; gap:.5rem; }
  .badge { background:#312e81; color:#a5b4fc; border-radius:999px;
           font-size:.65rem; padding:.15em .6em; font-weight:700; }

  label  { display: block; font-size: .8rem; color: #94a3b8; margin: .6rem 0 .2rem; }
  input, select {
    width: 100%; padding: .45rem .6rem; background: #0f1117;
    border: 1px solid #334155; border-radius: 6px; color: #e2e8f0;
    font-size: .85rem; outline: none;
  }
  input:focus, select:focus { border-color: #6366f1; }

  button {
    margin-top: .9rem; width: 100%; padding: .55rem;
    background: #4f46e5; color: #fff; border: none; border-radius: 6px;
    font-size: .88rem; cursor: pointer; font-weight: 600;
    transition: background .15s;
  }
  button:hover { background: #4338ca; }
  button:active { background: #3730a3; }

  .result {
    margin-top: .9rem; padding: .7rem .9rem; border-radius: 6px;
    font-size: .78rem; font-family: monospace; white-space: pre-wrap;
    word-break: break-all; min-height: 2.5rem;
    background: #0a0c14; border: 1px solid #1e2130; color: #94a3b8;
  }
  .result.ok  { border-color: #14532d; color: #86efac; }
  .result.err { border-color: #7f1d1d; color: #fca5a5; }

  .arrow { text-align: center; font-size: 1.4rem; color: #334155;
           display: flex; align-items: center; padding-top: 2.5rem; }

  /* State panel */
  .state-panel { background: #1e2130; border: 1px solid #2d3148;
                 border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
  .panel-head  { font-size: .9rem; text-transform: uppercase; letter-spacing:.08em;
                 color: #64748b; margin: 0 0 .75rem; display: flex; align-items: center; gap: .75rem; }
  .panel-head a { color:#6366f1; text-decoration:none; font-size:.78rem;
                  font-weight:400; text-transform:none; letter-spacing:0; }
  .state-grid  { display: flex; gap: 1.5rem; flex-wrap: wrap; }
  .state-col   { flex: 1; min-width: 200px; }
  .state-col h3 { font-size: .78rem; color: #475569; text-transform: uppercase;
                  letter-spacing:.06em; margin: 0 0 .5rem; }
  .state-col ul { list-style: none; margin: 0; padding: 0; }
  .state-col li {
    padding: .3rem 0; border-bottom: 1px solid #1a1f35;
    display: flex; align-items: center; gap: .5rem;
    font-size: .8rem; font-family: monospace; color: #94a3b8;
  }
  .state-col li:last-child { border-bottom: none; }
  .li-content  { flex: 1; }

  .tag   { background:#1e3a5f; color:#7dd3fc; border-radius:4px;
           font-size:.7rem; padding:.1em .4em; margin-left:.3em; }
  .allow { color: #86efac; }
  .deny  { color: #fca5a5; }
  .empty { color: #334155; font-family: monospace; font-size: .8rem; }

  /* Delete button */
  .del-btn {
    background: transparent; border: 1px solid #4b1c1c; color: #f87171;
    border-radius: 4px; padding: .15rem .45rem; font-size: .72rem;
    cursor: pointer; margin: 0; width: auto; flex-shrink: 0; font-weight: 700; line-height: 1;
  }
  .del-btn:hover { background: #7f1d1d; border-color: #7f1d1d; color: #fff; }

  /* Audit log */
  .audit-panel { background: #1e2130; border: 1px solid #2d3148;
                 border-radius: 10px; padding: 1.25rem 1.5rem; }
  .audit-feed  { font-family: monospace; font-size: .8rem;
                 max-height: 240px; overflow-y: auto; }
  .audit-entry { display: flex; gap: .75rem; padding: .3rem 0;
                 border-bottom: 1px solid #1a1f35; align-items: baseline; }
  .audit-entry:last-child { border-bottom: none; }
  .a-ts     { color: #475569; flex-shrink: 0; width: 5.2rem; }
  .a-who    { color: #94a3b8; flex: 1; }
  .a-result { flex-shrink: 0; font-weight: 700; font-size: .74rem; }
  .a-result.allowed { color: #86efac; }
  .a-result.denied  { color: #fca5a5; }
  .a-reason { color: #475569; font-size: .74rem; flex-shrink: 0; }

  /* Tier badge colours */
  .tier-public   { background:#1e3a5f; color:#7dd3fc; }
  .tier-group    { background:#1e2e1e; color:#86efac; }
  .tier-private  { background:#2e1e3a; color:#c4b5fd; }
  .tier-ephemeral{ background:#2e2a14; color:#fde68a; }
</style>
</head>
<body>

<h1>SARL Registry</h1>
<p class="sub">Secure Agent Reachability Layer &mdash; pre-contact filtering demo</p>

<!-- Explanation panel -->
<div class="explain-panel">
  <strong>What is SARL?</strong> The Secure Agent Reachability Layer acts as a gatekeeper in front of
  your agent network. Before any two agents can communicate, the registry enforces
  <em>pre-contact filtering</em>: an agent&rsquo;s endpoint is <strong>never revealed</strong> to a caller
  unless two gates both pass &mdash; (1)&nbsp;the caller is authenticated, and (2)&nbsp;an explicit
  policy rule permits the connection. No matching rule means permanent deny. Agents are assigned a
  <strong>tier</strong> (Public / Group / Private / Ephemeral) which doubles as their policy tag,
  letting you write rules like &ldquo;private agents may reach public agents&rdquo; without naming
  every agent individually. Use the panels below to register agents, add rules, and watch the
  <strong>Audit Log</strong> capture every resolution attempt live. Hit <strong>&#9654;&nbsp;Run Demo</strong>
  to see the full cycle automatically.
</div>

<!-- Toolbar -->
<div class="toolbar">
  <button class="btn-demo" onclick="runDemo()">&#9654; Run Demo</button>
  <button class="btn-reset" onclick="doReset()">&#10006; Reset All</button>
</div>

<!-- Demo step panel -->
<div class="demo-panel" id="demo-panel">
  <span class="step-lbl" id="demo-lbl"></span><span id="demo-txt"></span>
  <div class="step-res" id="demo-res"></div>
</div>

<!-- Action cards -->
<div class="flow">

  <!-- REGISTER -->
  <div class="card">
    <h2><span class="badge">POST</span>/register</h2>
    <label>Agent ID</label>
    <input id="r-id" value="alice">
    <label>Endpoint URL</label>
    <input id="r-ep" value="https://alice.internal/agent">
    <label>Tier</label>
    <select id="r-tier">
      <option value="public">Public</option>
      <option value="group">Group</option>
      <option value="private" selected>Private</option>
      <option value="ephemeral">Ephemeral</option>
    </select>
    <label>Credential</label>
    <input id="r-cred" value="s3cr3t">
    <button onclick="doRegister()">Register Agent</button>
    <div class="result" id="r-out">&mdash;</div>
  </div>

  <div class="arrow">&#8594;</div>

  <!-- POLICY -->
  <div class="card">
    <h2><span class="badge">POST</span>/policy</h2>
    <label>Requester (id or tag)</label>
    <input id="p-req" value="private">
    <label>Target (id or tag)</label>
    <input id="p-tgt" value="public">
    <label>Decision</label>
    <select id="p-allow">
      <option value="true">allow</option>
      <option value="false">deny</option>
    </select>
    <button onclick="doPolicy()">Add Rule</button>
    <div class="result" id="p-out">&mdash;</div>
  </div>

  <div class="arrow">&#8594;</div>

  <!-- RESOLVE -->
  <div class="card">
    <h2><span class="badge">GET</span>/resolve</h2>
    <label>Requester ID</label>
    <input id="v-rid" value="alice">
    <label>Credential</label>
    <input id="v-cred" value="s3cr3t">
    <label>Target Agent ID</label>
    <input id="v-tgt" value="bob">
    <button onclick="doResolve()">Resolve Endpoint</button>
    <div class="result" id="v-out">&mdash;</div>
  </div>

</div>

<!-- Registry state -->
<div class="state-panel">
  <div class="panel-head">
    Registry state
    <a href="#" onclick="refreshState();return false;">refresh</a>
  </div>
  <div class="state-grid">
    <div class="state-col">
      <h3>Agents</h3>
      <ul id="s-agents"><li style="border:none"><span class="empty">none</span></li></ul>
    </div>
    <div class="state-col">
      <h3>Policies (ordered)</h3>
      <ul id="s-policies"><li style="border:none"><span class="empty">none</span></li></ul>
    </div>
  </div>
</div>

<!-- Audit log -->
<div class="audit-panel">
  <div class="panel-head">
    Audit Log
    <span style="color:#475569;font-size:.75rem;font-weight:400;text-transform:none;letter-spacing:0">
      &mdash; live resolve attempts, newest first
    </span>
  </div>
  <div class="audit-feed" id="s-audit">
    <div class="empty">no attempts yet</div>
  </div>
</div>

<script>
const show = (id, data, ok) => {
  const el = document.getElementById(id);
  el.textContent = JSON.stringify(data, null, 2);
  el.className = 'result ' + (ok ? 'ok' : 'err');
};

const api = async (method, path, body) => {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const json = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, json };
};

const sleep = ms => new Promise(res => setTimeout(res, ms));

// ── Register ──────────────────────────────────────────────────────────────
async function doRegister() {
  const tier = document.getElementById('r-tier').value;
  const { ok, status, json } = await api('POST', '/register', {
    agent_id:   document.getElementById('r-id').value.trim(),
    endpoint:   document.getElementById('r-ep').value.trim(),
    tags:       [tier],
    credential: document.getElementById('r-cred').value.trim(),
  });
  show('r-out', ok ? json : { error: json.detail, status }, ok);
  refreshState();
}

// ── Policy ────────────────────────────────────────────────────────────────
async function doPolicy() {
  const { ok, status, json } = await api('POST', '/policy', {
    requester: document.getElementById('p-req').value.trim(),
    target:    document.getElementById('p-tgt').value.trim(),
    allow:     document.getElementById('p-allow').value === 'true',
  });
  show('p-out', ok ? json : { error: json.detail, status }, ok);
  refreshState();
}

// ── Resolve ───────────────────────────────────────────────────────────────
async function doResolve() {
  const rid  = document.getElementById('v-rid').value.trim();
  const cred = document.getElementById('v-cred').value.trim();
  const tgt  = document.getElementById('v-tgt').value.trim();
  const url  = `/resolve?target=${encodeURIComponent(tgt)}`
             + `&requester_id=${encodeURIComponent(rid)}`
             + `&credential=${encodeURIComponent(cred)}`;
  const { ok, status, json } = await api('GET', url);
  show('v-out', ok ? json : { error: json.detail, status }, ok);
  refreshState();
}

// ── Delete ────────────────────────────────────────────────────────────────
async function deleteAgent(id) {
  await api('DELETE', `/agents/${encodeURIComponent(id)}`);
  refreshState();
}

async function deletePolicy(index) {
  await api('DELETE', `/policies/${index}`);
  refreshState();
}

async function doReset() {
  await api('DELETE', '/reset');
  ['r-out', 'p-out', 'v-out'].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = '\u2014';
    el.className = 'result';
  });
  hideDemoPanel();
  refreshState();
}

// ── Demo ──────────────────────────────────────────────────────────────────
function showDemoPanel(lbl, txt, res) {
  document.getElementById('demo-panel').style.display = 'block';
  document.getElementById('demo-lbl').textContent = lbl;
  document.getElementById('demo-txt').textContent = txt;
  document.getElementById('demo-res').textContent = res || '';
}

function hideDemoPanel() {
  document.getElementById('demo-panel').style.display = 'none';
}

let _demoRunning = false;

async function runDemo() {
  if (_demoRunning) return;
  _demoRunning = true;

  await api('DELETE', '/reset');
  ['r-out', 'p-out', 'v-out'].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = '\u2014';
    el.className = 'result';
  });
  await refreshState();

  const steps = [
    {
      lbl:  'Step 1 / 5',
      txt:  ' \u2014 Registering alice as a private-tier agent.',
      run:  () => api('POST', '/register', {
        agent_id: 'alice', endpoint: 'https://alice.internal/agent',
        tags: ['private'], credential: 's3cr3t',
      }),
    },
    {
      lbl:  'Step 2 / 5',
      txt:  ' \u2014 Registering bob as a public-tier agent.',
      run:  () => api('POST', '/register', {
        agent_id: 'bob', endpoint: 'https://bob.example/agent',
        tags: ['public'], credential: 'b0bkey',
      }),
    },
    {
      lbl:  'Step 3 / 5',
      txt:  ' \u2014 alice tries to resolve bob. No policy exists yet \u2192 expect 403 DENIED.',
      run:  () => api('GET', '/resolve?target=bob&requester_id=alice&credential=s3cr3t'),
    },
    {
      lbl:  'Step 4 / 5',
      txt:  ' \u2014 Adding policy: private-tier agents may reach public-tier agents.',
      run:  () => api('POST', '/policy', { requester: 'private', target: 'public', allow: true }),
    },
    {
      lbl:  'Step 5 / 5',
      txt:  ' \u2014 alice resolves bob again. Policy now matches \u2192 expect 200 ALLOWED.',
      run:  () => api('GET', '/resolve?target=bob&requester_id=alice&credential=s3cr3t'),
    },
  ];

  for (const step of steps) {
    showDemoPanel(step.lbl, step.txt, '');
    await sleep(700);
    const { ok, status, json } = await step.run();
    showDemoPanel(step.lbl, step.txt,
      JSON.stringify(ok ? json : { error: json.detail, status }, null, 2));
    await refreshState();
    await sleep(1500);
  }

  showDemoPanel('Done', ' \u2014 Demo complete. Registry state reflects the full sequence.', '');
  _demoRunning = false;
}

// ── State refresh ─────────────────────────────────────────────────────────
async function refreshState() {
  const [{ json: agents }, { json: policies }, { json: audit }] = await Promise.all([
    api('GET', '/_state/agents'),
    api('GET', '/_state/policies'),
    api('GET', '/_state/audit'),
  ]);

  // Agents
  const aList = document.getElementById('s-agents');
  aList.innerHTML = agents.length
    ? agents.map(a => {
        const tagsHtml = a.tags.map(t =>
          `<span class="tag tier-${t}">${t}</span>`).join('');
        return `<li>
          <span class="li-content">
            <strong>${a.id}</strong>${tagsHtml}
            <br><span style="color:#475569">${a.endpoint}</span>
          </span>
          <button class="del-btn" onclick="deleteAgent('${a.id}')">&#10005;</button>
        </li>`;
      }).join('')
    : '<li style="border:none"><span class="empty">none</span></li>';

  // Policies
  const pList = document.getElementById('s-policies');
  pList.innerHTML = policies.length
    ? policies.map((p, i) => {
        const cls   = p.allow ? 'allow' : 'deny';
        const label = p.allow ? 'allow' : 'deny';
        return `<li>
          <span class="li-content">
            <strong class="${cls}">${label}</strong>
            &nbsp;${p.requester} &#8594; ${p.target}
          </span>
          <button class="del-btn" onclick="deletePolicy(${i})">&#10005;</button>
        </li>`;
      }).join('')
    : '<li style="border:none"><span class="empty">none</span></li>';

  // Audit log
  const auditEl = document.getElementById('s-audit');
  auditEl.innerHTML = audit.length
    ? audit.map(e => {
        const reasonHtml = e.reason
          ? `<span class="a-reason">${e.reason}</span>` : '';
        return `<div class="audit-entry">
          <span class="a-ts">${e.ts}</span>
          <span class="a-who">${e.requester} &#8594; ${e.target}</span>
          <span class="a-result ${e.result.toLowerCase()}">${e.result}</span>
          ${reasonHtml}
        </div>`;
      }).join('')
    : '<div class="empty">no attempts yet</div>';
}

refreshState();
</script>
</body>
</html>""")


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sarl_registry:app", host="0.0.0.0", port=8000, reload=True)
