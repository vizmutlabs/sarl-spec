"""
SARL Registry — Secure Agent Reachability Layer
Minimal prototype: pre-contact reachability filtering, nothing else.

Usage
-----
uvicorn sarl_registry:app --reload

Quickstart (httpie):
  http POST :8000/register agent_id=alice endpoint=https://alice.example tags:='["internal"]' credential=s3cr3t
  http POST :8000/register agent_id=bob   endpoint=https://bob.example  tags:='["external"]' credential=b0bkey
  http POST :8000/policy   requester=alice target=bob allow:=true
  http GET  ':8000/resolve?target=bob&requester_id=alice&credential=s3cr3t'
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="SARL Registry", version="0.1.0")

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_agents: dict[str, dict] = {}  # agent_id → {endpoint, tags, credential}
_policies: list[dict] = []     # ordered list of {requester, target, allow}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    agent_id: str
    endpoint: str
    tags: list[str] = []
    credential: str   # mock auth — compared verbatim at resolve time


class PolicyRule(BaseModel):
    requester: str    # agent_id  OR  a tag label
    target: str       # agent_id  OR  a tag label
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
    Default (no match) = DENY — the endpoint is never exposed without an
    explicit allow rule.  This is the core of pre-contact filtering.
    """
    for rule in _policies:
        req_match = _selector_matches(rule["requester"], req_id, req_tags)
        tgt_match = _selector_matches(rule["target"], tgt_id, tgt_tags)
        if req_match and tgt_match:
            return rule["allow"]
    return False  # closed-world default


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
         margin: 0; padding: 2rem; }
  h1   { font-size: 1.4rem; letter-spacing: .05em; color: #a78bfa; margin: 0 0 .25rem; }
  p.sub { color: #64748b; font-size: .85rem; margin: 0 0 2rem; }

  .flow { display: flex; gap: 1rem; flex-wrap: wrap; }
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

  .row { display: flex; gap: .5rem; }
  .row input { flex: 1; }

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
    background: #0a0c14; border: 1px solid #1e2130;
    color: #94a3b8;
  }
  .result.ok  { border-color: #14532d; color: #86efac; }
  .result.err { border-color: #7f1d1d; color: #fca5a5; }

  .arrow { text-align: center; font-size: 1.4rem; color: #334155;
           display: flex; align-items: center; padding-top: 2.5rem; }

  .state-panel { margin-top: 2rem; background: #1e2130; border: 1px solid #2d3148;
                 border-radius: 10px; padding: 1.25rem 1.5rem; }
  .state-panel h2 { font-size: .9rem; text-transform: uppercase; letter-spacing:.08em;
                    color: #64748b; margin: 0 0 .75rem; }
  .state-grid { display: flex; gap: 1.5rem; flex-wrap: wrap; }
  .state-col { flex: 1; min-width: 200px; }
  .state-col h3 { font-size: .78rem; color: #475569; text-transform: uppercase;
                  letter-spacing:.06em; margin: 0 0 .5rem; }
  .state-col ul { list-style: none; margin: 0; padding: 0; font-size: .8rem;
                  font-family: monospace; color: #94a3b8; }
  .state-col li { padding: .2rem 0; border-bottom: 1px solid #1a1f35; }
  .state-col li:last-child { border-bottom: none; }
  .tag { background:#1e3a5f; color:#7dd3fc; border-radius:4px;
         font-size:.7rem; padding:.1em .4em; margin-left:.3em; }
  .allow  { color: #86efac; }
  .deny   { color: #fca5a5; }
</style>
</head>
<body>
<h1>SARL Registry</h1>
<p class="sub">Secure Agent Reachability Layer &mdash; pre-contact filtering demo</p>

<div class="flow">

  <!-- REGISTER -->
  <div class="card">
    <h2><span class="badge">POST</span>/register</h2>
    <label>Agent ID</label>
    <input id="r-id" value="alice">
    <label>Endpoint URL</label>
    <input id="r-ep" value="https://alice.internal/agent">
    <label>Tags (comma-separated)</label>
    <input id="r-tags" value="internal">
    <label>Credential</label>
    <input id="r-cred" value="s3cr3t">
    <button onclick="doRegister()">Register Agent</button>
    <div class="result" id="r-out">—</div>
  </div>

  <div class="arrow">&#8594;</div>

  <!-- POLICY -->
  <div class="card">
    <h2><span class="badge">POST</span>/policy</h2>
    <label>Requester (id or tag)</label>
    <input id="p-req" value="alice">
    <label>Target (id or tag)</label>
    <input id="p-tgt" value="public">
    <label>Decision</label>
    <select id="p-allow">
      <option value="true">allow</option>
      <option value="false">deny</option>
    </select>
    <button onclick="doPolicy()">Add Rule</button>
    <div class="result" id="p-out">—</div>
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
    <div class="result" id="v-out">—</div>
  </div>

</div>

<!-- LIVE STATE -->
<div class="state-panel">
  <h2>Registry state &mdash; <a href="#" onclick="refreshState();return false;"
      style="color:#6366f1;text-decoration:none;font-size:.8rem;">refresh</a></h2>
  <div class="state-grid">
    <div class="state-col">
      <h3>Agents</h3>
      <ul id="s-agents"><li style="color:#334155">none</li></ul>
    </div>
    <div class="state-col">
      <h3>Policies (ordered)</h3>
      <ul id="s-policies"><li style="color:#334155">none</li></ul>
    </div>
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

async function doRegister() {
  const tags = document.getElementById('r-tags').value
    .split(',').map(t => t.trim()).filter(Boolean);
  const { ok, status, json } = await api('POST', '/register', {
    agent_id:   document.getElementById('r-id').value.trim(),
    endpoint:   document.getElementById('r-ep').value.trim(),
    tags,
    credential: document.getElementById('r-cred').value.trim(),
  });
  show('r-out', ok ? json : { error: json.detail, status }, ok);
  refreshState();
}

async function doPolicy() {
  const { ok, status, json } = await api('POST', '/policy', {
    requester: document.getElementById('p-req').value.trim(),
    target:    document.getElementById('p-tgt').value.trim(),
    allow:     document.getElementById('p-allow').value === 'true',
  });
  show('p-out', ok ? json : { error: json.detail, status }, ok);
  refreshState();
}

async function doResolve() {
  const rid  = document.getElementById('v-rid').value.trim();
  const cred = document.getElementById('v-cred').value.trim();
  const tgt  = document.getElementById('v-tgt').value.trim();
  const url  = `/resolve?target=${encodeURIComponent(tgt)}`
             + `&requester_id=${encodeURIComponent(rid)}`
             + `&credential=${encodeURIComponent(cred)}`;
  const { ok, status, json } = await api('GET', url);
  show('v-out', ok ? json : { error: json.detail, status }, ok);
}

async function refreshState() {
  const { json: agents }   = await api('GET', '/_state/agents');
  const { json: policies } = await api('GET', '/_state/policies');

  const aList = document.getElementById('s-agents');
  aList.innerHTML = agents.length
    ? agents.map(a =>
        `<li><strong>${a.id}</strong>`
        + a.tags.map(t => `<span class="tag">${t}</span>`).join('')
        + `<br><span style="color:#475569">${a.endpoint}</span></li>`
      ).join('')
    : '<li style="color:#334155">none</li>';

  const pList = document.getElementById('s-policies');
  pList.innerHTML = policies.length
    ? policies.map((p, i) =>
        `<li>${i}. <strong class="${p.allow ? 'allow' : 'deny'}">`
        + `${p.allow ? 'allow' : 'deny'}</strong> `
        + `${p.requester} &#8594; ${p.target}</li>`
      ).join('')
    : '<li style="color:#334155">none</li>';
}

refreshState();
</script>
</body>
</html>""")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/register", status_code=201)
def register(body: RegisterRequest):
    """
    Publish an agent into the registry.

    - agent_id   : unique name / identifier
    - endpoint   : address callers receive upon successful resolution
    - tags       : zero or more labels (used in policy selectors)
    - credential : shared secret for mock authentication
    """
    if body.agent_id in _agents:
        raise HTTPException(409, f"agent '{body.agent_id}' is already registered")

    _agents[body.agent_id] = {
        "endpoint":   body.endpoint,
        "tags":       body.tags,
        "credential": body.credential,
    }
    return {"registered": body.agent_id, "tags": body.tags}


@app.post("/policy", status_code=201)
def add_policy(rule: PolicyRule):
    """
    Append a reachability rule to the ordered policy list.

    Rules are evaluated first-to-last; the first match decides.
    A selector can be an exact agent_id or a tag label — matching either.

    Examples
    --------
    Allow agent 'alice' to reach anything tagged 'public':
        {"requester": "alice", "target": "public", "allow": true}

    Block all 'external'-tagged agents from reaching 'internal'-tagged ones:
        {"requester": "external", "target": "internal", "allow": false}
    """
    _policies.append(rule.model_dump())
    return {
        "policy_index": len(_policies) - 1,
        "rule":         rule.model_dump(),
        "total_rules":  len(_policies),
    }


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

    The target's endpoint is **never returned** unless both gates pass.
    This is pre-contact filtering: the registry enforces access before
    any network contact between agents occurs.
    """
    # Gate 1 — authenticate the requester (mock: verbatim credential match)
    requester = _agents.get(requester_id)
    if requester is None:
        raise HTTPException(404, f"requester '{requester_id}' not registered")
    if requester["credential"] != credential:
        raise HTTPException(401, "credential mismatch")

    # Gate 2 — target must be registered
    target_agent = _agents.get(target)
    if target_agent is None:
        raise HTTPException(404, f"target '{target}' not registered")

    # Gate 3 — pre-contact reachability filter
    if not _is_reachable(
        requester_id, requester["tags"],
        target,       target_agent["tags"],
    ):
        raise HTTPException(
            403,
            f"reachability policy denies '{requester_id}' → '{target}'",
        )

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


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sarl_registry:app", host="0.0.0.0", port=8000, reload=True)
