# SARL — Selective Agent Reachability Layer

**SARL is an open protocol specification that gives AI agents control over who can discover and reach them.**

SARL is a discovery-layer protocol; it does not perform authentication or policy enforcement itself.

SARL operates before contact is established — filtering discovery results prior to authentication or message exchange. Today's agent communication protocols (Google A2A, AGNTCY SLIM, MCP) assume that if an agent is discoverable, it is reachable by anyone who finds it. SARL adds the missing layer: the receiving agent decides who gets through.

---

## The Problem

When an AI agent publishes itself to a network, any other agent can attempt to contact it. There is no standard mechanism for an agent to say:

- *"Only agents from my organization can reach me on this identity"*
- *"Only agents presenting a verified healthcare credential can discover this endpoint"*
- *"This identity expires in 24 hours and is scoped to this task only"*

SARL solves this.

---

## How It Works

Each agent registers one or more **identity tiers** with a SARL registry. Different querying agents, presenting different credentials, receive different identity descriptors — or no descriptor at all.

| Tier | Who Can Discover It |
|---|---|
| **Public** | Anyone |
| **Verified Public** | Anyone (target agent carries proof of authenticity) |
| **Group** | Agents presenting a valid group identifier |
| **Private** | Agents who know the exact private identifier |
| **Ephemeral** | Temporary, expires after time or task completion |

One agent can maintain all five tiers simultaneously. This is the core architectural property.

If a querying agent does not match any tier, the registry returns a response indistinguishable from "agent not found."

SARL **extends** existing protocols — it does not replace them. When SARL resolution succeeds, it hands off to A2A, AGNTCY, or any other underlying communication protocol.

---

## Status

**v0.1 — Draft for review**

This is an early specification open for community feedback. The core concepts are stable; the API and schema details are subject to change.

---

## Contents

- [`SARL_Spec_v0.1.md`](./SARL_Spec_v0.1.md) — Full protocol specification

Planned:
- Reference implementation (Python)
- A2A integration example
- Demo registry

---

## Feedback

Open an issue or start a discussion. All feedback welcome.

---

## License

Apache 2.0
