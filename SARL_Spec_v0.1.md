# SARL Specification v0.1

**Selective Agent Reachability Layer**
Status: Draft for Review
Version: 0.1
Date: February 2026

---

## Abstract

This document specifies the Selective Agent Reachability Layer (SARL), a protocol for identity-based discovery filtering in AI agent networks. SARL enables agents to maintain multiple identity tiers with independent reachability rules, such that a querying agent receives only the identity information it is authorized to see — or no information at all. SARL operates before contact is established and is designed to extend, not replace, existing agent communication protocols such as Google A2A.

---

## Status of This Document

This is a v0.1 draft specification. The core concepts and architecture are stable. JSON schemas and API details are subject to change based on community feedback. Implementations against this draft are welcome; implementers should expect minor breaking changes before v1.0.

Feedback: open an issue at [https://github.com/vizmutlabs/sarl-spec](https://github.com/vizmutlabs/sarl-spec)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Architecture Overview](#3-architecture-overview)
4. [Identity Tiers](#4-identity-tiers)
5. [Reachability Rules](#5-reachability-rules)
6. [API Definition](#6-api-definition)
7. [A2A Integration](#7-a2a-integration)
8. [Security Considerations](#8-security-considerations)
9. [Future Work](#9-future-work)

---

## 1. Introduction

### 1.1 What SARL Is

SARL is a protocol specification for selective reachability in AI agent networks. It defines how agents register multiple identity tiers, how reachability rules are expressed and evaluated, and how registries resolve queries against those rules.

SARL is built on three design principles:

**1. Credential-aware, issuer-agnostic.**
SARL evaluates reachability rules against credentials presented by querying agents. SARL does not define credential verification mechanisms; registries MUST perform verification using external credential systems (Verifiable Credential issuers, enterprise IAM systems, or shared secret validators). SARL defines the rule format and evaluation logic; it does not define the credential infrastructure.

**2. Extension, not replacement.**
SARL adds a reachability resolution step before existing agent communication protocols. When resolution succeeds, SARL hands off to the underlying protocol (A2A, AGNTCY SLIM, or any other) for actual communication. Agents that do not use SARL continue to work normally.

**3. Multi-address by design.**
Each agent maintains one or more identity tiers. Different querying agents, presenting different credentials, receive different identity descriptors — or no descriptor at all. This is the core architectural property of SARL.

### 1.2 What SARL Does Not Define

- Credential issuance or verification infrastructure
- Message transport or agent-to-agent communication
- Agent runtime behavior or policy enforcement
- Federation between registries (future work)

### 1.3 Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1.4 Versioning

This document is `spec_version: "0.1"`. All JSON schemas defined in this specification include a `spec_version` field. Implementations MUST include this field in all messages and MUST reject messages with unrecognized spec versions. Unknown field ignoring (Section 1.5) applies only to objects with a recognized `spec_version`; messages with unrecognized `spec_version` MUST be rejected.

### 1.5 Unknown Field Handling

Registries MUST ignore unknown fields in JSON objects defined by this specification. This allows forward compatibility with future versions of the protocol without requiring coordinated upgrades.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Agent** | A software entity that acts autonomously on behalf of a user or organization. |
| **Identity Descriptor** | A JSON object describing an agent's identity at a specific tier: name, capabilities, contact endpoint, and metadata. |
| **Identity Tier** | A named level of identity visibility: Public, Verified Public, Group, Private, or Ephemeral. |
| **Reachability Rule** | A condition that a querying agent's credentials must satisfy to access a given identity tier. |
| **Registry** | A service that stores identity descriptors and reachability rules, and evaluates queries against them. |
| **Querying Agent** | An agent requesting discovery of another agent through the SARL registry. |
| **Target Agent** | An agent that has registered one or more identity tiers in the SARL registry. |
| **Resolution** | The process of evaluating a query against a target agent's reachability rules and returning the appropriate identity descriptor, or nothing. |
| **Agent Card** | A2A-specific: a JSON metadata document describing an agent's capabilities and contact information. |
| **Credential** | Any verifiable claim presented by a querying agent: Verifiable Credential, API key, enterprise domain token, shared secret, or bearer token. |
| **Agent ID** | A string identifier for an agent registered in the SARL registry. `agent_id` values MUST be treated as case-sensitive opaque strings. Registries MUST NOT normalize, transform, or canonicalize `agent_id` values in v0.1. DNS-label-like formatting (lowercase, hyphens, no spaces) is RECOMMENDED. |

---

## 3. Architecture Overview

### 3.1 System Components

A SARL system consists of three components:

1. **Target Agent** — registers identity descriptors and reachability rules with the registry.
2. **Querying Agent** — presents credentials to the registry and receives the matching identity descriptor, or an empty result.
3. **SARL Registry** — stores descriptors and rules, evaluates queries, and returns results.

### 3.2 Resolution Flow

When a querying agent wants to discover a target agent, SARL evaluates the request in five steps:

```
1. REGISTER   Target agent registers identity tiers and reachability rules
                  with the registry (one-time, updated as needed).

2. QUERY      Querying agent presents its credentials to the registry,
                  requesting discovery of a named target agent.

3. MATCH      Registry evaluates credentials against each tier's rules,
                  in precedence order (Ephemeral → Private → Group →
                  Verified Public → Public). Returns the highest matching tier.

4. RETURN     If a match exists: registry returns the identity descriptor
                  for that tier. If no match (or agent does not exist):
                  registry returns { "resolved": false } — identical in
                  both cases.

5. HANDOFF    On successful match, the querying agent uses the returned
                  descriptor to initiate contact via A2A or another protocol.
                  SARL's role ends here.
```

### 3.3 Discovery Model

SARL extends A2A Agent Card discovery. It does not replace it. Agents that do not register with a SARL registry remain discoverable via standard A2A mechanisms. SARL adds an optional reachability resolution step that agents and registries may implement.

### 3.4 Registry Model

SARL v0.1 uses a centralized registry model. A single SARL registry is operated by a trusted party. Federated and decentralized models are defined as future work (see Section 9).

---

## 4. Identity Tiers

### 4.1 Tier Definitions

Each agent registers one or more identity tiers. Each tier has its own identity descriptor and reachability rules. An agent that only meets Public criteria has no way to learn that higher tiers exist.

| Tier | Visibility | Credentials Required | Typical Use |
|------|-----------|---------------------|-------------|
| **Public** | Anyone | None | General discovery, limited capabilities exposed |
| **Verified Public** | Anyone | None required from querying agent | Enterprise or official agents proving their own legitimacy |
| **Group** | Credential holders only | Valid credential matching group rules | Business operations within a defined community |
| **Private** | Known identifier only | Exact private identifier (shared out-of-band) | Sensitive operations, trusted relationships |
| **Ephemeral** | Time/mission-scoped | Scoped identifier, auto-expires | Temporary collaborations, incident response |

**Verified Public semantics:** The Verified Public tier uses `rule_type: "open"` — any querying agent can discover it. The "verified" property refers to the target agent including a proof of authenticity within its own identity descriptor (e.g., a Verifiable Credential issued to the target agent), not to the querying agent presenting credentials. A Verified Public tier signals that the target agent's identity has been attested by a trusted issuer; it does not restrict who can discover it.

### 4.2 Identity Descriptor Schema

Each identity tier is described by an identity descriptor. Registries MUST store and return identity descriptors in the following format:

```json
{
  "spec_version": "0.1",
  "agent_id": "example-financial-advisor",
  "tier": "group",
  "name": "Example Financial Advisor",
  "description": "Portfolio management and tax advisory for example.com employees",
  "endpoint": "https://agents.example.com/financial-advisor",
  "capabilities": ["portfolio-analysis", "tax-planning", "reporting"],
  "metadata": {
    "owner_org": "example.com",
    "created_at": "2026-02-01T00:00:00Z"
  }
}
```

**Required fields:** `spec_version`, `agent_id`, `tier`, `name`, `endpoint`
**Optional fields:** `description`, `capabilities`, `metadata`

The `endpoint` field MUST be a valid absolute URI. HTTPS is RECOMMENDED.

An agent MAY register descriptors for multiple tiers. Each tier MUST have exactly one descriptor. If a tier has no descriptor registered, it MUST NOT be returned in resolution results.

---

## 5. Reachability Rules

### 5.1 Rule Types

SARL defines three rule types. Registries MUST support all three.

**`open`** — No credentials required. Any querying agent receives this tier.

```json
{
  "spec_version": "0.1",
  "tier": "public",
  "rule_type": "open"
}
```

**`credential_match`** — Querying agent must present a credential matching specified criteria. `required_claims` MUST be evaluated as exact key-value equality (case-sensitive) against the verified credential claims. Partial, wildcard, array, and nested-object matching are not defined in v0.1.

```json
{
  "spec_version": "0.1",
  "tier": "group",
  "rule_type": "credential_match",
  "credential": {
    "type": "VerifiableCredential",
    "issuer": "did:web:example.com",
    "required_claims": {
      "role": "employee"
    }
  }
}
```

**`identifier_match`** — Querying agent must present an exact identifier. Registries MUST store identifiers as salted hashes using a cryptographic hash function with at least 256-bit output (e.g., SHA-256) and a per-identifier random salt of at least 16 bytes. Registries MUST use constant-time comparison when evaluating identifier matches.

```json
{
  "spec_version": "0.1",
  "tier": "private",
  "rule_type": "identifier_match",
  "identifier_hash": "<salted-hash-of-identifier>"
}
```

Boolean composition of multiple credential constraints (AND/OR logic), multiple issuer matching, wildcards, and nested claim evaluation are not defined in v0.1. Each tier has exactly one rule.

### 5.2 Rule Evaluation

Registries MUST evaluate rules in the following precedence order:

1. Ephemeral
2. Private
3. Group
4. Verified Public
5. Public

For the Ephemeral tier, expiry MUST be evaluated at query time and MUST be checked before tier precedence ordering and rule evaluation begin. Expired Ephemeral tiers MUST NOT be considered for matching. Expiry evaluation MUST use the registry node's system time at the moment the query is received.

The registry MUST return the descriptor for the **highest matching tier** only. It MUST NOT return descriptors for lower tiers if a higher tier matches.

### 5.3 Credential Verification

The registry MUST verify credential signatures before evaluating reachability rules. Credential verification is performed against the issuer declared in the credential. The registry MUST reject credentials with invalid signatures, expired validity periods, or unrecognized issuers. If credential verification cannot be completed due to issuer unavailability or resolution failure, the registry MUST treat that credential as invalid for matching.

SARL does not define the credential verification mechanism. Issuer matching MUST use exact string equality against the `issuer` value defined in the reachability rule. Prefix matching, wildcard matching, and DID resolution-based matching are not defined in v0.1. For `VerifiableCredential`, the registry MUST extract `issuer` and claim values from the verified VC payload (JWT claims or JSON-LD document), not from the outer wrapper fields. For `format: jwt`, the VC MUST be a JWS-signed JWT; for `format: jsonld`, the VC MUST include a `proof` field that can be cryptographically verified. Credentials that do not satisfy these requirements MUST be treated as invalid for matching.

### 5.4 Ephemeral Tier Expiry

Ephemeral tier rules MUST include an expiry timestamp. Registries MUST automatically invalidate ephemeral registrations after their expiry time. Expired ephemeral tiers MUST NOT be returned in query results, even if not yet purged from storage.

```json
{
  "spec_version": "0.1",
  "tier": "ephemeral",
  "rule_type": "identifier_match",
  "identifier_hash": "<salted-hash>",
  "expires_at": "2026-02-19T12:00:00Z"
}
```

---

## 6. API Definition

### 6.1 POST /agents/register

Registers or updates an agent's identity descriptor and reachability rules for one tier. `POST /agents/register` MUST be idempotent per (`agent_id`, `tier`): if a registration already exists for that combination, the registry MUST replace the stored descriptor and rule with the new values. First registration returns `201 Created`; subsequent updates return `200 OK`.

The registry MUST bind each (`agent_id`, `tier`) registration to the authenticated registrant principal. Only the same principal MAY update that registration; attempts by a different principal MUST return `404` to avoid existence probing.

The `agent_id` field at the top level of the request and the `agent_id` field inside the `descriptor` object MUST be identical. Registries MUST reject requests where these values differ with `400`.

Registries MUST require authenticated registration. The authentication mechanism is implementation-defined in v0.1.

**Request:**

```json
{
  "spec_version": "0.1",
  "agent_id": "example-financial-advisor",
  "descriptor": {
    "spec_version": "0.1",
    "agent_id": "example-financial-advisor",
    "tier": "group",
    "name": "Example Financial Advisor",
    "description": "Portfolio management and tax advisory",
    "endpoint": "https://agents.example.com/financial-advisor",
    "capabilities": ["portfolio-analysis", "tax-planning"]
  },
  "rule": {
    "spec_version": "0.1",
    "tier": "group",
    "rule_type": "credential_match",
    "credential": {
      "type": "VerifiableCredential",
      "issuer": "did:web:example.com",
      "required_claims": { "role": "employee" }
    }
  }
}
```

**Response — 201 Created (first registration) or 200 OK (update):**

```json
{
  "spec_version": "0.1",
  "agent_id": "example-financial-advisor",
  "tier": "group",
  "registered_at": "2026-02-18T10:00:00Z"
}
```

**Error codes:** `400` (invalid request), `401` (authentication required or invalid). Registries SHOULD use `401` for all registration authorization failures; `403` is discouraged in v0.1.

### 6.2 POST /agents/query

Resolves a target agent against the querying agent's credentials. Returns the matching identity descriptor, or `{ "resolved": false }` if no tier matches or the agent does not exist. The `agent_id` field in the request refers to the `agent_id` of the Target Agent.

**Credential encoding:** Each `VerifiableCredential` entry MUST include a `format` field set to either `jwt` or `jsonld`. The `vc` field MUST contain a JWT string when `format` is `jwt`, or a JSON-LD VC object including its `proof` field when `format` is `jsonld`. Credential objects that do not meet the signature requirements defined in Section 5.3 MUST be treated as invalid for matching.

**Request:**

```json
{
  "spec_version": "0.1",
  "agent_id": "example-financial-advisor",
  "credentials": [
    {
      "type": "VerifiableCredential",
      "format": "jwt",
      "vc": "<JWT-encoded-VC-string>"
    }
  ]
}
```

**Response — match found — 200 OK:**

```json
{
  "spec_version": "0.1",
  "resolved": true,
  "tier": "group",
  "descriptor": {
    "spec_version": "0.1",
    "agent_id": "example-financial-advisor",
    "tier": "group",
    "name": "Example Financial Advisor",
    "endpoint": "https://agents.example.com/financial-advisor",
    "capabilities": ["portfolio-analysis", "tax-planning"]
  }
}
```

**Response — no match or agent does not exist — 200 OK:**

```json
{
  "spec_version": "0.1",
  "resolved": false
}
```

Both "no tier matched" and "agent does not exist" MUST return identical responses. This prevents enumeration attacks. Registries MUST NOT reveal whether an agent exists if the querying agent does not meet any reachability rule.

When multiple credentials are presented, the registry MUST treat a rule as satisfied if any valid credential satisfies it. Invalid credentials MUST be ignored for matching purposes and MUST NOT cause the request to fail unless the request is otherwise malformed.

**Error codes:** `400` (invalid request), `429` (rate limited)

### 6.3 GET /agents/{agent_id}/card

Returns an A2A-compatible Agent Card for the resolved tier. This endpoint MUST require a valid session token obtained from a prior successful `POST /agents/query` call, passed as `Authorization: Bearer <token>`. Credential re-presentation as an alternative to session tokens is not defined in v0.1.

Session token validity duration and binding semantics are implementation-defined in v0.1. Registries MUST ensure tokens are bound to the tier resolved at query time and MUST NOT allow tokens to be reused to access a higher tier than originally resolved.

To preserve the anti-enumeration guarantee, this endpoint MUST return `404` for both "agent does not exist" and "agent exists but the querying agent has no authorized tier." The two cases MUST be indistinguishable to the caller. `401` is reserved exclusively for missing or invalid session tokens. `403` MUST NOT be used.

**Response — 200 OK:**

```json
{
  "name": "Example Financial Advisor",
  "description": "Portfolio management and tax advisory for example.com employees",
  "url": "https://agents.example.com/financial-advisor",
  "version": "1.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false
  },
  "authentication": [],
  "sarl": {
    "spec_version": "0.1",
    "resolved_tier": "group",
    "registry": "https://registry.sarl.dev",
    "agent_id": "example-financial-advisor"
  }
}
```

**Error codes:** `401` (missing or invalid session token), `404` (agent not found or not authorized — indistinguishable by design)

---

## 7. A2A Integration

### 7.1 Agent Card Extension

SARL extends the A2A Agent Card with a `sarl` field. This field is OPTIONAL. Agents that include it signal SARL awareness; agents that omit it remain fully A2A-compatible.

```json
{
  "name": "Example Agent",
  "url": "https://example.com/agent",
  "sarl": {
    "spec_version": "0.1",
    "registry": "https://registry.sarl.dev",
    "agent_id": "example-agent"
  }
}
```

### 7.2 Combined Discovery Flow

When a SARL-aware querying agent discovers an A2A Agent Card containing a `sarl` field, it SHOULD perform SARL resolution before initiating contact:

1. Read `sarl.registry` and `sarl.agent_id` from the Agent Card.
2. Call `POST /agents/query` on the registry with the querying agent's credentials.
3. If resolved: use the returned descriptor endpoint for A2A communication.
4. If not resolved: do not initiate contact. The target agent is not reachable at any tier the querying agent qualifies for.

SARL-aware querying agents MUST NOT attempt direct A2A contact using endpoints learned outside SARL resolution when a `sarl` field is present in the Agent Card. Bypassing SARL resolution undermines the reachability guarantees of the target agent.

### 7.3 Backward Compatibility

Agents that do not include a `sarl` field in their Agent Card are unaffected by SARL. SARL-aware registries MUST NOT interfere with standard A2A discovery for non-SARL agents. SARL is strictly additive.

---

## 8. Security Considerations

| Attack Surface | Mitigation |
|---------------|------------|
| **Agent enumeration** | No-match and non-existent agent return identical responses. Registries MUST NOT reveal agent existence to unauthorized queriers. |
| **Identifier brute-force** | Private identifiers stored as salted hashes (SHA-256 minimum, 16-byte random salt minimum) with constant-time comparison. Registries MUST implement rate limiting on query endpoints. |
| **Credential forgery** | Registry MUST verify credential signatures before rule evaluation. Credentials with invalid signatures MUST be treated as invalid and excluded from rule evaluation. |
| **Registration spoofing** | Registries MUST require authenticated registration. Authentication mechanism is implementation-defined in v0.1. |
| **Ephemeral tier staleness** | Registries MUST check ephemeral expiry at query time. Expired ephemeral tiers MUST NOT be returned even if not yet purged from storage. |
| **Registry as single point of failure** | Operators SHOULD implement standard high-availability practices. Federation model (future work) addresses long-term resilience. |

### 8.1 Trust Model

SARL v0.1 assumes a trusted registry operator. The registry has access to all registered identity descriptors and reachability rules. Agents MUST trust the registry to enforce reachability rules correctly and to not disclose descriptors to unauthorized parties. Decentralized trust models are future work (see Section 9).

---

## 9. Future Work

The following extensions are planned for future versions. They are not defined in v0.1 and MUST NOT be assumed by implementations.

- **Multiple rules/identifiers per tier** — Allow a tier to have multiple independent reachability rules (e.g., different audiences within Group) and optionally multiple descriptors per tier. v0.1 restricts each tier to exactly one rule and one descriptor; this extension would require defining evaluation semantics, descriptor selection, and ownership rules per entry.
- **Federated registries** — Organizations operate their own SARL registry; cross-registry resolution protocol allows querying across federation members.
- **Distributed registry (DHT)** — Fully decentralized, no single operator. Modeled on DNS evolution.
- **Trust escalation** — Agents progressively earn access to higher tiers through successful interactions.
- **AGNTCY SLIM integration** — SARL reachability rules as an extension to AGNTCY's agent discovery model.
- **MCP integration** — SARL resolution as a pre-contact step in Model Context Protocol tool discovery.
- **agent:// URI integration** — SARL registry as a resolver for the agent:// URI scheme.
- **Batch resolution** — Query multiple agents in a single request.

---

## Appendix A: Schema Reference

### Identity Descriptor (required fields)

```json
{
  "spec_version": "0.1",
  "agent_id": "string (case-sensitive, DNS-label-like RECOMMENDED)",
  "tier": "public | verified_public | group | private | ephemeral",
  "name": "string",
  "endpoint": "string (absolute URI, HTTPS RECOMMENDED)"
}
```

### Reachability Rules

**`open`** (no extra fields required):
```json
{
  "spec_version": "0.1",
  "tier": "public | verified_public",
  "rule_type": "open"
}
```

**`credential_match`** (requires `credential` object; applies to `group` tier; `verified_public` uses `open` in v0.1):
```json
{
  "spec_version": "0.1",
  "tier": "group",
  "rule_type": "credential_match",
  "credential": {
    "type": "VerifiableCredential",
    "issuer": "string (exact match, case-sensitive)",
    "required_claims": { "key": "value" }
  }
}
```

**`identifier_match`** (requires `identifier_hash`; `expires_at` required when tier is `ephemeral`):
```json
{
  "spec_version": "0.1",
  "tier": "private | ephemeral",
  "rule_type": "identifier_match",
  "identifier_hash": "string (SHA-256 minimum, 16-byte random salt minimum)",
  "expires_at": "string (ISO 8601, required for ephemeral tier only)"
}
```

### Query Request Credential Encoding

JWT format:
```json
{ "type": "VerifiableCredential", "format": "jwt", "vc": "<JWT-VC-string>" }
```

JSON-LD format (must include `proof`):
```json
{ "type": "VerifiableCredential", "format": "jsonld", "vc": { "@context": ["..."], "proof": { "..." } } }
```

### Query Response

```json
{
  "spec_version": "0.1",
  "resolved": true,
  "tier": "string",
  "descriptor": { }
}
```

or

```json
{
  "spec_version": "0.1",
  "resolved": false
}
```

---

*SARL Specification v0.1 — February 2026*
*Open for community review and implementation feedback.*
*https://github.com/vizmutlabs/sarl-spec*
