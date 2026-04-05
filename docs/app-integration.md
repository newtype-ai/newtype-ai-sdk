# Login with nit — App Integration Guide

Verify AI agent identity with a single API call. No OAuth, no passwords, no crypto library needed.

**The agent controls what each app sees.** Each agent can maintain a separate card per app — different skills, different descriptions, different tools. When an agent logs into your app, you automatically receive the card they've prepared for your domain. You don't configure this. The agent decides what to share with you.

## How It Works

```
Agent                          Your App                     api.newtype-ai.org
  |                               |                               |
  |  1. nit sign --login app.com  |                               |
  |  (signs with Ed25519 key)     |                               |
  |                               |                               |
  |  --- sends login payload ---> |                               |
  |                               |                               |
  |                               |  2. POST /agent-card/verify   |
  |                               |     { agent_id, domain,       |
  |                               |       timestamp, signature }  |
  |                               | ----------------------------> |
  |                               |                               |
  |                               |  3. { verified: true,         |
  |                               |       card, branch,       |
  |                               |       readToken, ... }        |
  |                               | <---------------------------- |
  |                               |                               |
  |                               |  4. Create session, store     |
  |                               |     readToken for this agent  |
  |                               |                               |
  |  (agent updates card later)   |                               |
  |                               |                               |
  |                               |  5. GET agent-{uuid}          |
  |                               |     .newtype-ai.org/          |
  |                               |     .well-known/agent-card    |
  |                               |     .json?branch=app.com      |
  |                               |     Authorization: Bearer     |
  |                               |     <readToken>               |
  |                               | ----------------------------> |
  |                               |                               |
  |                               |  6. { name, skills, ... }     |
  |                               | <---------------------------- |
```

## API Endpoint

```
POST https://api.newtype-ai.org/agent-card/verify
Content-Type: application/json
```

### Request

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "your-app.com",
  "timestamp": 1710000000,
  "signature": "base64-encoded-ed25519-signature",
  "policy": {
    "max_identities_per_machine": 10,
    "min_age_seconds": 3600
  }
}
```

The first four fields come directly from the agent's login payload. `policy` is optional — omit it to accept all verified agents.

### Response (success)

```json
{
  "verified": true,
  "admitted": true,
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "your-app.com",
  "card": {
    "name": "Agent Name",
    "description": "What this agent does",
    "version": "1.0.0",
    "url": "https://agent-550e8400-....newtype-ai.org",
    "skills": [...]
  },
  "branch": "your-app.com",
  "wallet": { "solana": "7Xf3kQ...", "evm": "0x1a2b..." },
  "readToken": "eyJzdWIiOiI1NTBlODQwMC...",
  "identity": {
    "registration_timestamp": 1709000000,
    "machine_identity_count": 3,
    "ip_identity_count": 5,
    "total_logins": 42,
    "last_login_timestamp": 1709120000,
    "unique_domains": 4
  },
  "attestation": {
    "server_signature": "base64...",
    "server_url": "https://api.newtype-ai.org",
    "server_public_key": "ed25519:base64..."
  }
}
```

- `admitted` — whether the identity meets your `policy`. Always `true` if no policy were specified.
- `identity` — raw identity metadata. Use this for custom trust logic beyond what `policy` supports (e.g., "only accept agents that have logged into at least 3 other apps").
- `attestation` — server's Ed25519 signature over the verification result. Apps can cache and re-verify offline.
- `card` — the agent's card for your domain. If the agent has pushed a branch named after your domain, you get that tailored card. Otherwise you get the main (public) card.
- `branch` — which branch the card came from: your domain name or `"main"`.
- `wallet` — chain wallet addresses derived from the agent's Ed25519 keypair. `solana` (base58 of pubkey) and `evm` (EIP-55 checksummed). `null` for agents using older nit versions.
- `readToken` — a time-limited token (30 days) for fetching the agent's latest domain card. Store it alongside the agent's session.

### Trust Policy

The server acts as an **identity registry** — like a credit bureau, it stores data and never rejects identities. Your app defines its own trust policy via `policy`. The `policy` parameter is optional — if omitted (or empty), `admitted` is always `true`. The server is fully neutral; it only evaluates rules you explicitly provide.

| Field | Type | Description |
|---|---|---|
| `max_identities_per_ip` | number | Reject if too many identities from same registration IP |
| `max_identities_per_machine` | number | Reject if too many identities from same machine |
| `min_age_seconds` | number | Reject identities younger than this (e.g., 5) |
| `max_login_rate_per_hour` | number | Reject if login rate is too high |

Like Stripe Radar: the server evaluates rules server-side for convenience, and returns raw metadata for transparency. Your app can also inspect the `identity` object for custom logic beyond what `policy` supports.

**Policy behavior for new agents:** When an agent has no stored identity metadata (brand new or TOFU registration not yet complete), `min_age_seconds` and `max_login_rate_per_hour` cause `admitted: false`. New agents with no history fail these checks rather than silently bypassing them. If your app should accept brand-new agents, omit these fields from `policy` or handle `admitted: false` with a "try again later" message.

### Response (failure)

```json
{
  "verified": false,
  "error": "Signature verification failed"
}
```

| Status | Error | Meaning |
|--------|-------|---------|
| 400 | Invalid or missing field | Malformed payload |
| 401 | Timestamp expired | Payload older than 5 minutes — ask agent to sign again |
| 403 | Signature verification failed | Signature doesn't match the agent's registered public key |
| 404 | Agent not found | Agent hasn't pushed their identity yet (`nit push`) |

**SDK error handling:** When using `@newtype-ai/nit-sdk`, error behavior differs from raw HTTP:

| Function | 404 response | Other HTTP errors | Malformed JSON |
|----------|-------------|-------------------|----------------|
| `verifyAgent()` | Returns `{ verified: false, error: "..." }` | Returns `{ verified: false, error: "..." }` | Returns `{ verified: false, error: "..." }` |
| `fetchAgentCard()` | Returns `null` | Throws `NitSdkError` with `.status` | Throws `NitSdkError` with `status: 0` |

Previously, `fetchAgentCard()` returned `null` for all failures silently. It now distinguishes 404 (expected — branch not pushed) from server/auth errors (unexpected — should be surfaced).

## Code Examples

### JavaScript / TypeScript

```javascript
async function verifyAgent(payload) {
  const res = await fetch('https://api.newtype-ai.org/agent-card/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return res.json();
}

// Usage
const result = await verifyAgent({
  agent_id: payload.agent_id,
  domain: payload.domain,
  timestamp: payload.timestamp,
  signature: payload.signature,
});

if (result.verified) {
  // Create session for result.agent_id
  // Use result.card for agent name, skills, etc.
}
```

Or use the SDK: `npm install @newtype-ai/nit-sdk`

```javascript
import { verifyAgent, fetchAgentCard, NitSdkError } from '@newtype-ai/nit-sdk';

const result = await verifyAgent(payload, {
  policy: { max_identities_per_machine: 10, min_age_seconds: 3600 },
  timeoutMs: 5_000,
});
if (result.verified && result.admitted) {
  // result.card — domain-specific card (or main if no domain branch)
  // result.identity — registration time, login count, machine/IP grouping
  // result.readToken — store this to fetch updated cards later

  // Fetch the latest card anytime during the 30-day window:
  try {
    const freshCard = await fetchAgentCard(result.agent_id, 'your-app.com', result.readToken);
    // freshCard is null if the domain branch doesn't exist (404)
  } catch (err) {
    if (err instanceof NitSdkError) {
      console.error(`Card fetch failed (HTTP ${err.status}): ${err.message}`);
    }
  }
}
```

### Python

```python
import requests

def verify_agent(payload):
    resp = requests.post(
        'https://api.newtype-ai.org/agent-card/verify',
        json=payload,
    )
    return resp.json()

result = verify_agent({
    'agent_id': payload['agent_id'],
    'domain': payload['domain'],
    'timestamp': payload['timestamp'],
    'signature': payload['signature'],
})

if result['verified']:
    agent_id = result['agent_id']
    card = result['card']
    # Create session, use card data...
```

### curl

```bash
curl -X POST https://api.newtype-ai.org/agent-card/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "domain": "your-app.com",
    "timestamp": 1710000000,
    "signature": "base64-signature-here"
  }'
```

## Fetching Updated Cards

After login, agents may update their card (add skills, change description). Use the `readToken` to fetch the latest version at any time:

### Using the SDK

```typescript
import { verifyAgent, fetchAgentCard, NitSdkError } from '@newtype-ai/nit-sdk';

// At login
const result = await verifyAgent(payload);
if (result.verified) {
  const { agent_id, readToken, card } = result;
  // Store readToken with the agent's session
}

// Later — fetch the latest card
try {
  const latestCard = await fetchAgentCard(agent_id, 'your-app.com', readToken, {
    timeoutMs: 5_000,
  });
  if (!latestCard) {
    // 404 — agent hasn't pushed a branch for your domain
  }
} catch (err) {
  if (err instanceof NitSdkError) {
    // HTTP 401 (token expired), 500 (server error), etc.
    console.error(`Failed to fetch card: ${err.message} (HTTP ${err.status})`);
  }
}
```

### Using fetch directly

```javascript
const res = await fetch(
  `https://agent-${agent_id}.newtype-ai.org/.well-known/agent-card.json?branch=your-app.com`,
  { headers: { 'Authorization': `Bearer ${readToken}` } }
);
const card = await res.json();
```

### Token details

- **Scope:** each token is bound to one agent + one domain. A token for `app-a.com` cannot read the `app-b.com` branch.
- **Expiry:** 30 days. When expired, the agent must re-login (`nit sign --login your-app.com`) to get a fresh token.
- **Stateless:** the server verifies the token via HMAC — no database lookup, no revocation list.
- **Fallback:** if the domain branch doesn't exist (agent hasn't pushed it), the card serving endpoint returns 404 even with a valid token.

## After Verification

Once `verified: true`, the `agent_id` is the agent's permanent identity. Use it as the primary key in your database.

The `card` object contains the agent's profile for your domain: name, description, version, skills, and provider. If the agent hasn't pushed a domain-specific branch, you get their main (public) card. Use `branch` to check which one you received.

### Identity vs Admission

nit verifies **identity** (`verified: true`) and evaluates **trust policy** (`admitted: true`). These are separate concerns:

- `verified` — the Ed25519 signature is valid. The agent is who it claims to be. This is a cryptographic fact.
- `admitted` — the identity meets your app's trust policy. This is your policy.

An agent can be `verified: true` but `admitted: false` (too many identities from the same machine, too new, etc.). Your app controls admission.

```javascript
const result = await verifyAgent(payload, {
  policy: { min_age_seconds: 3600, max_identities_per_machine: 10 }
});
if (!result.verified) return deny('Invalid signature');
if (!result.admitted) return deny('Identity does not meet trust policy');

// Both checks passed — now inspect card content (your policy)
if (!result.card?.name) return reject("Set a name on your agent card");

createSession(result.agent_id);
```

The `identity` object gives you raw metadata for custom policies beyond what `policy` supports. The cryptographic fields (`publicKey`, `wallet`) are enforced by nit and cannot be faked. Everything else — name, description, skills — is agent-controlled.

## Prerequisites

The agent runs `nit sign --login your-app.com`. This single command handles everything — identity creation, publishing, and login payload generation. No separate init or push step needed.

If you get a 404 "Agent not found", the agent's auto-push may have failed (network issue). Ask them to run `nit push` and try again.

## Serving a Skill File (Recommended)

Serve a `skill.md` at your root domain so agents automatically learn how to use your app:

```
https://your-app.com/skill.md
```

The file should have YAML frontmatter with at least `name`, `description`, and `version`:

```markdown
---
name: your-skill-name
description: What the agent can do with your app
version: 0.1.0
---

# Your App Name

Brief description of what agents can do here.

## Authentication

This app uses [nit](https://github.com/newtype-ai/nit) for agent identity.

\`\`\`bash
nit sign --login your-app.com
\`\`\`

POST the JSON output to `https://your-app.com/api/login`:

\`\`\`bash
curl -X POST https://your-app.com/api/login \
  -H "Content-Type: application/json" \
  -d '<output from nit sign --login>'
\`\`\`

Response: `{ "api_key": "..." }`. Use this key as `Authorization: Bearer <api_key>` for all subsequent requests.

## API

Your endpoints, rules, etc.
```

The **Authentication** section is the key part. Agents read this and know exactly how to log in — one command, one POST. Customize the endpoint URL and response format for your app.

When an agent runs `nit sign --login your-app.com`, nit automatically:

1. Fetches `https://your-app.com/skill.md`
2. Saves it as a local SKILL.md in the agent's skills directory
3. On subsequent logins, compares the `version` field — if yours is newer, updates the local copy

If no `skill.md` is served (404 or no frontmatter), a generic template is created instead.

**Bump the `version`** whenever you update instructions so agents pick up changes on their next login.

## Forcing Agent Re-Login

Long-running agents hold tokens indefinitely. When your app updates, you can force all agents to re-login using a **version string**:

1. Maintain an app version string in your server code (e.g., `"0.2.0"`)
2. Stamp the current version into each token at login time
3. In your bearer auth middleware, compare the token's version against the code's current version
4. If they don't match, return `401 { "code": "RELOGIN_REQUIRED" }` — the agent re-logins and picks up your latest `skill.md` and any other changes

```javascript
// At login — stamp the version into the token
await storeToken(apiKey, { agentId, appVersion: '0.2.0', ... })

// In middleware — compare token version against current version
if (tokenData.appVersion !== APP_VERSION) {
  return c.json({ error: 'App updated — re-login required', code: 'RELOGIN_REQUIRED' }, 401)
}
```

When you release an update, bump the version and deploy. All existing tokens automatically trigger re-login — no manual intervention needed.

Agents using nit will automatically fetch your updated `skill.md` during re-login.

## Security Notes

- **Replay protection**: Payloads expire after 5 minutes. Always use the timestamp from the agent's payload, not your own.
- **Domain binding**: The domain is signed into the payload. A signature for `app-a.com` cannot be reused on `app-b.com`.
- **No secrets needed**: Your app doesn't need any API keys or secrets to call the verify endpoint.
- **HTTPS enforcement**: The SDK requires `https://` for custom `apiUrl` and `baseUrl` options. Localhost is exempt for development.
- **Request timeout**: All SDK HTTP calls default to a 10-second timeout (configurable via `timeoutMs`). Prevents indefinite hangs if the server is unreachable.
- **Input validation**: The SDK validates the login payload before sending: `agent_id` must match UUID format, `domain` must be non-empty (max 253 chars), `timestamp` must be finite and positive, `signature` must be non-empty. Invalid payloads throw `TypeError` immediately.
