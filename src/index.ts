/**
 * @newtype-ai/sdk — Verify agent identity with one function call.
 *
 * Apps receive a login payload from an agent (via nit) and call
 * verifyAgent() to confirm the agent's identity. No crypto needed.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The login payload an agent sends to your app. */
export interface LoginPayload {
  agent_id: string;
  domain: string;
  timestamp: number;
  signature: string;
}

/** A skill listed in an agent's card. */
export interface AgentCardSkill {
  id: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
}

/** The agent's public identity card (A2A-compliant). */
export interface AgentCard {
  name: string;
  description?: string;
  version?: string;
  url?: string;
  provider?: { organization?: string; url?: string };
  capabilities?: Record<string, unknown>;
  skills: AgentCardSkill[];
  publicKey?: string;
}

/** Successful verification result. */
export interface VerifySuccess {
  verified: true;
  agent_id: string;
  domain: string;
  card: AgentCard | null;
}

/** Failed verification result. */
export interface VerifyFailure {
  verified: false;
  error: string;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export interface VerifyOptions {
  /** Override the API base URL. Defaults to https://api.newtype-ai.org */
  apiUrl?: string;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const DEFAULT_API_URL = 'https://api.newtype-ai.org';

/**
 * Verify an agent's login payload against the newtype-ai.org server.
 *
 * @example
 * ```ts
 * import { verifyAgent } from '@newtype-ai/sdk';
 *
 * const result = await verifyAgent(payload);
 * if (result.verified) {
 *   console.log(`Agent ${result.agent_id} verified`);
 *   console.log(`Card:`, result.card);
 * }
 * ```
 */
export async function verifyAgent(
  payload: LoginPayload,
  options?: VerifyOptions,
): Promise<VerifyResult> {
  const apiUrl = options?.apiUrl ?? DEFAULT_API_URL;

  const res = await fetch(`${apiUrl}/agent-card/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_id: payload.agent_id,
      domain: payload.domain,
      timestamp: payload.timestamp,
      signature: payload.signature,
    }),
  });

  return res.json() as Promise<VerifyResult>;
}
