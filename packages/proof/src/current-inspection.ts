/** Thin authenticated API adapter. The server evaluates trust and durable state. */
import { requestReport } from './api-client.js';

export interface CurrentInspectionRequest {
  target_id: string;
  credential_id: string;
  proof_json: string;
  public_signals: string[];
}

export interface CurrentInspectionReport {
  schema_version: 'clearproof-current-inspection-v1';
  scope: 'current-statement-inspection';
  authorization_consumed: false;
  assurance: 'development-unapproved';
  cryptographic_valid: boolean;
  manifest_digest: string;
  proof_profile: 'pilot-transfer-v2';
}

/** Send exact JSON bytes, preserving duplicate keys for authoritative server rejection.
 * The selected API is the trust boundary. This is not independent local verification.
 */
export async function inspectCurrentProof(
  origin: string, token: string, input: Uint8Array,
): Promise<CurrentInspectionReport> {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 16384) {
      throw new Error('Invalid inspection input');
    }
    const result = await requestReport(origin, token, '/pilot/proof/inspect', Buffer.from(input));
    const keys = ['schema_version', 'scope', 'authorization_consumed', 'assurance',
      'cryptographic_valid', 'manifest_digest', 'proof_profile'];
    if (Object.keys(result).length !== keys.length || keys.some(key => !(key in result)) ||
        result.schema_version !== 'clearproof-current-inspection-v1' ||
        result.scope !== 'current-statement-inspection' || result.authorization_consumed !== false ||
        result.assurance !== 'development-unapproved' || typeof result.cryptographic_valid !== 'boolean' ||
        typeof result.manifest_digest !== 'string' || !/^[0-9a-f]{64}$/.test(result.manifest_digest) ||
        result.proof_profile !== 'pilot-transfer-v2') throw new Error('Invalid inspection report');
    return result as unknown as CurrentInspectionReport;
  } catch {
    // Do not expose submitted proof values, bearer tokens, response bodies or URLs.
    throw new Error('Current proof inspection unavailable or rejected');
  }
}
