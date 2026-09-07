/** Live retained-record discovery through an operator-selected API. */
import { requestReport } from './api-client.js';
import { validateObservationReport, type ObservationReport } from './observation.js';

export interface ObservationPageRequest { after?: string | null; limit?: number }
export interface ObservationPage {
  schema_version: 'clearproof-observation-page-v1';
  scope: 'live-retained-tenant-observations';
  order: 'observation-id-ascending';
  after: string | null;
  limit: number;
  observations: ObservationReport[];
  next_after: string | null;
}
const hex = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
function request(value: unknown): { after: string | null; limit: number } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid page request');
  const v = value as Record<string, unknown>;
  const after = v.after === undefined ? null : v.after;
  const limit = v.limit === undefined ? 32 : v.limit;
  if (Object.keys(v).some(k => !['after', 'limit'].includes(k)) || (after !== null && !hex(after)) ||
      typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > 64) throw new Error('Invalid page request');
  return { after: after as string | null, limit };
}
export function validateObservationPage(value: unknown, input: ObservationPageRequest): ObservationPage {
  const expected = request(input);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid page');
  const v = value as Record<string, unknown>;
  const keys = ['schema_version', 'scope', 'order', 'after', 'limit', 'observations', 'next_after'];
  if (Object.keys(v).length !== keys.length || keys.some(k => !(k in v)) ||
      v.schema_version !== 'clearproof-observation-page-v1' || v.scope !== 'live-retained-tenant-observations' ||
      v.order !== 'observation-id-ascending' || v.after !== expected.after || v.limit !== expected.limit ||
      !Array.isArray(v.observations) || v.observations.length > expected.limit) throw new Error('Invalid page');
  const observations = v.observations.map(validateObservationReport);
  let previous = expected.after ?? '';
  for (const observation of observations) {
    if (observation.observation_id <= previous || observation.tenant_id !== observations[0].tenant_id) {
      throw new Error('Invalid page order or tenant');
    }
    previous = observation.observation_id;
  }
  if (v.next_after !== null && (!hex(v.next_after) || observations.length !== expected.limit ||
      v.next_after !== previous)) throw new Error('Invalid page continuation');
  return value as ObservationPage;
}
export async function listObservations(origin: string, token: string, input: Uint8Array): Promise<ObservationPage> {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 1024) throw new Error('Invalid input');
    const parsed = JSON.parse(Buffer.from(input).toString('utf8'));
    request(parsed);
    return validateObservationPage(await requestReport(origin, token,
      '/pilot/proof/observations/list', Buffer.from(input)), parsed);
  } catch {
    throw new Error('Observation page unavailable or rejected');
  }
}
