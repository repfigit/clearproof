/** Shape checks for JSON files the CLI reads from disk, applied before anything reaches the SDK. */
import type { ComplianceInput } from '@clearproof/proof';

type FieldKind = 'string' | 'number' | 'string[]';
const REQUIRED: Record<string, FieldKind> = {
  sanctionsTreeRoot: 'string', issuerTreeRoot: 'string', amountTier: 'number', transferTimestamp: 'number',
  jurisdictionCode: 'number', credentialCommitment: 'string', tier2Threshold: 'number', tier3Threshold: 'number',
  tier4Threshold: 'number', credentialNullifier: 'string', proofExpiresAt: 'number', issuerDid: 'string',
  kycTier: 'number', sanctionsClear: 'number', issuedAt: 'number', expiresAt: 'number',
  issuerPathElements: 'string[]', issuerPathIndices: 'string[]', walletAddressHash: 'string', leftKey: 'string',
  rightKey: 'string', leftPathElements: 'string[]', leftPathIndices: 'string[]', rightPathElements: 'string[]',
  rightPathIndices: 'string[]', actualAmount: 'number',
};
const OPTIONAL: Record<string, FieldKind> = {
  domainChainId: 'number', domainContractHash: 'string', transferIdHash: 'string',
};

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const matches = (v: unknown, kind: FieldKind) => kind === 'string[]'
  ? Array.isArray(v) && v.every(e => typeof e === 'string')
  : typeof v === kind && (kind !== 'number' || Number.isFinite(v));

function parseJson(text: string, label: string): unknown {
  try { return JSON.parse(text); }
  catch (error) { throw new Error(`${label} is not valid JSON: ${(error as Error).message}`); }
}

/** Parse a legacy-profile input file. Every required field must be present with its type; unknown keys are rejected. */
export function parseComplianceInput(text: string): ComplianceInput {
  const value = parseJson(text, 'Input file');
  if (!isObject(value)) throw new Error('Input file must contain a JSON object of ComplianceInput fields');
  const problems: string[] = [];
  for (const [key, kind] of Object.entries(REQUIRED)) {
    if (!(key in value)) problems.push(`missing ${key}`);
    else if (!matches(value[key], kind)) problems.push(`${key} must be ${kind}`);
  }
  for (const [key, kind] of Object.entries(OPTIONAL)) {
    if (key in value && !matches(value[key], kind)) problems.push(`${key} must be ${kind}`);
  }
  for (const key of Object.keys(value)) {
    if (!(key in REQUIRED) && !(key in OPTIONAL)) problems.push(`unknown field ${key}`);
  }
  if (problems.length) throw new Error(`Invalid input file: ${problems.join('; ')}`);
  return value as unknown as ComplianceInput;
}

/** Parse a proof file written by `clearproof prove`: a proof object and an array of public signal strings. */
export function parseProofFile(text: string): { proof: object; publicSignals: string[] } {
  const value = parseJson(text, 'Proof file');
  if (!isObject(value) || !isObject(value.proof)) throw new Error('Proof file must contain a "proof" object');
  if (!matches(value.publicSignals, 'string[]')) throw new Error('Proof file must contain a "publicSignals" array of strings');
  return { proof: value.proof, publicSignals: value.publicSignals as string[] };
}
