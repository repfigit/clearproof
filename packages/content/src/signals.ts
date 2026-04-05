import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { CONTENT_DIR } from './parser.js';

export interface Signal {
  index: number;
  name: string;
  type: string;
  description: string;
  source: string;
  onChainUsage: string;
  isOutput: boolean;
}

interface SignalsFile {
  signals: Signal[];
}

/**
 * Read and parse the signals.yaml file.
 */
function loadSignals(): Signal[] {
  const filePath = resolve(CONTENT_DIR, 'signals.yaml');
  const raw = readFileSync(filePath, 'utf-8');
  const data = yaml.load(raw) as SignalsFile;
  return data.signals ?? [];
}

/**
 * List all 16 public circuit signals.
 */
export function listSignals(): Signal[] {
  return loadSignals();
}

/**
 * Get a single signal by name.
 */
export function getSignal(name: string): Signal | null {
  const signals = loadSignals();
  return signals.find((s) => s.name === name) ?? null;
}
