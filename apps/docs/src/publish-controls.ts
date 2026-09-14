/**
 * Publication controls for the clearproof docs site (CP-BOT-04).
 *
 * A single repository-level switch gates every rendered publication surface:
 * the RSS feed, the sitemap, the /updates and /explainers indexes, their
 * detail pages and the JSON content API. When paused, the surfaces still
 * respond (so caches do not start returning errors), but they render only
 * the pause notice — no draft, scheduled or previously approved item leaks
 * through any route while the switch is off.
 */

/** Reads the pause switch. Set PUBLISHING_ENABLED=false (or 0/off) to pause. */
export function publishingEnabled(): boolean {
  const raw = process.env.PUBLISHING_ENABLED;
  if (raw === undefined || raw === '') return true;
  return !['false', '0', 'off'].includes(raw.trim().toLowerCase());
}

const PAUSE_NOTICE =
  'Publication is temporarily paused. Previously published items may still be ' +
  'visible in cached copies and RSS readers.';

export function pauseNotice(): string {
  return PAUSE_NOTICE;
}

/** JSON payload returned by content API routes while publication is paused. */
export function pausedJson(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { paused: true, message: PAUSE_NOTICE, ...extra };
}
