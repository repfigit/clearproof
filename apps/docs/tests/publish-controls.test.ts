import { afterEach, describe, expect, it } from 'vitest';
import type { Update } from '@clearproof/content';
import { buildFeedXml, buildSitemapXml, gatedVisible, visibleUpdates } from '../src/feed';
import { pauseNotice, pausedJson, publishingEnabled } from '../src/publish-controls';

const NOW = new Date('2026-09-14T12:00:00Z');

function update(): Update {
  return {
    id: 'UP-P',
    slug: 'paused-update',
    title: 'Paused update',
    date: '2026-09-14',
    publishAfter: '2026-09-14T00:00:00Z',
    sourceCommit: 'abc123',
    claimRefs: ['docs/ADOPTION_ROADMAP.md'],
    status: 'approved',
    summary: 'Should not render while paused',
    body: 'Body paragraph.',
  };
}

const ENV_KEYS = ['PUBLISHING_ENABLED'] as const;

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
});

describe('publishingEnabled', () => {
  it('defaults to enabled when the switch is unset', () => {
    expect(publishingEnabled()).toBe(true);
  });

  it('is enabled for values other than false/0/off', () => {
    for (const value of ['true', '1', 'on', 'yes']) {
      process.env.PUBLISHING_ENABLED = value;
      expect(publishingEnabled()).toBe(true);
    }
  });

  it('is disabled for false/0/off in any case or with whitespace', () => {
    for (const value of ['false', 'False', '0', 'off', ' OFF ']) {
      process.env.PUBLISHING_ENABLED = value;
      expect(publishingEnabled()).toBe(false);
    }
  });
});

describe('gatedVisible', () => {
  it('passes visible items through while publishing is enabled', () => {
    const items = visibleUpdates([update()], NOW);
    expect(gatedVisible(items)).toHaveLength(1);
  });

  it('suppresses every item while publishing is paused', () => {
    process.env.PUBLISHING_ENABLED = 'false';
    expect(gatedVisible(visibleUpdates([update()], NOW))).toEqual([]);
  });
});

describe('pause behavior in rendered surfaces', () => {
  it('renders an empty feed channel while paused', () => {
    process.env.PUBLISHING_ENABLED = 'false';
    const xml = buildFeedXml([update()], NOW);
    expect(xml).toContain('<rss version="2.0"');
    expect(xml).not.toContain('<item>');
    expect(xml).not.toContain('Paused update');
  });

  it('omits update URLs from the sitemap while paused', () => {
    process.env.PUBLISHING_ENABLED = 'false';
    const xml = buildSitemapXml([update()], NOW);
    expect(xml).toContain('<loc>https://docs.clearproof.world/</loc>');
    expect(xml).not.toContain('/updates/paused-update');
  });

  it('does not affect rendered output once the switch is back on', () => {
    process.env.PUBLISHING_ENABLED = 'false';
    expect(buildFeedXml([update()], NOW)).not.toContain('<item>');
    delete process.env.PUBLISHING_ENABLED;
    const xml = buildFeedXml([update()], NOW);
    expect((xml.match(/<item>/g) ?? []).length).toBe(1);
    expect(xml).toContain('Paused update');
  });
});

describe('pause notices', () => {
  it('exposes a stable notice string and JSON payload', () => {
    expect(pauseNotice()).toContain('temporarily paused');
    expect(pausedJson({ kept: 1 })).toEqual({ paused: true, message: pauseNotice(), kept: 1 });
  });
});
