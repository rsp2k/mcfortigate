// Custom OG-image renderer (satori) — 1200x630 cards in the site's graphite
// and ember palette. Plain createElement rather than JSX, because this module
// is imported by astro.config.mjs where there is no JSX transform.
import { createElement as h } from 'react';

const MARK = '.:|:.';

export function ogRenderer({ title, description }) {
  const cleanTitle = (title || 'mcfortigate').replace(/\s*\|\s*mcfortigate\s*$/, '');
  const isHome = cleanTitle === 'mcfortigate';
  const desc = (description || '').slice(0, 180);

  return h(
    'div',
    {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        backgroundColor: '#14181b',
        padding: '64px 72px',
        fontFamily: 'Inter',
      },
    },
    h(
      'div',
      { style: { display: 'flex', alignItems: 'center', gap: '18px' } },
      h('span', {
        style: {
          fontFamily: 'JetBrains Mono',
          fontSize: '34px',
          color: '#cf5a2a',
          letterSpacing: '0.08em',
        },
      }, MARK),
      h('span', {
        style: { fontFamily: 'JetBrains Mono', fontSize: '30px', color: '#858c94' },
      }, isHome ? 'FortiGate × MCP' : 'mcfortigate'),
    ),
    h(
      'div',
      { style: { display: 'flex', flexDirection: 'column', gap: '26px', maxWidth: '1000px' } },
      h('div', {
        style: {
          fontSize: isHome ? '96px' : '62px',
          fontWeight: 600,
          color: '#f5f6f7',
          lineHeight: 1.1,
          fontFamily: isHome ? 'JetBrains Mono' : 'Inter',
        },
      }, cleanTitle),
      desc
        ? h('div', {
            style: { fontSize: '30px', color: '#b7bcc2', lineHeight: 1.45 },
          }, desc)
        : null,
    ),
    // Footer: a read-only marker and the domain.
    h(
      'div',
      { style: { display: 'flex', alignItems: 'center', gap: '16px' } },
      h('div', {
        style: {
          display: 'flex',
          alignItems: 'center',
          padding: '6px 16px',
          borderRadius: '999px',
          border: '2px solid #cf5a2a',
          color: '#ffb08c',
          fontFamily: 'JetBrains Mono',
          fontSize: '24px',
        },
      }, 'read-only'),
      h('span', {
        style: { fontFamily: 'JetBrains Mono', fontSize: '28px', color: '#858c94' },
      }, 'mcfortigate.warehack.ing'),
    ),
  );
}
