// @ts-check
import * as fs from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import opengraphImages from 'astro-opengraph-images';
import { ogRenderer } from './src/og/renderer.mjs';

// Set only in the dev container, where it carries the external hostname so the
// HMR websocket survives the TLS-terminating Caddy sitting in front.
const domain = process.env.DOMAIN;

/**
 * Wrap every markdown table in a scrollable div.
 *
 * The reference pages carry four-column argument tables whose natural minimum
 * width is around 460px. At phone width they overflow the content column, and
 * because nothing up the tree scrolls, the last column is simply unreachable —
 * the Meaning column vanishes off the right edge with no way to get to it.
 *
 * tabindex="0" is the part that matters for accessibility: a scrollable region
 * has to be reachable by keyboard, not only by touch or trackpad.
 */
function rehypeScrollableTables() {
  return (tree) => {
    const walk = (node) => {
      if (!Array.isArray(node.children)) return;
      node.children = node.children.map((child) => {
        walk(child);
        if (child.type === 'element' && child.tagName === 'table') {
          return {
            type: 'element',
            tagName: 'div',
            properties: { className: ['table-scroll'], tabIndex: 0 },
            children: [child],
          };
        }
        return child;
      });
    };
    walk(tree);
  };
}

export default defineConfig({
  site: 'https://mcfortigate.warehack.ing',
  telemetry: false,
  devToolbar: { enabled: false },
  markdown: {
    rehypePlugins: [rehypeScrollableTables],
  },
  vite: domain
    ? {
        server: {
          host: '0.0.0.0',
          hmr: { host: domain, protocol: 'wss', clientPort: 443 },
        },
      }
    : {},
  integrations: [
    starlight({
      title: 'mcfortigate',
      description:
        'A read-only MCP server for FortiGate firewalls. Question-shaped tools ' +
        'for policies, objects, routing, and live client state.',
      social: [
        { icon: 'seti:python', label: 'PyPI', href: 'https://pypi.org/project/mcfortigate/' },
        { icon: 'github', label: 'GitHub', href: 'https://github.com/rsp2k/mcfortigate' },
      ],
      customCss: ['./src/styles/custom.css'],
      components: {
        Footer: './src/components/Footer.astro',
        Head: './src/components/Head.astro',
      },
      plugins: [
        starlightLinksValidator(),
        starlightLlmsTxt({
          projectName: 'mcfortigate',
          description:
            'Read-only MCP server for FortiGate / FortiOS. Seventeen tools shaped ' +
            'around the questions operators ask — what is this device, what ' +
            'references this object, what does the ruleset actually allow — ' +
            'rather than around the REST endpoints FortiOS happens to expose.',
        }),
      ],
      sidebar: [
        {
          label: 'Tutorials',
          items: [
            { slug: 'tutorials/getting-started' },
            { slug: 'tutorials/first-questions' },
          ],
        },
        {
          label: 'How-to guides',
          items: [
            { slug: 'guides/claude-code' },
            { slug: 'guides/several-appliances' },
            { slug: 'guides/find-a-device' },
            { slug: 'guides/before-you-delete' },
            { slug: 'guides/read-a-ruleset' },
            { slug: 'guides/troubleshooting' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'reference/tools' },
            { slug: 'reference/configuration' },
            { slug: 'reference/response-shapes' },
            { slug: 'reference/fortios-endpoints' },
          ],
        },
        {
          label: 'Explanation',
          items: [
            { slug: 'explanation/question-shaped-tools' },
            { slug: 'explanation/config-vs-live' },
            { slug: 'explanation/fortios-quirks' },
            { slug: 'explanation/read-only' },
          ],
        },
      ],
    }),
    opengraphImages({
      options: {
        fonts: [
          {
            name: 'Inter',
            weight: 400,
            style: 'normal',
            data: fs.readFileSync(
              'node_modules/@fontsource/inter/files/inter-latin-400-normal.woff',
            ),
          },
          {
            name: 'Inter',
            weight: 600,
            style: 'normal',
            data: fs.readFileSync(
              'node_modules/@fontsource/inter/files/inter-latin-600-normal.woff',
            ),
          },
          {
            name: 'JetBrains Mono',
            weight: 400,
            style: 'normal',
            data: fs.readFileSync(
              'node_modules/@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff',
            ),
          },
        ],
      },
      render: ogRenderer,
    }),
  ],
});
