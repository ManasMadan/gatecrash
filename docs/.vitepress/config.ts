import { defineConfig } from 'vitepress'

/**
 * The documentation site.
 *
 * Built by `.github/workflows/docs.yml` and served from GitHub Pages at
 * gatecrash.mmadan.in. The DNS is a CNAME in Cloudflare pointing at
 * manasmadan.github.io, and the CNAME file in `public/` is what tells Pages which
 * hostname to answer for.
 */
export default defineConfig({
  title: 'gatecrash',
  description:
    'Self-hosted, offline-first event ticketing — gates, dashboard, attendee wallet and ' +
    'BLE mesh chat from one Raspberry Pi, with no internet.',

  // Every page's last-updated line comes from git, which is why the docs workflow does a
  // full clone rather than a shallow one.
  lastUpdated: true,
  cleanUrls: true,

  // A build that ships broken links is a documentation site nobody trusts, and the ones
  // that break are always the ones pointing at a renamed page.
  ignoreDeadLinks: false,

  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['meta', { name: 'theme-color', content: '#0b0d12' }],
    ['meta', { property: 'og:title', content: 'gatecrash' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'An entire event from one Raspberry Pi, with no internet.',
      },
    ],
  ],

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/what-it-is' },
      { text: 'Reference', link: '/reference/cli' },
      {
        text: 'v0.1.0',
        items: [
          { text: 'Releases', link: 'https://github.com/ManasMadan/gatecrash/releases' },
          {
            text: 'Decisions',
            link: 'https://github.com/ManasMadan/gatecrash/blob/master/DECISIONS.md',
          },
          {
            text: 'Guarantees',
            link: 'https://github.com/ManasMadan/gatecrash/blob/master/DELIVERY-GUARANTEES.md',
          },
        ],
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting started',
          items: [
            { text: 'What it is', link: '/guide/what-it-is' },
            { text: 'Try it in one command', link: '/guide/try-it' },
            { text: 'Running an event', link: '/guide/running-an-event' },
          ],
        },
        {
          text: 'The venue',
          items: [
            { text: 'Zones, seats and doors', link: '/guide/venue' },
            { text: 'Wayfinding', link: '/guide/wayfinding' },
          ],
        },
        {
          text: 'At the gate',
          items: [
            { text: 'How a scan is decided', link: '/guide/scanning' },
            { text: 'When the box is unreachable', link: '/guide/offline' },
            { text: 'Incidents and staffing', link: '/guide/incidents' },
          ],
        },
        {
          text: 'Backstage',
          items: [
            { text: 'Mesh chat', link: '/guide/mesh' },
            { text: 'The phone apps', link: '/guide/apps' },
            { text: 'The protocol', link: '/guide/mesh-protocol' },
          ],
        },
        {
          text: 'Operating it',
          items: [
            { text: 'Deploying a box', link: '/guide/deploying' },
            { text: 'After the event', link: '/guide/settlement' },
            { text: 'Correctness', link: '/guide/correctness' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Command line', link: '/reference/cli' },
            { text: 'Configuration', link: '/reference/config' },
            { text: 'Verdicts', link: '/reference/verdicts' },
            { text: 'HTTP API', link: '/reference/http-api' },
            { text: 'Venue plan', link: '/reference/venue-plan' },
            { text: 'Packages', link: '/reference/packages' },
          ],
        },
      ],
    },

    socialLinks: [{ icon: 'github', link: 'https://github.com/ManasMadan/gatecrash' }],

    editLink: {
      pattern: 'https://github.com/ManasMadan/gatecrash/edit/master/docs/:path',
      text: 'Improve this page',
    },

    search: { provider: 'local' },

    footer: {
      message: 'MIT licensed.',
      copyright: 'Built by Manas Madan.',
    },
  },
})
