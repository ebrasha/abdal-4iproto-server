/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name : docusaurus.config.ts
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-13 16:21:05
 * Description : Docusaurus site configuration for Abdal 4iProto Server documentation
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Abdal 4iProto Server',
  tagline:
    'High-performance SSH tunneling server with advanced security, accounting, and traffic control',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://ebrasha.github.io',
  baseUrl: '/abdal-4iproto-server/',

  organizationName: 'ebrasha',
  projectName: 'abdal-4iproto-server',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/ebrasha/abdal-4iproto-server/tree/main/website/',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          editUrl:
            'https://github.com/ebrasha/abdal-4iproto-server/tree/main/website/',
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/docusaurus-social-card.jpg',
    metadata: [
      {
        name: 'description',
        content:
          'Official documentation for Abdal 4iProto Server — secure SSH tunneling, accounting, traffic monitoring, and multi-platform clients.',
      },
      {
        name: 'keywords',
        content:
          'Abdal, 4iProto, SSH tunnel, SOCKS5, security, accounting, traffic monitoring',
      },
    ],
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Abdal 4iProto Server',
      logo: {
        alt: 'Abdal 4iProto Server Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {to: '/blog', label: 'Blog', position: 'left'},
        {
          to: '/docs/support/programmer',
          label: 'Programmer',
          position: 'left',
        },
        {
          href: 'https://github.com/ebrasha/abdal-4iproto-server',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Introduction',
              to: '/docs/intro',
            },
            {
              label: 'Getting Started',
              to: '/docs/getting-started/requirements',
            },
            {
              label: 'Configuration',
              to: '/docs/configuration/server-config',
            },
            {
              label: 'Clients',
              to: '/docs/clients/overview',
            },
          ],
        },
        {
          title: 'Ecosystem',
          items: [
            {
              label: '4iProto CLI',
              href: 'https://github.com/ebrasha/abdal-4iproto-cli',
            },
            {
              label: 'Graphical Panel',
              href: 'https://github.com/ebrasha/abdal-4iproto-panel',
            },
            {
              label: 'Desktop Client',
              href: 'https://github.com/ebrasha/abdal-4iproto-client',
            },
            {
              label: 'Android Client',
              href: 'https://github.com/ebrasha/abdal-4iproto-client-android',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'X / Twitter',
              href: 'https://x.com/ProfShafiei',
            },
            {
              label: 'Telegram',
              href: 'https://t.me/ProfShafiei',
            },
            {
              label: 'LinkedIn',
              href: 'https://www.linkedin.com/in/profshafiei/',
            },
            {
              label: 'Donation',
              href: 'https://t.me/AbdalDonationBot',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Blog',
              to: '/blog',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/ebrasha/abdal-4iproto-server',
            },
            {
              label: 'Programmer',
              to: '/docs/support/programmer',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Abdal 4iProto Server — Handcrafted with Passion by Ebrahim Shafiei (EbraSha).`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json', 'powershell'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
