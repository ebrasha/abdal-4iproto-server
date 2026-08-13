/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name : index.tsx
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-13 16:21:05
 * Description : Landing page for Abdal 4iProto Server documentation site
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import Heading from '@theme/Heading';

import styles from './index.module.css';

const PROGRAMMER_AVATAR = 'https://avatars.githubusercontent.com/u/9009001?v=4';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Read the Documentation
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            to="/docs/getting-started/installation-cli">
            Quick Install
          </Link>
        </div>
      </div>
    </header>
  );
}

function ProgrammerSpotlight(): ReactNode {
  return (
    <section className={styles.programmerSection}>
      <div className="container">
        <div className={styles.programmerInner}>
          <img
            src={PROGRAMMER_AVATAR}
            alt="Ebrahim Shafiei (EbraSha)"
            className={styles.programmerAvatar}
            width={120}
            height={120}
          />
          <div>
            <Heading as="h2">Handcrafted with Passion</Heading>
            <p>
              Built by <strong>Ebrahim Shafiei (EbraSha)</strong> — focused on
              cybersecurity, secure tunneling, and practical network tooling.
            </p>
            <div className={styles.programmerLinks}>
              <Link to="/docs/support/programmer">About the Programmer</Link>
              <a href="https://github.com/ebrasha" target="_blank" rel="noreferrer">
                GitHub
              </a>
              <a href="https://t.me/ProfShafiei" target="_blank" rel="noreferrer">
                Telegram
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} Docs`}
      description="Official documentation for Abdal 4iProto Server — secure SSH tunneling, accounting, and traffic control.">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <ProgrammerSpotlight />
      </main>
    </Layout>
  );
}
