/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name : index.tsx
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-13 16:21:05
 * Description : Homepage feature highlights for Abdal 4iProto Server
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

interface FeatureItem {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: ReactNode;
}

const FeatureList: FeatureItem[] = [
  {
    title: 'Secure by Design',
    Svg: require('@site/static/img/security.svg').default,
    description: (
      <>
        Protect connections through secure SSH tunneling with built-in brute
        force protection, automatic IP blocking, attack monitoring, and
        role-based access control.
      </>
    ),
  },
  {
    title: 'No Runtime Dependencies',
    Svg: require('@site/static/img/none_depen.svg').default,
    description: (
      <>
        Run the pre-built Abdal 4iProto Server without installing Go or external
        runtime packages. The CLI automatically prepares the required keys and
        configuration for you.
      </>
    ),
  },
  {
    title: 'Easy Installation',
    Svg: require('@site/static/img/easy_install.svg').default,
    description: (
      <>
        Deploy Abdal 4iProto effortlessly with the official CLI. It automatically
        detects your OS and architecture, verifies SHA-256 checksums, generates
        SSH keys, configures ports, installs persistent system services, and can
        install a graphical panel to manage users and full server settings.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
