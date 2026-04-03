import { Footer, Layout, Navbar } from 'nextra-theme-docs';
import { Head } from 'nextra/components';
import { getPageMap } from 'nextra/page-map';
import 'nextra-theme-docs/style.css';

export const metadata = {
  title: {
    template: '%s | clearproof docs',
    default: 'clearproof docs',
  },
  description:
    'Documentation for clearproof — ZK infrastructure for compliant value transfer.',
};

const navbar = (
  <Navbar
    logo={
      <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700 }}>
        <img src="/logo.png" alt="" width={28} height={28} />
        <span>clear<span
          style={{
            background: 'linear-gradient(to right, #6366f1, #06b6d4)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >proof</span></span>
      </span>
    }
    projectLink="https://github.com/clearproof/clearproof"
  >
    <a href="https://clearproof.world" style={{ fontSize: '0.875rem' }}>
      clearproof.world
    </a>
  </Navbar>
);

const footer = (
  <Footer>
    Apache-2.0 {new Date().getFullYear()} © clearproof contributors
  </Footer>
);

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <Layout
          navbar={navbar}
          pageMap={await getPageMap()}
          docsRepositoryBase="https://github.com/clearproof/clearproof/tree/main/apps/docs"
          footer={footer}
        >
          {children}
        </Layout>
      </body>
    </html>
  );
}
