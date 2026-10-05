/** Public documentation inventory: metadata and sitemap share the same routes. */
export const DOCUMENTATION_PAGES = [
  { path: '/', title: 'clearproof', description: 'Development pilot for private transfer evidence: current release, documentation and assurance limits.' },
  { path: '/docs', title: 'Introduction', description: 'Clearproof components, intended evaluation workflows and current interoperability limits.' },
  { path: '/docs/status', title: 'Project status', description: 'Published release, implemented pilot capabilities, software capacity and open adoption and assurance gates.' },
  { path: '/docs/quickstart', title: 'Quick start', description: 'Install Clearproof and evaluate synthetic evidence or the complete local pilot with development artifacts.' },
  { path: '/docs/architecture', title: 'Architecture', description: 'How authenticated inputs, proofs, policy, encrypted information and authorization fit together.' },
  { path: '/docs/system-diagram', title: 'System diagram', description: 'The pilot transfer workflow and its separate proof, authorization and observation state tracks.' },
  { path: '/docs/circuits', title: 'Circuits', description: 'The current eight-signal pilot-transfer-v3 circuit, tree depths, public bindings and development setup.' },
  { path: '/docs/contracts', title: 'Smart contracts', description: 'Pilot verifier and receipt-mirror contracts, historical legacy deployments and contract development.' },
  { path: '/docs/api', title: 'API reference', description: 'Authenticated pilot API routes, wallet ownership extensions, shared services and operational limits.' },
  { path: '/docs/sdk', title: 'TypeScript SDK', description: 'Current pilot SDK generation and verification, API discovery, artifact requirements and privacy boundaries.' },
  { path: '/docs/cli', title: 'CLI', description: 'Install the Clearproof CLI, inspect evidence and run pilot commands or the synthetic legacy demonstration.' },
  { path: '/docs/sanctions', title: 'Sanctions roots', description: 'Pilot sanctions tree construction, publisher trust, source freshness and legacy oracle operations.' },
  { path: '/docs/deployment', title: 'Development deployment', description: 'Configure and validate a source-based development deployment and sanctions publication workflow.' },
  { path: '/docs/gdpr', title: 'Privacy and data minimization', description: 'What proofs and encryption protect, what remains visible and questions for deployment review.' },
  { path: '/docs/security', title: 'Security and assurance', description: 'Current security boundaries, deployment controls, development key limitations and private vulnerability reporting.' },
  { path: '/docs/contributing', title: 'Contributing', description: 'Set up the locked monorepo, run appropriate checks and contribute reproducible changes.' },
  { path: '/docs/report-issues', title: 'Report an issue', description: 'Report reproducible defects safely, use the CLI report helper and handle security vulnerabilities privately.' },
] as const;

export function documentationMetadata(path: string) {
  const page = DOCUMENTATION_PAGES.find(page => page.path === path);
  if (!page) throw new Error(`Unknown documentation route: ${path}`);
  return { title: page.title, description: page.description, alternates: { canonical: page.path } };
}
