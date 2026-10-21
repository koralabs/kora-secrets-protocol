import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';

// yaml is already locked by the pinned sibling SDK; no test dependency is added.
const { parse } = createRequire(new URL('../../decentralized-minting/package.json', import.meta.url))('yaml');
const workflow = parse(readFileSync(new URL('../.github/workflows/deploy.yml', import.meta.url), 'utf8'));
const ciPaths = [
  '.github/workflows/pr-tests.yml',
  '.github/workflows/deploy.yml',
  'ci/prepare-library-builds.mjs',
  'ci/prepare-library-builds.test.mjs',
  'ci/publish-policy.test.mjs',
  'ci/README.md',
];

// Evaluate the narrow GitHub event/path-filter contract used by this workflow.
// No live source push or publication is performed by these policy tests.
function selected(config, event, files = []) {
  if (event === 'workflow_dispatch') return Object.hasOwn(config.on, event);
  if (event !== 'push' || !config.on.push?.branches?.includes('master')) return false;
  const ignored = config.on.push['paths-ignore'] ?? [];
  return files.some(path => !ignored.some(pattern => pattern === '**' || pattern === path));
}

function verifyPolicy(config) {
  assert.equal(selected(config, 'push', ciPaths), false, 'CI-only pushes must not publish');
  for (const path of ['src/index.ts', 'package.json', 'package-lock.json']) {
    assert.equal(selected(config, 'push', [path]), true, `${path} pushes must retain publication`);
    assert.equal(selected(config, 'push', [...ciPaths, path]), true, 'mixed source/CI pushes must retain publication');
  }
  assert.equal(selected(config, 'workflow_dispatch'), true, 'manual publication must remain available');
}

test('actual publication policy excludes only exact CI paths and retains source/package/manual events', () => {
  // Exclude pattern broadening: our selector intentionally covers exact paths, not arbitrary globs.
  assert.deepEqual(new Set(workflow.on.push['paths-ignore']), new Set(ciPaths));
  verifyPolicy(workflow);
});

test('negative control: missing CI exclusion fails the policy contract', () => {
  const broken = structuredClone(workflow);
  delete broken.on.push['paths-ignore'];
  assert.throws(() => verifyPolicy(broken), /CI-only pushes must not publish/);
});

test('negative control: blanket publication suppression fails source-push coverage', () => {
  const broken = structuredClone(workflow);
  broken.on.push['paths-ignore'] = ['**'];
  assert.throws(() => verifyPolicy(broken), /src\/index.ts pushes must retain publication/);
});

test('negative control: removing workflow_dispatch fails manual-publication coverage', () => {
  const broken = structuredClone(workflow);
  delete broken.on.workflow_dispatch;
  assert.throws(() => verifyPolicy(broken), /manual publication must remain available/);
});
