import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const common = {
  version: '5.1.41',
  integrity: 'sha512-5bck8GFihuW6fBv28oNWLDtaK6XD1ZiNDfyf+DC1AekXUvC38TiSnpyCgSR72R8YO1g6lLV2KYnu8rBlQggqqA==',
  oldUrl: 'https://registry.npmjs.org/@koralabs/kora-labs-common/-/kora-labs-common-5.1.41.tgz',
  url: 'https://npm.pkg.github.com/download/@koralabs/kora-labs-common/5.1.41/51979cdcdf4b20ce8acc4669ffad241ed4200ad1',
};

export function validateVersions(manifests) {
  for (const [directory, name, version] of [
    ['kora-secrets-protocol', '@koralabs/kora-secrets-protocol', '1.0.0'],
    ['decentralized-minting', '@koralabs/handles-decentralized-minting', '3.0.1'],
    ['kora-secrets-crypto', '@koralabs/kora-secrets-crypto', '1.0.0'],
  ]) {
    assert.equal(manifests[directory]?.name, name, `${directory}: unexpected package`);
    assert.equal(manifests[directory]?.version, version, `${directory}: unexpected version`);
  }
}

export function resolveCommonArchive(lock) {
  const result = structuredClone(lock);
  const entry = result.packages['node_modules/@koralabs/kora-labs-common'];
  assert.equal(entry?.version, common.version, 'unexpected common version');
  assert.equal(entry?.integrity, common.integrity, 'unexpected common archive integrity');
  assert.ok([common.oldUrl, common.url].includes(entry.resolved), 'unexpected common distribution URL');
  entry.resolved = common.url;
  return result;
}

// Only an ephemeral sibling install input is changed, never its source or manifest.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = resolve(process.argv[2] ?? '.');
  const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
  validateVersions(Object.fromEntries(['kora-secrets-protocol', 'decentralized-minting', 'kora-secrets-crypto'].map(directory => [directory, readJson(resolve(root, directory, 'package.json'))])));
  const path = resolve(root, 'decentralized-minting/package-lock.json');
  writeFileSync(path, JSON.stringify(resolveCommonArchive(readJson(path)), null, 2) + '\n');
}
