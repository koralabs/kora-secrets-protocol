import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveCommonArchive, validateVersions } from './prepare-library-builds.mjs';

const original = () => ({
  lockfileVersion: 3,
  packages: {
    '': { name: '@koralabs/handles-decentralized-minting', version: '3.0.1' },
    'node_modules/@koralabs/kora-labs-common': {
      version: '5.1.41',
      integrity: 'sha512-5bck8GFihuW6fBv28oNWLDtaK6XD1ZiNDfyf+DC1AekXUvC38TiSnpyCgSR72R8YO1g6lLV2KYnu8rBlQggqqA==',
      resolved: 'https://registry.npmjs.org/@koralabs/kora-labs-common/-/kora-labs-common-5.1.41.tgz',
      dependencies: { cbor: '^9.0.2' },
    },
    'node_modules/other': { version: '2.0.0', integrity: 'unchanged', resolved: 'https://registry.npmjs.org/other' },
  },
});
const key = 'node_modules/@koralabs/kora-labs-common';

test('corrects only the distribution URL, preserving every other locked field and its input', () => {
  const input = original();
  const result = resolveCommonArchive(input);
  assert.equal(result.packages[key].resolved, 'https://npm.pkg.github.com/download/@koralabs/kora-labs-common/5.1.41/51979cdcdf4b20ce8acc4669ffad241ed4200ad1');
  result.packages[key].resolved = input.packages[key].resolved;
  assert.deepEqual(result, original());
  assert.deepEqual(input, original());
});

test('already-corrected immutable inputs remain unchanged', () => {
  const once = resolveCommonArchive(original());
  assert.deepEqual(resolveCommonArchive(once), once);
});

for (const [field, value] of [['version', '5.1.40'], ['integrity', 'sha512-wrong'], ['resolved', 'https://untrusted.invalid/archive']]) {
  test(`rejects a different ${field} rather than silently changing dependency identity`, () => {
    const lock = original();
    lock.packages[key][field] = value;
    assert.throws(() => resolveCommonArchive(lock));
    assert.equal(lock.packages[key][field], value);
  });
}

test('rejects a missing archive instead of inventing a lock entry', () => {
  const lock = original();
  delete lock.packages[key];
  assert.throws(() => resolveCommonArchive(lock), /unexpected common version/);
});

test('accepts exact source versions and rejects a mismatched sibling build', () => {
  const manifests = {
    'kora-secrets-protocol': { name: '@koralabs/kora-secrets-protocol', version: '1.0.0' },
    'decentralized-minting': { name: '@koralabs/handles-decentralized-minting', version: '3.0.1' },
    'kora-secrets-crypto': { name: '@koralabs/kora-secrets-crypto', version: '1.0.0' },
  };
  validateVersions(manifests);
  manifests['decentralized-minting'].version = '4.0.0';
  assert.throws(() => validateVersions(manifests), /unexpected version/);
});
