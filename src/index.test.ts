import assert from 'node:assert/strict';
import test from 'node:test';

import { SSR_PROTOCOL_PACKAGE } from './index.ts';

// Scaffold smoke test: the package surface loads and exposes its identity.
// Negative control: changing the exported package name breaks this assertion.
test('ssr-protocol package surface exposes its package name', () => {
  assert.equal(SSR_PROTOCOL_PACKAGE, '@koralabs/ssr-protocol');
});
