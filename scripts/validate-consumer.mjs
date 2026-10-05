import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
const consumer = resolve(process.argv[2] ?? '.');
const requireConsumer = createRequire(join(consumer, 'package.json'));
const protocolPath = requireConsumer.resolve('@koralabs/kora-secrets-protocol');
const requireProtocol = createRequire(protocolPath);
for (const name of ['@koralabs/kora-secrets-crypto', '@koralabs/handles-decentralized-minting']) {
  assert.equal(requireProtocol.resolve(name), requireConsumer.resolve(name), `${name} must have one shared instance`);
}
const protocol = await import(pathToFileURL(protocolPath));
const chain = await import(pathToFileURL(requireConsumer.resolve('@koralabs/kora-secrets-protocol/chain')));
const crypto = await import(pathToFileURL(requireConsumer.resolve('@koralabs/kora-secrets-crypto')));
const sdk = await import(pathToFileURL(requireConsumer.resolve('@koralabs/handles-decentralized-minting')));
assert.equal(typeof sdk.prepareLabelAssetsTransaction, 'function');
const session = crypto.newRecoverySession({ session_id: 'cafebabe' });
const artifact = crypto.reencryptShareToSession(Uint8Array.from([1, 2, 3]), session.recovery_pub, {
  policy_id: 'f0f06f776e6572', session_id: session.session_id, guardian_id: 'aa01'
});
assert.throws(() => protocol.validateApprovalArtifact(artifact, {
  policy_ref: { owner_handle_asset_id: 'f0f06f776e6572', policy_nonce: 0 }, session_id: 'deadbeef'
}), error => crypto.isSsrError(error, crypto.SsrErrorCode.SessionMismatch));
const root = '583981b7af47e5bd20ad91cd26e0ffdb52898211d95c8b95e7d18272408d835b';
const boundary = async input => {
  const url = new URL(String(input));
  assert.equal(url.origin, 'https://preview.api.handle.me');
  if (url.pathname === '/handles') return new Response('alpha\nbeta\n', { headers: { 'x-handles-search-total': '2' } });
  if (url.pathname === '/mpt-root/registry-labels') return Response.json({ network: 'preview', current_root: root, count: 1, labels: { beta: '00003090' } });
  if (url.pathname === '/handles/handle_root@handle_settings/datum') return Response.json({ constructor_0: ['0x' + root] });
  throw new Error('Unexpected request');
};
const result = await chain.reconstructRegistryTrie('preview', 'package-consumer-check', boundary);
assert.equal(result.rootHex, root);
assert.equal((await result.trie.get('beta')).toString('hex'), '00003090');
const proof = await result.trie.prove('beta');
assert.equal(proof.verify(true, Buffer.from('beta')).toString('hex'), root);
assert.ok(proof.toCBOR().length > 0);
console.log(JSON.stringify({ sharedCryptoAndSdk: true, crossPackageSsrError: true, labelMintApi: true, goldenRootAndProof: true }));
