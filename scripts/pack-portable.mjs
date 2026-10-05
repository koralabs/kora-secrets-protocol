// Freshly compile a portable package; public SDK/crypto class identity belongs to consumer peers.
import { mkdtemp, mkdir, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
if (!process.env.npm_execpath) throw new Error('Run via npm run pack:portable');
const root = resolve(import.meta.dirname, '..');
const destination = resolve(process.argv[2] ?? root);
await mkdir(destination, { recursive: true });
const stage = await mkdtemp(join(tmpdir(), 'kora-protocol-pack-'));
try {
  for (const name of ['vendor', 'README.md']) await cp(join(root, name), join(stage, name), { recursive: true });
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(root, 'tsconfig.json'), '--outDir', join(stage, 'lib')], { cwd: root, stdio: 'inherit' });
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  delete manifest.devDependencies;
  delete manifest.scripts;
  await writeFile(join(stage, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
  const provenance = JSON.parse(await readFile(join(root, 'vendor/PROVENANCE.json'), 'utf8'));
  for (const artifact of provenance.artifacts) {
    const path = join(root, artifact.path);
    if (createHash('sha256').update(await readFile(path)).digest('hex') !== artifact.sha256) throw new Error(`Vendor integrity mismatch: ${artifact.package}`);

  }
  const result = execFileSync(process.execPath, [process.env.npm_execpath, 'pack', '--ignore-scripts', '--json', '--pack-destination', destination], { cwd: stage, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  const packed = JSON.parse(result)[0];
  process.stdout.write(JSON.stringify({ filename: packed.filename, size: packed.size, integrity: packed.integrity, bundled: packed.bundled, fileCount: packed.files.length }) + '\n');
} finally {
  await rm(stage, { recursive: true, force: true });
}
