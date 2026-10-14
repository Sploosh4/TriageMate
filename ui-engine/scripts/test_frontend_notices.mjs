import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { renderNotices, runtimePackages, writeNotices } from './frontend_notices.mjs';

const LICENSE =
  'MIT License\r\n\r\nCopyright 2026 Synthetic fixture\r\n' +
  'Permission is hereby granted, free of charge, to any person obtaining a copy\r\n' +
  'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.\r\n';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'triagemate-notices-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { component: '1.0.0' } },
      'node_modules/component': {
        version: '1.0.0',
        license: 'MIT',
        resolved: 'https://registry.npmjs.org/component/-/component-1.0.0.tgz',
        integrity: 'sha512-c3ludGhldGlj',
        dependencies: { helper: '1.0.0' },
        peerDependencies: { peer: '1.0.0' },
      },
      'node_modules/component/node_modules/helper': {
        version: '1.0.0',
        license: 'MIT',
        resolved: 'https://registry.npmjs.org/helper/-/helper-1.0.0.tgz',
        integrity: 'sha512-c3ludGhldGlj',
      },
      'node_modules/peer': {
        version: '1.0.0',
        license: 'MIT',
        resolved: 'https://registry.npmjs.org/peer/-/peer-1.0.0.tgz',
        integrity: 'sha512-c3ludGhldGlj',
      },
      'node_modules/build-tool': { dev: true, license: 'unreviewed' },
    },
  };
  for (const [location, record] of Object.entries(lock.packages)) {
    if (!location || record.dev) continue;
    const directory = path.join(root, location);
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, 'package.json'),
      JSON.stringify({ name: location.split('node_modules/').at(-1), ...record }),
    );
    await writeFile(path.join(directory, 'LICENSE'), LICENSE);
  }
  const manifest = { dependencies: { component: '1.0.0' } };
  await writeFile(path.join(root, 'package.json'), JSON.stringify(manifest));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify(lock));
  return { root, lock, manifest };
}

test('deterministic notices retain exact license bytes, transitive packages and peers', async (t) => {
  const { root, lock, manifest } = await fixture(t);
  assert.deepEqual(runtimePackages(lock, manifest), [
    'node_modules/component',
    'node_modules/component/node_modules/helper',
    'node_modules/peer',
  ]);
  const text = await renderNotices(root);
  assert.equal(await renderNotices(root), text);
  assert.equal(text.split(LICENSE).length - 1, 3);
  assert(!text.includes('build-tool'));
  await writeNotices(root);
  assert.equal(await readFile(path.join(root, 'dist/third-party-notices.txt'), 'utf8'), text);
});

test('unlocked or missing required packages fail before notices are published', async (t) => {
  const { root, lock, manifest } = await fixture(t);
  assert.throws(() => runtimePackages(lock, { dependencies: {} }), /Manifest and lock disagree/);
  delete lock.packages['node_modules/peer'];
  assert.throws(() => runtimePackages(lock, manifest), /Runtime dependency missing from lock/);
  await rm(path.join(root, 'node_modules/component/package.json'));
  await assert.rejects(renderNotices(root), /ENOENT/);
});

test('changed installed versions and missing license files fail', async (t) => {
  const { root } = await fixture(t);
  const installed = path.join(root, 'node_modules/component/package.json');
  const manifest = JSON.parse(await readFile(installed, 'utf8'));
  await writeFile(installed, JSON.stringify({ ...manifest, version: '2.0.0' }));
  await assert.rejects(renderNotices(root), /Installed package differs from lock/);
  await writeFile(installed, JSON.stringify(manifest));
  await rm(path.join(root, 'node_modules/component/LICENSE'));
  await assert.rejects(renderNotices(root), /Expected one distributed license file/);
});

test('new license policies and incomplete MIT text require review', async (t) => {
  const { root } = await fixture(t);
  const installed = path.join(root, 'node_modules/component/package.json');
  const manifest = JSON.parse(await readFile(installed, 'utf8'));
  await writeFile(installed, JSON.stringify({ ...manifest, license: 'GPL-3.0-only' }));
  await assert.rejects(renderNotices(root), /Unreviewed frontend license/);
  await writeFile(installed, JSON.stringify(manifest));
  await writeFile(path.join(root, 'node_modules/component/LICENSE'), 'MIT License');
  await assert.rejects(renderNotices(root), /Missing complete MIT copyright/);
});

test('nonregistry package provenance fails explicitly', async (t) => {
  const { root, lock } = await fixture(t);
  lock.packages['node_modules/component'].resolved = 'https://example.invalid/component.tgz';
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify(lock));
  await assert.rejects(renderNotices(root), /Unreviewed frontend package source/);
});

test('checked-in notices match the installed locked runtime packages', async () => {
  await writeNotices(undefined, { checkDocs: true });
});
