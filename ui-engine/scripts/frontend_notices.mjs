import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DOCUMENT = '../docs/ui/engine/FrontendThirdPartyNotices.txt';
const ARTIFACT = 'dist/third-party-notices.txt';

function packageName(location) {
  return location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

function dependencyLocation(packages, parent, name, optional = false) {
  if (!/^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/.test(name)) {
    throw new Error(`Unsupported dependency name: ${name}`);
  }
  let directory = parent;
  while (true) {
    const candidate = path.posix.join(directory, 'node_modules', name);
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (!directory) break;
    directory = path.posix.dirname(directory);
    if (directory === '.') directory = '';
  }
  if (optional) return undefined;
  throw new Error(`Runtime dependency missing from lock: ${name} (${parent || 'root'})`);
}

/** Include the locked runtime dependency closure, including required peer dependencies. */
export function runtimePackages(lock, manifest) {
  if (lock.lockfileVersion !== 3 || !lock.packages?.['']) {
    throw new Error('Frontend notices require an npm lockfile v3');
  }
  const locked = lock.packages[''];
  for (const field of ['dependencies', 'optionalDependencies']) {
    const declared = Object.entries(manifest[field] ?? {}).sort();
    const recorded = Object.entries(locked[field] ?? {}).sort();
    if (JSON.stringify(declared) !== JSON.stringify(recorded)) {
      throw new Error(
        `Manifest and lock disagree about ${field}; run npm ci after updating the lock`,
      );
    }
  }
  const pending = [''];
  const found = new Set();
  while (pending.length) {
    const parent = pending.pop();
    const record = lock.packages[parent];
    const optional = record.optionalDependencies ?? {};
    const names = new Set([
      ...Object.keys(record.dependencies ?? {}),
      ...Object.keys(optional),
      ...Object.keys(record.peerDependencies ?? {}),
    ]);
    for (const name of names) {
      const location = dependencyLocation(
        lock.packages,
        parent,
        name,
        Object.hasOwn(optional, name) || record.peerDependenciesMeta?.[name]?.optional === true,
      );
      if (location && !found.has(location)) {
        found.add(location);
        pending.push(location);
      }
    }
  }
  return [...found].sort();
}

export async function renderNotices(root = ROOT) {
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
  const sections = [
    'TriageMate bundled frontend third-party notices\n\n' +
      'Generated from the locked runtime dependency closure. Each package retains its own license.\n' +
      'License texts below are copied verbatim from installed npm packages; build tools are excluded.\n',
  ];
  for (const location of runtimePackages(lock, manifest)) {
    const record = lock.packages[location];
    const name = packageName(location);
    const directory = path.join(root, location);
    const installed = JSON.parse(await readFile(path.join(directory, 'package.json'), 'utf8'));
    if (installed.name !== name || installed.version !== record.version) {
      throw new Error(`Installed package differs from lock: ${location}; restore with npm ci`);
    }
    if (record.license !== 'MIT' || installed.license !== 'MIT') {
      throw new Error(
        `Unreviewed frontend license for ${name}; update the notice policy before building`,
      );
    }
    const source = new URL(record.resolved);
    if (
      source.protocol !== 'https:' ||
      source.hostname !== 'registry.npmjs.org' ||
      source.username ||
      source.password ||
      source.search ||
      source.hash ||
      !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(record.integrity ?? '')
    ) {
      throw new Error(`Unreviewed frontend package source: ${name}`);
    }
    const licenses = (await readdir(directory))
      .filter((entry) => /^licen[cs]e(?:\.(?:txt|md))?$/i.test(entry))
      .sort();
    if (licenses.length !== 1) {
      throw new Error(
        `Expected one distributed license file for ${name}; found ${licenses.length}`,
      );
    }
    const license = await readFile(path.join(directory, licenses[0]), 'utf8');
    if (
      !/Copyright/i.test(license) ||
      !license.includes('Permission is hereby granted') ||
      !license.includes('THE SOFTWARE IS PROVIDED')
    ) {
      throw new Error(`Missing complete MIT copyright/license text for ${name}`);
    }
    sections.push(
      `\n${'='.repeat(72)}\n${name} ${record.version}\n` +
        `Locked package: ${location}\nSource: ${source.href}\n` +
        `Integrity: ${record.integrity}\nLicense: MIT (${licenses[0]})\n\n` +
        license +
        (license.endsWith('\n') ? '' : '\n'),
    );
  }
  return sections.join('');
}

export async function writeNotices(root = ROOT, { updateDocs = false, checkDocs = false } = {}) {
  const text = await renderNotices(root);
  const document = path.resolve(root, DOCUMENT);
  if (checkDocs) {
    if ((await readFile(document, 'utf8')) !== text) {
      throw new Error(
        'Frontend notices are stale; run npm run notices:update and review the result',
      );
    }
    return;
  }
  if (updateDocs) await writeFile(document, text);
  await mkdir(path.join(root, 'dist'), { recursive: true });
  await writeFile(path.join(root, ARTIFACT), text);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some((arg) => !['--update-docs', '--check-docs'].includes(arg))) {
    throw new Error('Usage: frontend_notices.mjs [--update-docs | --check-docs]');
  }
  await writeNotices(ROOT, {
    updateDocs: args.includes('--update-docs'),
    checkDocs: args.includes('--check-docs'),
  });
}
