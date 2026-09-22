import {readFile, writeFile} from 'node:fs/promises';
import {downloadCatalog, validateCatalog} from './catalog.mjs';

const root = new URL('../', import.meta.url);
const previous = validateCatalog(JSON.parse(await readFile(new URL('data/catalog.json', root), 'utf8')));
const next = await downloadCatalog(previous, fetch, {mirror:true, conditional:false});
const serialized = JSON.stringify(next).replaceAll('<', '\\u003c');
const pages = [];
for (const name of ['index.html', 'nmap-command-lab.html']) {
  const url = new URL(name, root);
  const html = await readFile(url, 'utf8');
  const marker = /const EMBEDDED_CATALOG=([^\r\n]+);/g;
  const matches = [...html.matchAll(marker)];
  if (matches.length !== 1) throw new Error('Expected exactly one embedded catalog in ' + name);
  const updated = html.replace(marker, () => 'const EMBEDDED_CATALOG=' + serialized + ';');
  pages.push([url, updated]);
}
// Validate every source and page before replacing any local snapshot.
await writeFile(new URL('data/catalog.json', root), JSON.stringify(next, null, 2) + '\n');
for (const [url, html] of pages) await writeFile(url, html);
console.log('Updated both pages: Nmap ' + next.version + ', ' + next.options.length + ' options, ' + next.scripts.length + ' NSE scripts. Checked ' + next.checkedAt);
