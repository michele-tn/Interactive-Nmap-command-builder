export const SOURCES = {
  reference: 'https://svn.nmap.org/nmap/docs/refguide.xml',
  usage: 'https://svn.nmap.org/nmap/docs/nmap.usage.txt',
  scripts: 'https://svn.nmap.org/nmap/scripts/script.db',
};
export const MIRROR_SOURCES = {
  reference: 'https://raw.githubusercontent.com/nmap/nmap/master/docs/refguide.xml',
  usage: 'https://raw.githubusercontent.com/nmap/nmap/master/docs/nmap.usage.txt',
  scripts: 'https://raw.githubusercontent.com/nmap/nmap/master/scripts/script.db',
};
export const REFRESH_INTERVAL = 3600000;
export const CATEGORIES = {
  'man-target-specification': 'Targets and DNS', 'man-host-discovery': 'Host discovery',
  'man-port-scanning-techniques': 'Scan techniques', 'man-port-specification': 'Ports',
  'man-version-detection': 'Services and versions', 'man-os-detection': 'Operating system',
  'man-nse': 'NSE scripting', 'man-performance': 'Timing and performance',
  'man-bypass-firewalls-ids': 'Packets and source', 'man-output': 'Output', 'man-misc-options': 'Other options',
};
const plain = s => s.replace(/<indexterm\b[\s\S]*?<\/indexterm>/g, '').replace(/<[^>]*>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/\s+/g, ' ').trim();
const requiredOverrides = { '--scanflags': 'flags', '--max-os-tries': 'number', '--mtu': 'number', '--nsock-engine': 'engine', '-T': '0–5' };
const optionalAttached = new Set(['-PS', '-PA', '-PU', '-PY', '-PO', '-v', '-d']);

export function parseReference(xml) {
  if (!xml.includes("id='man-nmap1'") && !xml.includes('id="man-nmap1"')) throw new Error('Unrecognized reference format');
  const found = new Map();
  for (const section of xml.split(/<refsect1\s/).slice(1)) {
    const id = section.match(/id=['"]([^'"]+)['"]/)?.[1];
    if (!CATEGORIES[id]) continue;
    for (const match of section.matchAll(/<term>([\s\S]*?)<\/term>/g)) {
      const term = match[1].replace(/<indexterm\b[\s\S]*?<\/indexterm>/g, '');
      const label = plain(term).match(/\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$/)?.[1];
      for (const option of term.matchAll(/<option\b[^>]*>([\s\S]*?)<\/option>/g)) {
        const flag = plain(option[1].replace(/<replaceable>[\s\S]*?<\/replaceable>/g, ' ')).match(/^(--[a-z][a-z0-9-]*|-[A-Za-z0-9]+)/)?.[0];
        if (!flag) continue;
        const placeholder = requiredOverrides[flag] || plain(option[1].match(/<replaceable>([\s\S]*?)<\/replaceable>/)?.[1] || '');
        const mode = optionalAttached.has(flag) ? 'optional' : placeholder ? 'required' : 'none';
        const item = { flag, label: label || flag, category: id, argument: mode, placeholder,
          join: optionalAttached.has(flag) || flag === '-T' ? 'attached' : 'separate',
          docs: `https://nmap.org/book/${id}.html` };
        if (!found.has(flag) || (placeholder && !found.get(flag).placeholder)) found.set(flag, item);
      }
    }
  }
  const result = [...found.values()];
  if (result.length < 110 || result.length > 500 || !found.has('-sS') || !found.has('--script')) throw new Error('Incomplete option catalog: keeping the previous copy');
  return result;
}

export function parseScripts(db) {
  const scripts = [...db.matchAll(/Entry\s*\{\s*filename\s*=\s*"([a-zA-Z0-9_-]+)\.nse"\s*,\s*categories\s*=\s*\{([^}]+)\}\s*\}/g)].map(m => ({name: m[1], categories: [...m[2].matchAll(/"([a-z]+)"/g)].map(c => c[1])}));
  if (scripts.length < 500 || scripts.length > 3000 || new Set(scripts.map(s => s.name)).size !== scripts.length) throw new Error('Invalid NSE index');
  return scripts;
}

export function validateCatalog(candidate) {
  const fail = () => { throw new Error('Invalid or incompatible catalog'); };
  if (!candidate || candidate.schemaVersion !== 1 || candidate.parserRevision !== 2 || !/^[\w.+-]{1,40}$/.test(candidate.version)) fail();
  const checked = Date.parse(candidate.checkedAt);
  if (!Number.isFinite(checked) || checked > Date.now() + 300000) fail();
  if (!Array.isArray(candidate.options) || candidate.options.length < 110 || candidate.options.length > 500 || !Array.isArray(candidate.scripts) || candidate.scripts.length < 500 || candidate.scripts.length > 3000) fail();
  const flags = new Set();
  for (const option of candidate.options) {
    if (!/^--?[A-Za-z0-9][A-Za-z0-9-]*$/.test(option.flag) || flags.has(option.flag) || !CATEGORIES[option.category] || !['none','required','optional'].includes(option.argument) || !['attached','separate'].includes(option.join) || typeof option.label !== 'string' || option.label.length > 500 || typeof option.placeholder !== 'string' || option.placeholder.length > 300 || option.docs !== `https://nmap.org/book/${option.category}.html`) fail();
    flags.add(option.flag);
  }
  if (!flags.has('-sS') || !flags.has('--script')) fail();
  const scripts = new Set();
  for (const script of candidate.scripts) {
    if (!/^[a-zA-Z0-9_-]+$/.test(script.name) || scripts.has(script.name) || !Array.isArray(script.categories) || script.categories.some(c => !/^[a-z]+$/.test(c))) fail();
    scripts.add(script.name);
  }
  for (const key of Object.keys(SOURCES)) {
    const source = candidate.sources?.[key];
    if (!source || ![SOURCES[key],MIRROR_SOURCES[key]].includes(source.url) || !/^[a-f0-9]{64}$/.test(source.sha256)) fail();
  }
  if (candidate.changes && (typeof candidate.changes.updated !== 'boolean' || !Array.isArray(candidate.changes.addedOptions) || !Array.isArray(candidate.changes.addedScripts))) fail();
  return candidate;
}

export function newestCatalog(...candidates) {
  const valid = candidates.filter(candidate => { try { validateCatalog(candidate); return true; } catch { return false; } });
  return valid.sort((a,b) => Date.parse(b.checkedAt) - Date.parse(a.checkedAt))[0];
}

export function catalogFreshness(catalog, now = Date.now()) {
  const age = now - Date.parse(catalog.checkedAt);
  return { stale: !Number.isFinite(age) || age >= REFRESH_INTERVAL, age: Math.max(0,age), nextCheckAt: new Date(Date.parse(catalog.checkedAt)+REFRESH_INTERVAL).toISOString() };
}

export async function downloadCatalog(previous, fetcher = fetch, { mirror = false, conditional = true, onProgress = () => {} } = {}) {
  const sources = mirror ? MIRROR_SOURCES : SOURCES;
  const downloaded = await Promise.all(Object.entries(sources).map(async ([key, url]) => {
    const old = conditional && previous?.parserRevision === 2 && previous.sources?.[key]?.url === url ? previous.sources[key] : undefined;
    const headers = { Accept: 'text/plain, application/xml;q=0.9' };
    if (old?.etag) headers['If-None-Match'] = old.etag;
    if (old?.lastModified) headers['If-Modified-Since'] = old.lastModified;
    onProgress(key, 'checking');
    const response = await fetcher(url, { headers, signal: AbortSignal.timeout(12000), redirect: 'error', credentials: 'omit' });
    if (response.status === 304 && old) { onProgress(key, 'verified'); return [key, null, old]; }
    if (!response.ok || response.status !== 200) throw new Error(`Source ${key}: HTTP ${response.status}`);
    const reader = response.body.getReader();
    let length = 0; const chunks = [];
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      length += value.length;
      if (length > 1500000) { await reader.cancel(); throw new Error('Source size limit exceeded'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const body = new TextDecoder().decode(bytes);
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2,'0')).join('');
    onProgress(key, 'verified');
    return [key, body, { url, etag: response.headers.get('etag'), lastModified: response.headers.get('last-modified'), sha256: hash }];
  }));
  const contents = Object.fromEntries(downloaded.map(([k,v]) => [k,v]));
  const version = contents.usage === null ? previous.version : contents.usage.match(/^Nmap\s+(\S+)/)?.[1];
  if (!version) throw new Error('Unrecognized Nmap version');
  const options = contents.reference === null ? previous.options : parseReference(contents.reference);
  const scripts = contents.scripts === null ? previous.scripts : parseScripts(contents.scripts);
  if (previous && (options.length < previous.options.length * .95 || scripts.length < previous.scripts.length * .95)) throw new Error('Unexpected catalog reduction: update rejected');
  const now = new Date().toISOString();
  const changed = downloaded.some(([key,,value]) => value.sha256 !== previous?.sources?.[key]?.sha256);
  const before = new Set(previous?.options?.map(o => o.flag) || []);
  const beforeScripts = new Set(previous?.scripts?.map(s => s.name) || []);
  return validateCatalog({ schemaVersion: 1, parserRevision: 2, version, channel: 'Official SVN / development', transport: mirror ? 'github-mirror' : 'svn', checkedAt: now,
    changedAt: changed ? now : previous?.changedAt || previous?.checkedAt || now,
    changes: { updated: changed, addedOptions: previous ? options.filter(o => !before.has(o.flag)).map(o => o.flag) : [], addedScripts: previous ? scripts.filter(s => !beforeScripts.has(s.name)).map(s => s.name) : [] },
    options, scripts, sources: Object.fromEntries(downloaded.map(([k,,v]) => [k,v])) });
}

export async function synchronizeCatalog(previous, fetcher = fetch) {
  try { return await downloadCatalog(previous, fetcher); }
  catch { return await downloadCatalog(previous, fetcher, { mirror:true }); }
}
