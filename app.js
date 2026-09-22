import { buildCommand } from '/command.mjs';
import { downloadCatalog, validateCatalog, newestCatalog, catalogFreshness, REFRESH_INTERVAL } from '/catalog.mjs';
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const categories = {'man-target-specification':'Targets and DNS','man-host-discovery':'Host discovery','man-port-scanning-techniques':'Scan techniques','man-port-specification':'Ports','man-version-detection':'Services and versions','man-os-detection':'Operating system','man-nse':'NSE scripting','man-performance':'Timing and performance','man-bypass-firewalls-ids':'Packets and source','man-output':'Output','man-misc-options':'Other options'};
const translations = {'-sT':'Full TCP connection','-sS':'TCP SYN scan','-sU':'UDP port scan','-sn':'Discover active hosts only','-sV':'Service and version detection','-O':'Operating system detection','-T':'Timing template','-p':'Ports to explore','-F':'Top 100 common ports','-6':'IPv6 scan','-n':'Disable DNS resolution','--open':'Show open ports only','--reason':'Explain port states','--script':'Run the selected scripts','--script-args':'Script arguments','-oA':'Save in all three main formats','-oN':'Save a text report','-oX':'Save an XML report'};
let catalog = null, currentView = 'builder', scriptLimit = 60, result;
let syncing = false, lastAttempt = 0, refreshTimer;
const sourceProgress = new Map();
const state = {target:'192.168.1.0/24',shell:'posix', options:new Map([['-sT',''],['-sV',''],['-T','3']])};
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(message) { $('#toast').textContent = message; $('#toast').hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => $('#toast').hidden = true, 3000); }
function customProfile() { $$('[data-profile]').forEach(b => b.classList.remove('active')); }
function setOption(flag, enabled, value = '') { if (enabled) state.options.set(flag, value); else state.options.delete(flag); customProfile(); update(); }
function update() {
  if (!catalog) return;
  result = buildCommand(state, catalog);
  $('#command').innerHTML = escape(result.command).replace(/(^|\s)(--?[a-zA-Z0-9][a-zA-Z0-9-]*)/g, '$1<span class="syntax-flag">$2</span>');
  $('#active-count').textContent = `${state.options.size} active options`;
  $('#parts-count').textContent = String(state.options.size).padStart(2,'0');
  $('#command-parts').innerHTML = result.parts.map(p => `<div class="command-part"><code>${escape(p.flag)}${p.value ? '<br>'+escape(p.value) : ''}</code><div>${escape(translations[p.flag] || p.label)}</div><button class="remove-option" data-remove="${escape(p.flag)}" aria-label="Remove ${escape(p.flag)}" title="Remove ${escape(p.flag)}">×</button></div>`).join('') || '<p class="input-hint">Choose a profile or add options from the catalog.</p>';
  $('#validation').innerHTML = [...result.errors.map(e=>`<div class="error">${escape(e)}</div>`),...result.warnings.map(w=>`<div class="warning">${escape(w)}</div>`)].join('');
  $('#copy').disabled = $('#export').disabled = result.errors.length > 0;
  $('#config-state').textContent = result.errors.length ? `${result.errors.length} issue${result.errors.length===1?'':'s'} to resolve` : 'Ready to copy';
  $('.terminal').classList.toggle('has-errors',result.errors.length>0);
  const scanNames={'-sT':'TCP Connect','-sS':'TCP SYN','-sU':'UDP','-sn':'Discovery','-sL':'List only','-sO':'IP protocol'};
  $('#plan-scan').textContent = [...state.options.keys()].filter(f=>scanNames[f]).map(f=>scanNames[f]).join(' + ') || 'Default / custom';
  $('#plan-ports').textContent = state.options.has('-sn') || state.options.has('-sL') ? 'No port scan' : state.options.get('-p') === '-' ? 'All 65,535' : state.options.has('-p') ? 'Custom range' : state.options.has('-F') ? 'Top 100' : state.options.has('--top-ports') ? `Top ${state.options.get('--top-ports')}` : 'Top 1,000';
  $('#plan-timing').textContent = `T${state.options.get('-T')||'3'}`;
  $$('.pace-meter span').forEach((bar,i)=>bar.classList.toggle('lit',i<=Number(state.options.get('-T')||3)));
  if(!matchMedia('(prefers-reduced-motion: reduce)').matches) $('#command').animate([{opacity:.5,transform:'translateY(3px)'},{opacity:1,transform:'translateY(0)'}],{duration:190});
}
function syncControls() {
  $('#target').value = state.target;
  $$('[data-flag]').forEach(input => {input.checked = state.options.has(input.dataset.flag);});
  $$('[name=scan]').forEach(input => input.checked = state.options.has(input.value));
  const p = state.options.get('-p');
  $('#ports-mode').value = state.options.has('-F') ? 'fast' : p === '-' ? 'all' : p !== undefined ? 'custom' : 'default';
  $('#ports').disabled = $('#ports-mode').value !== 'custom'; $('#ports').value = p && p !== '-' ? p : '';
  $('#timing').value = state.options.get('-T') || '3';
  $('#timing-name').textContent = state.options.has('-T') ? `T${state.options.get('-T')} · ${['Paranoid','Sneaky','Polite','Normal','Aggressive','Insane'][state.options.get('-T')] || 'Custom'}` : 'Default timing';
  const out = ['-oN','-oX','-oG','-oA'].find(f => state.options.has(f));
  $('#output-format').value = out || ''; $('#output-file').disabled = !out;
  if (out) $('#output-file').value = state.options.get(out);
  $('#script-expression').value = state.options.get('--script') || '';
  $('#script-args').value = state.options.get('--script-args') || '';
}
function profile(name) {
  state.options = new Map(name === 'discovery' ? [['-sn',''],['-T','3']] : name === 'complete' ? [['-sT',''],['-sV',''],['-p','-'],['-T','3']] : [['-sT',''],['-sV',''],['-T','3']]);
  $$('[data-profile]').forEach(b => b.classList.toggle('active',b.dataset.profile === name)); syncControls(); update();
}
const titles = {builder:['Command builder','Build your next command','From your first scan to the finer details. Make every option count.'], catalog:['Option catalog','Every option at your fingertips','Explore the official reference and shape your configuration.'], scripts:['NSE scripts','Give your scan new capabilities','Scripts and categories from the official Nmap index.'], sources:['Sources & updates','Official data. Clear provenance','Verify your catalog and inspect the sources behind every update.']};
function showView(view) {
  if (!titles[view]) return;
  currentView = view;
  $$('.view').forEach(section => section.hidden = section.id !== `${view}-view`);
  $$('.nav-item[data-view]').forEach(b => b.classList.toggle('active',b.dataset.view === view));
  $('#breadcrumb').textContent = titles[view][0]; $('#page-title').innerHTML = escape(titles[view][1])+'<span>.</span>'; $('#page-subtitle').textContent = titles[view][2];
  if (catalog) {syncControls(); if(view === 'catalog') renderOptions(); if(view === 'scripts') renderScripts();}
}
function renderOptions() {
  const query = $('#option-search').value.toLowerCase(); const category = $('#category-filter').value;
  const options = catalog.options.filter(o => (!category || o.category === category) && (!$('#only-active').checked || state.options.has(o.flag)) && `${o.flag} ${o.label} ${translations[o.flag] || ''}`.toLowerCase().includes(query));
  $('#catalog-total').textContent = `${options.length} OPTIONS`;
  $('#option-list').innerHTML = options.map(o => `<div class="catalog-option"><div class="check"><input type="checkbox" data-option="${escape(o.flag)}" aria-label="Enable ${escape(o.flag)}" ${state.options.has(o.flag)?'checked':''}><div class="option-text"><code>${escape(o.flag)}</code>${escape(translations[o.flag] || o.label)}<small>${escape(categories[o.category] || o.category)}</small></div><a href="${escape(o.docs)}" target="_blank" rel="noreferrer" aria-label="Reference for ${escape(o.flag)}">↗</a></div>${o.argument !== 'none' ? `<input type="text" data-value="${escape(o.flag)}" aria-label="Value for ${escape(o.flag)}" placeholder="${escape(o.placeholder || 'optional value')}${o.argument==='optional'?' (optional)':''}" value="${escape(state.options.get(o.flag)||'')}" ${state.options.has(o.flag)?'':'disabled'}>`:''}</div>`).join('') || '<div class="empty">No options match your search.</div>';
}
function renderScripts() {
  const query = $('#script-search').value.toLowerCase(), category = $('#script-category').value;
  const scripts = catalog.scripts.filter(s => s.name.includes(query) && (!category || s.categories.includes(category)));
  const selected = (state.options.get('--script') || '').split(',').map(s=>s.trim());
  $('#script-selection').textContent = `${scripts.length} scripts found · ${selected.filter(s => catalog.scripts.some(c => c.name === s)).length} selected individually`;
  $('#script-list').innerHTML = scripts.slice(0,scriptLimit).map(s=>`<div class="script-row"><label class="check"><input type="checkbox" data-script="${s.name}" ${selected.includes(s.name)?'checked':''}><span><code>${s.name}</code><small>${s.categories.join(' · ')}</small></span></label><a href="https://nmap.org/nsedoc/scripts/${s.name}.html" target="_blank" rel="noreferrer" aria-label="Documentation for ${s.name}">↗</a></div>`).join('') || '<div class="empty">No scripts match your search.</div>';
  $('#more-scripts').hidden = scripts.length <= scriptLimit;
}
function renderSources() {
  $('#option-count').textContent = catalog.options.length; $('#script-count').textContent = catalog.scripts.length;
  const freshness = catalogFreshness(catalog);
  const failed = catalog.status === 'fallback';
  const status = syncing ? 'Checking official sources' : failed ? 'Update unavailable · saved copy active' : freshness.stale ? 'Verification overdue' : 'Verified against official sources';
  const sourceName = catalog.sources.reference.url.includes('githubusercontent') ? 'Nmap GitHub mirror' : 'Nmap SVN';
  const checked = new Date(catalog.checkedAt).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'});
  $('#catalog-status').textContent = syncing ? 'Checking for updates…' : failed || freshness.stale ? status : `Nmap ${catalog.version} · Verified`;
  $('#catalog-date').textContent = `Last verified ${checked}`;
  $('#sync-title').textContent = status;
  $('#sync-subtitle').textContent = `${sourceName} · Last verified ${checked}`;
  $('#sync-options').textContent = catalog.options.length;
  $('#sync-scripts').textContent = catalog.scripts.length;
  $('.sync-banner').classList.toggle('is-stale', !syncing && (failed || freshness.stale));
  $('.sync-banner').classList.toggle('is-syncing', syncing);
  $('.catalog-status').classList.toggle('is-stale', failed || freshness.stale);
  $('#sync-now').disabled = $('#refresh').disabled = syncing;
  $('#sync-now').textContent = syncing ? 'Syncing…' : 'Sync now ↻';
  $('#source-details').innerHTML = `<div class="source-overview"><span class="source-edition">NMAP ${escape(catalog.version)}</span><h3>Your catalog. Connected.</h3><p>${catalog.options.length} documented options and ${catalog.scripts.length} NSE scripts, from the Nmap project.</p><div class="verification-time"><span>LAST SUCCESSFUL VERIFICATION</span><strong>${checked}</strong></div></div><div class="source-cards">`+Object.entries(catalog.sources).map(([key,source],i)=>`<article class="source-card"><div class="source-card-top"><span>0${i+1}</span><span class="source-state">${syncing ? sourceProgress.get(key)||'checking' : failed ? 'saved copy' : freshness.stale ? 'check due' : 'verified'}</span></div><h3>${escape({reference:'Command reference',usage:'CLI version',scripts:'NSE script index'}[key] || key)}</h3><p>${escape({reference:'Flags, parameters, syntax and categories.',usage:'The development version behind this catalog.',scripts:'Script names and their official categories.'}[key])}</p><a href="${escape(source.url)}" target="_blank" rel="noreferrer">View official source ↗</a><details><summary>Source fingerprint</summary><code>${escape(source.sha256)}</code></details></article>`).join('')+'</div>';
  const changes = catalog.changes;
  $('#catalog-changes').textContent = changes?.updated ? `Last successful check: source content changed. ${changes.addedOptions.length} new options and ${changes.addedScripts.length} new scripts detected.` : changes ? 'Last successful check: source content is unchanged. Verification time has been refreshed.' : 'Embedded reference loaded. Sync to compare it with the official sources.';
  $('#refresh-status').textContent = syncing ? 'Downloading and validating the three official source files…' : catalog.warning || `Automatic verification is enabled. Next check due ${new Date(freshness.nextCheckAt).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'})}.`;
}
function activateCatalog(candidate) {
  validateCatalog(candidate);
  const selectedCategory = $('#category-filter').value;
  const selectedScriptCategory = $('#script-category').value;
  catalog = candidate;
  $('#category-filter').innerHTML = '<option value="">All categories</option>'+Object.entries(categories).map(([k,v])=>`<option value="${k}">${v}</option>`).join('');
  $('#script-category').innerHTML = '<option value="">All categories</option>'+[...new Set(catalog.scripts.flatMap(s=>s.categories))].sort().map(c=>`<option>${escape(c)}</option>`).join('');
  $('#category-filter').value = selectedCategory;
  $('#script-category').value = selectedScriptCategory;
  renderSources(); syncControls(); update(); showView(currentView);
}
async function loadCatalog(refresh = false) {
  if(syncing || Date.now()-lastAttempt < 60000) { if(refresh && !syncing) toast('Please wait one minute between checks.'); return; }
  if(!refresh && catalog && catalog.status !== 'fallback' && !catalogFreshness(catalog).stale) {renderSources();scheduleRefresh();return;}
  syncing = true; lastAttempt = Date.now(); sourceProgress.clear(); renderSources();
  try {
    let candidate;
    if(location.protocol !== 'file:') {
      try {
        const response = await fetch('/api/catalog'+(refresh?'?refresh=1':''), {signal:AbortSignal.timeout(28000)});
        if(!response.ok)throw new Error('Catalog service unavailable');
        candidate=validateCatalog(await response.json());
        if(candidate.status==='fallback') candidate=undefined;
      } catch { candidate=undefined; }
    }
    if(!candidate) candidate={...await downloadCatalog(catalog,fetch,{mirror:true,conditional:false,onProgress(key,status){sourceProgress.set(key,status);renderSources();}}),status:'verified'};
    const newest = newestCatalog(candidate,catalog);
    activateCatalog({...newest,status:candidate.status||'verified',warning:undefined});
    try {const {status,warning,...persisted}=catalog;localStorage.setItem('nmap-catalog-v1',JSON.stringify(persisted));} catch {}
    if (refresh) toast(catalog.changes?.updated ? 'Catalog updated from the Nmap project.' : 'Catalog verified. You have the latest available source data.');
  } catch {
    if (catalog) {activateCatalog({...catalog,status:'fallback',warning:'Live verification failed. The last available verified catalog is still usable; its date has not been changed.'});if(refresh)toast('Sources could not be verified. Your saved catalog is still available.');}
    else {$('#command').textContent='Catalog unavailable';$('#catalog-status').textContent='Connection unavailable';$('#catalog-date').textContent='Try again in Sources & updates';$('#refresh-status').textContent='Unable to load the catalog. Select Check for updates to try again.';}
  } finally {syncing=false;renderSources();scheduleRefresh();}
}
function scheduleRefresh(){clearTimeout(refreshTimer);const age=catalog?catalogFreshness(catalog).age:REFRESH_INTERVAL;const delay=catalog?.status==='fallback'?300000:Math.max(60000,REFRESH_INTERVAL-age);refreshTimer=setTimeout(()=>{if(!document.hidden)loadCatalog();else scheduleRefresh();},delay);}
$$('[data-view]').forEach(b => b.addEventListener('click',()=>showView(b.dataset.view)));
$$('[data-profile]').forEach(b => b.addEventListener('click',()=>profile(b.dataset.profile)));
$('#target').addEventListener('input',e=>{state.target=e.target.value;update();});
$$('[data-flag]').forEach(input=>input.addEventListener('change',()=>setOption(input.dataset.flag,input.checked)));
$$('[name=scan]').forEach(input=>input.addEventListener('change',()=>{
  ['-sS','-sT','-sU','-sA','-sW','-sM','-sN','-sF','-sX','-sI','-sY','-sZ','-sO','-b','-sn','-sL'].forEach(f=>state.options.delete(f));
  if(input.value==='-sn') ['-sV','-O','-A','-p','-F','--top-ports','--port-ratio','-Pn'].forEach(f=>state.options.delete(f));
  setOption(input.value,true);syncControls();
}));
$('#ports-mode').addEventListener('change',e=>{['-p','-F','--top-ports','--port-ratio'].forEach(f=>state.options.delete(f));if(e.target.value==='fast')state.options.set('-F','');if(e.target.value==='all')state.options.set('-p','-');if(e.target.value==='custom')state.options.set('-p',$('#ports').value);$('#ports').disabled=e.target.value!=='custom';customProfile();update();});
$('#ports').addEventListener('input',e=>setOption('-p',true,e.target.value));
$('#timing').addEventListener('input',e=>{setOption('-T',true,e.target.value);$('#timing-name').textContent=`T${e.target.value} · ${['Paranoid','Sneaky','Polite','Normal','Aggressive','Insane'][e.target.value]}`;});
$('#output-format').addEventListener('change',e=>{['-oN','-oX','-oG','-oA'].forEach(f=>state.options.delete(f));$('#output-file').disabled=!e.target.value;if(e.target.value)state.options.set(e.target.value,$('#output-file').value);customProfile();update();});
$('#output-file').addEventListener('input',e=>{if($('#output-format').value)setOption($('#output-format').value,true,e.target.value);});
$('#shell').addEventListener('change',e=>{state.shell=e.target.value;update();});
$('#reset').addEventListener('click',()=>{state.target='';state.options.clear();customProfile();syncControls();update();showView(currentView);toast('Configuration cleared.');});
$('#option-search').addEventListener('input',()=>catalog&&renderOptions());$('#category-filter').addEventListener('change',()=>catalog&&renderOptions());$('#only-active').addEventListener('change',()=>catalog&&renderOptions());
$('#option-list').addEventListener('change',e=>{if(e.target.dataset.option){setOption(e.target.dataset.option,e.target.checked);renderOptions();}});
$('#option-list').addEventListener('input',e=>{if(e.target.dataset.value)setOption(e.target.dataset.value,true,e.target.value);});
for (const [id,flag] of [['script-expression','--script'],['script-args','--script-args']]) $(`#${id}`).addEventListener('input',e=>{setOption(flag,Boolean(e.target.value.trim()),e.target.value);if(id==='script-expression')renderScripts();});
for (const id of ['script-search','script-category']) $(`#${id}`).addEventListener(id==='script-search'?'input':'change',()=>{scriptLimit=60;if(catalog)renderScripts();});
$('#script-list').addEventListener('change',e=>{if(!e.target.dataset.script)return;const scripts=new Set((state.options.get('--script')||'').split(',').map(s=>s.trim()).filter(Boolean));if(e.target.checked)scripts.add(e.target.dataset.script);else scripts.delete(e.target.dataset.script);setOption('--script',scripts.size>0,[...scripts].join(','));$('#script-expression').value=state.options.get('--script')||'';renderScripts();});
$('#more-scripts').addEventListener('click',()=>{scriptLimit+=60;renderScripts();});
$('#command-parts').addEventListener('click',event=>{const button=event.target.closest('[data-remove]');if(!button)return;setOption(button.dataset.remove,false);syncControls();if(currentView==='catalog')renderOptions();if(currentView==='scripts')renderScripts();});
$('#refresh').addEventListener('click',()=>loadCatalog(true));
$('#sync-now').addEventListener('click',()=>loadCatalog(true));
document.addEventListener('visibilitychange',()=>{if(!document.hidden)loadCatalog();});
window.addEventListener('online',()=>{lastAttempt=0;loadCatalog(true);});
$('#copy').addEventListener('click',async()=>{if(!result||result.errors.length)return;try {await navigator.clipboard.writeText(result.command);toast('Command copied to the clipboard.');}catch{const range=document.createRange();range.selectNodeContents($('#command'));const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);toast('Command selected. Press Ctrl+C to copy.');}});
$('#export').addEventListener('click',()=>{if(!result||result.errors.length)return;const blob=new Blob([result.command+'\n'],{type:'text/plain;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='nmap-command.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
if(document.modelContext?.registerTool){try {Promise.resolve(document.modelContext.registerTool({name:'read_nmap_command',title:'Read the Nmap command',description:'Return the current command and configuration errors. Does not execute scans.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute(input){if(!input||typeof input!=='object'||Object.keys(input).length)throw new Error('No parameters are allowed');if(!result)throw new Error('Catalog is not ready');return result;}})).catch(()=>{});}catch{}}
let storedCatalog;
try {storedCatalog=JSON.parse(localStorage.getItem('nmap-catalog-v1'));} catch {}
const initialCatalog=newestCatalog(typeof EMBEDDED_CATALOG!=='undefined'?EMBEDDED_CATALOG:undefined,storedCatalog);
if(initialCatalog)activateCatalog({...initialCatalog,status:'snapshot',warning:undefined});
loadCatalog();
