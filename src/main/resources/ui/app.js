'use strict';

// ---------------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------------

const view = document.getElementById('view');
const SEVERITIES = ['ERROR', 'WARN', 'INFO'];
const SEVERITY_LABELS = {ERROR: 'Errors', WARN: 'Warnings', INFO: 'Info'};
const CATEGORY_LABELS = {HYBRID: 'Hybrid compatibility', SECURITY: 'Security', PERFORMANCE: 'Performance', DESIGN: 'Design'};

/** Builds an element; strings become text nodes, so page content is never parsed as HTML. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else if (key === 'value') el.value = value;
    else if (key === 'checked') el.checked = !!value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

async function request(method, path, body) {
  const options = {method, headers: {}};
  if (method !== 'GET') options.headers['X-Apigee-Map'] = '1';
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

const api = {
  settings: () => request('GET', '/api/settings'),
  saveSettings: settings => request('PUT', '/api/settings', settings),
  proxies: () => request('GET', '/api/proxies'),
  proxy: id => request('GET', '/api/proxy?id=' + encodeURIComponent(id)),
  apply: (id, overwrite) => request('POST', '/api/apply?id=' + encodeURIComponent(id) + (overwrite ? '&overwrite=true' : '')),
  overview: () => request('GET', '/api/overview'),
};

let toastTimer;
function toast(message, bad) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = 'toast' + (bad ? ' bad' : '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 7000 : 3500);
}

function confirmDialog(title, message, confirmLabel) {
  return new Promise(resolve => {
    const dialog = h('dialog', {},
      h('h2', {}, title), h('p', {}, message),
      h('div', {class: 'actions'},
        h('button', {type: 'button', onclick: () => { dialog.close(); resolve(false); }}, 'Cancel'),
        h('button', {type: 'button', class: 'primary', onclick: () => { dialog.close(); resolve(true); }}, confirmLabel)));
    dialog.addEventListener('close', () => { dialog.remove(); resolve(false); });
    document.body.append(dialog);
    dialog.showModal();
  });
}

function count(n, severity) {
  return h('span', {class: n ? severity : 'zero'}, n);
}

function severity(value) {
  return h('span', {class: value}, value);
}

function fixBadge(finding, applied) {
  if (finding.fix === 'MANUAL') return h('span', {class: 'badge'}, 'manual');
  return h('span', {class: 'badge auto'}, applied ? 'fixed' : 'auto-fix');
}

function cards(items) {
  return h('div', {class: 'cards'}, items.map(([value, label]) => h('div', {class: 'card'}, h('b', {}, value), h('span', {}, label))));
}

function table(headers, rows) {
  return h('div', {class: 'wrap'}, h('table', {},
    h('thead', {}, h('tr', {}, headers.map(header => typeof header === 'string'
      ? h('th', {}, header) : h('th', {class: header.class}, header.label)))),
    h('tbody', {}, rows)));
}

function empty(message, action) {
  return h('div', {class: 'empty'}, h('p', {}, message), action);
}

function errorBox(error) {
  return h('div', {class: 'error-box'}, error.message || String(error));
}

/** Toggle buttons; {@code selected} is the current value, '' meaning "All". */
function chips(options, selected, onChange) {
  return h('div', {class: 'chips'}, options.map(([value, label]) =>
    h('button', {type: 'button', class: 'chip' + (value === selected ? ' on' : ''), onclick: () => onChange(value)}, label)));
}

// ---------------------------------------------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------------------------------------------

let renderToken = 0;
let leaveGuard = null;
let currentHash = location.hash;

/** Renders the view for the current hash; results of a previous, slower render are dropped. */
async function route() {
  const [name = 'proxies', ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  const routes = {proxies: proxiesView, proxy: proxyView, overview: overviewView, settings: settingsView};
  const render = routes[name] || proxiesView;
  document.querySelectorAll('[data-nav]').forEach(a =>
    a.classList.toggle('active', a.dataset.nav === (name === 'proxy' ? 'proxies' : name)));
  const token = ++renderToken;
  leaveGuard = null;
  view.replaceChildren(h('div', {class: 'loading'}, 'Loading…'));
  try {
    const content = await render(decodeURIComponent(rest.join('/')), () => token === renderToken);
    if (token === renderToken && content) view.replaceChildren(content);
  } catch (error) {
    if (token === renderToken) view.replaceChildren(errorBox(error));
  }
}

window.addEventListener('hashchange', () => {
  if (leaveGuard && !leaveGuard()) {
    history.replaceState(null, '', currentHash || '#/settings');
    return;
  }
  currentHash = location.hash;
  route();
});
window.addEventListener('beforeunload', event => {
  if (leaveGuard && !leaveGuard(true)) event.preventDefault();
});

// ---------------------------------------------------------------------------------------------------------------
// Proxies
// ---------------------------------------------------------------------------------------------------------------

const proxyFilter = {text: '', status: ''};

async function proxiesView() {
  const [{settings}, proxies] = await Promise.all([api.settings(), api.proxies()]);
  const page = h('div', {});
  const head = h('div', {class: 'head'},
    h('div', {}, h('h1', {}, 'Proxies'),
      h('p', {class: 'meta'}, settings.proxiesRoot ? 'From ' + settings.proxiesRoot : 'No proxies folder configured')),
    h('div', {class: 'actions'}, h('button', {type: 'button', onclick: route}, 'Refresh')));
  page.append(head);

  if (!settings.proxiesRoot) {
    page.append(h('div', {style: 'margin-top:16px'}, empty('Set the folder that contains your exported proxies to get started.',
      h('a', {class: 'button', href: '#/settings'}, 'Open Settings'))));
    return page;
  }
  if (!proxies.length) {
    page.append(h('div', {style: 'margin-top:16px'}, empty('No apiproxy/ folder found under ' + settings.proxiesRoot + '.',
      h('a', {class: 'button', href: '#/settings'}, 'Check Settings'))));
    return page;
  }

  const sum = key => proxies.reduce((total, p) => total + p[key], 0);
  page.append(cards([
    [proxies.length, 'Proxies'],
    [sum('errors'), 'Errors'],
    [sum('warnings'), 'Warnings'],
    [sum('autoFixes'), 'Fixable automatically'],
    [proxies.filter(p => p.migrated).length + ' / ' + proxies.length, 'Migrated'],
  ]));

  const body = h('tbody', {});
  const search = h('input', {type: 'search', placeholder: 'Search proxies', value: proxyFilter.text, 'aria-label': 'Search proxies',
    oninput: e => { proxyFilter.text = e.target.value; fill(); }});
  const statusChips = h('div', {});
  const renderChips = () => statusChips.replaceChildren(chips(
    [['', 'All'], ['errors', 'With errors'], ['pending', 'Not migrated'], ['migrated', 'Migrated'], ['failed', 'Analysis failed']],
    proxyFilter.status, value => { proxyFilter.status = value; renderChips(); fill(); }));
  renderChips();

  function matches(p) {
    const text = proxyFilter.text.trim().toLowerCase();
    if (text && !(p.name + ' ' + p.id).toLowerCase().includes(text)) return false;
    switch (proxyFilter.status) {
      case 'errors': return p.errors > 0;
      case 'pending': return !p.migrated && !p.error;
      case 'migrated': return p.migrated;
      case 'failed': return !!p.error;
      default: return true;
    }
  }

  function fill() {
    const rows = proxies.filter(matches).map(p => h('tr', {class: 'click', tabindex: 0,
        onclick: () => { location.hash = '#/proxy/' + encodeURIComponent(p.id); },
        onkeydown: e => { if (e.key === 'Enter') location.hash = '#/proxy/' + encodeURIComponent(p.id); }},
      h('td', {}, h('div', {}, h('b', {}, p.name), p.revision ? h('span', {class: 'sub'}, '  rev ' + p.revision) : null),
        h('div', {class: 'sub mono'}, p.id)),
      p.error
        ? h('td', {colspan: 6}, h('span', {class: 'badge bad'}, 'Analysis failed'), ' ', h('span', {class: 'sub'}, p.error))
        : [h('td', {class: 'num'}, p.sharedFlows),
          h('td', {class: 'num'}, count(p.errors, 'ERROR')),
          h('td', {class: 'num'}, count(p.warnings, 'WARN')),
          h('td', {class: 'num'}, count(p.infos, 'INFO')),
          h('td', {class: 'num'}, p.autoFixes),
          h('td', {}, p.migrated ? h('span', {class: 'badge ok'}, 'Migrated') : h('span', {class: 'badge'}, 'Not migrated'))]));
    body.replaceChildren(...(rows.length ? rows : [h('tr', {}, h('td', {colspan: 7, class: 'sub'}, 'No proxy matches the filter.'))]));
  }
  fill();

  page.append(h('div', {class: 'toolbar'}, search, statusChips));
  page.append(h('div', {class: 'wrap'}, h('table', {style: 'min-width:720px'},
    h('thead', {}, h('tr', {}, h('th', {}, 'Proxy'), h('th', {class: 'num'}, 'Shared flows'), h('th', {class: 'num'}, 'Errors'),
      h('th', {class: 'num'}, 'Warnings'), h('th', {class: 'num'}, 'Info'), h('th', {class: 'num'}, 'Auto-fixes'), h('th', {}, 'Status'))),
    body)));
  return page;
}

// ---------------------------------------------------------------------------------------------------------------
// Proxy detail
// ---------------------------------------------------------------------------------------------------------------

const detailState = {tab: 'findings', severity: '', category: '', fix: ''};

async function proxyView(id) {
  const detail = await api.proxy(id);
  const {summary, migration} = detail;
  const page = h('div', {});

  const applyButton = h('button', {type: 'button', class: 'primary', disabled: !detail.outputDir,
      title: detail.outputDir ? 'Writes the migrated proxy and its shared flows to ' + detail.outputDir : 'Set the output folder in Settings first',
      onclick: () => applyMigration(id, summary, detail.outputDir, applyButton)},
    summary.migrated ? 'Migrate again' : 'Apply migration');
  page.append(h('div', {class: 'head'},
    h('div', {},
      h('p', {class: 'meta'}, h('a', {href: '#/proxies'}, '← Proxies')),
      h('h1', {}, summary.name),
      h('p', {class: 'meta'}, [summary.revision ? 'Revision ' + summary.revision : null, summary.description]
        .filter(Boolean).join(' · ')),
      h('p', {class: 'meta mono'}, detail.path)),
    h('div', {class: 'actions'},
      h('a', {class: 'button', href: '/api/report?id=' + encodeURIComponent(id)}, 'Download report'),
      applyButton)));

  if (summary.migrated) {
    page.append(h('p', {class: 'meta'}, h('span', {class: 'badge ok'}, 'Migrated'), ' ', h('span', {class: 'mono'}, detail.outputDir)));
  }

  page.append(cards([
    [summary.errors, 'Errors'], [summary.warnings, 'Warnings'], [summary.infos, 'Info'],
    [summary.autoFixes, 'Fixable automatically'], [summary.manual, 'Manual'],
    [summary.sharedFlows, 'Shared flows migrated with it'],
  ]));

  const findings = migration.bundles.flatMap(b => b.findings);
  const files = migration.bundles.flatMap(b => b.files);
  const tabs = [
    ['findings', 'Findings', findings.length],
    ['changes', 'Changes', files.length],
    ['resources', 'To create in hybrid', migration.resources.length],
    ['map', 'Dependency map', null],
  ];
  const panel = h('div', {});
  const tabBar = h('div', {class: 'tabs', role: 'tablist'});
  function showTab(tab) {
    detailState.tab = tab;
    tabBar.replaceChildren(...tabs.map(([key, label, n]) => h('button', {type: 'button', role: 'tab',
        class: key === tab ? 'on' : '', 'aria-selected': String(key === tab), onclick: () => showTab(key)},
      label, n === null ? null : h('span', {class: 'count'}, n))));
    const render = {findings: () => findingsPanel(findings, migration.applied), changes: () => changesPanel(migration),
      resources: () => resourcesPanel(migration.resources), map: () => mapPanel(id)}[tab];
    panel.replaceChildren(render());
  }
  showTab(detailState.tab);
  page.append(tabBar, panel);
  return page;
}

async function applyMigration(id, summary, outputDir, button) {
  const target = outputDir;
  if (summary.migrated) {
    const ok = await confirmDialog('Replace the existing migration?',
      'The folder ' + target + ' will be deleted and written again from the current bundles and settings.', 'Replace');
    if (!ok) return;
  }
  button.disabled = true;
  button.textContent = 'Migrating…';
  try {
    const report = await api.apply(id, summary.migrated);
    toast('Migrated ' + report.bundles.length + ' bundle(s) to ' + report.outputDir);
    route();
  } catch (error) {
    toast(error.message, true);
    button.disabled = false;
    button.textContent = summary.migrated ? 'Migrate again' : 'Apply migration';
  }
}

function findingsPanel(findings, applied) {
  const box = h('div', {});
  if (!findings.length) return empty('No findings: nothing to change for hybrid.');
  const filters = h('div', {class: 'toolbar'});
  const body = h('tbody', {});
  function render() {
    filters.replaceChildren(
      chips([['', 'All severities'], ...SEVERITIES.map(s => [s, SEVERITY_LABELS[s]])], detailState.severity,
        value => { detailState.severity = value; render(); }),
      chips([['', 'All categories'], ...Object.entries(CATEGORY_LABELS)], detailState.category,
        value => { detailState.category = value; render(); }),
      chips([['', 'Any fix'], ['AUTO', 'Automatic'], ['MANUAL', 'Manual']], detailState.fix,
        value => { detailState.fix = value; render(); }));
    const rows = findings
      .filter(f => (!detailState.severity || f.severity === detailState.severity)
        && (!detailState.category || f.category === detailState.category)
        && (!detailState.fix || f.fix === detailState.fix))
      .map(f => h('tr', {},
        h('td', {}, severity(f.severity)),
        h('td', {class: 'nowrap'}, h('code', {}, f.rule)),
        h('td', {}, f.bundle),
        h('td', {}, h('code', {}, f.location)),
        h('td', {}, f.message),
        h('td', {class: 'sub'}, f.action),
        h('td', {}, fixBadge(f, applied))));
    body.replaceChildren(...(rows.length ? rows : [h('tr', {}, h('td', {colspan: 7, class: 'sub'}, 'No finding matches the filter.'))]));
  }
  render();
  box.append(filters, h('div', {class: 'wrap'}, h('table', {style: 'min-width:960px'},
    h('thead', {}, h('tr', {}, ['Severity', 'Rule', 'Bundle', 'Where', 'Finding', 'What to do', 'Fix'].map(t => h('th', {}, t)))),
    body)));
  return box;
}

function changesPanel(migration) {
  const box = h('div', {});
  const bundles = migration.bundles.filter(b => b.files.length);
  if (!bundles.length) return empty('The migration makes no automatic change to these bundles.');
  box.append(h('p', {class: 'meta', style: 'margin-top:16px'},
    migration.applied ? 'Changes written by the migration.' : 'Preview: nothing is written until you apply the migration.'));
  for (const bundle of bundles) {
    box.append(h('h3', {}, bundle.name, h('span', {class: 'sub'}, '  ' + (bundle.type === 'API_PROXY' ? 'API proxy' : 'Shared flow'))));
    for (const file of bundle.files) {
      const lines = diffLines(file.before, file.after);
      const added = lines.filter(l => l[0] === 'add').length;
      const removed = lines.filter(l => l[0] === 'del').length;
      const details = h('details', {class: 'file'},
        h('summary', {}, h('code', {}, file.path),
          file.after === null ? h('span', {class: 'badge bad'}, 'removed') : h('span', {class: 'badge auto'}, 'modified'),
          h('span', {class: 'sub mono'}, '+' + added + ' −' + removed)));
      details.addEventListener('toggle', () => {
        if (details.open && details.children.length === 1) details.append(diffView(lines));
      }, {once: false});
      box.append(details);
    }
  }
  return box;
}

/** Line diff (longest common subsequence) of two texts; {@code after} null means the file is removed. */
function diffLines(before, after) {
  const split = text => text === null ? [] : text.replace(/\n$/, '').split('\n');
  const a = split(before), b = split(after);
  const n = a.length, m = b.length;
  const lcs = Array.from({length: n + 1}, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push(['same', a[i]]); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) out.push(['del', a[i++]]);
    else out.push(['add', b[j++]]);
  }
  while (i < n) out.push(['del', a[i++]]);
  while (j < m) out.push(['add', b[j++]]);
  return out;
}

/** Unified diff with 3 lines of context; longer unchanged runs are folded. */
function diffView(lines) {
  const CONTEXT = 3;
  const out = h('div', {class: 'diff'});
  let k = 0;
  while (k < lines.length) {
    if (lines[k][0] !== 'same') {
      out.append(h('div', {class: lines[k][0]}, lines[k][1]));
      k++;
      continue;
    }
    let end = k;
    while (end < lines.length && lines[end][0] === 'same') end++;
    const run = lines.slice(k, end);
    const head = k === 0 ? 0 : CONTEXT;
    const tail = end === lines.length ? 0 : CONTEXT;
    if (run.length > head + tail + 1) {
      run.slice(0, head).forEach(l => out.append(h('div', {class: 'same'}, l[1])));
      out.append(h('div', {class: 'gap'}, '… ' + (run.length - head - tail) + ' unchanged line(s)'));
      run.slice(run.length - tail).forEach(l => out.append(h('div', {class: 'same'}, l[1])));
    } else {
      run.forEach(l => out.append(h('div', {class: 'same'}, l[1])));
    }
    k = end;
  }
  return out;
}

function resourcesPanel(resources) {
  if (!resources.length) return empty('Nothing to create in hybrid for this proxy.');
  return h('div', {style: 'margin-top:16px'}, table(['Kind', 'Name', 'Details', 'Needed by'], resources.map(r => h('tr', {},
    h('td', {class: 'nowrap'}, r.kind), h('td', {}, h('code', {}, r.name)), h('td', {class: 'sub'}, r.details), h('td', {}, r.requiredBy)))));
}

function mapPanel(id) {
  return h('div', {},
    h('p', {class: 'meta', style: 'margin-top:16px'}, 'The graph is drawn with Mermaid, loaded from the internet; the tables below it work offline.'),
    h('iframe', {class: 'frame', title: 'Dependency map', src: '/api/map?id=' + encodeURIComponent(id)}));
}

// ---------------------------------------------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------------------------------------------

async function overviewView() {
  const overview = await api.overview();
  const page = h('div', {}, h('div', {class: 'head'},
    h('div', {}, h('h1', {}, 'Overview'), h('p', {class: 'meta'}, 'All proxies of the proxies folder, with their shared flows.')),
    h('div', {class: 'actions'}, h('button', {type: 'button', onclick: route}, 'Refresh'))));
  if (!overview.proxies && !overview.failed) {
    page.append(h('div', {style: 'margin-top:16px'}, empty('No proxies to summarize yet.', h('a', {class: 'button', href: '#/settings'}, 'Open Settings'))));
    return page;
  }
  page.append(cards([
    [overview.proxies, 'Proxies analyzed'],
    [overview.migrated + ' / ' + overview.proxies, 'Migrated'],
    [overview.errors, 'Errors'],
    [overview.warnings, 'Warnings'],
    [overview.autoFixes, 'Fixable automatically'],
    [overview.manual, 'Manual fixes'],
  ]));
  if (overview.failed) page.append(errorBox({message: overview.failed + ' proxy(ies) could not be analyzed: see the Proxies list.'}));

  page.append(h('h2', {}, 'Most frequent findings'));
  page.append(overview.rules.length ? table(['Rule', 'Category', {label: 'Proxies', class: 'num'}, {label: 'Findings', class: 'num'}, 'By severity'],
    overview.rules.map(r => h('tr', {},
      h('td', {}, h('code', {}, r.id), ' ', r.title),
      h('td', {class: 'nowrap'}, r.category),
      h('td', {class: 'num'}, r.proxies),
      h('td', {class: 'num'}, r.findings),
      h('td', {class: 'nowrap'}, Object.entries(r.bySeverity).map(([s, n]) => h('span', {class: s, style: 'margin-right:10px'}, n + ' ' + s))))))
    : empty('No findings.'));

  page.append(h('h2', {}, 'To create in hybrid'));
  page.append(overview.resources.length ? table(['Kind', 'Name', 'Details', 'Needed by'], overview.resources.map(r => {
    const shown = r.proxies.slice(0, 5).join(', ');
    return h('tr', {},
      h('td', {class: 'nowrap'}, r.kind), h('td', {}, h('code', {}, r.name)), h('td', {class: 'sub'}, r.details),
      h('td', {title: r.proxies.join(', ')}, shown, r.proxies.length > 5 ? h('span', {class: 'sub'}, ' +' + (r.proxies.length - 5) + ' more') : null));
  })) : empty('Nothing to create.'));
  return page;
}

// ---------------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------------

async function settingsView() {
  const data = await api.settings();
  const saved = JSON.stringify(data.settings);
  const draft = JSON.parse(saved);
  draft.namingPrefixes = {...draft.namingPrefixes};
  draft.severities = {...draft.severities};
  const dirty = () => JSON.stringify(normalize(draft)) !== JSON.stringify(normalize(JSON.parse(saved)));
  leaveGuard = silent => !dirty() || (!silent && confirm('Discard your unsaved settings?'));

  const page = h('div', {}, h('h1', {}, 'Settings'),
    h('p', {class: 'meta'}, 'Folders are absolute paths on this computer, e.g. C:\\apigee\\proxies or /home/me/apigee/proxies.'));
  const saveButton = h('button', {type: 'button', class: 'primary', onclick: save}, 'Save settings');
  const discardButton = h('button', {type: 'button', onclick: () => { leaveGuard = null; route(); }}, 'Discard changes');
  const changed = () => { saveButton.disabled = !dirty(); discardButton.disabled = !dirty(); };

  // Folders
  const sharedList = h('div', {});
  function renderShared() {
    sharedList.replaceChildren(...draft.sharedFlowDirs.map((dir, index) => {
      const check = (data.checks.sharedFlowDirs || []).find(c => c.path === dir);
      return h('div', {},
        h('div', {class: 'row'},
          h('input', {type: 'text', value: dir, 'aria-label': 'Shared flows folder ' + (index + 1), spellcheck: 'false',
            oninput: e => { draft.sharedFlowDirs[index] = e.target.value; changed(); }}),
          h('button', {type: 'button', 'aria-label': 'Remove folder', onclick: () => { draft.sharedFlowDirs.splice(index, 1); renderShared(); changed(); }}, 'Remove')),
        check ? status(check) : null);
    }));
    sharedList.append(h('button', {type: 'button', onclick: () => { draft.sharedFlowDirs.push(''); renderShared(); changed(); }}, 'Add folder'));
  }
  renderShared();

  page.append(h('section', {class: 'form-section'}, h('h2', {}, 'Folders'),
    folderField('proxiesRoot', 'Proxies folder', 'Searched for apiproxy/ folders, up to 6 levels deep. One sub-folder per proxy.', data.checks.proxiesRoot),
    h('div', {class: 'field'}, h('label', {}, 'Shared flow folders'),
      h('p', {class: 'hint'}, 'Searched for sharedflowbundle/ folders. Shared flows called by a proxy are analyzed and migrated with it.'),
      sharedList),
    folderField('outputDir', 'Output folder', 'Each migrated proxy is written to <output folder>/<proxy name>, with its shared flows. The source bundles are never modified.', data.checks.outputDir)));

  function folderField(key, label, hint, check) {
    return h('div', {class: 'field'}, h('label', {for: 'f-' + key}, label), h('p', {class: 'hint'}, hint),
      h('div', {class: 'row'}, h('input', {type: 'text', id: 'f-' + key, value: draft[key], spellcheck: 'false',
        oninput: e => { draft[key] = e.target.value; changed(); }})),
      status(check));
  }

  function status(check) {
    if (!check || (!check.path && !check.message)) return null;
    return h('div', {class: 'status ' + (check.exists ? 'ok' : 'bad')}, (check.exists ? '✓ ' : '! ') + check.message);
  }

  // Rules
  const rulesSection = h('section', {class: 'form-section'}, h('h2', {}, 'Migration rules'),
    h('p', {class: 'meta', style: 'margin:-4px 0 12px'}, 'A disabled rule is not checked, and its automatic fix is not applied.'));
  for (const [category, label] of Object.entries(CATEGORY_LABELS)) {
    const rules = data.rules.filter(r => r.category === category);
    rulesSection.append(h('h3', {}, label), table(['Enabled', 'Rule', 'Severity'], rules.map(rule => h('tr', {},
      h('td', {style: 'width:72px'}, h('input', {type: 'checkbox', checked: !draft.disabledRules.includes(rule.id),
        'aria-label': 'Enable ' + rule.id,
        onchange: e => {
          draft.disabledRules = draft.disabledRules.filter(id => id !== rule.id);
          if (!e.target.checked) draft.disabledRules.push(rule.id);
          changed();
        }})),
      h('td', {}, h('code', {}, rule.id), ' ', rule.title, rule.autoFix ? [' ', h('span', {class: 'badge auto'}, 'auto-fix')] : null),
      h('td', {style: 'width:170px'}, h('select', {'aria-label': 'Severity of ' + rule.id,
          onchange: e => { if (e.target.value) draft.severities[rule.id] = e.target.value; else delete draft.severities[rule.id]; changed(); }},
        [['', 'Default'], ...SEVERITIES.map(s => [s, s])].map(([value, text]) =>
          h('option', {value, selected: (draft.severities[rule.id] || '') === value}, text))))))));
  }
  page.append(rulesSection);

  // Naming prefixes
  const types = Object.keys({...data.defaultNamingPrefixes, ...draft.namingPrefixes}).sort();
  page.append(h('section', {class: 'form-section'}, h('h2', {}, 'Policy naming prefixes'),
    h('p', {class: 'meta', style: 'margin:-4px 0 12px'},
      'Used by rule DES-06. Comma-separated prefixes accepted for each policy type (a name passes when it starts with a prefix followed by - or _). Leave a field empty to keep the default.'),
    table(['Policy type', 'Accepted prefixes'], types.map(type => h('tr', {},
      h('td', {class: 'nowrap'}, h('code', {}, type)),
      h('td', {}, h('input', {type: 'text', class: 'prefix-input', 'aria-label': 'Prefixes for ' + type, spellcheck: 'false',
        value: (draft.namingPrefixes[type] || []).join(', '),
        placeholder: (data.defaultNamingPrefixes[type] || []).join(', ') || 'no check',
        oninput: e => {
          const prefixes = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
          if (prefixes.length) draft.namingPrefixes[type] = prefixes; else delete draft.namingPrefixes[type];
          changed();
        }})))))));

  page.append(h('div', {class: 'savebar'}, h('div', {},
    h('span', {class: 'sub', title: data.file}, 'Saved in ' + data.file), discardButton, saveButton)));
  changed();

  async function save() {
    saveButton.disabled = true;
    try {
      await api.saveSettings(normalize(draft));
      leaveGuard = null;
      toast('Settings saved');
      route();
    } catch (error) {
      toast(error.message, true);
      changed();
    }
  }
  return page;
}

function normalize(settings) {
  return {
    proxiesRoot: (settings.proxiesRoot || '').trim(),
    sharedFlowDirs: (settings.sharedFlowDirs || []).map(s => s.trim()).filter(Boolean),
    outputDir: (settings.outputDir || '').trim(),
    disabledRules: [...(settings.disabledRules || [])].sort(),
    severities: Object.fromEntries(Object.entries(settings.severities || {}).sort()),
    namingPrefixes: Object.fromEntries(Object.entries(settings.namingPrefixes || {}).sort()),
  };
}

route();
