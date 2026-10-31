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
  saveToken: token => request('PUT', '/api/token', {token}),
  proxies: () => request('GET', '/api/proxies'),
  proxy: id => request('GET', '/api/proxy?id=' + encodeURIComponent(id)),
  apply: (id, overwrite) => request('POST', '/api/apply?id=' + encodeURIComponent(id) + (overwrite ? '&overwrite=true' : '')),
  overview: () => request('GET', '/api/overview'),
  variables: id => request('GET', '/api/variables?id=' + encodeURIComponent(id)),
  // a failed fix answers 200 with an error
  proposeFix: (id, finding) => request('POST', '/api/fix?id=' + encodeURIComponent(id),
    {bundle: finding.bundle, rule: finding.rule, location: finding.location})
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  proposeFixes: (id, findings) => request('POST', '/api/fix/all?id=' + encodeURIComponent(id),
    {findings: findings.map(f => ({bundle: f.bundle, rule: f.rule, location: f.location}))})
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  // a failed port answers 200 with an error
  proposePort: (id, finding) => request('POST', '/api/port?id=' + encodeURIComponent(id),
    {bundle: finding.bundle, rule: finding.rule, location: finding.location})
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  // a failed triage answers 200 with an error
  triage: (id, findings) => request('POST', '/api/triage?id=' + encodeURIComponent(id),
    {findings: findings.map(f => ({bundle: f.bundle, rule: f.rule, location: f.location}))})
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  // a failed review answers 200 with an error
  reviewScripts: (id, again) => request('POST', '/api/review?id=' + encodeURIComponent(id) + (again ? '&again=true' : ''))
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  documentation: id => request('GET', '/api/document?id=' + encodeURIComponent(id)),
  // a failed documentation answers 200 with an error
  document: id => request('POST', '/api/document?id=' + encodeURIComponent(id))
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  testPlan: id => request('GET', '/api/tests?id=' + encodeURIComponent(id)),
  // a failed test plan answers 200 with an error
  planTests: (id, options) => request('POST', '/api/tests?id=' + encodeURIComponent(id), options)
    .then(data => { if (data.error) throw new Error(data.error); return data; }),
  runTests: (id, run) => request('POST', '/api/tests/run?id=' + encodeURIComponent(id), run),
  acceptFix: proposal => request('POST', '/api/fix/accept?proposal=' + encodeURIComponent(proposal)),
  rejectFix: proposal => request('POST', '/api/fix/reject?proposal=' + encodeURIComponent(proposal)),
  markFalsePositive: (finding, reason) => request('POST', '/api/false-positive',
    {rule: finding.rule, bundle: finding.bundle, location: finding.location, reason}),
  unmarkFalsePositive: f => request('POST', '/api/false-positive/remove', {rule: f.rule, bundle: f.bundle, location: f.location}),
  history: id => request('GET', '/api/history?id=' + encodeURIComponent(id)),
  stepDiff: (id, bundle, step) => request('GET', '/api/history/diff?' + stepQuery(id, bundle, step)),
  revertStep: (id, bundle, step) => request('POST', '/api/history/revert?' + stepQuery(id, bundle, step)),
  editor: id => request('GET', '/api/editor?id=' + encodeURIComponent(id)),
  editorFile: (id, bundle, path) => request('GET', '/api/editor/file?id=' + encodeURIComponent(id)
    + '&bundle=' + encodeURIComponent(bundle) + '&path=' + encodeURIComponent(path)),
  editorCheck: (id, buffers) => request('POST', '/api/editor/check?id=' + encodeURIComponent(id), {buffers}),
  editorSave: (id, files) => request('POST', '/api/editor/save?id=' + encodeURIComponent(id), {files}),
  editorAssist: (id, asked) => request('POST', '/api/editor/assist?id=' + encodeURIComponent(id), asked),
  editorSimulate: (id, call) => request('POST', '/api/editor/simulate?id=' + encodeURIComponent(id), call),
  editorRename: (id, change) => request('POST', '/api/editor/rename?id=' + encodeURIComponent(id), change),
};

function stepQuery(id, bundle, step) {
  return 'id=' + encodeURIComponent(id) + '&bundle=' + encodeURIComponent(bundle) + '&step=' + encodeURIComponent(step);
}

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

/** Asks for a text that cannot be blank; resolves to it, or to null when cancelled. */
function textDialog(title, message, label, confirmLabel) {
  return new Promise(resolve => {
    const input = h('textarea', {rows: 3, 'aria-label': label, placeholder: label,
      oninput: () => { confirmButton.disabled = !input.value.trim(); }});
    const confirmButton = h('button', {type: 'button', class: 'primary', disabled: true,
      onclick: () => { const text = input.value.trim(); dialog.close(); resolve(text); }}, confirmLabel);
    const dialog = h('dialog', {},
      h('h2', {}, title), h('p', {}, message), input,
      h('div', {class: 'actions'},
        h('button', {type: 'button', onclick: () => { dialog.close(); resolve(null); }}, 'Cancel'), confirmButton));
    dialog.addEventListener('close', () => { dialog.remove(); resolve(null); });
    document.body.append(dialog);
    dialog.showModal();
    input.focus();
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
let leaveView = null;
let currentHash = location.hash;

/** Renders the view for the current hash; results of a previous, slower render are dropped. */
async function route() {
  const [name = 'proxies', ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  const routes = {proxies: proxiesView, proxy: proxyView, editor: editorView, overview: overviewView, settings: settingsView};
  const render = routes[name] || proxiesView;
  document.querySelectorAll('[data-nav]').forEach(a =>
    a.classList.toggle('active', a.dataset.nav === (name === 'proxy' || name === 'editor' ? 'proxies' : name)));
  document.body.classList.toggle('wide', name === 'editor');
  const token = ++renderToken;
  leaveGuard = null;
  if (leaveView) leaveView();
  leaveView = null;
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
/** The likely false positives found by a triage, by proxy id then finding key, until confirmed or kept. */
const triaged = {};

function findingKey(f) {
  return f.bundle + '\n' + f.rule + '\n' + f.location;
}

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
  const falsePositives = migration.bundles.flatMap(b => b.falsePositives);
  const stale = migration.bundles.flatMap(b => b.staleFalsePositives);
  const files = migration.bundles.flatMap(b => b.files);
  const tabs = [
    ['editor', 'Editor', null],
    ['findings', 'Findings', findings.length],
    ['documentation', 'Documentation', null],
    ['tests', 'Regression tests', null],
    ['changes', 'Changes', files.length],
    ['resources', 'To create in hybrid', migration.resources.length],
    ['variables', 'Variables', null],
    ['map', 'Dependency map', null],
    ['history', 'History', null],
  ];
  const panel = h('div', {});
  const tabBar = h('div', {class: 'tabs', role: 'tablist'});
  function showTab(tab) {
    if (tab === 'editor') {
      location.hash = '#/editor/' + encodeURIComponent(id);
      return;
    }
    detailState.tab = tab;
    tabBar.replaceChildren(...tabs.map(([key, label, n]) => h('button', {type: 'button', role: 'tab',
        class: key === tab ? 'on' : '', 'aria-selected': String(key === tab), onclick: () => showTab(key)},
      label, n === null ? null : h('span', {class: 'count'}, n))));
    const render = {findings: () => h('div', {}, reviewBar(id, detail.scripts), findingsPanel(id, findings, migration.applied, falsePositives, stale)), changes: () => changesPanel(migration),
      resources: () => resourcesPanel(migration.resources), variables: () => variablesPanel(id), map: () => mapPanel(id),
      history: () => historyPanel(id), documentation: () => documentationPanel(id), tests: () => testsPanel(id)}[tab];
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

/** How many scripts of the proxy were reviewed as they are now, and a button to review the others; null without scripts. */
function reviewBar(id, scripts) {
  if (!scripts || !scripts.total) return null;
  const pending = scripts.total - scripts.reviewed;
  const label = () => pending ? 'Review scripts' : 'Review again';
  const button = h('button', {type: 'button', class: pending ? 'primary' : '',
    title: pending ? 'Look for problems in the JavaScript that the rules cannot see; the result is kept until a script changes'
      : 'Review every script again, replacing the REV-01 findings', onclick: () => review()}, label());
  const status = h('span', {class: 'meta'}, !scripts.reviewed
    ? scripts.total + ' script(s), not reviewed yet: a review looks for problems the rules cannot see.'
    : pending ? scripts.reviewed + ' of ' + scripts.total + ' script(s) reviewed: the REV-01 findings come from the reviewed ones.'
    : 'All ' + scripts.total + ' script(s) reviewed: their findings are listed under REV-01.');
  const bar = h('div', {class: 'review-bar'}, status, button);

  /** Starts a review, or waits for the one running since {@code since}. */
  async function review(since) {
    button.disabled = true;
    button.replaceChildren(h('span', {class: 'spinner'}), ' Reviewing…');
    status.replaceChildren('Reviewing ' + (pending || scripts.total) + ' script(s) for ', elapsed(since),
      '. This can take a few minutes.');
    try {
      const result = await api.reviewScripts(id, !pending);
      toast('Reviewed ' + result.reviewed + ' script(s): ' + result.remarks + ' finding(s)');
      route();
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
      button.textContent = label();
    }
  }
  if (scripts.running) review(scripts.running);
  return bar;
}

function findingsPanel(id, findings, applied, falsePositives, stale) {
  const marked = falsePositivesSection(falsePositives, stale);
  if (!findings.length) return h('div', {}, empty('No findings: nothing to change for hybrid.'), marked);
  const box = h('div', {});
  const filters = h('div', {class: 'toolbar'});
  const notice = h('div', {});
  const body = h('tbody', {});
  function render() {
    filters.replaceChildren(
      chips([['', 'All severities'], ...SEVERITIES.map(s => [s, SEVERITY_LABELS[s]])], detailState.severity,
        value => { detailState.severity = value; render(); }),
      chips([['', 'All categories'], ...Object.entries(CATEGORY_LABELS)], detailState.category,
        value => { detailState.category = value; render(); }),
      chips([['', 'Any fix'], ['AUTO', 'Automatic'], ['MANUAL', 'Manual']], detailState.fix,
        value => { detailState.fix = value; render(); }));
    const shown = findings
      .filter(f => (!detailState.severity || f.severity === detailState.severity)
        && (!detailState.category || f.category === detailState.category)
        && (!detailState.fix || f.fix === detailState.fix));
    const manual = shown.filter(f => f.fix === 'MANUAL');
    const likely = triaged[id] || new Map();
    const flagged = shown.filter(f => likely.has(findingKey(f)));
    if (shown.length) {
      const tooMany = shown.length > MAX_TRIAGE;
      filters.append(h('button', {type: 'button', class: 'push', disabled: tooMany,
        title: tooMany ? 'At most ' + MAX_TRIAGE + ' findings can be triaged together: filter them first'
          : 'Look for false positives among the ' + shown.length + ' findings shown; nothing is marked until you confirm',
        onclick: event => triage(event.currentTarget, shown)}, 'Spot false positives'));
    }
    if (manual.length > 1) {
      const tooMany = manual.length > MAX_GROUPED;
      filters.append(h('button', {type: 'button', class: shown.length ? '' : 'push', disabled: tooMany,
        title: tooMany ? 'At most ' + MAX_GROUPED + ' findings can be fixed together: filter them first'
          : 'Get one set of changes for the ' + manual.length + ' manual findings shown, and review it before it is written',
        onclick: () => groupFixDialog(id, manual)}, 'Propose fixes for ' + manual.length + ' findings'));
    }
    notice.replaceChildren(...(flagged.length ? [h('div', {class: 'triage-bar'},
      h('span', {}, h('b', {}, flagged.length), flagged.length === 1 ? ' finding looks like a false positive.'
        : ' findings look like false positives.', ' ', h('span', {class: 'sub'}, 'Check the reason under each one before you confirm it.')),
      h('div', {class: 'row-actions'},
        h('button', {type: 'button', onclick: () => { flagged.forEach(f => likely.delete(findingKey(f))); render(); }}, 'Keep all'),
        h('button', {type: 'button', class: 'primary', onclick: () => confirmAll(flagged)}, 'Confirm all')))] : []));
    const rows = shown
      .flatMap(f => [h('tr', {class: likely.has(findingKey(f)) ? 'flagged' : ''},
        h('td', {}, severity(f.severity)),
        h('td', {class: 'nowrap'}, h('code', {}, f.rule)),
        h('td', {}, f.bundle),
        h('td', {}, h('code', {}, f.location)),
        h('td', {}, f.message),
        h('td', {class: 'sub'}, f.action),
        h('td', {}, fixBadge(f, applied)),
        h('td', {}, h('div', {class: 'row-actions'},
          portable(f)
            ? h('button', {type: 'button', title: 'Get a proposed replacement for this target, as policies or as a service of its own, and review it before it is written',
                onclick: () => portDialog(id, f)}, 'Propose a port')
            : f.fix === 'MANUAL'
            ? h('button', {type: 'button', title: 'Get a proposed fix for this finding and review it before it is written',
                onclick: () => fixDialog(id, f)}, 'Propose a fix')
            : null,
          h('button', {type: 'button', title: 'Stop reporting this finding' + (f.fix === 'AUTO' ? ' and do not apply its automatic fix' : ''),
            onclick: () => markFalsePositive(f)}, 'False positive')))),
        likely.has(findingKey(f)) ? h('tr', {class: 'triage'}, h('td', {colspan: 8}, h('div', {},
          h('span', {class: 'badge warn'}, 'likely false positive'), ' ',
          h('span', {}, likely.get(findingKey(f))),
          h('div', {class: 'row-actions'},
            h('button', {type: 'button', title: 'Keep reporting this finding',
              onclick: () => { likely.delete(findingKey(f)); render(); }}, 'Keep'),
            h('button', {type: 'button', class: 'primary', title: 'Mark it as a false positive, with this reason',
              onclick: () => confirmOne(f)}, 'Confirm'))))) : null]
        .filter(Boolean));
    body.replaceChildren(...(rows.length ? rows : [h('tr', {}, h('td', {colspan: 8, class: 'sub'}, 'No finding matches the filter.'))]));
  }

  async function triage(button, picked) {
    button.disabled = true;
    button.replaceChildren(h('span', {class: 'spinner'}), ' Triaging…');
    try {
      const result = await api.triage(id, picked);
      const likely = triaged[id] || (triaged[id] = new Map());
      picked.forEach(f => likely.delete(findingKey(f)));
      result.falsePositives.forEach(f => likely.set(findingKey(f), f.reason));
      toast(result.falsePositives.length
        ? result.falsePositives.length + ' of ' + picked.length + ' findings look like false positives'
        : 'No false positive spotted among ' + picked.length + ' findings');
    } catch (error) {
      toast(error.message, true);
    }
    render();
  }

  async function confirmOne(f) {
    try {
      await api.markFalsePositive(f, triaged[id].get(findingKey(f)));
      triaged[id].delete(findingKey(f));
      toast(f.rule + ' at ' + f.bundle + ' · ' + f.location + ' marked as a false positive');
      route();
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function confirmAll(flagged) {
    const ok = await confirmDialog('Mark ' + flagged.length + ' findings as false positives?',
      'They will no longer be reported nor counted, and their automatic fixes will not be applied. Each keeps its reason. '
        + 'You can report any of them again at any time.', 'Mark as false positives');
    if (!ok) return;
    let marked = 0;
    try {
      for (const f of flagged) {
        await api.markFalsePositive(f, triaged[id].get(findingKey(f)));
        triaged[id].delete(findingKey(f));
        marked++;
      }
      toast(marked + ' findings marked as false positives');
    } catch (error) {
      toast(error.message, true);
    }
    route();
  }

  render();
  box.append(filters, notice, h('div', {class: 'wrap'}, h('table', {style: 'min-width:1060px'},
    h('thead', {}, h('tr', {}, ['Severity', 'Rule', 'Bundle', 'Where', 'Finding', 'What to do', 'Fix', ''].map(t => h('th', {}, t)))),
    body)), marked);
  return box;
}

async function markFalsePositive(finding) {
  const where = finding.bundle + ' · ' + finding.location;
  const reason = await textDialog('Mark as a false positive',
    finding.rule + ' at ' + where + ' will no longer be reported nor counted'
      + (finding.fix === 'AUTO' ? ', and its automatic fix will not be applied' : '')
      + '. Every finding of this rule at this place is covered. You can report it again at any time.',
    'Why this is not a problem', 'Mark as false positive');
  if (reason === null) return;
  try {
    await api.markFalsePositive(finding, reason);
    toast(finding.rule + ' at ' + where + ' marked as a false positive');
    route();
  } catch (error) {
    toast(error.message, true);
  }
}

async function unmarkFalsePositive(falsePositive) {
  try {
    await api.unmarkFalsePositive(falsePositive);
    toast(falsePositive.rule + ' at ' + falsePositive.bundle + ' · ' + falsePositive.location + ' is reported again');
    route();
  } catch (error) {
    toast(error.message, true);
  }
}

/** The findings marked as false positives, and those that no longer match anything; null when there are none. */
function falsePositivesSection(falsePositives, stale) {
  if (!falsePositives.length && !stale.length) return null;
  const rows = [
    ...falsePositives.map(({finding: f, reason}) => h('tr', {},
      h('td', {class: 'nowrap'}, h('code', {}, f.rule)), h('td', {}, f.bundle), h('td', {}, h('code', {}, f.location)),
      h('td', {}, f.message), h('td', {class: 'sub'}, reason),
      h('td', {class: 'nowrap'}, h('button', {type: 'button', onclick: () => unmarkFalsePositive(f)}, 'Report again')))),
    ...stale.map(f => h('tr', {},
      h('td', {class: 'nowrap'}, h('code', {}, f.rule)), h('td', {}, f.bundle), h('td', {}, h('code', {}, f.location)),
      h('td', {}, h('span', {class: 'badge'}, 'no longer found'), ' ', h('span', {class: 'sub'},
        'The finding is gone, or its rule is disabled.')),
      h('td', {class: 'sub'}, f.reason),
      h('td', {class: 'nowrap'}, h('button', {type: 'button', onclick: () => unmarkFalsePositive(f)}, 'Remove')))),
  ];
  return h('details', {class: 'false-positives'},
    h('summary', {}, 'Marked as false positives', h('span', {class: 'count'}, falsePositives.length + stale.length)),
    h('p', {class: 'meta'}, 'Not reported nor counted, and their automatic fixes are not applied.'),
    table(['Rule', 'Bundle', 'Where', 'Finding', 'Why', ''], rows));
}

/** At most this many findings are fixed together (UiService.MAX_GROUPED). */
const MAX_GROUPED = 30;
/** At most this many findings are triaged together (UiService.MAX_TRIAGE). */
const MAX_TRIAGE = 100;

/**
 * Asks the backend for a fix of one finding and shows it as diffs. Accept writes it to the source bundles as a step
 * of their history; Reject drops it. Nothing is written before Accept.
 */
function fixDialog(id, finding) {
  proposalDialog([h('code', {}, finding.rule), ' ', finding.message],
    h('p', {class: 'meta mono'}, finding.bundle + ' · ' + finding.location),
    ' Preparing a fix. This can take a minute or two.', () => api.proposeFix(id, finding),
    'No change proposed for this finding.');
}

/** Whether the finding is a Node.js or hosted target to port (PortContext.portable). */
function portable(finding) {
  return finding.rule === 'HYB-04' && finding.location.startsWith('TargetEndpoint ');
}

/**
 * Asks the backend how to replace a Node.js or hosted target: policies of the proxy, or a service of its own. Accept
 * writes the bundle changes as a step of their history, and the service to its folder.
 */
function portDialog(id, finding) {
  proposalDialog(['Port of ', h('code', {}, finding.location.replace(/^TargetEndpoint /, ''))],
    h('p', {class: 'meta mono'}, finding.bundle + ' · ' + finding.message),
    ' Preparing a port. This can take several minutes.', () => api.proposePort(id, finding),
    'No change proposed for this target.');
}

/** The approach of a port and the service it moves the target to, if any. */
function portView(proposal) {
  if (!proposal.approach) return null;
  const approach = h('p', {}, h('span', {class: 'badge auto'},
    proposal.approach === 'SERVICE' ? 'own service' : 'policies'), ' ',
    proposal.approach === 'SERVICE' ? 'The application moves to a service of its own, reached through a TargetServer.'
      : 'The application is rewritten as policies of the proxy.');
  const service = proposal.service;
  if (!service) return approach;
  const server = service.targetServer;
  return h('div', {}, approach, h('div', {class: 'service'},
    h('h3', {}, 'Service ', h('code', {}, service.name), service.runtime ? h('span', {class: 'sub'}, '  ' + service.runtime) : null),
    h('p', {class: 'meta'}, 'Written to ', h('code', {}, service.folder), ' when you accept.'),
    server ? h('p', {}, 'TargetServer ', h('code', {}, server.name), ' → ', h('code', {},
      (server.host || '?') + ':' + server.port), server.sslEnabled ? ' with TLS' : ' without TLS',
      h('span', {class: 'sub'}, ' · to create in every environment')) : null,
    service.steps.length ? h('div', {}, h('b', {}, 'To deploy it'), h('ol', {}, service.steps.map(step => h('li', {}, step)))) : null,
    service.files.map(file => h('details', {class: 'file'},
      h('summary', {}, h('code', {}, file.path), h('span', {class: 'sub'}, file.content.replace(/\n$/, '').split('\n').length + ' lines')),
      h('pre', {class: 'message'}, file.content)))));
}

/** The same for several findings at once: one set of changes, recorded as one step per bundle. */
function groupFixDialog(id, findings) {
  proposalDialog(['Fixes of ' + findings.length + ' findings'],
    h('details', {class: 'grouped'}, h('summary', {class: 'meta'}, 'The findings to fix'),
      h('ul', {}, findings.map(f => h('li', {}, h('code', {}, f.rule), ' ', h('span', {class: 'mono'},
        f.bundle + ' · ' + f.location), ' ', h('span', {class: 'sub'}, f.message))))),
    ' Preparing one set of changes for ' + findings.length + ' findings. This can take several minutes.',
    () => api.proposeFixes(id, findings), 'No change proposed for these findings.');
}

async function proposalDialog(title, subtitle, waiting, ask, nothing) {
  let proposal = null;
  const body = h('div', {class: 'proposal'},
    h('p', {class: 'meta'}, h('span', {class: 'spinner'}), waiting));
  const reject = h('button', {type: 'button', onclick: () => dialog.close()}, 'Reject');
  const accept = h('button', {type: 'button', class: 'primary', disabled: true, onclick: acceptProposal}, 'Accept');
  const dialog = h('dialog', {class: 'wide'},
    h('h2', {}, ...title),
    subtitle,
    body,
    h('div', {class: 'actions'}, reject, accept));
  dialog.addEventListener('close', () => {
    if (proposal && !dialog.dataset.accepted) api.rejectFix(proposal.proposal).catch(() => {});
    dialog.remove();
  });
  document.body.append(dialog);
  dialog.showModal();

  try {
    proposal = await ask();
  } catch (error) {
    body.replaceChildren(errorBox(error));
    reject.textContent = 'Close';
    return;
  }
  if (!dialog.open) {
    api.rejectFix(proposal.proposal).catch(() => {});
    return;
  }
  body.replaceChildren(
    h('p', {class: 'meta'}, 'Nothing is written until you accept.'),
    h('p', {}, proposal.summary),
    proposal.warnings.length ? h('div', {class: 'warnings'}, h('b', {}, 'Check before deploying'),
      h('ul', {}, proposal.warnings.map(w => h('li', {}, w)))) : null,
    portView(proposal),
    proposal.edits.length ? h('div', {}, proposal.edits.map(edit => h('div', {class: 'file-edit'},
      h('div', {}, h('span', {class: 'badge ' + (edit.action === 'delete' ? 'bad' : 'auto')}, edit.action), ' ',
        h('code', {}, edit.bundle + '/' + edit.path)),
      h('p', {class: 'sub'}, edit.reason),
      diffView(diffLines(edit.before, edit.after)))))
      : proposal.service ? null : empty(nothing));
  accept.disabled = !proposal.edits.length && !proposal.service;

  async function acceptProposal() {
    accept.disabled = reject.disabled = true;
    accept.textContent = 'Writing…';
    try {
      const steps = await api.acceptFix(proposal.proposal);
      dialog.dataset.accepted = 'true';
      dialog.close();
      toast((proposal.approach ? 'Port' : 'Fix') + ' written to the sources'
        + (steps.length ? ', recorded as step ' + steps.map(s => s.id).join(', ') : '')
        + (proposal.service ? '; service written to ' + proposal.service.folder : ''));
      detailState.tab = 'history';
      route();
    } catch (error) {
      toast(error.message, true);
      accept.textContent = 'Accept';
      reject.disabled = false;
    }
  }
}

/** The steps of the source bundles changed in place, each with its diff and a way to undo it. */
function historyPanel(id) {
  const box = h('div', {style: 'margin-top:16px'}, h('p', {class: 'meta'}, 'Loading…'));
  api.history(id).then(bundles => {
    if (!bundles.length) {
      box.replaceChildren(empty('No change made to the sources yet. Fixes you accept are recorded here, one step each, and can be undone.'));
      return;
    }
    box.replaceChildren(h('p', {class: 'meta'}, 'Changes made to the source bundles, newest first. Undoing a step records a new step.'));
    for (const bundle of bundles) {
      box.append(h('h3', {}, bundle.bundle, h('span', {class: 'sub'}, '  ' + (bundle.type === 'API_PROXY' ? 'API proxy' : 'Shared flow'))));
      if (bundle.pending.length) {
        box.append(h('p', {class: 'meta'}, h('span', {class: 'badge'}, 'not recorded'), ' Changed by hand since the last step: ',
          h('span', {class: 'mono'}, bundle.pending.join(', '))));
      }
      for (const step of bundle.steps) box.append(stepView(id, bundle, step));
    }
  }).catch(error => box.replaceChildren(errorBox(error)));
  return box;
}

function stepView(id, bundle, step) {
  const when = new Date(step.time).toLocaleString();
  const details = h('details', {class: 'file'},
    h('summary', {}, h('code', {}, step.id), h('span', {}, step.title),
      h('span', {class: 'sub'}, when + (step.original ? '' : ' · ' + step.files.length + ' file(s)'))));
  details.addEventListener('toggle', async () => {
    if (!details.open || details.dataset.loaded) return;
    details.dataset.loaded = 'true';
    const message = step.message.split('\n').slice(1).join('\n').trim();
    if (message) details.append(h('pre', {class: 'message'}, message));
    if (step.original) {
      details.append(h('p', {class: 'sub'}, 'The bundle as it was before any change: ' + step.files.length + ' file(s).'));
      return;
    }
    details.append(h('div', {class: 'actions', style: 'margin:8px 0'},
      h('button', {type: 'button', onclick: event => revert(event.target)}, 'Undo this step')));
    try {
      details.append(unifiedDiffView((await api.stepDiff(id, bundle.bundle, step.id)).diff));
    } catch (error) {
      details.append(errorBox(error));
    }
  });

  async function revert(button) {
    const ok = await confirmDialog('Undo step ' + step.id + '?',
      'The changes of "' + step.title + '" are undone in ' + bundle.bundle + ' and recorded as a new step.', 'Undo');
    if (!ok) return;
    button.disabled = true;
    try {
      const done = await api.revertStep(id, bundle.bundle, step.id);
      toast('Undone, recorded as step ' + done.id);
      route();
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }
  return details;
}

/** A git unified diff: file headers, hunk headers, added and removed lines. */
function unifiedDiffView(text) {
  const out = h('div', {class: 'diff'});
  for (const line of text.replace(/\n$/, '').split('\n')) {
    if (line.startsWith('diff --git ')) out.append(h('div', {class: 'file-head'}, line.slice(11).replace(/^a\/(\S+) b\/\S+$/, '$1')));
    else if (/^(index |--- |\+\+\+ |new file|deleted file|similarity|rename )/.test(line)) continue;
    else if (line.startsWith('@@')) out.append(h('div', {class: 'gap'}, line));
    else if (line.startsWith('+')) out.append(h('div', {class: 'add'}, line.slice(1)));
    else if (line.startsWith('-')) out.append(h('div', {class: 'del'}, line.slice(1)));
    else out.append(h('div', {class: 'same'}, line.slice(1)));
  }
  return out;
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
  const split = text => text === null ? [] : text.replace(/\r?\n$/, '').split(/\r?\n/);
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

const DEPENDENCY_KINDS = {TARGET: 'Target', CALLOUT: 'Service callout', SHARED_FLOW: 'Shared flow', KVM: 'Key value map',
  CACHE: 'Cache', OTHER: 'Other'};

/** The functional documentation of the proxy, kept once written, and a button to write it or write it again. */
function documentationPanel(id) {
  const box = h('div', {}, h('div', {class: 'loading'}, 'Loading the documentation…'));
  api.documentation(id).then(show, error => box.replaceChildren(errorBox(error)));

  function show(stored) {
    const button = h('button', {type: 'button', class: stored.doc && stored.current ? '' : 'primary',
      title: 'Describe what the proxy does from its files and those of its shared flows; it goes into the downloaded report',
      onclick: () => write()}, stored.doc ? 'Write again' : 'Write documentation');
    const status = h('span', {class: 'meta'}, !stored.doc
      ? 'No documentation yet: it describes the operations, security, dependencies and errors of the proxy for the team taking it over.'
      : stored.current ? 'Written on ' + day(stored.written) + '. It is part of the downloaded report.'
      : h('span', {}, 'Written on ' + day(stored.written) + ': ', h('span', {class: 'WARN'}, 'the proxy changed since, it may be out of date.')));
    const exportLink = stored.doc && h('a', {class: 'button', href: '/api/document/export?id=' + encodeURIComponent(id),
      title: 'Download the documentation as a Markdown file, to keep next to the proxy or in a wiki'}, 'Export Markdown');
    box.replaceChildren(...[h('div', {class: 'review-bar'}, status, h('div', {class: 'actions'}, exportLink, button)),
      stored.doc && docView(stored.doc)].filter(Boolean));

    if (stored.running) write(stored.running);

    /** Writes the documentation, or waits for the writing running since {@code since}. */
    async function write(since) {
      delete stored.running;
      button.disabled = true;
      button.replaceChildren(h('span', {class: 'spinner'}), ' Writing…');
      status.replaceChildren('Reading the proxy and its shared flows for ', elapsed(since), '. This can take a few minutes.');
      try {
        show(await api.document(id));
        toast('Documentation written');
      } catch (error) {
        toast(error.message, true);
        show(stored);
      }
    }
  }
  return box;
}

/** The last run of each proxy's plan, kept while the page is open; variable values are never kept. */
const testRuns = {};
const OUTCOMES = {SAME: ['ok', 'Same'], DIFFERENT: ['bad', 'Different'], ERROR: ['warn', 'Error'], SKIPPED: ['', 'Skipped']};

/**
 * The regression test plan of the proxy, kept once prepared, and a form to replay its requests on Edge then on hybrid
 * and compare the statuses and headers.
 */
function testsPanel(id) {
  const box = h('div', {}, h('div', {class: 'loading'}, 'Loading the test plan…'));
  api.testPlan(id).then(show, error => box.replaceChildren(errorBox(error)));

  function show(stored) {
    const button = h('button', {type: 'button', class: stored.plan && stored.current ? '' : 'primary',
      title: 'Plan requests from the flows and conditions of the proxy, to replay on Edge and on hybrid',
      onclick: () => prepare()}, stored.plan ? 'Prepare again' : 'Prepare test plan');
    const status = h('span', {class: 'meta'}, !stored.plan
      ? 'No test plan yet: it lists requests that go through each flow and condition of the proxy, to send to Edge and to hybrid and compare what they answer.'
      : stored.current ? 'Prepared on ' + day(stored.written) + '.'
      : h('span', {}, 'Prepared on ' + day(stored.written) + ': ', h('span', {class: 'WARN'}, 'the proxy changed since, it may be out of date.')));
    const profile = profileView(id, stored.profile);
    box.replaceChildren(...[h('div', {class: 'review-bar'}, status, button), profile.element,
      stored.plan && planView(id, stored.plan, stored.targets || [], stored.uncovered || [])].filter(Boolean));

    if (stored.running) prepare(stored.running);

    /** Prepares the plan, or waits for the preparation running since {@code since}. */
    async function prepare(since) {
      delete stored.running;
      button.disabled = true;
      button.replaceChildren(h('span', {class: 'spinner'}), ' Preparing…');
      status.replaceChildren('Reading the flows and conditions of the proxy for ', elapsed(since),
        '. This can take a few minutes.');
      try {
        const prepared = await api.planTests(id, profile.options());
        delete testRuns[id];
        show(prepared);
        toast('Test plan prepared: ' + prepared.plan.cases.length + ' request(s)');
      } catch (error) {
        toast(error.message, true);
        show(stored);
      }
    }
  }
  return box;
}

/**
 * The kind of proxy the plan is prepared for, as read from its OAuthV2 policies or as chosen, and for an OAuth
 * authorization server the fields of the identity provider's login form the plan fills; remembered in the browser.
 */
function profileView(id, detected) {
  const saved = loadSaved('apigee-map.tests.profile.' + id);
  const described = detected.kind === 'authorizationServer'
    ? 'Detected: OAuth authorization server' + (detected.grants.length ? ' (' + detected.grants.join(', ') + ')' : '') + '.'
    : 'Detected: standard proxy' + (detected.operations.includes('verify') ? ', which verifies tokens: the plan asks for one.' : '.');
  const kind = h('select', {'aria-label': 'Plan the tests as'},
    h('option', {value: ''}, 'As detected'),
    h('option', {value: 'standard'}, 'Standard proxy'),
    h('option', {value: 'authorizationServer'}, 'OAuth authorization server'));
  kind.value = saved.profile || '';
  const field = (value, label) => h('input', {type: 'text', value, spellcheck: 'false', autocomplete: 'off',
    class: 'short', 'aria-label': label, oninput: remember});
  const user = field(saved.user || 'login', 'User field of the login form');
  const password = field(saved.password || 'password', 'Password field of the login form');
  const login = h('span', {class: 'login-fields', title: 'Names of the fields of the identity provider\'s login form, which the plan fills to go through the authorization code flow'},
    'Login form fields ', user, password);

  function remember() {
    saveSaved('apigee-map.tests.profile.' + id, {profile: kind.value, user: user.value.trim(), password: password.value.trim()});
    login.hidden = (kind.value || detected.kind) !== 'authorizationServer';
  }
  kind.addEventListener('change', remember);
  login.hidden = (kind.value || detected.kind) !== 'authorizationServer';
  return {
    element: h('div', {class: 'export-bar profile-bar'}, h('span', {class: 'sub'}, described),
      h('label', {class: 'check'}, 'Plan as ', kind), login),
    options: () => ({profile: kind.value || undefined, loginForm: {user: user.value.trim(), password: password.value.trim()}}),
  };
}

/**
 * The plan, how much of the proxy it covers ({@code targets}, the points read from the proxy and its shared flows,
 * {@code uncovered} the ids of those no request covers), the run on both environments and the exports.
 */
function planView(id, plan, targets, uncovered) {
  const pointsById = Object.fromEntries(targets.map(t => [t.id, t]));
  const remembered = loadEnvironments(id);
  const edge = h('input', {type: 'text', placeholder: 'https://edge-api.example.com', value: remembered.edge || '', spellcheck: 'false'});
  const hybrid = h('input', {type: 'text', placeholder: 'https://hybrid-api.example.com', value: remembered.hybrid || '', spellcheck: 'false'});
  const values = {};
  const unsafeCount = plan.cases.filter(c => !c.safe).length;
  const unsafe = h('input', {type: 'checkbox'});
  const runButton = h('button', {type: 'button', class: 'primary', onclick: () => run(null, runButton)}, 'Run on both');
  const summary = h('div', {});
  const rows = h('tbody', {});

  const form = h('div', {class: 'form-section'},
    h('h2', {}, 'Run on both environments'),
    h('div', {class: 'env-grid'},
      h('div', {class: 'field'}, h('label', {}, 'Edge'), h('p', {class: 'hint'}, 'Scheme and host of the virtual host the proxy is deployed on.'), edge),
      h('div', {class: 'field'}, h('label', {}, 'Hybrid'), h('p', {class: 'hint'}, 'Scheme and host of the environment group the migrated proxy is deployed to.'), hybrid)),
    plan.variables.length ? h('div', {class: 'env-grid'}, plan.variables.map(v => {
      const input = h('input', {type: /key|token|secret|password|auth|credential/i.test(v.name) ? 'password' : 'text',
        autocomplete: 'off', spellcheck: 'false', oninput: () => { values[v.name] = input.value; }});
      return h('div', {class: 'field'}, h('label', {}, h('code', {}, '{{' + v.name + '}}')),
        v.description ? h('p', {class: 'hint'}, v.description) : null, input);
    })) : null,
    h('p', {class: 'sub'}, 'Values are used for this run only and never saved.'),
    h('div', {class: 'review-bar'},
      unsafeCount ? h('label', {class: 'check'}, unsafe, ' Include the ' + unsafeCount + ' request(s) that change data, on both environments')
        : h('span', {}),
      runButton));

  function render() {
    const last = testRuns[id];
    const byIndex = {};
    (last ? last.results : []).forEach(r => { byIndex[r.index] = r; });
    if (last) {
      const n = outcome => last.results.filter(r => r.outcome === outcome).length;
      summary.replaceChildren(cards([[n('SAME'), 'Same'], [n('DIFFERENT'), 'Different'], [n('ERROR'), 'Errors'], [n('SKIPPED'), 'Skipped']]),
        h('p', {class: 'meta'}, 'Last run on ', h('code', {}, last.edge), ' and ', h('code', {}, last.hybrid), '.'));
    } else {
      summary.replaceChildren();
    }
    rows.replaceChildren(...plan.cases.map((c, i) => {
      const result = byIndex[i];
      const again = h('button', {type: 'button', class: 'link', title: 'Run this request again on both environments',
        onclick: () => run([i], again)}, 'Run');
      return h('tr', {class: result && result.outcome === 'DIFFERENT' ? 'flagged-row' : ''},
        h('td', {}, h('b', {}, c.name), c.safe ? null : [' ', h('span', {class: 'badge warn', title: 'Changes data on the backend'}, 'changes data')],
          c.purpose ? h('div', {class: 'purpose'}, c.purpose) : null,
          c.covers && c.covers.length ? h('div', {class: 'sub', title: c.covers.map(p => pointsById[p] ? pointsById[p].description : p).join('\n')},
            'Covers ' + c.covers.length + ' point(s) of the proxy') : null,
          c.flow ? h('div', {class: 'sub'}, 'Flow ', h('code', {}, c.flow)) : null,
          c.form ? h('div', {class: 'sub'}, 'Submits the form ', h('code', {}, '{{' + c.form + '}}')) : null,
          c.captures.length ? h('div', {class: 'sub', title: 'Read from the answer of each environment, for the next requests on the same environment'},
            'Captures ', c.captures.map((k, n) => [n ? ', ' : '', h('code', {}, '{{' + k.name + '}}'), ' from ' + captureSource(k)])) : null),
        h('td', {}, h('code', {class: 'request'}, c.method + ' ' + c.path),
          c.headers.map(hd => h('div', {class: 'sub mono'}, hd.name + ': ' + hd.value)),
          c.body ? h('details', {class: 'body'}, h('summary', {class: 'sub'}, 'Body'), h('pre', {class: 'mono'}, c.body)) : null),
        h('td', {class: 'nowrap'}, c.expectedStatus || h('span', {class: 'sub'}, 'any'),
          c.compareHeaders.length ? h('div', {class: 'sub'}, c.compareHeaders.join(', ')) : null,
          c.shapeOnly ? h('div', {class: 'sub', title: 'The answers change on every call: the Location is compared by its parameter names, a JSON body by its keys, the headers by their presence'}, 'shape only') : null),
        h('td', {}, result ? resultView(result) : h('span', {class: 'sub'}, 'Not run')),
        h('td', {class: 'nowrap'}, again));
    }));
  }

  async function run(only, button) {
    saveEnvironments(id, {edge: edge.value.trim(), hybrid: hybrid.value.trim()});
    const label = [...button.childNodes];
    runButton.disabled = true;
    button.disabled = true;
    button.replaceChildren(h('span', {class: 'spinner'}), only ? '' : ' Running…');
    try {
      const result = await api.runTests(id, {edge: edge.value, hybrid: hybrid.value, values,
        unsafe: unsafe.checked, cases: only || undefined});
      const previous = testRuns[id];
      if (only && previous && previous.edge === result.edge && previous.hybrid === result.hybrid) {
        // with the earlier requests that capture what it uses, run again too
        const again = result.results.map(r => r.index);
        previous.results = previous.results.filter(r => !again.includes(r.index)).concat(result.results)
          .sort((a, b) => a.index - b.index);
      } else {
        testRuns[id] = result;
      }
      render();
      const different = result.results.filter(r => r.outcome === 'DIFFERENT').length;
      const errors = result.results.filter(r => r.outcome === 'ERROR').length;
      toast(different || errors ? different + ' different, ' + errors + ' error(s)' : 'No difference', different > 0);
    } catch (error) {
      toast(error.message, true);
    } finally {
      runButton.disabled = false;
      button.disabled = false;
      button.replaceChildren(...label);
    }
  }

  const format = h('select', {'aria-label': 'Export format'},
    h('option', {value: 'postman'}, 'Postman collection'),
    h('option', {value: 'curl'}, 'curl script'),
    h('option', {value: 'karate'}, 'Karate feature'));
  const exportLink = h('a', {class: 'button', title: 'Download the plan to run it outside apigee-map, on Edge then on hybrid'}, 'Export');
  const exportHint = h('span', {class: 'sub'});
  const EXPORT_HINTS = {
    postman: 'Set edgeUrl, hybridUrl and the variables of the collection; includeUnsafe=true runs the requests that change data.',
    curl: 'Run with EDGE, HYBRID and the variables in the environment; INCLUDE_UNSAFE=1 runs the requests that change data. Exits with 1 on a difference.',
    karate: 'Run with -DedgeUrl, -DhybridUrl and the variables as system properties; --tags ~@unsafe leaves out the requests that change data.',
  };
  function chooseFormat() {
    exportLink.href = '/api/tests/export?id=' + encodeURIComponent(id) + '&format=' + format.value;
    exportHint.textContent = EXPORT_HINTS[format.value];
  }
  format.addEventListener('change', chooseFormat);
  chooseFormat();

  render();
  return h('div', {class: 'doc'},
    h('p', {}, inlineCode(plan.summary)),
    h('div', {class: 'export-bar'}, format, exportLink, exportHint),
    plan.warnings.length ? h('div', {class: 'proposal'}, h('div', {class: 'warnings'}, h('b', {}, 'Before running'),
      h('ul', {}, plan.warnings.map(w => h('li', {}, inlineCode(w)))))) : null,
    coverageView(targets, uncovered),
    form, summary,
    h('h3', {}, plan.cases.length + ' request(s)'),
    h('div', {class: 'wrap'}, h('table', {class: 'tests'},
      h('thead', {}, h('tr', {}, ['Case', 'Request', 'Expected', 'Result', ''].map(t => h('th', {}, t)))), rows)));
}

const POINT_KINDS = {flow: 'Flow', route: 'Route rule', faultRule: 'Fault rule', fault: 'Raised fault',
  change: 'Migration change', oauth: 'OAuth operation', check: 'Check', callout: 'Callout', script: 'Script', condition: 'Conditional step'};

/** How many of the points read from the proxy and its shared flows have a request, and those that have none. */
function coverageView(targets, uncovered) {
  if (!targets.length) return null;
  const missing = targets.filter(t => uncovered.includes(t.id));
  const line = h('span', {}, (targets.length - missing.length) + ' of ' + targets.length
    + ' points of the proxy and its shared flows have a request', missing.length ? ': ' : '.',
    missing.length ? h('span', {class: 'WARN'}, missing.length + ' without one') : null);
  if (!missing.length) return h('p', {class: 'meta coverage'}, line);
  return h('details', {class: 'coverage'}, h('summary', {class: 'meta'}, line),
    h('p', {class: 'sub'}, 'Points no request goes through: prepare the plan again, or test them another way. The warnings may say why some cannot be reached from outside.'),
    h('ul', {}, missing.map(t => h('li', {}, h('span', {class: 'badge'}, POINT_KINDS[t.kind] || t.kind), ' ',
      inlineCode(t.description)))));
}

function captureSource(capture) {
  return {location: 'the Location', query: capture.key + ' in the Location', header: 'the header ' + capture.key,
    json: capture.key + ' in the body', form: 'the login form'}[capture.from] || capture.from;
}

function resultView(result) {
  const [cls, label] = OUTCOMES[result.outcome];
  const statuses = result.edge && result.hybrid
    ? h('span', {class: 'sub'}, ' Edge ' + (result.edge.status || '–') + ' · hybrid ' + (result.hybrid.status || '–')) : null;
  const errors = [result.edge && result.edge.error && 'Edge: ' + result.edge.error,
    result.hybrid && result.hybrid.error && 'Hybrid: ' + result.hybrid.error].filter(Boolean);
  return h('div', {},
    h('span', {class: 'badge ' + cls}, label), statuses,
    result.differences.map(d => h('div', {class: 'ERROR result-line'}, d)),
    errors.map(e => h('div', {class: 'WARN result-line'}, e)),
    result.notes.map(n => h('div', {class: 'sub result-line'}, n)));
}

/** Settings remembered in the browser; they hold no secret. */
function loadSaved(key) {
  try {
    return JSON.parse(localStorage.getItem(key)) || {};
  } catch (e) {
    return {};
  }
}

function saveSaved(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    // not remembered: chosen again next time
  }
}

/** The environment URLs of a proxy, remembered in the browser; they hold no secret. */
function loadEnvironments(id) {
  try {
    return JSON.parse(localStorage.getItem('apigee-map.tests.' + id)) || {};
  } catch (e) {
    return {};
  }
}

function saveEnvironments(id, environments) {
  try {
    localStorage.setItem('apigee-map.tests.' + id, JSON.stringify(environments));
  } catch (e) {
    // not remembered: they are typed again next time
  }
}

function docView(doc) {
  const points = (title, items) => items.length ? [h('h3', {}, title), h('ul', {}, items.map(p => h('li', {}, inlineCode(p))))] : null;
  return h('div', {class: 'doc'},
    h('p', {}, inlineCode(doc.summary)),
    doc.operations.length ? [h('h3', {}, 'Operations'), table(['Method', 'Path', 'Flow', 'What it does'], doc.operations.map(o => h('tr', {},
      h('td', {class: 'nowrap'}, h('code', {}, o.method)), h('td', {class: 'nowrap'}, h('code', {}, o.path || '/')),
      h('td', {}, o.flow), h('td', {}, inlineCode(o.description)))))] : null,
    points('Security', doc.security),
    doc.dependencies.length ? [h('h3', {}, 'Dependencies'), table(['Name', 'Kind', 'Used for'], doc.dependencies.map(d => h('tr', {},
      h('td', {}, h('code', {}, d.name)), h('td', {class: 'nowrap'}, DEPENDENCY_KINDS[d.kind] || 'Other'),
      h('td', {}, inlineCode(d.description)))))] : null,
    points('Errors', doc.errors),
    points('Good to know', doc.notes));
}

/** Text with what is in backticks as code. */
function inlineCode(text) {
  return text.split(/`([^`]+)`/).map((part, i) => i % 2 ? h('code', {}, part) : part);
}

/** How long an operation has been running, from {@code since} or now, kept up to date while it is on the page. */
function elapsed(since) {
  const start = since ? new Date(since).getTime() : Date.now();
  const span = h('span', {});
  const tick = () => {
    const seconds = Math.max(0, Math.round((Date.now() - start) / 1000));
    span.textContent = seconds >= 60 ? Math.floor(seconds / 60) + ' min ' + seconds % 60 + ' s' : seconds + ' s';
  };
  tick();
  const timer = setInterval(() => {
    if (span.isConnected) span.dataset.shown = 'true';
    else if (span.dataset.shown) clearInterval(timer);
    tick();
  }, 1000);
  return span;
}

function day(instant) {
  return new Date(instant).toLocaleDateString(undefined, {year: 'numeric', month: 'short', day: 'numeric'});
}

const READ_STATUS = {
  SET: ['ok', 'set earlier'], BUILT_IN: ['', 'built-in'], SET_LATER: ['bad', 'set later'],
  UNSET: ['warn', 'set nowhere'], UNKNOWN: ['', 'maybe set'],
};
const READ_PROBLEMS = ['SET_LATER', 'UNSET', 'UNKNOWN'];
const variableState = {id: null, flow: null, text: '', show: null, builtIn: false};

/** The flow variables of the proxy, loaded once per proxy; the analysis takes a moment on large bundles. */
function variablesPanel(id) {
  const box = h('div', {}, h('div', {class: 'loading'}, 'Analysing the variables…'));
  if (variableState.id !== id) Object.assign(variableState, {id, flow: api.variables(id), text: '', show: null});
  variableState.flow.then(flow => box.replaceChildren(variablesView(flow)),
    error => { variableState.id = null; box.replaceChildren(errorBox(error)); });
  return box;
}

function variablesView(flow) {
  const steps = flow.steps;
  const reads = steps.flatMap(s => s.reads);
  const total = source => reads.filter(r => r.source === source).length;
  const problems = reads.filter(r => READ_PROBLEMS.includes(r.source)).length;
  if (variableState.show === null) variableState.show = problems ? 'problems' : 'all';
  // who reads what each step sets, to follow a variable forward
  const readers = new Map();
  for (const step of steps) {
    for (const read of step.reads) {
      for (const index of read.producerSteps) {
        if (!readers.has(index)) readers.set(index, []);
        readers.get(index).push({step, name: read.name});
      }
    }
  }

  const box = h('div', {});
  box.append(cards([
    [steps.length, 'Steps'], [total('SET'), 'Reads set earlier'], [total('BUILT_IN'), 'Built-in reads'],
    [total('SET_LATER'), 'Set later'], [total('UNSET'), 'Set nowhere'], [total('UNKNOWN'), 'Maybe set'],
  ]));
  box.append(h('p', {class: 'meta', style: 'margin-top:16px'},
    'Steps in the order Apigee runs them, with the variables each one reads and writes. ',
    'Click a variable to follow it from the step that sets it to the steps that read it.'));

  const search = h('input', {type: 'search', placeholder: 'Filter by variable or policy', value: variableState.text,
    'aria-label': 'Filter by variable or policy', oninput: e => { variableState.text = e.target.value; fill(); }});
  const filters = h('div', {class: 'chips'});
  const list = h('div', {});

  function follow(name) {
    variableState.text = name;
    variableState.show = 'all';
    search.value = name;
    fill();
    search.scrollIntoView({block: 'nearest'});
  }

  const variable = (name, text) => h('button', {type: 'button', class: 'var' + (text && name.toLowerCase() === text ? ' hit' : ''),
    title: 'Follow ' + name, onclick: () => follow(name)}, name);

  function visibleReads(step, text) {
    return step.reads.filter(r => r.source !== 'BUILT_IN' || variableState.builtIn || (text && r.name.toLowerCase().includes(text)));
  }

  function matches(step, text) {
    if (variableState.show === 'problems' && !step.reads.some(r => READ_PROBLEMS.includes(r.source))) return false;
    if (!text) return true;
    return step.label.toLowerCase().includes(text)
      || step.reads.some(r => r.name.toLowerCase().includes(text))
      || step.writes.some(w => w.name.toLowerCase().includes(text));
  }

  function stepBlock(step, text) {
    const rows = [];
    for (const read of visibleReads(step, text)) {
      const [cls, label] = READ_STATUS[read.source];
      const from = read.producers.length
        ? (read.source === 'SET_LATER' ? 'by ' : '← ') + [...new Set(read.producerSteps.map(i => steps.find(s => s.index === i)?.label ?? '?'))].join(', ')
        : '';
      rows.push(h('tr', {class: READ_PROBLEMS.includes(read.source) ? 'problem' : null},
        h('td', {class: 'sub'}, 'reads'), h('td', {}, variable(read.name, text)),
        h('td', {}, h('span', {class: 'badge ' + cls}, label), from ? ' ' + from : null,
          read.note ? h('div', {class: 'note'}, read.note) : null),
        h('td', {class: 'sub'}, read.via)));
    }
    for (const write of step.writes) {
      rows.push(h('tr', {}, h('td', {class: 'sub'}, 'writes'), h('td', {}, variable(write.name, text)),
        h('td', {}), h('td', {class: 'sub'}, write.via)));
    }
    const hidden = step.reads.length - visibleReads(step, text).length;
    const readBy = readers.get(step.index) || [];
    return h('div', {class: 'vstep'},
      h('div', {class: 'vstep-head'},
        h('b', {}, step.label),
        step.type === 'RouteRule' ? null : h('span', {class: 'sub'}, step.type),
        step.condition ? h('code', {class: 'cond'}, step.condition) : null,
        step.opaque ? h('span', {class: 'badge warn', title: 'A Java callout, a script that builds variable names, or an unresolved shared flow'},
          'may use variables it does not name') : null,
        hidden ? h('span', {class: 'sub', style: 'margin-left:auto'}, hidden + ' built-in read(s) hidden') : null),
      rows.length ? h('table', {class: 'vars'}, h('tbody', {}, rows)) : null,
      readBy.length ? h('p', {class: 'sub readby'}, 'Read later by ',
        readBy.map(({step: reader, name}, i) => [i ? ', ' : '', h('b', {}, reader.label), ' (', variable(name, text), ')'])) : null);
  }

  function fill() {
    const text = variableState.text.trim().toLowerCase();
    filters.replaceChildren(
      chips([['problems', 'Reads to check (' + problems + ')'], ['all', 'All steps']], variableState.show,
        value => { variableState.show = value; fill(); }),
      h('label', {class: 'sub check'}, h('input', {type: 'checkbox', checked: variableState.builtIn,
        onchange: e => { variableState.builtIn = e.target.checked; fill(); }}), ' Show built-in reads'));
    const shown = steps.filter(s => matches(s, text));
    const content = [];
    let location = null;
    for (const step of shown) {
      if (step.location !== location) {
        location = step.location;
        content.push(h('h3', {class: 'mono'}, location));
      }
      content.push(stepBlock(step, text));
    }
    if (!shown.length) {
      content.push(empty(variableState.show === 'problems' && !text
        ? 'Every variable is set before the step that reads it.'
        : 'No step matches the filter.'));
    }
    list.replaceChildren(...content);
  }
  fill();
  box.append(h('div', {class: 'toolbar'}, search, filters), list);
  return box;
}

function mapPanel(id) {
  return h('div', {},
    h('p', {class: 'meta', style: 'margin-top:16px'}, 'The graph is drawn with Mermaid, loaded from the internet; the tables below it work offline.'),
    h('iframe', {class: 'frame', title: 'Dependency map', src: '/api/map?id=' + encodeURIComponent(id)}));
}

// ---------------------------------------------------------------------------------------------------------------
// Editor
// ---------------------------------------------------------------------------------------------------------------

/** How long typing has to pause before what was typed is checked. */
const CHECK_DELAY = 500;
const LANGUAGES = {xml: 'xml', xsl: 'xml', xslt: 'xml', xsd: 'xml', wsdl: 'xml', js: 'javascript', py: 'python', json: 'json'};
/** A file to show when the page comes back after a rename. */
let editorReturn = null;
let monacoLoad = null;

function loadMonaco() {
  monacoLoad = monacoLoad || new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/assets/monaco/vs/loader.js';
    script.onerror = () => reject(new Error('The code editor could not be loaded'));
    script.onload = () => {
      window.require.config({paths: {vs: '/assets/monaco/vs'}});
      window.require(['vs/editor/editor.main'], () => resolve(window.monaco), reject);
    };
    document.head.append(script);
  });
  return monacoLoad;
}

function fileKey(bundle, path) {
  return bundle + '\n' + path;
}

function worst(problems) {
  return SEVERITIES.find(s => problems.some(p => p.severity === s));
}

async function editorView(id, isCurrent) {
  const [workspace, monaco] = await Promise.all([api.editor(id), loadMonaco()]);
  if (!isCurrent()) return null;

  const root = workspace.bundles[0].name;
  const shared = new Set(workspace.bundles.slice(1).map(b => b.name));
  const opened = new Map();
  const tabs = [];
  let active = null;
  let findings = [];
  let syntax = [];
  let general = [];
  let scope = 'all';
  let timer = null;
  let checks = 0;
  let saving = false;
  let outline = null;
  let panel = 'problems';
  /** What the last simulated call did at each step of the proxy, by policy, until the text changes. */
  let simulated = new Map();
  const disposables = [];

  const status = h('span', {class: 'meta'});
  const saveButton = h('button', {type: 'button', class: 'primary', onclick: save}, 'Save');
  const newPolicyButton = h('button', {type: 'button', onclick: () => policyDialog(null)}, 'New policy');
  let pageElement = null;
  const composeButton = h('button', {type: 'button', onclick: () => composeDialog()}, 'Compose');
  const renameButton = h('button', {type: 'button', onclick: () => renameDialog(activePolicy()?.name)}, 'Rename policy');
  const rail = h('aside', {class: 'editor-rail', 'aria-label': 'Flow'});
  const tree = h('nav', {class: 'editor-tree', 'aria-label': 'Files'});
  const tabBar = h('div', {class: 'editor-tabs', role: 'tablist'});
  const host = h('div', {class: 'editor-host'});
  const problemsHead = h('div', {class: 'editor-problems-head'});
  const problemsList = h('div', {class: 'editor-problems-list'});
  const problemsPanel = h('div', {class: 'editor-problems'}, problemsHead, problemsList);
  const simulatePanel = simulationPanel();

  const editor = monaco.editor.create(host, {
    automaticLayout: true, minimap: {enabled: false}, fontSize: 13, scrollBeyondLastLine: false, model: null,
    theme: matchMedia('(prefers-color-scheme: dark)').matches ? 'vs-dark' : 'vs',
  });
  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, save);
  editor.addCommand(monaco.KeyCode.F12, () => goToDefinition(editor.getModel(), editor.getPosition()));
  editor.addCommand(monaco.KeyCode.F2, () => {
    const token = tokenAt(editor.getModel(), editor.getPosition());
    const policy = (token && outlinePolicy(token.text)) || activePolicy();
    if (policy) renameDialog(policy.name);
  });
  disposables.push(editor.onMouseDown(event => {
    if ((event.event.ctrlKey || event.event.metaKey) && event.target.position) goToDefinition(editor.getModel(), event.target.position);
  }));

  const dirty = () => [...opened.values()].filter(f => f.deleted ? f.base !== null : f.model.getValue() !== f.base);
  const buffers = () => dirty().map(f => f.deleted ? {path: f.path, deleted: true} : {path: f.path, content: f.model.getValue()});
  const problems = () => [...syntax, ...findings];
  const label = p => p.bundle === root ? p.file : p.bundle + '/' + p.file;

  /** A proxy opened broken is known by its id until it can be analyzed: its problems are about the same bundle. */
  function localized(list) {
    return list.map(p => ({...p, findingBundle: p.bundle, bundle: shared.has(p.bundle) ? p.bundle : root}));
  }

  function renderTree() {
    const all = problems();
    tree.replaceChildren(...workspace.bundles.map(bundle => {
      const folders = new Map();
      for (const file of bundle.files) {
        const slash = file.path.lastIndexOf('/');
        const folder = slash < 0 ? '' : file.path.slice(0, slash);
        if (!folders.has(folder)) folders.set(folder, []);
        folders.get(folder).push(file);
      }
      return h('section', {},
        h('h3', {}, bundle.name, bundle.editable ? null : h('span', {class: 'badge'}, 'read-only')),
        [...folders].map(([folder, files]) => [
          folder ? h('div', {class: 'editor-folder'}, folder) : null,
          files.map(file => {
            const key = fileKey(bundle.name, file.path);
            const here = all.filter(p => p.bundle === bundle.name && p.file === file.path);
            const changed = opened.has(key) && opened.get(key).model.getValue() !== opened.get(key).base;
            const deleted = opened.get(key)?.deleted;
            const name = file.path.slice(file.path.lastIndexOf('/') + 1);
            return h('button', {type: 'button', class: 'editor-file' + (key === active ? ' on' : '') + (deleted ? ' deleted' : ''), disabled: !file.text || deleted,
                title: file.text ? file.path : 'Too large, or not UTF-8 text',
                onclick: () => open(bundle.name, file.path, bundle.editable)},
              h('span', {class: 'name'}, (changed ? '● ' : '') + name),
              here.length ? h('span', {class: 'badge ' + (worst(here) === 'ERROR' ? 'bad' : worst(here) === 'WARN' ? 'warn' : '')}, here.length) : null);
          })]));
    }));
  }

  function renderTabs() {
    tabBar.replaceChildren(...tabs.map(key => {
      const file = opened.get(key);
      return h('div', {class: 'editor-tab' + (key === active ? ' on' : ''), role: 'tab', 'aria-selected': String(key === active)},
        h('button', {type: 'button', class: 'link', title: file.path, onclick: () => open(file.bundle, file.path)},
          (file.model.getValue() !== file.base ? '● ' : '') + file.path.slice(file.path.lastIndexOf('/') + 1)),
        h('button', {type: 'button', class: 'link', 'aria-label': 'Close ' + file.path, onclick: () => closeTab(key)}, '×'));
    }));
  }

  function renderProblems() {
    const all = problems();
    const file = active && opened.get(active);
    const here = all.filter(p => file && p.bundle === file.bundle && p.file === file.path);
    const shown = scope === 'file' ? here : [...all, ...general];
    problemsHead.replaceChildren(
      panelTabs(),
      chips([['all', 'All ' + (all.length + general.length)], ['file', 'This file ' + here.length]], scope, value => {
        scope = value || 'all';
        renderProblems();
      }));
    problemsList.replaceChildren(...(shown.length ? shown.map(p => {
      const place = p.file ? label(p) + (p.span ? ':' + p.span.line : '') : 'Proxy';
      return h('div', {class: 'editor-problem-row'},
        h('button', {type: 'button', class: 'editor-problem', disabled: !p.file,
            onclick: () => p.file && open(p.bundle, p.file, p.bundle === root, p.span)},
          severity(p.severity),
          p.rule ? h('span', {class: 'mono'}, p.rule) : null,
          h('span', {class: 'text', title: p.action || ''}, p.message),
          h('span', {class: 'mono place'}, place)),
        p.rule ? h('button', {type: 'button', class: 'link', onclick: () => fixProblem(p)}, 'Fix') : null);
    }) : [h('p', {class: 'meta'}, 'Nothing to report.')]));
  }

  function renderMarkers() {
    const severities = {ERROR: monaco.MarkerSeverity.Error, WARN: monaco.MarkerSeverity.Warning, INFO: monaco.MarkerSeverity.Info};
    const all = problems();
    for (const file of opened.values()) {
      monaco.editor.setModelMarkers(file.model, 'apigee-map', all
        .filter(p => p.bundle === file.bundle && p.file === file.path && p.span)
        .map(p => ({severity: severities[p.severity], source: p.rule || 'XML', message: p.message + (p.action ? '\n\n' + p.action : ''),
          startLineNumber: p.span.line, startColumn: p.span.column, endLineNumber: p.span.endLine, endColumn: p.span.endColumn})));
    }
  }

  function panelTabs() {
    return h('div', {class: 'editor-panel-tabs', role: 'tablist'}, [['problems', 'Problems'], ['simulate', 'Simulate']].map(([value, title]) =>
      h('button', {type: 'button', role: 'tab', class: 'link' + (panel === value ? ' on' : ''), 'aria-selected': String(panel === value), onclick: () => {
        panel = value;
        problemsPanel.hidden = value !== 'problems';
        simulatePanel.hidden = value !== 'simulate';
        pageElement?.classList.toggle('simulating', value === 'simulate');
        renderProblems();
        simulatePanel.querySelector('.editor-panel-tabs')?.replaceWith(panelTabs());
      }}, title)));
  }

  /** "name: value" or "name=value" lines as an object. */
  function pairs(text, separator) {
    const values = {};
    for (const line of text.split('\n')) {
      const at = line.indexOf(separator);
      if (at > 0) values[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
    return values;
  }

  function simulationPanel() {
    const field = (label, control) => h('label', {}, label, control);
    const verb = h('select', {'aria-label': 'Verb'}, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(v => h('option', {}, v)));
    const path = h('input', {type: 'text', 'aria-label': 'Path', value: '/', spellcheck: 'false'});
    const headers = h('textarea', {rows: 3, placeholder: 'x-api-key: abc', spellcheck: 'false'});
    const body = h('textarea', {rows: 3, spellcheck: 'false'});
    const status = h('input', {type: 'number', min: 100, max: 599, value: '200'});
    const targetBody = h('textarea', {rows: 3, spellcheck: 'false'});
    const variables = h('textarea', {rows: 3, placeholder: 'config.backend.timeout=3000', spellcheck: 'false'});
    const failing = h('input', {type: 'text', placeholder: 'Verify-API-Key, Q-Partner', spellcheck: 'false'});
    const result = h('div', {class: 'editor-trace'}, h('p', {class: 'meta'}, 'Plays a call through the text in the editor, without deploying it. The target answers what you set here.'));
    const run = h('button', {type: 'button', class: 'primary', onclick: async () => {
      run.disabled = true;
      try {
        const trace = await api.editorSimulate(id, {buffers: buffers(), verb: verb.value, path: path.value, headers: pairs(headers.value, ':'),
          body: body.value, status: status.value, targetBody: targetBody.value, variables: pairs(variables.value, '='),
          failing: failing.value.split(',').map(s => s.trim()).filter(Boolean)});
        simulated = new Map();
        for (const entry of trace.entries) {
          if (entry.file && entry.bundle === root) simulated.set(entry.name, entry.status);
        }
        renderRail();
        renderTrace(trace);
      } catch (error) {
        result.replaceChildren(errorBox(error));
      } finally {
        run.disabled = false;
      }
    }}, 'Run');

    function renderTrace(trace) {
      const response = trace.response;
      result.replaceChildren(h('div', {},
        h('div', {class: 'editor-trace-head'},
          h('strong', {}, response.status + (response.reason ? ' ' + response.reason : '')),
          trace.fault ? h('span', {class: 'badge bad'}, trace.fault) : null,
          h('span', {class: 'mono meta'}, response.body || '(empty body)')),
        trace.warnings.map(w => h('p', {class: 'meta'}, w)),
        trace.entries.map(entry => h('details', {class: 'editor-trace-entry sim-' + entry.status.toLowerCase()},
          h('summary', {},
            h('span', {class: 'badge'}, entry.status.replace('_', ' ').toLowerCase()),
            h('span', {class: 'mono'}, entry.name),
            entry.changes.length ? h('span', {class: 'badge'}, entry.changes.length + ' changed') : null,
            h('span', {class: 'meta'}, entry.location)),
          entry.note ? h('p', {class: 'meta'}, entry.note) : null,
          entry.condition ? h('p', {class: 'mono meta'}, 'If ' + entry.condition) : null,
          entry.file ? h('button', {type: 'button', class: 'link', onclick: () => open(entry.bundle, entry.file, entry.bundle === root)}, 'Open ' + entry.file) : null,
          entry.changes.map(change => h('div', {class: 'mono'}, change.name + ': ' + (change.before ?? '(none)') + ' → ' + (change.after ?? '(removed)')))))));
    }

    const form = h('div', {class: 'editor-sim-form'},
      h('div', {class: 'editor-sim-line'}, verb, path, run),
      field('Request headers', headers), field('Request body', body),
      field('Target status', status), field('Target body', targetBody),
      field('Variables set from outside', variables), field('Policies to fail', failing));
    const panelElement = h('div', {class: 'editor-simulate', hidden: true},
      h('div', {class: 'editor-problems-head'}, h('div', {class: 'editor-panel-tabs'})),
      h('div', {class: 'editor-sim-body'}, form, result));
    return panelElement;
  }

  function renderRail() {
    if (!outline) {
      rail.replaceChildren(h('p', {class: 'meta'}, 'The flow shows once the proxy can be analyzed.'));
      return;
    }
    const all = problems();
    const current = activePolicy();
    rail.replaceChildren(...outline.lanes.map(lane => h('section', {},
      h('h3', {}, lane.title),
      lane.segments.map(segment => h('div', {class: 'editor-segment'},
        h('div', {class: 'editor-segment-head'},
          h('button', {type: 'button', class: 'link', title: segment.condition || 'Show in ' + segment.file,
            onclick: () => open(root, segment.file, true, segment.span)}, segment.label),
          segment.element ? h('button', {type: 'button', class: 'link', 'aria-label': 'Add a policy to ' + segment.label,
            title: 'Add a policy here', onclick: () => policyDialog(segment)}, '+') : null),
        segment.condition ? h('div', {class: 'mono editor-condition', title: segment.condition}, segment.condition) : null,
        segment.steps.map(step => {
          const here = all.filter(p => p.bundle === root && p.file === step.file);
          const notes = step.unset.map(u => u.name + ': ' + u.why);
          if (!step.file) notes.push('No policy has this name');
          if (step.condition) notes.unshift('If ' + step.condition);
          const ran = simulated.get(step.policy);
          return h('button', {type: 'button', class: 'editor-step' + (step.policy === current?.name ? ' on' : '') + (step.enabled ? '' : ' off') + (ran ? ' sim-' + ran.toLowerCase() : ''),
              title: notes.join('\n'), onclick: () => step.file ? open(root, step.file, true) : open(root, segment.file, true, step.span)},
            h('span', {class: 'name'}, step.policy),
            step.condition ? h('span', {class: 'badge'}, 'if') : null,
            !step.file ? h('span', {class: 'badge bad'}, 'missing') : null,
            step.unset.length ? h('span', {class: 'badge warn'}, step.unset.length + ' unset') : null,
            here.length ? h('span', {class: 'badge ' + (worst(here) === 'ERROR' ? 'bad' : worst(here) === 'WARN' ? 'warn' : '')}, here.length) : null);
        }))))));
  }

  function renderAll() {
    renderTree();
    renderTabs();
    renderProblems();
    renderMarkers();
    renderRail();
    saveButton.disabled = !dirty().length;
    renameButton.disabled = !activePolicy();
  }

  function outlinePolicy(name) {
    return outline?.policies.find(p => p.name === name);
  }

  /** The policy of the proxy in the active file. */
  function activePolicy() {
    const file = active && opened.get(active);
    return file && file.bundle === root ? outline?.policies.find(p => p.file === file.path) : undefined;
  }

  /** The word under a position, with the dots and dashes of variable and policy names. */
  function tokenAt(model, position) {
    if (!model || !position) return null;
    for (const match of model.getLineContent(position.lineNumber).matchAll(/[A-Za-z_][\w-]*(?:\.[\w*-]+)*/g)) {
      const start = match.index + 1;
      const end = start + match[0].length;
      if (position.column >= start && position.column <= end) {
        return {text: match[0], range: new monaco.Range(position.lineNumber, start, position.lineNumber, end)};
      }
    }
    return null;
  }

  /** The entries of the outline that hold a variable: its own, or a family or a part it belongs to. */
  function variableEntries(name) {
    const wanted = name.toLowerCase();
    return (outline?.variables || []).filter(v => {
      const base = v.name.replace(/\.\*$/, '').toLowerCase();
      return wanted === base || wanted.startsWith(base + '.');
    });
  }

  function isBuiltIn(name) {
    const [first, second] = name.toLowerCase().split('.');
    const fields = workspace.builtIns[first];
    return !!fields && (!second || !fields.length || fields.includes(second));
  }

  /** Where the policy of the model runs among the steps, or null when the text is not a policy that runs. */
  function orderOf(model) {
    const file = [...opened.values()].find(f => f.model === model);
    const policy = file && file.bundle === root ? outline?.policies.find(p => p.file === file.path) : null;
    return policy && policy.order >= 0 ? policy.order : null;
  }

  function usesText(uses) {
    return [...new Map(uses.map(u => [u.policy + u.location, u])).values()].slice(0, 6)
      .map(u => '- `' + u.policy + '`, ' + u.location);
  }

  function variableHover(model, name) {
    const entries = variableEntries(name);
    if (!entries.length && !(name.includes('.') && isBuiltIn(name))) return null;
    const setBy = entries.flatMap(v => v.setBy);
    const readBy = entries.flatMap(v => v.readBy);
    const lines = ['**`' + name + '`**'];
    if (isBuiltIn(name)) lines.push('Set by Apigee.');
    if (setBy.length) lines.push('Set by:', ...usesText(setBy));
    if (readBy.length) lines.push('Read by:', ...usesText(readBy));
    const order = orderOf(model);
    if (order !== null && !isBuiltIn(name) && !setBy.some(u => u.order < order)) {
      lines.push(setBy.length ? 'Only later steps set it: it is null here.' : 'No step sets it: it is null here.');
    }
    return lines.join('\n\n');
  }

  async function goToDefinition(model, position) {
    const token = tokenAt(model, position);
    if (!token) return;
    const policy = outlinePolicy(token.text);
    if (policy) {
      await open(root, policy.file, true);
      return;
    }
    const order = orderOf(model);
    const writers = variableEntries(token.text).flatMap(v => v.setBy.map(use => ({use, variable: v}))).filter(w => w.use.file);
    const writer = writers.filter(w => order === null || w.use.order < order).at(-1) || writers[0];
    if (!writer) return;
    await open(root, writer.use.file, true);
    const text = writer.variable.name.replace(/\.\*$/, '');
    const {model: target} = opened.get(fileKey(root, writer.use.file));
    const match = target.findMatches(text.slice(text.lastIndexOf('.') + 1), false, false, false, null, false)[0];
    if (match) {
      editor.setSelection(match.range);
      editor.revealRangeInCenterIfOutsideViewport(match.range);
    }
  }

  function variableItems(model, range) {
    const order = orderOf(model);
    const items = [];
    for (const variable of outline?.variables || []) {
      if (!variable.setBy.length) continue;
      const earlier = order === null || variable.setBy.some(u => u.order < order);
      const family = variable.name.endsWith('.*');
      items.push({label: variable.name, kind: monaco.languages.CompletionItemKind.Variable, range,
        insertText: family ? variable.name.slice(0, -1) : variable.name,
        detail: (earlier ? 'Set by ' : 'Null here, set later by ') + variable.setBy[0].policy,
        sortText: (earlier ? '0' : '2') + variable.name});
    }
    for (const [first, fields] of Object.entries(workspace.builtIns)) {
      for (const name of [first, ...fields.map(f => first + '.' + f)]) {
        items.push({label: name, kind: monaco.languages.CompletionItemKind.Field, range, insertText: name, detail: 'Apigee', sortText: '1' + name});
      }
    }
    return items;
  }

  function provideCompletion(model, position) {
    if (!outline) return {suggestions: []};
    const before = model.getValueInRange(new monaco.Range(position.lineNumber, 1, position.lineNumber, position.column));
    const typed = before.match(/[\w.*-]*$/)[0];
    const range = new monaco.Range(position.lineNumber, position.column - typed.length, position.lineNumber, position.column);
    const file = [...opened.values()].find(f => f.model === model);
    if (!file) return {suggestions: []};
    if (model.getLanguageId() === 'javascript') {
      const inCall = /context\.(?:get|set|remove)Variable\(\s*["'][\w.*-]*$/.test(before);
      return {suggestions: inCall ? variableItems(model, range) : []};
    }
    if (/<Name>\s*[\w-]*$/.test(before) && /^(proxies|targets)\//.test(file.path)) {
      return {suggestions: outline.policies.map(p => ({label: p.name, kind: monaco.languages.CompletionItemKind.Function, range,
        insertText: p.name, detail: p.type + (p.order < 0 ? ', not attached' : '')}))};
    }
    return {suggestions: /<[\w/-]*$/.test(before) ? [] : variableItems(model, range)};
  }

  disposables.push(...['xml', 'javascript'].map(language => monaco.languages.registerCompletionItemProvider(language, {
    triggerCharacters: ['.', '{', '>', '"'], provideCompletionItems: provideCompletion})));
  disposables.push(...['xml', 'javascript'].map(language => monaco.languages.registerHoverProvider(language, {
    provideHover(model, position) {
      const token = tokenAt(model, position);
      if (!token || !outline) return null;
      const policy = outlinePolicy(token.text);
      const text = policy
        ? ['**' + policy.name + '**, ' + policy.type + (policy.enabled ? '' : ' (disabled)'),
          ...(policy.attachments.length ? policy.attachments.map(a => '- ' + a) : ['Not attached to a flow.'])].join('\n\n')
        : variableHover(model, token.text);
      return text ? {range: token.range, contents: [{value: text}]} : null;
    }})));

  /** Shows a file that is not saved yet, or that comes from the server. */
  function addBuffer(bundle, path, editable, content, base) {
    const key = fileKey(bundle, path);
    const language = LANGUAGES[path.slice(path.lastIndexOf('.') + 1).toLowerCase()] || 'plaintext';
    const model = monaco.editor.createModel(content, language);
    opened.set(key, {bundle, path, editable, base, model});
    model.onDidChangeContent(() => {
      simulated = new Map();
      renderTree();
      renderTabs();
      saveButton.disabled = !dirty().length;
      schedule();
    });
  }

  function listFile(path) {
    const files = workspace.bundles[0].files;
    files.push({path, text: true});
    files.sort((a, b) => a.path.localeCompare(b.path));
  }

  /** Adds a Step at the end of a segment, in the text of its file, where undo can take it back. */
  function addStep(segment, name) {
    const {model} = opened.get(fileKey(root, segment.file));
    const start = model.getOffsetAt({lineNumber: segment.span.line, column: segment.span.column});
    const text = model.getValue();
    const tag = '<' + (segment.parent || segment.element);
    if (!text.startsWith(tag, start)) return false;
    const close = text.indexOf('>', start);
    const line = model.getLineContent(segment.span.line);
    const indent = line.slice(0, line.length - line.trimStart().length);
    const step = indent + '    <Step><Name>' + name + '</Name></Step>\n';
    const edit = (from, to, inserted) => model.pushEditOperations([], [{
      range: monaco.Range.fromPositions(model.getPositionAt(from), model.getPositionAt(to)), text: inserted}], () => null);
    if (segment.parent) {
      const phase = (pad, phaseName) => phaseName === segment.element
        ? pad + '<' + phaseName + '>\n' + pad + '    <Step><Name>' + name + '</Name></Step>\n' + pad + '</' + phaseName + '>\n'
        : pad + '<' + phaseName + '/>\n';
      const inner = indent + '    ';
      const block = segment.parent === 'PreFlow' ? phase(inner, segment.element)
        : inner + '<PreFlow name="PreFlow">\n' + phase(inner + '    ', 'Request') + phase(inner + '    ', 'Response') + inner + '</PreFlow>\n';
      edit(close + 1, close + 1, '\n' + block.trimEnd());
      return true;
    }
    if (text[close - 1] === '/') {
      const opening = text.slice(start, close - 1).trimEnd();
      edit(start, close + 1, opening + '>\n' + step + indent + '</' + segment.element + '>');
      return true;
    }
    const end = text.indexOf('</' + segment.element, close);
    if (end < 0) return false;
    const lineStart = text.lastIndexOf('\n', end) + 1;
    const ownLine = !text.slice(lineStart, end).trim();
    if (ownLine) edit(lineStart, lineStart, step);
    else edit(end, end, '\n' + step + indent);
    return true;
  }

  /** Takes a file out of the page, once it is gone. */
  function forget(file) {
    const key = fileKey(file.bundle, file.path);
    if (tabs.includes(key)) closeTab(key);
    opened.delete(key);
    file.model.dispose();
    workspace.bundles[0].files = workspace.bundles[0].files.filter(f => f.path !== file.path);
  }

  /** Puts the edits of an answer in the buffers: nothing is written before Save. */
  async function applyEdits(edits) {
    for (const edit of edits) {
      const key = fileKey(root, edit.path);
      if (edit.action === 'create') {
        addBuffer(root, edit.path, true, edit.after, null);
        listFile(edit.path);
        continue;
      }
      await open(root, edit.path, true);
      const file = opened.get(key);
      if (!file) continue;
      if (edit.action === 'delete') {
        if (file.base === null) {
          forget(file);
        } else {
          file.deleted = true;
          closeTab(key);
        }
      } else {
        file.model.pushEditOperations([], [{range: file.model.getFullModelRange(), text: edit.after}], () => null);
      }
    }
    const shown = edits.find(e => e.action !== 'delete');
    if (shown) await open(root, shown.path, true);
    renderAll();
    schedule();
  }

  function assistDialog(title, request) {
    const body = h('div', {class: 'editor-assist'}, h('p', {class: 'meta'}, 'Working on it. This can take a few minutes.'));
    const apply = h('button', {type: 'button', class: 'primary', hidden: true}, 'Apply to the editor');
    const dialog = h('dialog', {class: 'wide'}, h('h2', {}, title), body,
      h('div', {class: 'actions'}, h('button', {type: 'button', onclick: () => dialog.close()}, 'Close'), apply));
    let diff = null;
    dialog.addEventListener('close', () => {
      const model = diff?.getModel();
      diff?.dispose();
      model?.original.dispose();
      model?.modified.dispose();
      dialog.remove();
    });
    document.body.append(dialog);
    dialog.showModal();

    function show(edit, tabsBar) {
      [...tabsBar.children].forEach(b => b.classList.toggle('on', b.dataset.path === edit.path));
      const old = diff.getModel();
      const language = LANGUAGES[edit.path.slice(edit.path.lastIndexOf('.') + 1).toLowerCase()] || 'plaintext';
      diff.setModel({original: monaco.editor.createModel(edit.before || '', language), modified: monaco.editor.createModel(edit.after || '', language)});
      old?.original.dispose();
      old?.modified.dispose();
    }

    api.editorAssist(id, {buffers: buffers(), ...request}).then(result => {
      if (!dialog.open) return;
      if (result.error) {
        body.replaceChildren(errorBox({message: result.error}));
        return;
      }
      const own = result.edits.filter(e => e.bundle === root);
      const others = result.edits.filter(e => e.bundle !== root);
      const review = result.review;
      body.replaceChildren(h('div', {},
        h('p', {class: 'editor-answer'}, result.summary),
        result.warnings.length ? h('ul', {}, result.warnings.map(w => h('li', {}, w))) : null,
        others.length ? h('p', {class: 'meta'}, 'Left out, shared flows are read-only here: ' + others.map(e => e.bundle + '/' + e.path).join(', ')) : null,
        own.length && !review.analyzed ? errorBox({message: 'This change leaves XML to fix: ' + review.added.map(p => p.file + ': ' + p.message).join('; ')}) : null,
        own.length && review.analyzed ? h('p', {class: 'meta'}, 'Checked: ' + review.resolved + ' problem(s) resolved, ' + review.added.length + ' new.') : null,
        own.length && review.added.length && review.analyzed ? h('ul', {}, review.added.map(p => h('li', {}, severity(p.severity), ' ', p.rule, ' ', p.message))) : null));
      if (!own.length) return;
      const bar = h('div', {class: 'editor-tabs'}, own.map(edit => h('button', {type: 'button', 'data-path': edit.path,
        class: 'editor-assist-file', title: edit.reason, onclick: () => show(edit, bar)}, edit.action + ' ' + edit.path)));
      const host = h('div', {class: 'editor-diff'});
      body.append(bar, host);
      diff = monaco.editor.createDiffEditor(host, {automaticLayout: true, readOnly: true, minimap: {enabled: false}, fontSize: 13,
        renderSideBySide: true, theme: matchMedia('(prefers-color-scheme: dark)').matches ? 'vs-dark' : 'vs'});
      show(own[0], bar);
      apply.hidden = false;
      apply.addEventListener('click', async () => {
        const changed = own.find(e => {
          const file = opened.get(fileKey(root, e.path));
          return e.action !== 'create' && file && !file.deleted && file.model.getValue() !== e.before;
        });
        if (changed) {
          toast(changed.path + ' changed in the meantime: ask again', true);
          return;
        }
        dialog.close();
        await applyEdits(own);
        toast('Applied: check it, then save');
      });
    }).catch(error => {
      if (dialog.open) body.replaceChildren(errorBox(error));
    });
  }

  function selection() {
    const file = active && opened.get(active);
    const range = editor.getSelection();
    if (!file || !range || range.isEmpty()) return null;
    return {path: file.path, text: file.model.getValueInRange(range)};
  }

  async function composeDialog() {
    const asked = await textDialog('Compose', 'Say what the proxy should do, or ask about it. Your unsaved text is taken into account, and nothing changes until you apply and save.',
      'What do you need?', 'Send');
    if (asked) assistDialog('Compose', {request: asked, selection: selection()});
  }

  const contextActions = [
    ['apigee.explain', 'Explain', 'Explain what this does and when it runs in the flow.'],
    ['apigee.review', 'Review', 'Review this: list what could go wrong, on Edge and on hybrid. Change nothing.'],
  ];
  for (const [actionId, label, asked] of contextActions) {
    disposables.push(editor.addAction({id: actionId, label, contextMenuGroupId: 'apigee', run: () => {
      const file = active && opened.get(active);
      if (file) assistDialog(label, {request: asked, selection: selection() || {path: file.path, text: file.model.getValue()}});
    }}));
  }

  const fixCommand = editor.addCommand(0, (accessor, problem) => fixProblem(problem));
  disposables.push(...['xml', 'javascript'].map(language => monaco.languages.registerCodeActionProvider(language, {
    provideCodeActions(model, range) {
      const file = [...opened.values()].find(f => f.model === model);
      const here = findings.filter(p => file && p.bundle === file.bundle && p.file === file.path && p.span
        && p.span.line <= range.endLineNumber && p.span.endLine >= range.startLineNumber);
      return {dispose() {}, actions: here.map(p => ({title: 'Fix ' + p.rule, kind: 'quickfix',
        command: {id: fixCommand, title: 'Fix ' + p.rule, arguments: [p]}}))};
    }})));

  function fixProblem(problem) {
    assistDialog('Fix ' + problem.rule, {finding: {bundle: problem.findingBundle, rule: problem.rule, location: problem.location}});
  }

  async function createPolicy(entry, name, segment) {
    const path = 'policies/' + name + '.xml';
    const fill = text => text.replaceAll('{{name}}', name);
    addBuffer(root, path, true, fill(entry.template), null);
    listFile(path);
    if (entry.script !== null) {
      const script = 'resources/jsc/' + name + '.js';
      addBuffer(root, script, true, fill(entry.script), null);
      listFile(script);
    }
    if (segment) {
      await open(root, segment.file, true);
      if (!addStep(segment, name)) toast('The flow changed: add the step by hand', true);
    }
    await open(root, path, true);
    schedule();
  }

  function policyDialog(segment) {
    const targets = (outline?.lanes || []).flatMap(lane => lane.segments.filter(s => s.element).map(s => ({lane, segment: s})));
    const taken = () => [...workspace.bundles[0].files.map(f => f.path), ...opened.keys()];
    let entry = workspace.catalog[0];
    const search = h('input', {type: 'search', placeholder: 'Filter policies', 'aria-label': 'Filter policies', oninput: renderList});
    const list = h('div', {class: 'editor-catalog'});
    const name = h('input', {type: 'text', 'aria-label': 'Policy name', oninput: validate});
    const attach = h('select', {'aria-label': 'Attach to'},
      h('option', {value: ''}, 'Not attached yet'),
      targets.map((t, i) => h('option', {value: String(i), selected: t.segment === segment}, t.lane.title + ' › ' + t.segment.label)));
    const problem = h('p', {class: 'meta'});
    const create = h('button', {type: 'button', class: 'primary', onclick: () => {
      const target = attach.value === '' ? null : targets[Number(attach.value)].segment;
      const chosen = entry;
      const value = name.value;
      dialog.close();
      createPolicy(chosen, value, target);
    }}, 'Create');
    const dialog = h('dialog', {class: 'wide'},
      h('h2', {}, 'New policy'), search, list,
      h('div', {class: 'editor-form'}, h('label', {}, 'Name ', name), h('label', {}, 'Attach to ', attach)),
      problem,
      h('p', {class: 'meta'}, 'The policy stays in the editor until you save.'),
      h('div', {class: 'actions'}, h('button', {type: 'button', onclick: () => dialog.close()}, 'Cancel'), create));
    dialog.addEventListener('close', () => dialog.remove());

    function renderList() {
      const words = search.value.toLowerCase();
      const shown = workspace.catalog.filter(e => (e.type + ' ' + e.summary + ' ' + e.group).toLowerCase().includes(words));
      list.replaceChildren(...[...new Set(shown.map(e => e.group))].map(group => h('section', {},
        h('h3', {}, group),
        shown.filter(e => e.group === group).map(e => h('button', {type: 'button', class: 'editor-file' + (e === entry ? ' on' : ''), onclick: () => choose(e)},
          h('span', {class: 'name'}, e.type), h('span', {class: 'meta'}, e.summary))))));
    }

    function choose(chosen) {
      entry = chosen;
      name.value = chosen.prefix + '-New';
      renderList();
      validate();
    }

    function validate() {
      const value = name.value;
      const message = !/^[A-Za-z0-9_-]+$/.test(value) ? 'A policy name uses letters, digits, - and _ only.'
        : taken().some(p => p.endsWith('policies/' + value + '.xml')) || outlinePolicy(value) ? 'A policy already has this name.' : '';
      problem.textContent = message;
      create.disabled = !!message;
    }

    choose(entry);
    document.body.append(dialog);
    dialog.showModal();
    search.focus();
  }

  function renameDialog(from) {
    if (!from) return;
    if (dirty().length) {
      toast('Save your changes before renaming a policy', true);
      return;
    }
    const to = h('input', {type: 'text', value: from, 'aria-label': 'New name', oninput: () => { plan = null; apply.disabled = true; preview.replaceChildren(); }});
    const preview = h('div', {class: 'editor-rename'});
    let plan = null;
    const change = () => ({from, to: to.value.trim()});
    const show = h('button', {type: 'button', onclick: async () => {
      try {
        plan = await api.editorRename(id, change());
      } catch (error) {
        toast(error.message, true);
        return;
      }
      preview.replaceChildren(
        ...plan.files.map(file => h('section', {},
          h('h3', {}, file.path + (file.newPath ? ' → ' + file.newPath : '')),
          file.lines.map(line => h('div', {class: 'mono'}, line.line + ': ' + line.after)))),
        plan.unchanged.length ? h('p', {class: 'meta'}, 'Also mentions the name, left as it is: ' + plan.unchanged.join(', ')) : '');
      apply.disabled = false;
    }}, 'Preview');
    const apply = h('button', {type: 'button', class: 'primary', disabled: true, onclick: async () => {
      try {
        const done = await api.editorRename(id, {...change(), apply: true});
        editorReturn = done.file;
        dialog.close();
        toast('Renamed ' + from + ' to ' + done.to);
        route();
      } catch (error) {
        toast(error.message, true);
      }
    }}, 'Rename');
    const dialog = h('dialog', {class: 'wide'},
      h('h2', {}, 'Rename ' + from),
      h('p', {class: 'meta'}, 'Updates the policy, the steps that run it and the variables it sets, as one saved step of history.'),
      h('div', {class: 'editor-form'}, h('label', {}, 'New name ', to), show),
      preview,
      h('div', {class: 'actions'}, h('button', {type: 'button', onclick: () => dialog.close()}, 'Cancel'), apply));
    dialog.addEventListener('close', () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    to.select();
  }

  async function open(bundle, path, editable, span) {
    const key = fileKey(bundle, path);
    if (!opened.has(key)) {
      let content;
      try {
        ({content} = await api.editorFile(id, bundle, path));
      } catch (error) {
        toast(error.message, true);
        return;
      }
      if (!isCurrent()) return;
      addBuffer(bundle, path, editable, content, content);
    }
    if (!tabs.includes(key)) tabs.push(key);
    active = key;
    const file = opened.get(key);
    editor.setModel(file.model);
    editor.updateOptions({readOnly: !file.editable});
    renderAll();
    if (span) {
      editor.setSelection({startLineNumber: span.line, startColumn: span.column, endLineNumber: span.endLine, endColumn: span.endColumn});
      editor.revealRangeInCenterIfOutsideViewport(editor.getSelection());
    }
    editor.focus();
  }

  function closeTab(key) {
    const index = tabs.indexOf(key);
    tabs.splice(index, 1);
    if (active === key) {
      active = tabs[Math.min(index, tabs.length - 1)] || null;
      const next = active && opened.get(active);
      editor.setModel(next ? next.model : null);
      if (next) editor.updateOptions({readOnly: !next.editable});
    }
    renderAll();
  }

  function schedule() {
    clearTimeout(timer);
    status.textContent = 'Checking…';
    timer = setTimeout(check, CHECK_DELAY);
  }

  async function check() {
    const asked = ++checks;
    const started = performance.now();
    let result;
    try {
      result = await api.editorCheck(id, buffers());
    } catch (error) {
      if (asked === checks && isCurrent()) status.textContent = error.message;
      return;
    }
    if (asked !== checks || !isCurrent()) return;
    syntax = [];
    if (result.analyzed) {
      findings = localized(result.problems);
      general = localized(result.general);
      outline = result.outline;
    } else {
      syntax = localized(result.problems);
    }
    renderAll();
    status.textContent = result.error ? result.error
      : (result.analyzed ? 'Checked' : 'XML to fix before the rules can run') + ' in ' + Math.round(performance.now() - started) + ' ms';
  }

  async function save() {
    const files = dirty();
    if (!files.length || saving) return;
    saving = true;
    const contents = files.map(f => f.model.getValue());
    try {
      await api.editorSave(id, files.map((f, i) => f.deleted ? {path: f.path, deleted: true, base: f.base}
        : {path: f.path, content: contents[i], base: f.base}));
      files.forEach((f, i) => { f.base = f.deleted ? null : contents[i]; });
      files.filter(f => f.deleted).forEach(f => forget(f));
      toast(files.length === 1 ? 'Saved ' + files[0].path : 'Saved ' + files.length + ' files');
      renderAll();
      check();
    } catch (error) {
      toast(error.message, true);
    } finally {
      saving = false;
    }
  }

  leaveGuard = silent => !dirty().length || (!silent && confirm('Discard your unsaved changes?'));
  leaveView = () => {
    clearTimeout(timer);
    disposables.forEach(d => d.dispose());
    editor.dispose();
    opened.forEach(file => file.model.dispose());
  };

  const page = pageElement = h('div', {class: 'editor-page'},
    h('div', {class: 'editor-head'},
      h('a', {href: '#/proxy/' + encodeURIComponent(id)}, '← ' + workspace.proxy),
      status,
      h('span', {class: 'spacer'}),
      composeButton, renameButton, newPolicyButton, saveButton),
    h('div', {class: 'editor-body'}, tree, h('div', {class: 'editor-main'}, tabBar, host), rail),
    problemsPanel, simulatePanel);

  renderAll();
  const first = workspace.bundles[0].files.find(f => f.path === editorReturn)
    || workspace.bundles[0].files.find(f => f.text && f.path.startsWith('proxies/'))
    || workspace.bundles[0].files.find(f => f.text);
  editorReturn = null;
  if (first) open(root, first.path, workspace.bundles[0].editable);
  schedule();
  return page;
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

  // Token: kept in memory by the app, never shown again once saved
  const tokenInput = h('input', {type: 'password', id: 'f-token', autocomplete: 'off', spellcheck: 'false',
    oninput: () => { tokenButton.disabled = !tokenInput.value.trim(); }});
  const tokenButton = h('button', {type: 'button', disabled: true, onclick: saveToken}, 'Save token');
  page.append(h('section', {class: 'form-section'}, h('h2', {}, 'Access token'),
    h('div', {class: 'field'}, h('label', {for: 'f-token'}, 'Token'),
      h('p', {class: 'hint'}, 'Needed to propose fixes. Kept in memory only, never written to disk, and forgotten after 30 minutes or when the app stops.'),
      h('div', {class: 'row'}, tokenInput, tokenButton))));

  async function saveToken() {
    tokenButton.disabled = true;
    try {
      await api.saveToken(tokenInput.value.trim());
      tokenInput.value = '';
      toast('Token saved');
    } catch (error) {
      toast(error.message, true);
      tokenButton.disabled = false;
    }
  }

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

  // False positives
  draft.falsePositives = [...(draft.falsePositives || [])];
  const falsePositivesBox = h('div', {});
  function renderFalsePositives() {
    falsePositivesBox.replaceChildren(draft.falsePositives.length
      ? table(['Rule', 'Bundle', 'Where', 'Why', ''], draft.falsePositives.map((f, index) => h('tr', {},
        h('td', {class: 'nowrap'}, h('code', {}, f.rule)), h('td', {}, f.bundle), h('td', {}, h('code', {}, f.location)),
        h('td', {class: 'sub'}, f.reason),
        h('td', {class: 'nowrap'}, h('button', {type: 'button', 'aria-label': 'Remove false positive ' + f.rule + ' at ' + f.location,
          onclick: () => { draft.falsePositives.splice(index, 1); renderFalsePositives(); changed(); }}, 'Remove')))))
      : h('p', {class: 'sub'}, 'None. Mark one from the Findings tab of a proxy.'));
  }
  renderFalsePositives();
  page.append(h('section', {class: 'form-section'}, h('h2', {}, 'False positives'),
    h('p', {class: 'meta', style: 'margin:-4px 0 12px'},
      'Findings no longer reported nor counted, and whose automatic fixes are not applied. A finding of a shared flow is covered in every proxy that calls it.'),
    falsePositivesBox));

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
    falsePositives: (settings.falsePositives || []).map(({rule, bundle, location, reason}) => ({rule, bundle, location, reason})),
  };
}

route();
