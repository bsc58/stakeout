// Stakeout's page. Every value from the server goes into the page as text (textContent, text
// nodes, attribute values), never as HTML.
'use strict';

(() => {
  const BUSY = ['starting', 'running', 'stopping', 'analyzing'];
  const APPS_SHOWN = 20;     // rows of the app list shown before "显示其余"
  const ROWS_SHOWN = 10;     // rows of a section's table shown before "显示全部"
  const LEVEL_TEXT = {
    high: '在后台用到了敏感信息',
    medium: '在你打开它的时候用到了敏感信息，或者在后台用到了较敏感的信息',
    low: '其他',
  };

  const $ = (id) => document.getElementById(id);
  const token = new URLSearchParams(location.search).get('token') || '';
  const ui = {
    device: null, status: null, runs: [], current: null, apps: null, appsLoading: false,
    pollTimer: null, tickTimer: null, deviceTimer: null,
  };

  // -- building blocks ------------------------------------------------------------------

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : String(c));
    }
    return node;
  }

  const enc = encodeURIComponent;
  const isBusy = (st) => !!st && BUSY.includes(st.state);

  function fmtNumber(n) {
    return typeof n === 'number' ? n.toLocaleString('zh-CN') : String(n);
  }

  function fmtDuration(s) {
    if (typeof s !== 'number' || s < 0) return '';
    if (s < 60) return `${s} 秒`;
    const m = Math.floor(s / 60), r = Math.round(s % 60);
    return r ? `${m} 分 ${r} 秒` : `${m} 分钟`;
  }

  function fmtClock(s) {
    s = Math.max(0, Math.floor(s));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
    const two = (x) => String(x).padStart(2, '0');
    return h ? `${h}:${two(m)}:${two(r)}` : `${m}:${two(r)}`;
  }

  function fmtStart(t) {
    // "2026-11-19 10:01:22" -> "11月19日 10:01"
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/.exec(t || '');
    return m ? `${Number(m[2])}月${Number(m[3])}日 ${m[4]}:${m[5]}` : (t || '');
  }

  function fmtBytes(n) {
    if (typeof n !== 'number') return '';
    if (n < 1024) return `${n} 字节`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  // A bar's text with its numbers in bold: "定位 12 次" -> 定位 <b>12</b> 次
  function withNumbers(text) {
    return String(text).split(/(\d[\d,.]*)/).filter((p) => p !== '')
      .map((p) => (/^\d/.test(p) ? el('b', null, p) : p));
  }

  // -- server ---------------------------------------------------------------------------

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function api(path, body) {
    const opts = { headers: { 'X-Stakeout-Token': token }, cache: 'no-store' };
    if (body !== undefined) {
      opts.method = 'POST';
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      throw new ApiError(0, '连不上 Stakeout：请确认终端里的 Stakeout 还开着。');
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* no JSON body */ }
    if (!res.ok) {
      const err = new ApiError(res.status, (data && data.message) || `出错了（${res.status}）。`);
      if (res.status === 403) showNotice(err.message);
      throw err;
    }
    return data;
  }

  function showNotice(text) {
    const n = $('notice');
    n.textContent = text;
    n.hidden = !text;
  }

  // -- phone ----------------------------------------------------------------------------

  function phoneReady() {
    return !!(ui.device && ui.device.connected && ui.device.root);
  }

  function canDecrypt() {
    return !!(ui.device && ui.device.tshark && ui.device.ecapture);
  }

  async function refreshDevice() {
    clearTimeout(ui.deviceTimer);
    try {
      ui.device = await api('/api/device');
    } catch (e) {
      ui.device = null;
      setPhone('bad', '', e.message);
      updateStartButton();
      return;
    }
    const d = ui.device;
    const name = [d.model, d.android ? `Android ${d.android}` : null].filter(Boolean).join(' · ');
    setPhone(phoneReady() ? (canDecrypt() ? 'ok' : 'warn') : (d.connected ? 'warn' : 'off'),
      phoneReady() ? name : '', d.message || '');
    const box = $('decrypt');
    box.disabled = !canDecrypt();
    if (!canDecrypt()) box.checked = false;
    const missing = $('decrypt-missing');
    missing.hidden = canDecrypt() || !d.connected;
    missing.textContent = '这台电脑上缺少解密要用的程序，现在不能解密；不解密也可以观察。';
    updateStartButton();
    if (phoneReady() && scopeValue() === 'app' && ui.apps === null) loadApps();
    // Plugged in later: look again by itself while the phone is not ready.
    if (!phoneReady() && !isBusy(ui.status)) ui.deviceTimer = setTimeout(refreshDevice, 4000);
  }

  function setPhone(state, name, text) {
    $('phone').dataset.state = state;
    $('phone-name').textContent = name;
    $('phone-text').textContent = text;
  }

  // -- start form -----------------------------------------------------------------------

  const form = () => $('start-form');
  const scopeValue = () => form().elements.scope.value;

  function updateStartButton() {
    let why = '';
    if (ui.device && !phoneReady()) why = '手机准备好后才能开始。';
    else if (phoneReady() && scopeValue() === 'app' && !$('app-select').value) why = '先在上面选一个应用。';
    $('start-btn').disabled = !token || !phoneReady() || !!why || isBusy(ui.status);
    $('start-why').textContent = why;
  }

  function onScopeChange() {
    const app = scopeValue() === 'app';
    $('app-picker').hidden = !app;
    if (app && ui.apps === null) loadApps();
    updateStartButton();
  }

  async function loadApps() {
    if (ui.appsLoading) return;
    ui.appsLoading = true;
    $('app-hint').textContent = '正在读取手机上的应用……第一次要读出每个应用的名称，可能要一两分钟，以后会快很多。';
    try {
      ui.apps = await api('/api/apps');
      $('app-hint').textContent = '';
      renderAppOptions();
    } catch (e) {
      $('app-hint').textContent = e.message;
    } finally {
      ui.appsLoading = false;
      updateStartButton();
    }
  }

  function renderAppOptions() {
    const select = $('app-select');
    const keep = select.value;
    const q = $('app-filter').value.trim().toLowerCase();
    const match = (a) => !q || a.package.toLowerCase().includes(q) || (a.label || '').toLowerCase().includes(q);
    const option = (a) => el('option', { value: a.package, selected: a.package === keep },
      a.label ? `${a.label}（${a.package}）` : a.package);
    const shown = (ui.apps || []).filter(match);
    const mine = shown.filter((a) => a.third_party), system = shown.filter((a) => !a.third_party);
    select.replaceChildren(
      mine.length ? el('optgroup', { label: '你装的应用' }, mine.map(option)) : null,
      system.length ? el('optgroup', { label: '系统自带的应用' }, system.map(option)) : null);
    if (!shown.length) $('app-hint').textContent = q ? `没有找到“${$('app-filter').value.trim()}”。` : '手机上没有读到应用。';
    else $('app-hint').textContent = '';
    updateStartButton();
  }

  async function onStart(ev) {
    ev.preventDefault();
    const f = form();
    const scope = scopeValue();
    const seconds = f.elements.seconds.value;
    const body = {
      scope,
      package: scope === 'app' ? ($('app-select').value || null) : null,
      seconds: seconds ? Number(seconds) : null,
      decrypt: $('decrypt').checked,
    };
    $('start-btn').disabled = true;
    $('form-msg').hidden = true;
    try {
      await api('/api/start', body);
    } catch (e) {
      $('form-msg').textContent = e.message;
      $('form-msg').hidden = false;
      updateStartButton();
      return;
    }
    $('last-message').hidden = true;
    await refreshStatus();
  }

  async function onStop() {
    $('stop-btn').disabled = true;
    try {
      await api('/api/stop', {});
    } catch (e) {
      $('run-message').textContent = e.message;
    }
    await refreshStatus();
  }

  // -- capture status -------------------------------------------------------------------

  async function refreshStatus() {
    clearTimeout(ui.pollTimer);
    let st;
    try {
      st = await api('/api/status');
    } catch (e) {
      if (isBusy(ui.status)) {
        $('run-message').textContent = e.message;
        ui.pollTimer = setTimeout(refreshStatus, 2000);
      }
      return;
    }
    const was = ui.status;
    ui.status = st;
    renderStatus(st);
    if (isBusy(st)) {
      ui.pollTimer = setTimeout(refreshStatus, 1000);
    } else if (isBusy(was)) {           // the capture just ended
      await refreshRuns();
      if (st.state === 'done' && st.run) showRun(st.run, true);
      refreshDevice();
    }
  }

  function renderStatus(st) {
    const busy = isBusy(st);
    if (busy) setPhone('ok', $('phone-name').textContent, '手机已连接。');
    $('start-card').hidden = busy;
    $('run-card').hidden = !busy;
    clearInterval(ui.tickTimer);
    if (!busy) {
      const last = $('last-message');
      last.hidden = !(st.message && (st.state === 'done' || st.state === 'error'));
      last.className = st.state === 'error' ? 'last error' : 'last';
      last.textContent = st.message || '';
      updateStartButton();
      return;
    }
    const who = st.scope === 'phone' ? '整部手机' : appName(st.package);
    const stage = {
      starting: '正在准备观察',
      running: `正在观察${st.scope === 'phone' ? '整部手机' : `：${who}`}`,
      stopping: '正在停止，从手机取回数据',
      analyzing: '正在整理结果',
    }[st.state];
    $('run-stage').textContent = stage;
    $('run-message').textContent = st.message || '';
    $('stop-btn').hidden = !(st.state === 'starting' || st.state === 'running');
    $('stop-btn').disabled = false;
    $('run-advice').textContent = st.state === 'running'
      ? (st.scope === 'phone'
        ? '照常使用手机就好。如果开了解密：想看得最完整，现在把你关心的应用彻底关掉，再重新打开。'
        : '照常使用这个应用就好。如果开了解密：想看得最完整，现在把它彻底关掉，再重新打开。')
      : (st.state === 'analyzing' && st.scope === 'phone' ? '整部手机的数据比较多，整理要一会儿。' : '');
    $('planned').textContent = st.seconds ? `共 ${fmtDuration(st.seconds)}` : '直到你点“现在停止”（最长 60 分钟）';
    $('progress').hidden = !st.seconds || st.state !== 'running';
    const tick = () => {
      const elapsed = st.started ? Date.now() / 1000 - st.started : 0;
      $('elapsed').textContent = fmtClock(st.seconds ? Math.min(elapsed, st.seconds) : elapsed);
      if (st.seconds) $('progress-bar').style.width = `${Math.min(100, (elapsed / st.seconds) * 100)}%`;
    };
    tick();
    if (st.state === 'running') ui.tickTimer = setInterval(tick, 1000);
  }

  function appName(pkg) {
    const a = (ui.apps || []).find((x) => x.package === pkg);
    return (a && a.label) || pkg || '';
  }

  // -- history --------------------------------------------------------------------------

  async function refreshRuns() {
    try {
      ui.runs = await api('/api/runs');
    } catch (e) {
      $('runs').replaceChildren(el('p', { class: 'error' }, e.message));
      return;
    }
    renderRuns();
  }

  function renderRuns() {
    const box = $('runs');
    if (!ui.runs.length) {
      box.replaceChildren(el('p', { class: 'empty' }, '还没有观察记录。连上手机，点“开始观察”。'));
      return;
    }
    const busyRun = isBusy(ui.status) ? ui.status.run : null;
    box.replaceChildren(
      el('div', { class: 'runs-tools' },
        el('button', { type: 'button', class: 'link danger', onclick: deleteAllRuns }, '全部删除')),
      el('ul', { class: 'runs' }, ui.runs.map((r) => {
        const current = r.id === ui.current;
        const title = r.scope === 'phone' ? '整部手机' : (r.label || r.package);
        const meta = [fmtStart(r.start_time), fmtDuration(r.seconds),
          r.scope === 'phone' && typeof r.apps === 'number' ? `${r.apps} 个应用` : null,
          r.decrypt ? '解密了网络内容' : null].filter(Boolean).join(' · ');
        return el('li', { class: 'run-row' }, el('button', {
          type: 'button', class: current ? 'run current' : 'run', 'aria-current': current ? 'true' : null,
          onclick: () => { showRun(r.id, true); },
        },
        el('span', { class: 'run-title' }, title,
          r.scope === 'app' && r.label ? el('span', { class: 'pkg' }, r.package) : null),
        el('span', { class: 'run-meta' }, meta),
        current ? el('span', { class: 'run-now' }, '正在看') : null),
        el('button', {
          type: 'button', class: 'del', disabled: r.id === busyRun,
          'aria-label': `删除 ${title} ${fmtStart(r.start_time)} 的观察`,
          onclick: () => { deleteRuns([r], `永久删除这次观察（${title}，${fmtStart(r.start_time)}）？`); },
        }, '删除'));
      })));
  }

  // Deleting is for good: the run's captured data, its results and its downloads leave this computer.
  async function deleteRuns(runs, question) {
    if (!window.confirm(`${question}\n抓到的数据、整理出的结果和可下载的文件都会从这台电脑上删除，无法恢复。`)) return;
    let failed = null;
    for (const r of runs) {
      try {
        await api(`/api/runs/${enc(r.id)}/delete`, {});
        if (ui.current === r.id) {
          ui.current = null;
          $('result').hidden = true;
          $('result').replaceChildren();
        }
      } catch (e) {
        failed = failed || e.message;
      }
    }
    await refreshRuns();
    if (failed) window.alert(failed);
  }

  function deleteAllRuns() {
    const busyRun = isBusy(ui.status) ? ui.status.run : null;
    const runs = ui.runs.filter((r) => r.id !== busyRun);
    if (runs.length) deleteRuns(runs, `永久删除全部 ${runs.length} 次观察？`);
  }

  // -- result ---------------------------------------------------------------------------

  async function showRun(id, scroll) {
    ui.current = id;
    renderRuns();
    const box = $('result');
    box.hidden = false;
    box.replaceChildren(el('p', { class: 'loading' }, '正在打开这次观察的结果……以前的观察第一次打开时要先整理，可能要一会儿。'));
    if (scroll) box.scrollIntoView({ behavior: 'smooth', block: 'start' });
    let ov;
    try {
      ov = await api(`/api/runs/${enc(id)}/overview`);
    } catch (e) {
      if (ui.current === id) box.replaceChildren(el('p', { class: 'error' }, e.message));
      return;
    }
    if (ui.current !== id) return;
    renderOverview(box, ov, id);
    // A run analysed just now: the history learns its app count (or its app's name).
    const entry = ui.runs.find((r) => r.id === id);
    const named = entry && entry.scope === 'app' && !entry.label && ov.apps && ov.apps[0] && ov.apps[0].label;
    if (entry && (entry.apps === null || named)) refreshRuns();
  }

  function renderOverview(box, ov, id) {
    const run = ov.run || {};
    const apps = ov.apps || [];
    const phone = run.scope === 'phone';
    const only = !phone && apps.length ? apps[0] : null;
    const title = phone ? '整部手机' : ((only && only.label) || run.package || '');
    const line = [`${fmtStart(run.start_time)} 开始`, run.seconds != null ? `看了 ${fmtDuration(run.seconds)}` : null,
      run.decrypt ? '解密了网络内容' : '没有解密网络内容', run.net === false ? '没有记录网络数据' : null]
      .filter(Boolean).join(' · ');

    // A phone run lists the apps the owner installed first; the ones that came with the phone are folded.
    const mine = phone ? apps.filter((a) => a.third_party !== false) : apps;
    const system = phone ? apps.filter((a) => a.third_party === false) : [];
    box.replaceChildren(...[
      el('div', { class: 'result-head' },
        el('h2', null, '观察结果'),
        el('p', { class: 'result-title' }, title,
          !phone && only && only.label ? el('span', { class: 'pkg' }, only.package) : null),
        el('p', { class: 'result-meta' }, line),
        run.device ? el('p', { class: 'result-meta' }, run.device) : null),
      cleartext(ov.cleartext, apps, phone),
      apps.length ? null : el('p', { class: 'empty' },
        '这段时间里，没有看到哪个应用用了权限、读了你的信息或者联网。'),
      apps.length ? explain(phone, mine.length, system.length) : null,
      mine.length ? appList(mine, id, !phone || apps.length === 1) : null,
      system.length ? el('details', { class: 'system-apps', open: !mine.length },
        el('summary', null, `系统自带的应用（${system.length} 个）`),
        appList(system, id, false)) : null,
      limits(ov.limits || [])].filter(Boolean));
  }

  // Which apps sent requests without encryption: names and counts only, at the top so it is seen first.
  function cleartext(c, apps, phone) {
    if (!c) return null;            // an overview made before the check
    const head = el('h3', null, '没加密就发出去的请求（明文 HTTP）');
    if (!c.checked) {
      return el('section', { class: 'cleartext' }, head,
        el('p', null, `这次看不出来。${c.note || ''}`));
    }
    const names = {};
    for (const a of apps) if (a.label) names[a.package] = a.label;
    const list = c.apps || [];
    const other = c.unattributed || {};
    const hosts = (hs) => {
      const parts = hs.filter((h) => h[0]).map((h) => `${h[0]}（${fmtNumber(h[1])}）`);
      const nameless = hs.filter((h) => !h[0]).reduce((n, h) => n + h[1], 0);
      if (nameless) parts.push(`只知道地址的服务器（${fmtNumber(nameless)}）`);
      return parts.length > 3 ? `${parts.slice(0, 3).join('、')} 等 ${parts.length} 个` : parts.join('、');
    };
    const toward = (text) => (/^[\x00-\x7f]/.test(text) ? `发往 ${text}` : `发往${text}`);
    const who = phone ? `${list.length} 个应用` : '它';
    const lead = list.length
      ? `${who}没加密就发出了请求。这些请求在路上谁都看得到：同一个网络里的其他人（例如同一个 Wi-Fi 上的人）和网络运营商都能看到内容。`
      : (phone ? '这次没有看到哪个应用没加密就发请求。' : '这次没有看到它没加密就发请求。');
    const rows = list.map((a) => [
      names[a.package] || a.label ? `${names[a.package] || a.label}（${a.package}）` : a.package,
      a.requests, a.background, hosts(a.hosts || []), (a.kinds || []).join('、') || '—']);
    const notes = [];
    if (other.requests) {
      notes.push(`另有 ${fmtNumber(other.requests)} 个没加密的请求不知道是哪个应用发的（可能是连接太短，没对上应用），`
        + `${toward(hosts(other.hosts || []))}。`);
    }
    if (c.system) notes.push(`系统本身没加密发了 ${fmtNumber(c.system)} 个请求，没有算到应用上。`);
    return el('section', { class: list.length ? 'cleartext found' : 'cleartext' }, head,
      el('p', null, lead),
      rows.length ? table(['应用', '没加密的请求', '你没打开它时', '发往', '带了哪些信息（按字段名）'], rows) : null,
      notes.map((t) => el('p', { class: 'note' }, t)));
  }

  function explain(phone, mine, system) {
    const count = [mine ? `你装的应用 ${mine} 个` : null, system ? `系统自带的 ${system} 个` : null]
      .filter(Boolean).join('，');
    return el('div', { class: 'explain' },
      phone ? el('p', { class: 'order' },
        `${count}。排序看应用拿走了什么：用到的敏感信息越多、越敏感，排得越靠前；在后台（也就是你没打开它的时候）用到的，算得更重。`)
        : el('p', { class: 'order' }, '“在后台”是指你没打开它的时候。'),
      el('ul', { class: 'legend', 'aria-label': '颜色的意思' },
        ['high', 'medium', 'low'].map((lvl) => el('li', null,
          el('i', { class: `sw ${lvl}`, 'aria-hidden': 'true' }),
          lvl === 'low' ? '其他，比如联网' : LEVEL_TEXT[lvl]))));
  }

  function appList(apps, runId, openFirst) {
    const list = el('ol', { class: apps.length === 1 ? 'apps single' : 'apps' });
    const add = (from, to) => {
      for (let i = from; i < to; i++) list.append(appRow(apps[i], i, runId, openFirst && i === 0));
    };
    add(0, Math.min(apps.length, APPS_SHOWN));
    const rest = apps.length - APPS_SHOWN;
    if (rest <= 0) return list;
    const more = el('button', {
      type: 'button', class: 'more-apps',
      onclick: () => { add(APPS_SHOWN, apps.length); more.remove(); },
    }, `显示其余 ${rest} 个应用`);
    return el('div', null, list, more);
  }

  function bar(b) {
    const level = LEVEL_TEXT[b.level] ? b.level : 'low';
    const text = b.text || `${b.key} ${b.count}`;
    return el('span', { class: `bar ${level}`, title: LEVEL_TEXT[level] },
      withNumbers(text),
      b.background > 0 && !String(text).includes('后台')
        ? el('span', { class: 'bg' }, '后台 ', el('b', null, fmtNumber(b.background))) : null,
      b.denied > 0 ? el('span', { class: 'bg' }, '被拒 ', el('b', null, fmtNumber(b.denied))) : null,
      b.cleartext > 0 ? el('span', { class: 'bg' }, '没加密 ', el('b', null, fmtNumber(b.cleartext))) : null);
  }

  function appRow(app, index, runId, open) {
    const levels = {};
    for (const b of app.bars || []) levels[b.key] = b.level;
    const summary = el('summary', null,
      el('span', { class: 'rank', 'aria-hidden': 'true' }, String(index + 1)),
      el('span', { class: 'who' },
        el('span', { class: 'label' }, app.label || app.package),
        app.label ? el('span', { class: 'pkg' }, app.package) : null,
        app.third_party === false ? el('span', { class: 'tag' }, '系统自带') : null),
      el('span', { class: 'bars' }, (app.bars || []).map(bar)),
      el('span', { class: 'chev', 'aria-hidden': 'true' }));
    const details = el('details', { class: 'app' }, summary);
    let built = false;
    details.addEventListener('toggle', () => {
      if (details.open && !built) {
        built = true;
        details.append(appDetail(app, runId, levels));
      }
    });
    if (open) details.open = true;
    return el('li', null, details);
  }

  function appDetail(app, runId, levels) {
    return el('div', { class: 'detail' },
      (app.sections || []).map((s) => section(s, levels[s.key])),
      downloads(app, runId));
  }

  function section(s, level) {
    return el('section', { class: 'sec' },
      el('h3', null, el('i', { class: `sw ${LEVEL_TEXT[level] ? level : 'low'}`, 'aria-hidden': 'true' }), s.title || s.key),
      s.summary ? el('p', { class: 'summary' }, s.summary) : null,
      s.rows && s.rows.length ? table(s.columns || [], s.rows) : null,
      s.more > 0 ? el('p', { class: 'more' }, `还有 ${fmtNumber(s.more)} 行没有列出，完整的列表在下面“下载数据”的文件里。`) : null);
  }

  function table(columns, rows) {
    const body = el('tbody', null, rows.map((row, i) => el('tr', { hidden: i >= ROWS_SHOWN },
      row.map((cell, j) => el('td', {
        class: typeof cell === 'number' ? 'num' : null, 'data-label': columns[j] || '',
      }, cell === null || cell === undefined || cell === '' ? '—' : fmtNumber(cell))))));
    const t = el('table', { class: 'rows' },
      el('thead', null, el('tr', null, columns.map((c, j) => el('th', {
        class: rows.length && typeof rows[0][j] === 'number' ? 'num' : null, scope: 'col',
      }, c)))),
      body);
    const wrap = el('div', { class: 'table-wrap' }, t);
    if (rows.length <= ROWS_SHOWN) return wrap;
    const more = el('button', {
      type: 'button', class: 'link',
      onclick: () => {
        for (const tr of body.children) tr.hidden = false;
        more.remove();
      },
    }, `显示全部 ${rows.length} 行`);
    return el('div', null, wrap, more);
  }

  function downloads(app, runId) {
    const list = app.downloads || [];
    if (!list.length) return null;
    const href = (d) => `/api/runs/${enc(runId)}/apps/${enc(app.package)}/${enc(d.kind)}?token=${enc(token)}`;
    return el('div', { class: 'downloads' },
      el('h3', null, '下载数据'),
      el('ul', null, list.map((d) => el('li', null,
        el('a', { href: href(d), download: '' }, d.title || d.kind),
        el('span', { class: 'size' }, fmtBytes(d.bytes)),
        d.private ? el('span', { class: 'badge' }, '私密') : null))),
      list.some((d) => d.private)
        ? el('p', { class: 'hint' }, '标着“私密”的文件里是抓到的原始内容（请求的全部内容和各种标识），只留给自己看，不要发给别人。')
        : null);
  }

  function limits(items) {
    if (!items.length) return null;
    return el('details', { class: 'limits' },
      el('summary', null, `这次观察看不到的地方（${items.length} 条）`),
      el('ul', null, items.map((t) => el('li', null, t))));
  }

  // -- start ----------------------------------------------------------------------------

  async function init() {
    const f = form();
    for (const r of f.elements.scope) r.addEventListener('change', onScopeChange);
    $('app-filter').addEventListener('input', renderAppOptions);
    $('app-select').addEventListener('change', updateStartButton);
    f.addEventListener('submit', onStart);
    $('stop-btn').addEventListener('click', onStop);
    onScopeChange();
    if (!token) {
      showNotice('这个网址少了口令，页面不能使用。请打开终端里 Stakeout 给出的完整网址。');
      setPhone('off', '', '');
      $('runs').replaceChildren();
      return;
    }
    await Promise.all([refreshStatus(), refreshRuns()]);
    if (!isBusy(ui.status)) refreshDevice();
    if (ui.current === null) {
      const st = ui.status;
      if (st && st.state === 'done' && st.run) showRun(st.run, false);
      else if (ui.runs.length) showRun(ui.runs[0].id, false);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
