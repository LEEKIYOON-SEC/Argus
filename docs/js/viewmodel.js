(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./context.js') : root.ArgusContext,
                      node ? require('./lifecycle.js') : root.ArgusLifecycle,
                      node ? require('./cwe.js') : root.ArgusCWE);
  root.ArgusViewModel = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (CTX, LC, CWE) {
  'use strict';


  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'None'];

  function josa(word, withFinal, withoutFinal) {
    const s = String(word || '').trim();
    const ch = s.charCodeAt(s.length - 1);
    const last = s.slice(-1);
    const final = ch >= 0xac00 && ch <= 0xd7a3 ? (ch - 0xac00) % 28 > 0
      : /[0-9]/.test(last) ? '013678'.includes(last)
      : /[lmn]/i.test(last) || /ng$/i.test(s);
    return s + (final ? withFinal : withoutFinal);
  }

  const band =s => (CTX ? CTX.sevBand(s) : (s >= 9 ? 'Critical' : s >= 7 ? 'High' : s >= 4 ? 'Medium' : s > 0 ? 'Low' : 'None'));
  const fmt = n => (Number(n) || 0).toLocaleString();

  function epssPct(p, digits) {
    const v = Number(p) || 0;
    const s = (v * 100).toFixed(digits);
    return v < 1 && Number(s) >= 100 ? (100 - 10 ** -digits).toFixed(digits) : s;
  }

  function scores(cve) {
    const cvss = Number(cve.cvss) || 0;
    const epss = Number(cve.epss) || 0;
    const pctl = Number(cve.epss_percentile) || 0;
    const alt = Object.entries(cve.cvss_alt || {}).filter(([, v]) => Number(v) > 0)
      .sort((a, b) => (a[0] < b[0] ? 1 : -1)).map(([version, v]) => ({ version, value: Number(v), band: band(Number(v)) }));
    return {
      cvss: cvss > 0 ? { value: cvss, text: cvss.toFixed(1), version: cve.cvss_version || '', band: cve.severity || band(cvss), alt,
                         mixed: new Set(alt.map(a => a.band)).size > 1 } : null,
      epss: epss > 0 || pctl > 0 ? { value: epss, text: epss > 0 && epss < 0.0001 ? '<0.01%' : `${epssPct(epss, epss < 0.001 ? 2 : 1)}%`,
                                     text2: `${epssPct(epss, 2)}%`,
                                     percentile: pctl || null,
                                     top: pctl ? `상위 ${Math.max(0.1, (1 - pctl) * 100).toFixed(1)}%` : '' } : null,
    };
  }


  const VERSION_JUNK = ['', 'unknown', 'n/a', '-', 'n/a (단일 버전)', '정보 없음'];
  const isJunk = v => VERSION_JUNK.includes(String(v || '').trim().toLowerCase());
  const shortHash = v => (/^[0-9a-f]{12,40}$/i.test(v) ? `커밋 ${v.slice(0, 7)}` : v);
  const NO_LOWER = /^(0|\*|unspecified|n\/a)$/i;

  function shortRange(p) {
    let m = /^(.+) \(단일 버전\)$/.exec(p);
    if (m) return shortHash(m[1].trim());
    m = /^(.+?) 부터 (.+) (이전|이하)$/.exec(p);
    if (m) {
      const lo = m[1].trim(), hi = m[2].trim();
      if (lo === hi && m[3] === '이하') return shortHash(hi);
      return !lo || NO_LOWER.test(lo) || lo === hi ? `${shortHash(hi)} ${m[3]}` : `${shortHash(lo)} 부터 ${shortHash(hi)} ${m[3]}`;
    }
    m = /^(.+) (이전|이하)$/.exec(p);
    return m ? `${shortHash(m[1].trim())} ${m[2]}` : shortHash(p);
  }

  function shortVersions(v) {
    const s = String(v || '').trim();
    if (isJunk(s)) return '';
    const parts = s.split(', ').map(x => x.trim()).filter(x => x && !isJunk(x));
    if (!parts.length) return '';
    const singles = parts.every(x => / \(단일 버전\)$/.test(x));
    const shownCount = singles ? Math.min(4, parts.length) : 1;
    const shown = parts.slice(0, shownCount).map(shortRange).join(', ');
    return parts.length > shownCount ? `${shown} 외 ${parts.length - shownCount}` : shown;
  }


  const ENGINE_FAMILY = { snort2: 'Snort', snort3: 'Snort', suricata5: 'Suricata', suricata7: 'Suricata',
                          sigma: 'Sigma', splunk: 'Splunk', yara: 'YARA', nuclei: 'nuclei' };
  const clean = v => { const s = String(v || '').trim(); return ['', 'unknown', 'n/a', '-'].includes(s.toLowerCase()) ? '' : s; };
  const EXPLOIT_SHORT = { 'CISA KEV': 'KEV', 'VulnCheck KEV': 'VulnCheck', 'SSVC active': 'SSVC' };

  const SNIPPET_MAX = 160;
  function snippetOf(cve, names) {
    let s = String(cve.description || '').replace(/\s+/g, ' ').trim();
    if (!s || ['n/a', '정보 없음'].includes(s.toLowerCase()) || s === String(cve.title || '').replace(/\s+/g, ' ').trim()) return '';
    for (const n of [...new Set(names.filter(Boolean))].sort((a, b) => b.length - a.length)) {
      if (!s.toLowerCase().startsWith(n.toLowerCase())) continue;
      const m = /^(?:의|에서|[,:])?\s+/.exec(s.slice(n.length));
      if (m) { s = s.slice(n.length + m[0].length); break; }
    }
    return s.length > SNIPPET_MAX ? `${s.slice(0, SNIPPET_MAX)}…` : s;
  }

  function listRow(cve, env) {
    const e = env || {};
    const s = (e.ctx && e.ctx.states) || {};
    const sc = scores(cve);
    const threat = [];
    if (s.EXPLOITATION_CONFIRMED === 'yes') {
      const src = [cve.is_kev && 'CISA KEV', cve.is_vulncheck_kev && 'VulnCheck KEV',
                   cve.ssvc_exploitation === 'active' && 'SSVC active'].filter(Boolean);
      threat.push({ kind: 'exploit', label: EXPLOIT_SHORT[src[0]] || src[0], extra: src.length > 1 ? `외 ${src.length - 1}` : '',
                    title: `악용 근거: ${src.join(' · ')}` });
    }
    if (s.RANSOMWARE === 'yes') {
      threat.push({ kind: 'exploit', label: '랜섬웨어', extra: '', title: 'CISA KEV에 랜섬웨어 캠페인 사용으로 적혀 있음' });
    }
    if (s.PUBLIC_EXPLOIT === 'yes') {
      const src = [cve.has_metasploit_module && 'MSF', cve.has_public_exploit && 'EDB', cve.has_poc && 'PoC'].filter(Boolean);
      const names = [cve.has_metasploit_module && 'Metasploit 모듈', cve.has_public_exploit && 'Exploit-DB 항목',
                     cve.has_poc && 'PoC 저장소'].filter(Boolean);
      threat.push({ kind: 'weapon', label: src.join('·') || '공개 익스플로잇', extra: '',
                    title: `공개 익스플로잇: ${names.join(' · ')}. 공개돼 있다는 뜻이며 실제 공격이 있었다는 뜻은 아닙니다` });
    }
    if (s.AUTOMATABLE === 'yes') {
      threat.push({ kind: 'auto', label: '자동화', extra: '', title: 'CISA SSVC 판정: 자동화 가능 (정찰부터 공격까지 자동화할 수 있음)' });
    }
    const aff = e.affected || [];
    const shown = e.shown || aff[0] || {};
    const vendor = clean(shown.vendor), product = clean(shown.product);
    let lifecycle = null;
    if (e.lc && LC) {
      const present = LC.DISPLAY_ORDER.filter(st => e.lc.counts[st] > 0);
      if (present.length) {
        const top = present[0];
        const first = e.lc.entries.find(x => LC.statusOf(x.rel, (e.lcProducts || {})[x.slug], e.today) === top);
        const relName = first ? `${((e.lcProducts || {})[first.slug] || {}).label || first.slug} ${first.rel.cycle}` : '';
        const others = e.lc.entries.length + e.lc.unresolved.length - (first ? 1 : 0);
        lifecycle = { status: top, short: LC.SHORT[top], cycle: first ? first.rel.cycle : '', product: relName, others,
                      title: `${relName ? relName + ': ' : ''}영향 버전의 지원 상태 ${present.map(st => `${LC.SHORT[st]} ${e.lc.counts[st]}개`).join(' · ')}${
                        top === 'UNKNOWN' && e.lc.unresolved.length ? ' (제품은 찾았지만 릴리스를 정하지 못함)' : ''}. CVE가 아니라 제품 버전의 상태입니다` };
      }
    }
    const engines = CTX ? CTX.detectionEngines(cve) : (cve.rule_engines || []);
    const name = product ? (vendor && !product.toLowerCase().startsWith(vendor.toLowerCase()) ? `${vendor} ${product}` : product) : (vendor || '');
    const names = [name, ...aff.flatMap(a => [`${clean(a.vendor)} ${clean(a.product)}`.trim(), clean(a.product)])];
    return {
      id: cve.id, severity: cve.severity || 'None', tier: cve.tier || '', title: cve.title || 'N/A',
      ai: cve.ai_discovered ? { program: cve.ai_program || '' } : null,
      cvss: sc.cvss, epss: sc.epss, threat,
      type: CWE ? CWE.typeOf(cve.cwe) : null,
      snippet: snippetOf(cve, names),
      product: { name, more: aff.length > 1 ? aff.length - 1 : 0, versions: clean(shown.versions), short: shortVersions(shown.versions),
                 packages: e.packages || [] },
      lifecycle,
      detection: s.PUBLIC_DETECTION === 'yes'
        ? { state: 'yes', text: [...new Set(engines.map(x => ENGINE_FAMILY[x] || x))].join(' · ') || '공식 룰', engines }
        : CTX ? { state: 'no', text: '없음', engines: [] } : { state: 'unknown', text: '미확인', engines: [] },
      fix: s.PATCH_AVAILABLE === 'yes' ? { state: 'yes', text: '있음' }
        : s.PATCH_AVAILABLE === 'no' ? { state: 'no', text: '기록 없음' } : { state: 'unknown', text: '미확인' },
      conflicts: (e.ctx && e.ctx.conflicts) || [],
      date: cve.date || '',
    };
  }


  function kpis(agg, stats, extra) {
    const s = (stats && stats.cve) || {};
    const src = (agg && agg.sources) || null;
    const v = k => (src ? src[k] : null);
    const x = extra || {};
    const delta = (n, what) => (n === null || n === undefined ? null : { n, text: what });
    const exploited = agg ? agg.signals.EXPLOITATION_CONFIRMED.yes : null;
    return [
      { id: 'stat-total', key: 'total', label: '추적 중 CVE', value: s.total || (agg && agg.total) || 0, query: '',
        delta: delta(x.published7, '최근 7일 공개'), line: '최근 90일 안에 갱신된 CVE',
        title: 'Argus가 최근 90일 안에 평가하거나 상태를 갱신한 CVE입니다. CVE 공개일 기준이 아닙니다' },
      { id: 'stat-24h', key: 'recent', label: '24시간 알림·갱신', value: s.recent_24h || 0, query: 'recent:24h',
        delta: null, line: x.recentCritical != null ? `Critical ${fmt(x.recentCritical)} · KEV ${fmt(x.recentKev)}` : '새 공개와 상태 변경 포함',
        title: '데이터 기준 시각 전 24시간 동안 Argus가 알림을 보냈거나 상태가 바뀐 CVE입니다. 새로 공개된 CVE만 세지 않습니다' },
      { id: 'stat-kev', key: 'kev', label: 'CISA KEV', value: v('cisa_kev'), query: 'has:cisa-kev', group: 'exploit',
        delta: delta(x.kevAdded7, '최근 7일 등재'), line: exploited != null ? `악용 근거 전체 ${fmt(exploited)}건` : '',
        title: `CISA KEV 카탈로그에 등재된 CVE입니다${exploited != null ? `. VulnCheck KEV와 SSVC active까지 합친 악용 근거는 ${fmt(exploited)}건입니다` : ''}` },
      { id: 'stat-weapon', key: 'weaponized', label: '무기화', value: v('weaponized'), query: 'has:weaponized', group: 'weapon',
        delta: null, line: src ? `MSF ${fmt(src.metasploit)} · EDB ${fmt(src.exploit_db)}` : '',
        title: `Metasploit(MSF) 모듈이나 Exploit-DB(EDB) 항목이 있는 CVE입니다${src ? `. Metasploit ${fmt(src.metasploit)}건 · Exploit-DB ${fmt(src.exploit_db)}건` : ''}. PoC 저장소와 nuclei 점검 템플릿은 세지 않습니다` },
      { id: 'stat-poc', key: 'poc', label: '공개 PoC', value: v('poc'), query: 'has:poc', group: 'weapon',
        delta: null, line: 'GitHub 공개 저장소 기준',
        title: 'PoC-in-GitHub에 공개 저장소가 있는 CVE입니다. 실제 공격이 있었다는 뜻은 아닙니다' },
      { id: 'stat-ai', key: 'ai', label: 'AI 발견', value: v('ai_discovered'), query: 'has:ai', group: 'src',
        delta: delta(x.ai7, '최근 7일 공개'), line: 'AI가 찾아낸 취약점',
        title: 'Anthropic CVD 원장과 CVE 크레딧에서 AI가 발견자로 적힌 CVE입니다. Argus의 AI 분석과는 관계없습니다' },
    ];
  }

  function correlations(agg) {
    if (!CTX || !agg) return [];
    return CTX.CORRELATIONS.map(c => {
      const n = agg.correlations[c.code] || 0;
      const scope = (agg.correlation_scope || {})[c.code];
      const first = CTX.SIGNAL[c.parts[0]];
      const secondCode = c.parts[1].replace('!', '');
      const second = CTX.SIGNAL[secondCode];
      const firstYes = agg.signals[c.parts[0]].yes;
      const canBeNo = agg.signals[secondCode].no > 0;
      const share = scope && canBeNo ? n / scope : null;
      return {
        code: c.code, label: c.label, short: c.short, query: c.query, n, parts: c.parts.map(p => ({
          code: p.replace('!', ''), negated: p[0] === '!' })),
        scope: scope == null ? null : scope, share, firstShort: first.short, firstYes,
        scopeText: scope == null ? ''
          : !canBeNo ? '나머지는 미확인'
          : scope === firstYes ? `${first.short} 중`
          : `판정된 ${fmt(scope)}건 중`,
        scopeTitle: scope == null ? ''
          : !canBeNo ? `${josa(second.short, '은', '는')} 출처가 '있음'만 기록합니다. ${first.short} ${fmt(firstYes)}건 가운데 나머지는 없음이 아니라 미확인입니다`
          : `${first.short} ${fmt(firstYes)}건 가운데 ${second.short} 여부를 알 수 있는 ${fmt(scope)}건 기준`,
      };
    }).sort((a, b) => b.n - a.n);
  }

  function matrix(agg) {
    if (!CTX || !agg) return null;
    const axes = CTX.MATRIX.map(code => ({ code, short: CTX.SIGNAL[code].short, total: agg.signals[code].yes,
                                           query: CTX.yesQuery(code) }));
    const cells = {};
    let max = 0;
    for (let i = 0; i < axes.length; i++) {
      for (let j = i + 1; j < axes.length; j++) {
        const n = agg.cooccur[`${axes[i].code}|${axes[j].code}`] || 0;
        cells[`${i}|${j}`] = { n, query: `${axes[i].query} ${axes[j].query}` };
        if (n > max) max = n;
      }
    }
    return { axes, cells, max };
  }

  function overview(agg) {
    const days = (agg && agg.daily) || [];
    const series = ['Critical', 'High', 'Medium', 'Low', 'None'];
    const totals = days.map(d => series.reduce((a, s) => a + (d[s] || 0), 0));
    return { days, series, totals, max: Math.max(1, ...totals), sum: totals.reduce((a, b) => a + b, 0),
             last7: totals.slice(-7).reduce((a, b) => a + b, 0) };
  }

  function recent(list, refIso) {
    const ref = Date.parse(refIso || '');
    const refDay = isNaN(ref) ? null : new Date(ref).toISOString().slice(0, 10);
    return (list || []).map(r => {
      let ago = '';
      if (refDay && r.published) {
        const days = Math.round((Date.parse(`${refDay}T00:00:00Z`) - Date.parse(`${r.published}T00:00:00Z`)) / 864e5);
        ago = days <= 0 ? '오늘 공개' : days === 1 ? '어제 공개' : `${days}일 전 공개`;
      }
      return Object.assign({}, r, { ago,
        corrLabels: (r.correlations || []).map(code => (CTX && CTX.CORRELATION[code] ? CTX.CORRELATION[code].short : code)),
        signalLabels: (r.signals || []).filter(k => k !== 'EXPLOITATION_CONFIRMED' || !r.signals.includes('CISA_KEV'))
          .map(k => (CTX ? CTX.SIGNAL[k].short : k)) });
    });
  }


  function sources(EN, agg, extra) {
    if (!EN) return [];
    const src = (agg && agg.sources) || {};
    const sig = (agg && agg.signals) || {};
    const counts = agg ? {
      'cve-record': agg.total, 'cisa-adp': src.ssvc_assessed, 'first-epss': src.epss_scored,
      'cisa-kev': src.cisa_kev, 'vulncheck-kev': src.vulncheck_kev, 'exploit-db': src.exploit_db,
      metasploit: src.metasploit, 'poc-in-github': src.poc, nuclei: src.nuclei, 'ai-discovery': src.ai_discovered,
      osv: sig.PATCH_AVAILABLE ? sig.PATCH_AVAILABLE.yes + sig.PATCH_AVAILABLE.no : null,
      endoflife: agg.lifecycle ? agg.lifecycle.mapped : null,
    } : {};
    Object.assign(counts, extra || {});
    return (EN.SOURCE_GROUPS || []).map(g => ({
      label: g.label,
      rows: g.ids.map(id => {
        const s = EN.SOURCES[id];
        const n = Number(counts[id]);
        return { id, name: s.name, provider: s.provider || '', url: s.url || '', role: s.role, cadence: s.cadence || '',
                 count: counts[id] == null || !Number.isFinite(n) ? null : n,
                 terms: (s.terms || []).map(t => ({ label: t.label, url: t.url || '', note: t.note || '' })) };
      }),
    }));
  }

  return { SEVERITIES, josa, epssPct, scores, shortVersions, listRow, kpis, correlations, matrix, overview, recent, sources,
           ENGINE_FAMILY };
});
