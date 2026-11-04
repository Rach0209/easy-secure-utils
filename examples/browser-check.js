/*
 * 브라우저 호환성 자체 점검 (examples/browser-check.html 에서 사용).
 * 어떤 브라우저/기기에서 열어도 라이브러리의 핵심 동작과, html`` 을 "그 브라우저의 HTML 파서"로 대조한 결과를 보여줍니다.
 * 오래된 브라우저에서도 이 파일 자체가 실행되도록 ES2015 문법만 사용합니다.
 */
(function () {
  'use strict';

  var U = window.SecureWebUtils;
  var results = [];
  var BS = String.fromCharCode(92);
  var TAB = String.fromCharCode(9);
  var LF = String.fromCharCode(10);
  var CR = String.fromCharCode(13);
  var NUL = String.fromCharCode(0);

  function record(group, name, status, detail) {
    results.push({ group: group, name: name, status: status, detail: detail || '' });
  }
  function eq(actual, expected) {
    var a = JSON.stringify(actual);
    var e = JSON.stringify(expected);
    return a === e ? true : 'got ' + a + ' / want ' + e;
  }
  function check(group, name, fn) {
    try {
      var r = fn();
      if (r === true) record(group, name, 'pass');
      else record(group, name, 'fail', r === false ? 'returned false' : String(r));
    } catch (e) {
      record(group, name, 'fail', (e && e.name ? e.name + ': ' : '') + (e && e.message ? e.message : String(e)));
    }
  }
  function throwsOf(fn, ctor) {
    try { fn(); } catch (e) { return ctor ? e instanceof ctor : true; }
    return false;
  }
  function str(v) { return String(v); }

  // ---------------------------------------------------------------------------
  // 라이브러리 로드 확인
  // ---------------------------------------------------------------------------
  if (!U || typeof U.html !== 'function') {
    record('로드', 'dist/easy-secure-utils.js (UMD) 로드', 'fail', 'window.SecureWebUtils 가 없습니다. 파일 경로/콘솔 오류를 확인하세요.');
    finalize();
    return;
  }

  // ---------------------------------------------------------------------------
  // 1. 환경
  // ---------------------------------------------------------------------------
  var features = {
    structuredClone: typeof structuredClone === 'function',
    'crypto.getRandomValues': typeof crypto === 'object' && crypto !== null && typeof crypto.getRandomValues === 'function',
    DOMParser: typeof DOMParser === 'function',
    URL: typeof URL === 'function',
    WeakMap: typeof WeakMap === 'function',
    Symbol: typeof Symbol === 'function',
    Reflect: typeof Reflect === 'object',
    Promise: typeof Promise === 'function',
    Uint8Array: typeof Uint8Array === 'function',
    'script type=module': 'noModule' in document.createElement('script'),
    'isSecureContext': window.isSecureContext === true,
    protocol: location.protocol
  };

  check('환경', '필수 기능 (Reflect·WeakMap·Symbol·URL·Uint8Array·DOMParser·crypto.getRandomValues)', function () {
    var need = ['Reflect', 'WeakMap', 'Symbol', 'URL', 'Uint8Array', 'DOMParser', 'crypto.getRandomValues'];
    var missing = need.filter(function (k) { return !features[k]; });
    return missing.length === 0 ? true : '지원하지 않음: ' + missing.join(', ');
  });

  check('API', '공개 함수 15개가 모두 존재', function () {
    var want = ['escapeHTML', 'escapeAttribute', 'escapeRegExp', 'html', 'unsafeHTML', 'isSafeHTML', 'isSafeURL', 'sanitizeURL',
      'safeJSONParse', 'safeDeepClone', 'safeMerge', 'formatBytes', 'debounce', 'throttle', 'randomToken'];
    var missing = want.filter(function (k) { return typeof U[k] !== 'function'; });
    return missing.length === 0 ? true : '없음: ' + missing.join(', ');
  });
  check('API', '공개 객체가 동결(변조 방지)되어 있다', function () { return Object.isFrozen(U) || 'not frozen'; });

  // ---------------------------------------------------------------------------
  // 2. 인코딩
  // ---------------------------------------------------------------------------
  check('인코딩', 'escapeHTML', function () {
    return eq(U.escapeHTML('<img src=x onerror="a(\'1\')">`&'), '&lt;img src=x onerror=&quot;a(&#39;1&#39;)&quot;&gt;&#96;&amp;') === true &&
      eq([U.escapeHTML(0), U.escapeHTML(null), U.escapeHTML({})], ['0', '', '']) === true || 'mismatch';
  });
  check('인코딩', 'escapeAttribute (영숫자 외 전부 &#x..;)', function () {
    return eq(U.escapeAttribute('a b"c'), 'a&#x20;b&#x22;c');
  });
  check('인코딩', 'escapeRegExp (특수문자·문자 클래스 안의 -)', function () {
    var special = '.*+?^${}()|[]' + BS + '/-a1 ';
    if (!new RegExp('^' + U.escapeRegExp(special) + '$').test(special)) return 'literal match failed';
    var cls = new RegExp('[' + U.escapeRegExp('a-z') + ']');
    return (cls.test('-') && !cls.test('b')) || 'class dash handling';
  });

  // ---------------------------------------------------------------------------
  // 3. URL
  // ---------------------------------------------------------------------------
  check('URL', 'isSafeURL: 위험 URL 차단 (스킴·탭/개행·백슬래시·//·자격증명)', function () {
    var bad = ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'java' + TAB + 'script:alert(1)', 'java' + LF + 'script:alert(1)',
      ' javascript:alert(1)', 'data:text/html,<script>', 'vbscript:x', 'blob:https://a.com/x', 'file:///etc/passwd',
      '//evil.com', '/' + TAB + '/evil.com', '/' + LF + '/evil.com', '/' + BS + 'evil.com', BS + BS + 'evil.com',
      'https://user:pw@evil.com', 'https://a@evil.com', 'https:' + BS + BS + 'evil.com', '', null, undefined, 123];
    for (var i = 0; i < bad.length; i++) if (U.isSafeURL(bad[i]) !== false) return '통과해버림: ' + JSON.stringify(bad[i]);
    return true;
  });
  check('URL', 'isSafeURL: 정상 URL 허용', function () {
    var ok = ['https://example.com', 'http://example.com/a?b=c#d', '/path', '/a/b?x=1', '?q=1', '#frag', 'relative/path', 'mailto:a@b.com', 'tel:+8210123456'];
    for (var i = 0; i < ok.length; i++) if (U.isSafeURL(ok[i]) !== true) return '거부됨: ' + ok[i];
    return true;
  });
  check('URL', 'isSafeURL: allowedHosts (접미/접두 위장 차단)', function () {
    var o = { allowedHosts: ['app.example.com'] };
    return U.isSafeURL('https://app.example.com/x', undefined, o) === true &&
      U.isSafeURL('https://app.example.com.evil.com/', undefined, o) === false &&
      U.isSafeURL('https://evilapp.example.com/', undefined, o) === false || 'host check';
  });
  check('URL', 'sanitizeURL', function () {
    return eq([U.sanitizeURL('https://a.com'), U.sanitizeURL('javascript:1'), U.sanitizeURL('//x.com', '/home')], ['https://a.com', '#', '/home']);
  });

  // ---------------------------------------------------------------------------
  // 4. JSON / 병합 / 복제 (Prototype Pollution)
  // ---------------------------------------------------------------------------
  var polluted = function () { return ({}).pwn !== undefined || Object.prototype.pwn !== undefined || Array.prototype.pwn !== undefined; };
  var cleanup = function () { delete Object.prototype.pwn; delete Array.prototype.pwn; };
  var escapedProto = '{"' + BS + 'u005f' + BS + 'u005f' + 'proto' + BS + 'u005f' + BS + 'u005f":{"pwn":1}}';
  var payloads = ['{"__proto__":{"pwn":1}}', '{"a":{"b":{"__proto__":{"pwn":1}}}}', '{"constructor":{"prototype":{"pwn":1}}}', '[{"__proto__":{"pwn":1}}]', escapedProto];

  check('오염 방지', 'safeJSONParse: 위험 키 제거 (유니코드 이스케이프 위장 포함)', function () {
    try {
      for (var i = 0; i < payloads.length; i++) {
        U.safeJSONParse(payloads[i]);
        if (polluted()) return '오염됨: ' + payloads[i];
        var s = JSON.stringify(U.safeJSONParse(payloads[i]));
        if (/proto|constructor|prototype/.test(s)) return '위험 키 남음: ' + s;
      }
      return eq(U.safeJSONParse('{"constructor":"Acme","prototype":"v2"}'), { constructor: 'Acme', prototype: 'v2' });
    } finally { cleanup(); }
  });
  check('오염 방지', 'safeMerge: 순수 JSON.parse 결과를 병합해도 오염 없음', function () {
    try {
      for (var i = 0; i < payloads.length; i++) {
        U.safeMerge({}, JSON.parse(payloads[i]));
        U.safeMerge(function Target() {}, JSON.parse(payloads[i]));
        if (polluted()) return '오염됨: ' + payloads[i];
      }
      return eq(U.safeMerge({ a: { x: 1 }, arr: [1] }, { a: { y: 2 }, arr: [2, 3] }), { a: { x: 1, y: 2 }, arr: [2, 3] });
    } finally { cleanup(); }
  });
  check('오염 방지', 'safeDeepClone: 순환·Map·Set·Date, getter 미실행, 깊이 제한', function () {
    var ran = false;
    var src = { get boom() { ran = true; return 1; }, ok: 1 };
    var cyc = { n: 1 }; cyc.self = cyc;
    var c = U.safeDeepClone(cyc);
    var m = U.safeDeepClone(new Map([[1, new Set([2])]]));
    var nest = {}; var cur = nest; for (var i = 0; i < 20; i++) { cur.n = {}; cur = cur.n; }
    return (c.self === c && m instanceof Map && m.get(1) instanceof Set && U.safeDeepClone(new Date(5)).getTime() === 5 &&
      eq(Object.keys(U.safeDeepClone(src)), ['ok']) === true && ran === false && throwsOf(function () { U.safeDeepClone(nest, 5); }, RangeError)) || 'clone check';
  });

  // ---------------------------------------------------------------------------
  // 5. 유틸리티
  // ---------------------------------------------------------------------------
  check('유틸', 'formatBytes (경계·비정상 입력)', function () {
    return eq([U.formatBytes(0), U.formatBytes(1536), U.formatBytes(1048575), U.formatBytes(0.5), U.formatBytes(NaN), U.formatBytes(1073741824)],
      ['0 Bytes', '1.5 KB', '1 MB', '0.5 Bytes', '0 Bytes', '1 GB']);
  });
  check('유틸', 'randomToken (길이·문자집합·유일성)', function () {
    var seen = {};
    for (var i = 0; i < 200; i++) seen[U.randomToken(16)] = 1;
    return (/^[0-9a-f]{64}$/.test(U.randomToken()) && /^[A-Za-z0-9_-]{43}$/.test(U.randomToken(32, 'base64url')) &&
      Object.keys(seen).length === 200 && throwsOf(function () { U.randomToken(0); }, RangeError)) || 'token check';
  });
  check('유틸', 'debounce/throttle: cancel·flush·인자 검증', function () {
    var calls = [];
    var d = U.debounce(function (x) { calls.push(x); }, 1000);
    d(1); d(2); d.flush();
    var t = U.throttle(function (x) { calls.push('t' + x); }, 1000);
    t(1); t(2); t.cancel();
    return (eq(calls, [2, 't1']) === true && throwsOf(function () { U.debounce('x'); }, TypeError) && throwsOf(function () { U.throttle(function () {}, 1, { leading: false, trailing: false }); }, TypeError)) || eq(calls, [2, 't1']);
  });

  // ---------------------------------------------------------------------------
  // 6. html`` 출력
  // ---------------------------------------------------------------------------
  var H = U.html;
  check('html', '텍스트·따옴표 속성 이스케이프', function () {
    return eq([
      str(H`<p>${'<b>&"\''}</p>`),
      str(H`<a title="${'" onmouseover="x'}">`),
      str(H`<i>${null}${false}${0}</i>`)
    ], ['<p>&lt;b&gt;&amp;&quot;&#39;</p>', '<a title="&quot; onmouseover=&quot;x">', '<i>0</i>']);
  });
  check('html', 'URL 속성: 위험 URL 은 #, 고정 문자열 뒤 보간은 인코딩', function () {
    return eq([
      str(H`<a href="${'javascript:alert(1)'}">`),
      str(H`<a href="${'//evil.com'}">`),
      str(H`<a href="/u/${'a/b c'}?q=${'1&2'}">`)
    ], ['<a href="#">', '<a href="#">', '<a href="/u/a%2Fb%20c?q=1%262">']);
  });
  check('html', '중첩·배열은 이중 인코딩 없이, 속성 안에서는 일반 문자열로', function () {
    return eq([
      str(H`<ul>${[1, 2].map(function (i) { return H`<li>${i}</li>`; })}</ul>`),
      str(H`<p>${H`<i>${'<'}</i>`}</p>`),
      str(H`<a title="${H`<b>`}">`)
    ], ['<ul><li>1</li><li>2</li></ul>', '<p><i>&lt;</i></p>', '<a title="&lt;b&gt;">']);
  });
  check('html', 'SafeHTML 위조 불가 (데이터·constructor)', function () {
    var forged = new (H`x`.constructor)('<script>alert(1)</script>');
    return (!U.isSafeHTML({ value: '<b>' }) && !U.isSafeHTML(JSON.parse('{"toString":"x"}')) && !U.isSafeHTML(forged) &&
      str(H`<p>${forged}</p>` ) === '<p></p>' && Object.isFrozen(H`x`)) || 'forgery check';
  });
  check('html', '허용되지 않는 위치의 보간은 Error (on*·script 본문·태그 이름·따옴표 없는 값 등)', function () {
    var x = 'ok';
    var cases = [
      function () { return H`<img onerror=${x}>`; }, function () { return H`<a onclick="${x}">`; }, function () { return H`<div style="${x}">`; },
      function () { return H`<script>${x}</script>`; }, function () { return H`<style>${x}</style>`; }, function () { return H`<script src="${x}"></script>`; },
      function () { return H`<${x}>`; }, function () { return H`<div ${x}>`; }, function () { return H`<!-- ${x} -->`; },
      function () { return H`<input value=${x} class="c">`; }, function () { return H`a<${x}`; }
    ];
    for (var i = 0; i < cases.length; i++) if (!throwsOf(cases[i], Error)) return '던지지 않음: case #' + i;
    return throwsOf(function () { return U.html('plain string'); }, TypeError) || 'html(string) should throw TypeError';
  });

  // ---------------------------------------------------------------------------
  // 7. html`` × "이 브라우저의 HTML 파서" 대조 (브라우저마다 달라질 수 있는 핵심 검증)
  //    구조 불변 / 데이터 왕복 / URL 안전성을 DOMParser 결과로 확인한다.
  // ---------------------------------------------------------------------------
  function parseBody(s) {
    return new DOMParser().parseFromString('<!doctype html><html><body>' + s + '</body></html>', 'text/html');
  }
  function signature(doc) {
    return Array.prototype.map.call(doc.body.querySelectorAll('*'), function (e) {
      return e.tagName + '[' + Array.prototype.map.call(e.attributes, function (a) { return a.name; }).sort().join(',') + ']';
    }).join('|');
  }
  function norm(s) { return s.replace(/\r\n?/g, '\n'); }
  function skipRoundtrip(p) {
    for (var i = 0; i < p.length; i++) {
      var c = p.charCodeAt(i);
      if (c === 0 || c === 13 || (c >= 0xD800 && c <= 0xDFFF)) return true; // NUL/CR 정규화, 짝 없는 서로게이트는 파서가 U+FFFD 로 치환
    }
    return false;
  }
  function byId(d, id) { return d.getElementById(id); }

  var TPLS = [
    { n: '텍스트', f: function (v) { return H`<p id="t">${v}</p>`; }, get: function (d) { return byId(d, 't').textContent; } },
    { n: '텍스트(중첩 요소)', f: function (v) { return H`<div><span id="t">a${v}b</span></div>`; }, get: function (d) { return byId(d, 't').textContent; }, wrap: function (p) { return 'a' + p + 'b'; } },
    { n: '속성(")', f: function (v) { return H`<a id="t" title="${v}">x</a>`; }, get: function (d) { return byId(d, 't').getAttribute('title'); } },
    { n: "속성(')", f: function (v) { return H`<a id="t" title='${v}'>x</a>`; }, get: function (d) { return byId(d, 't').getAttribute('title'); } },
    { n: '속성 + 뒤따르는 속성', f: function (v) { return H`<input id="t" value="${v}" class="c" data-k=1>`; }, get: function (d) { return byId(d, 't').getAttribute('value'); } },
    { n: 'textarea 본문', f: function (v) { return H`<textarea id="t">${v}</textarea>`; }, get: function (d) { return byId(d, 't').textContent; }, leadNL: true },
    { n: 'title 본문', f: function (v) { return H`<title id="t">${v}</title>`; }, get: function (d) { var e = byId(d, 't'); return e ? e.textContent : null; } },
    { n: 'href', f: function (v) { return H`<a id="t" href="${v}">x</a>`; }, url: function (d) { return byId(d, 't').getAttribute('href'); } },
    { n: 'img src', f: function (v) { return H`<img id="t" src="${v}">`; }, url: function (d) { return byId(d, 't').getAttribute('src'); } },
    { n: 'form action', f: function (v) { return H`<form id="t" action="${v}"></form>`; }, url: function (d) { return byId(d, 't').getAttribute('action'); } },
    { n: 'href 경로 조각', f: function (v) { return H`<a id="t" href="/p/${v}">x</a>`; }, mid: function (d) { return byId(d, 't').getAttribute('href'); } },
    { n: 'href 쿼리 조각', f: function (v) { return H`<a id="t" href="/p?q=${v}&r=1">x</a>`; }, mid: function (d) { return byId(d, 't').getAttribute('href'); } },
    { n: '목록(중첩 html)', f: function (v) { return H`<ul id="t">${[v, v].map(function (i) { return H`<li>${i}</li>`; })}</ul>`; }, list: true },
    { n: '테이블 셀', f: function (v) { return H`<table id="t"><tr><td>${v}</td></tr></table>`; }, get: function (d) { return d.querySelector('td').textContent; } },
    { n: 'select/option', f: function (v) { return H`<select><option id="t" value="${v}">${v}</option></select>`; }, get: function (d) { return byId(d, 't').getAttribute('value'); } },
    { n: 'svg text', f: function (v) { return H`<svg><text id="t">${v}</text></svg>`; }, get: function (d) { return byId(d, 't').textContent; } },
    { n: '주석 뒤', f: function (v) { return H`<!-- c " ' --><p id="t">${v}</p>`; }, get: function (d) { return byId(d, 't').textContent; } },
    { n: 'script 뒤', f: function (v) { return H`<script>1</script><p id="t">${v}</p>`; }, get: function (d) { return byId(d, 't').textContent; } },
    { n: '속성 안의 > 뒤', f: function (v) { return H`<a id="t" title=">" href="${v}">${v}</a>`; }, get: function (d) { return byId(d, 't').textContent; } }
  ];

  var corpus = [
    '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "' onmouseover='alert(1)", ' onfocus=alert(1) autofocus ', 'x onmouseover=alert(1)',
    'javascript:alert(1)', 'JaVaScRiPt:alert(1)', '</textarea><script>alert(1)</script>', '</title><script>alert(1)</script>', '--><img src=x onerror=1>',
    '&#x3C;script&#x3E;', '&lt;b&gt;', '%3Cscript%3E', '`onmouseover=alert(1)`', 'a' + TAB + 'b' + LF + 'c', LF + 'leading newline',
    '//evil.com/x', '/' + BS + 'evil.com', 'data:text/html,<script>alert(1)</script>', '= / > < " \' ` & ;', '', ' ', 'x',
    'https://example.com/a?b=1&c=2', '/relative/path', '#frag', 'mailto:a@b.com', 'tel:+82101234', 'https://user:pw@evil.com',
    String.fromCharCode(0xD800), 'a' + String.fromCharCode(0xD800) + 'b', '</p><p>', '<!--', '-->', '<![CDATA[x]]>', NUL, CR + LF, CR
  ];
  var frags = ['<', '>', '"', "'", '`', '&', '&#x3C;', '&lt;', '&amp;', '=', ' ', TAB, LF, '/', '//', '--', '-->', '<!--', '</p>', '</a>', '</textarea>', '</title>',
    '</script>', '<script>', '<img src=x onerror=1>', 'javascript:', 'data:', 'vbscript:', 'x', 'onload=', 'style=', '%', BS, 'a', '1', ':', '?', '#', '@',
    '</svg>', '<svg onload=1>', ']]>', '</style>', '<style>', '<noscript>', '</noscript><img src=x onerror=1>'];
  var seed = 20241104;
  function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
  var inputs = corpus.slice();
  for (var ci = 0; ci < 250; ci++) {
    var s = ''; var k = 1 + Math.floor(rnd() * 6);
    for (var j = 0; j < k; j++) s += frags[Math.floor(rnd() * frags.length)];
    inputs.push(s);
  }

  var totalRenders = 0;
  function runTemplate(t) {
    var base = signature(parseBody(str(t.f('x'))));
    var firstFail = null;
    var count = 0;
    var fail = function (p, why) { if (!firstFail) firstFail = why + ' | payload=' + JSON.stringify(p.slice(0, 60)); };
    for (var i = 0; i < inputs.length; i++) {
      var p = inputs[i];
      var out = str(t.f(p));
      count++;
      var doc = parseBody(out);
      if (signature(doc) !== base) { fail(p, '구조가 바뀜'); continue; }
      if (t.get && !skipRoundtrip(p)) {
        var want = norm(t.wrap ? t.wrap(p) : p);
        if (t.leadNL) want = want.replace(/^\n/, '');
        var got = t.get(doc);
        if (got !== want) fail(p, '값 왕복 불일치 got=' + JSON.stringify(got));
      }
      if (t.url) {
        var v = t.url(doc);
        if (v !== '#') {
          var u = new URL(v, 'http://h.test/');
          var rel = !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(v);
          if (['http:', 'https:', 'mailto:', 'tel:'].indexOf(u.protocol) < 0 || (rel && u.host !== 'h.test') || u.username || u.password) fail(p, '안전하지 않은 URL ' + JSON.stringify(v));
        }
      }
      if (t.mid) {
        var m = new URL(t.mid(doc), 'http://h.test/');
        if (m.host !== 'h.test' || m.pathname.indexOf('/p') !== 0) fail(p, '경로를 벗어남');
      }
      if (t.list) {
        var lis = doc.querySelectorAll('#t > li');
        if (lis.length !== 2 || (!skipRoundtrip(p) && (lis[0].textContent !== norm(p) || lis[1].textContent !== norm(p)))) fail(p, '목록 불일치');
      }
    }
    totalRenders += count;
    return firstFail;
  }

  if (features.DOMParser) {
    TPLS.forEach(function (t) {
      check('html × 이 브라우저의 HTML 파서', t.n + ' (' + inputs.length + '개 입력)', function () {
        var f = runTemplate(t);
        return f === null ? true : f;
      });
    });
  } else {
    record('html × 이 브라우저의 HTML 파서', 'DOMParser 가 없어 건너뜀', 'skip', '이 브라우저는 DOMParser 를 지원하지 않습니다');
  }

  // ---------------------------------------------------------------------------
  // 8. 비동기: 타이머, ESM
  // ---------------------------------------------------------------------------
  var esmState = null; // { ok, detail } 또는 null(대기 중)
  window.__reportEsm = function (ok, detail) { esmState = { ok: ok, detail: detail || '' }; };
  var esmEl = document.getElementById('esmScript');
  if (esmEl) esmEl.addEventListener('error', function () {
    // file:// 에서는 모든 브라우저가 모듈 로드를 막는다(CORS) → 실패가 아니라 "건너뜀" 으로 취급
    esmState = location.protocol === 'file:' ? { skip: true } : { ok: false, detail: '모듈 로드 실패 (파일 경로 / 서버 설정 / MIME 타입 확인)' };
  });

  var dCalls = [];
  var d = U.debounce(function (x) { dCalls.push(x); }, 40);
  d(1); d(2); d(3);
  var tCalls = [];
  var th = U.throttle(function (x) { tCalls.push(x); }, 60);
  th(1); th(2); th(3);

  setTimeout(function () {
    check('타이머', 'debounce: 연속 호출은 마지막 한 번만 실행', function () { return eq(dCalls, [3]); });
    check('타이머', 'throttle: 첫 호출 즉시 + 구간 끝에 마지막 호출', function () { return eq(tCalls, [1, 3]); });

    var deadline = Date.now() + 3000;
    (function waitEsm() {
      var moduleSupported = features['script type=module'];
      if (esmState === null && moduleSupported && location.protocol !== 'file:' && Date.now() < deadline) { setTimeout(waitEsm, 50); return; }
      if (esmState !== null && !esmState.skip) record('ESM', '네이티브 ESM import (dist/easy-secure-utils.mjs)', esmState.ok ? 'pass' : 'fail', esmState.detail);
      else if (!moduleSupported) record('ESM', '네이티브 ESM import', 'skip', '이 브라우저는 type=module 을 지원하지 않습니다');
      else if (location.protocol === 'file:') record('ESM', '네이티브 ESM import', 'skip', 'file:// 에서는 브라우저가 모듈을 막습니다. http(s) 로 열면 검사됩니다 (예: GitHub Pages)');
      else record('ESM', '네이티브 ESM import', 'fail', '응답 없음 (시간 초과)');
      finalize();
    })();
  }, 350);

  // ---------------------------------------------------------------------------
  // 결과 표시
  // ---------------------------------------------------------------------------
  function finalize() {
    var pass = 0, fail = 0, skip = 0;
    results.forEach(function (r) { if (r.status === 'pass') pass++; else if (r.status === 'fail') fail++; else skip++; });
    var status = fail === 0 ? 'pass' : 'fail';
    document.body.setAttribute('data-status', status);
    document.title = (status === 'pass' ? 'PASS' : 'FAIL') + ' ' + pass + '/' + (pass + fail) + ' - 브라우저 호환성 점검';

    var summary = document.getElementById('summary');
    summary.className = 'summary ' + status;
    summary.textContent = (status === 'pass' ? '✅ 모두 통과' : '❌ 실패 ' + fail + '개') + ' — 통과 ' + pass + ' / 실패 ' + fail + ' / 건너뜀 ' + skip +
      (totalRenders ? ' (html 파서 대조 ' + totalRenders + '회 렌더)' : '');

    document.getElementById('ua').textContent = navigator.userAgent;
    var featText = Object.keys(features).map(function (k) { return k + ': ' + features[k]; }).join('\n');
    document.getElementById('features').textContent = featText;

    var table = document.getElementById('results');
    var lastGroup = null;
    results.forEach(function (r) {
      if (r.group !== lastGroup) {
        var gh = document.createElement('tr');
        var gc = document.createElement('th');
        gc.colSpan = 2; gc.textContent = r.group;
        gh.appendChild(gc); table.appendChild(gh); lastGroup = r.group;
      }
      var tr = document.createElement('tr');
      tr.className = r.status;
      var c1 = document.createElement('td'); c1.textContent = (r.status === 'pass' ? '✅ ' : r.status === 'fail' ? '❌ ' : '⏭️ ') + r.name;
      var c2 = document.createElement('td'); c2.className = 'detail'; c2.textContent = r.detail;
      tr.appendChild(c1); tr.appendChild(c2); table.appendChild(tr);
    });

    var json = JSON.stringify({
      library: 'easy-secure-utils', userAgent: navigator.userAgent, status: status, pass: pass, fail: fail, skip: skip, renders: totalRenders, features: features,
      failures: results.filter(function (r) { return r.status === 'fail'; }),
      skipped: results.filter(function (r) { return r.status === 'skip'; }).map(function (r) { return r.name + ': ' + r.detail; })
    }, null, 2);
    var box = document.getElementById('json');
    box.textContent = json; // DOM 직렬화(자동 점검 도구)에서도 읽을 수 있도록 텍스트로도 설정
    box.value = json;
    box.addEventListener('focus', function () { box.select(); });
  }
})();
