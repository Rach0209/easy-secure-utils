import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const umd = require('../dist/easy-secure-utils.js');
const esm = await import('../dist/easy-secure-utils.mjs');

const BS = String.fromCharCode(92);        // 백슬래시 (소스에 이스케이프 표기를 직접 쓰지 않기 위함)
const TAB = String.fromCharCode(9);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// 빌드 산출물 / 패키지 일관성
// ---------------------------------------------------------------------------
test('dist 는 src 로부터의 최신 빌드와 동일하다 (npm run build 필요 여부)', () => {
  const { build } = require('../scripts/build.js');
  const { umd: wantUmd, esm: wantEsm } = build();
  const norm = (f) => fs.readFileSync(path.join(ROOT, 'dist', f), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(norm('easy-secure-utils.js'), wantUmd);
  assert.equal(norm('easy-secure-utils.mjs'), wantEsm);
});

test('package.json 버전 == 소스 배너 버전, exports 경로가 실제로 존재', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const banner = fs.readFileSync(path.join(ROOT, 'src', 'easy-secure-utils.mjs'), 'utf8').match(/SecureWebUtils v(\S+)/)[1];
  assert.equal(pkg.version, banner);
  const paths = [pkg.main, pkg.module, pkg.types, pkg.exports['.'].import, pkg.exports['.'].require, pkg.exports['.'].types];
  for (const p of paths) assert.ok(fs.existsSync(path.join(ROOT, p)), p + ' 없음');
});

test('UMD 와 ESM 의 공개 API 목록이 동일하다 (+ .d.ts 선언과 일치)', () => {
  const names = Object.keys(umd).sort();
  assert.deepEqual(Object.keys(esm).sort(), names);
  const dts = fs.readFileSync(path.join(ROOT, 'types', 'easy-secure-utils.d.ts'), 'utf8');
  const declared = [...dts.matchAll(/export function (\w+)/g)].map((m) => m[1]).sort();
  assert.deepEqual(declared, names);
});

test('UMD: 전역(<script>) 로드 방식에서도 SecureWebUtils 가 노출된다', () => {
  const vm = require('node:vm');
  const code = fs.readFileSync(path.join(ROOT, 'dist', 'easy-secure-utils.js'), 'utf8');
  const ctx = vm.createContext({ self: undefined });
  vm.runInContext(code, ctx, { filename: 'umd-global.js' });
  assert.equal(typeof vm.runInContext('SecureWebUtils.escapeHTML', ctx), 'function');
  assert.equal(vm.runInContext('Object.isFrozen(SecureWebUtils)', ctx), true);
});

// ---------------------------------------------------------------------------
// 취약한 병합 유틸 (Prototype Pollution 재현용)
// ---------------------------------------------------------------------------
const isObj = (v) => v !== null && (typeof v === 'object' || typeof v === 'function');
const vulnerableMerges = {
  recursiveWithFunctions: function merge(t, s) {
    for (const k in s) {
      if (isObj(s[k]) && isObj(t[k])) merge(t[k], s[k]);
      else if (isObj(s[k])) { t[k] = {}; merge(t[k], s[k]); } else t[k] = s[k];
    }
    return t;
  },
  recursiveObjectOnly: function merge(t, s) {
    for (const k in s) {
      if (s[k] && typeof s[k] === 'object') { if (!t[k] || typeof t[k] !== 'object') t[k] = {}; merge(t[k], s[k]); } else t[k] = s[k];
    }
    return t;
  },
  pathSetter(t, s) {
    const flat = (o, p = []) => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? flat(v, [...p, k]) : [[[...p, k], v]]));
    for (const [pathKeys, v] of flat(s)) {
      let c = t;
      for (let i = 0; i < pathKeys.length - 1; i++) c = c[pathKeys[i]] = c[pathKeys[i]] || {};
      c[pathKeys[pathKeys.length - 1]] = v;
    }
    return t;
  }
};
function pollutionDetected() {
  return ({}).pwn !== undefined || Object.pwn !== undefined || Function.prototype.pwn !== undefined || Array.prototype.pwn !== undefined;
}
function cleanPollution() { for (const o of [Object.prototype, Object, Function.prototype, Array.prototype]) delete o.pwn; }
/** 오염이 발생한 (병합 방식, 대상 종류) 조합의 수를 반환 */
function countPollution(valueFactory) {
  let hits = 0;
  try {
    for (const merge of Object.values(vulnerableMerges)) {
      for (const makeTarget of [() => ({}), () => class Target {}]) {
        const target = makeTarget();
        try { merge(target, valueFactory()); } catch (_) { /* ignore */ }
        if (pollutionDetected() || (typeof target === 'function' && target.prototype.pwn !== undefined)) hits++;
        cleanPollution();
      }
    }
  } finally { cleanPollution(); }
  return hits;
}
const U_ESC = (hex) => BS + 'u' + hex; // JSON 유니코드 이스케이프 표기 생성
const pollutionPayloads = {
  proto: '{"__proto__":{"pwn":1}}',
  protoNested: '{"a":{"b":{"__proto__":{"pwn":1}}}}',
  protoInArray: '[{"__proto__":{"pwn":1}}]',
  ctorProto: '{"constructor":{"prototype":{"pwn":1}}}',
  ctorObject: '{"constructor":{"pwn":1}}',
  protoKeyObject: '{"prototype":{"pwn":1}}',
  escapedProto: '{"' + U_ESC('005f') + U_ESC('005f') + 'proto' + U_ESC('005f') + U_ESC('005f') + '":{"pwn":1}}',
  escapedCtorProto: '{"' + U_ESC('0063') + 'onstructor":{"' + U_ESC('0070') + 'rototype":{"pwn":1}}}'
};

// ---------------------------------------------------------------------------
// 기능/보안 테스트 (UMD 와 ESM 양쪽에 동일하게 적용)
// ---------------------------------------------------------------------------
for (const [fmt, U] of [['umd', umd], ['esm', esm]]) {
  const T = (name, fn) => test(`[${fmt}] ${name}`, fn);

  T('escapeHTML', () => {
    assert.equal(U.escapeHTML('<img src=x onerror="a(\'1\')">`'), '&lt;img src=x onerror=&quot;a(&#39;1&#39;)&quot;&gt;&#96;');
    assert.equal(U.escapeHTML('hello 한글'), 'hello 한글');
    assert.equal(U.escapeHTML(0), '0');
    assert.equal(U.escapeHTML(false), 'false');
    assert.equal(U.escapeHTML(null), '');
    assert.equal(U.escapeHTML(undefined), '');
    assert.equal(U.escapeHTML({ toString() { return '<x>'; } }), '');
  });

  T('escapeAttribute: 따옴표 없는 속성에서도 탈출 불가', () => {
    const hostile = ' onmouseover=alert(1) x="\'`><svg/onload=1>' + LF + TAB + String.fromCharCode(0);
    const out = U.escapeAttribute(hostile);
    assert.match(out, /^[A-Za-z0-9,._\-&#;x]*$/);
    assert.doesNotMatch(out, /[ "'<>=`\s]/);
    assert.equal(U.escapeAttribute('😀'), '&#x1F600;');
    assert.equal(U.escapeAttribute(null), '');
  });

  T('isSafeURL: 차단되어야 하는 입력', () => {
    const blocked = [
      'javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)', 'javascript:alert(1) ',
      'java' + TAB + 'script:alert(1)', 'java' + LF + 'script:alert(1)', 'java' + CR + 'script:alert(1)',
      String.fromCharCode(1) + 'javascript:alert(1)', String.fromCharCode(0) + 'javascript:alert(1)',
      String.fromCharCode(0xA0) + 'javascript:alert(1)', String.fromCharCode(0xFEFF) + 'javascript:alert(1)',
      'javascript' + String.fromCharCode(0) + ':alert(1)',
      'data:text/html,<script>alert(1)</script>', 'DATA:text/html;base64,PHNjcmlwdD4=', 'vbscript:msgbox(1)',
      'blob:https://a.com/uuid', 'file:///etc/passwd', 'filesystem:https://a.com/x', 'about:blank', 'view-source:https://a.com',
      '//evil.com', '///evil.com', '////evil.com', BS + BS + 'evil.com', '/' + BS + 'evil.com', BS + '/evil.com', '/' + BS + '/evil.com',
      '/' + TAB + '/evil.com', '/' + LF + '/evil.com', '/' + CR + '/evil.com', TAB + '//evil.com', '/' + String.fromCharCode(0) + '/evil.com',
      'https:' + BS + BS + 'evil.com', 'https:/' + BS + 'evil.com', 'http:' + BS + 'evil.com',
      'https://user@evil.com', 'https://trusted.com@evil.com', 'https://trusted.com:pw@evil.com', 'https://trusted.com%2f@evil.com',
      'https://', 'http://', 'ftp://a.com', 'ws://a.com', 'chrome://settings', 'intent://x#Intent;end', 'x:y', 'a:b/c',
      '', ' ', null, undefined, 123, {}, [], ['https://a.com'], 'h'.repeat(9000)
    ];
    for (const u of blocked) assert.equal(U.isSafeURL(u), false, JSON.stringify(typeof u === 'string' ? u.slice(0, 40) : u));
  });

  T('isSafeURL: 허용되어야 하는 입력', () => {
    const allowed = [
      'https://example.com', 'http://example.com/a?b=c#d', 'https://sub.example.com:8443/x', 'https://한글.kr/x',
      '/', '/path', '/a/b?x=1#y', '?q=1', '#frag', 'relative/path', './rel', '../up', 'mailto:a@b.com?subject=hi', 'tel:+8210123456',
      '/%2F/not-protocol-relative', '/search?q=a b', 'https://example.com/path:with:colons'
    ];
    for (const u of allowed) assert.equal(U.isSafeURL(u), true, u);
  });

  T('isSafeURL: 호출자 오용 방어 및 옵션', () => {
    assert.equal(U.isSafeURL('javascript:1', 'javascript:'), false);        // 문자열 부분일치 우회
    assert.equal(U.isSafeURL('https://a.com', 'https:'), false);
    assert.equal(U.isSafeURL('https://a.com', null), false);
    assert.equal(U.isSafeURL('javascript:1', ['javascript:']), false);      // 허용목록에 넣어도 차단
    assert.equal(U.isSafeURL('data:text/html,x', ['data:', 'https:']), false);
    assert.equal(U.isSafeURL('ftp://a.com', ['ftp:']), true);
    const hosts = { allowedHosts: ['app.example.com'] };
    assert.equal(U.isSafeURL('https://app.example.com/x', undefined, hosts), true);
    assert.equal(U.isSafeURL('https://APP.Example.com/', undefined, hosts), true);
    assert.equal(U.isSafeURL('https://evil.com/x', undefined, hosts), false);
    assert.equal(U.isSafeURL('https://app.example.com.evil.com/', undefined, hosts), false);
    assert.equal(U.isSafeURL('https://evilapp.example.com/', undefined, hosts), false);
    assert.equal(U.isSafeURL('/x', undefined, hosts), true);
    assert.equal(U.isSafeURL('mailto:a@b.com', undefined, { allowedHosts: ['x.com'] }), true);
    assert.equal(U.isSafeURL('https://a.com', undefined, { allowedHosts: 'a.com' }), false);
    assert.equal(U.isSafeURL('/x', undefined, { allowRelative: false }), false);
  });

  T('safeJSONParse: 취약한 병합 유틸에 넘겨도 오염되지 않는다', () => {
    // 대조군: 일반 JSON.parse 결과는 실제로 오염을 일으킨다 (테스트가 의미 있음을 증명)
    assert.ok(countPollution(() => JSON.parse(pollutionPayloads.ctorProto)) > 0, '대조군이 오염을 재현하지 못함');
    assert.ok(countPollution(() => JSON.parse(pollutionPayloads.proto)) > 0, '대조군이 오염을 재현하지 못함');
    for (const [name, payload] of Object.entries(pollutionPayloads)) {
      assert.equal(countPollution(() => U.safeJSONParse(payload)), 0, name);
    }
  });

  T('safeJSONParse: 위험 키는 모든 깊이에서 제거, 정상 원시값 데이터는 보존', () => {
    assert.deepEqual(U.safeJSONParse(pollutionPayloads.protoNested), { a: { b: {} } });
    assert.deepEqual(U.safeJSONParse(pollutionPayloads.protoInArray), [{}]);
    assert.deepEqual(U.safeJSONParse(pollutionPayloads.escapedProto), {});
    assert.deepEqual(U.safeJSONParse('{"__proto__":1,"ok":true}'), { ok: true });
    // 정당한 데이터: 원시값을 가진 constructor / prototype 키는 유지
    assert.deepEqual(
      U.safeJSONParse('{"constructor":"Acme Corp","prototype":"v2","meta":{"constructor":7}}'),
      { constructor: 'Acme Corp', prototype: 'v2', meta: { constructor: 7 } }
    );
    // 객체/배열 값은 제거
    assert.deepEqual(U.safeJSONParse('{"constructor":[1],"prototype":{"a":1},"keep":1}'), { keep: 1 });
    assert.equal(Object.prototype.hasOwnProperty.call(U.safeJSONParse(pollutionPayloads.proto), '__proto__'), false);
  });

  T('safeJSONParse: fallback / 길이 제한 / 깊은 중첩', () => {
    assert.deepEqual(U.safeJSONParse('{"a":[1,2,{"b":"c"}]}'), { a: [1, 2, { b: 'c' }] });
    assert.equal(U.safeJSONParse('{bad', 'FB'), 'FB');
    assert.equal(U.safeJSONParse({}, 'FB'), 'FB');
    assert.equal(U.safeJSONParse('[' + '1,'.repeat(100) + '1]', 'FB', 50), 'FB');
    assert.deepEqual(U.safeJSONParse('[1]', 'FB', 'abc'), [1]);
    assert.equal(U.safeJSONParse('['.repeat(200000) + ']'.repeat(200000), 'FB') !== undefined, true); // 예외 없이 종료
  });

  T('safeDeepClone: 위험 키 제거 + 병합 유틸 오염 없음', () => {
    const src = JSON.parse('{"__proto__":{"pwn":1},"constructor":{"prototype":{"pwn":2}},"name":"x","constructor_ok":1}');
    const c = U.safeDeepClone(src);
    assert.deepEqual(Object.getOwnPropertyNames(c).sort(), ['constructor_ok', 'name']);
    assert.equal(countPollution(() => U.safeDeepClone(src)), 0);
    // 원시값 constructor 는 보존 (safeJSONParse 와 동일 규칙)
    assert.equal(U.safeDeepClone(JSON.parse('{"constructor":"Acme"}')).constructor, 'Acme');
  });

  T('safeDeepClone: getter 미실행, 비열거 제외, 프로토타입 setter 우회', () => {
    let ran = false;
    const c = U.safeDeepClone({ get boom() { ran = true; return 1; }, safe: 1 });
    assert.equal(ran, false);
    assert.deepEqual(Object.keys(c), ['safe']);

    let setterRan = false;
    const withProtoSetter = Object.create({ set x(v) { setterRan = true; } });
    Object.defineProperty(withProtoSetter, 'x', { value: 5, enumerable: true, configurable: true, writable: true });
    U.safeDeepClone(withProtoSetter);
    assert.equal(setterRan, false);

    const hidden = Object.defineProperty({ a: 1 }, 'h', { value: 1, enumerable: false });
    assert.equal(Object.getOwnPropertyDescriptor(U.safeDeepClone(hidden), 'h'), undefined);
  });

  T('safeDeepClone: 순환, Map/Set/Date/RegExp/TypedArray/Error, 희소 배열, Symbol', () => {
    const circ = { n: 1, arr: [] }; circ.self = circ; circ.arr.push(circ);
    const cc = U.safeDeepClone(circ);
    assert.ok(cc.self === cc && cc.arr[0] === cc && cc !== circ);

    const m = new Map([[{ k: 1 }, new Set([1, { d: 2 }])]]);
    const cm = U.safeDeepClone(m);
    const [[k, v]] = [...cm];
    assert.ok(cm instanceof Map && k.k === 1 && v instanceof Set && [...v][1].d === 2);
    assert.notEqual(k, [...m.keys()][0]);

    assert.equal(U.safeDeepClone(new Date(5)).getTime(), 5);
    assert.equal(U.safeDeepClone(/a/gi).flags, 'gi');
    const u8 = new Uint8Array([1, 2, 3]);
    const cu8 = U.safeDeepClone(u8);
    assert.deepEqual(Array.from(cu8), [1, 2, 3]);
    assert.notEqual(cu8.buffer, u8.buffer);
    assert.equal(U.safeDeepClone(new TypeError('x')).message, 'x');

    const sparse = U.safeDeepClone([1, , 3]);
    assert.equal(sparse.length, 3);
    assert.equal(1 in sparse, false);

    const sym = Symbol('s');
    assert.equal(U.safeDeepClone({ [sym]: 1 })[sym], 1);
    assert.equal(U.safeDeepClone(new (class Foo { constructor() { this.a = 1; } })()).constructor.name, 'Foo');
    assert.equal(Object.getPrototypeOf(U.safeDeepClone(Object.create(null))), null);
    assert.deepEqual([U.safeDeepClone(1), U.safeDeepClone('a'), U.safeDeepClone(null), U.safeDeepClone(undefined)], [1, 'a', null, undefined]);
  });

  T('safeDeepClone: 미지원 타입 TypeError, 깊이 폭탄 RangeError', () => {
    assert.throws(() => U.safeDeepClone(new WeakMap()), TypeError);
    assert.throws(() => U.safeDeepClone(Promise.resolve()), TypeError);
    let deep = {}; let cur = deep;
    for (let i = 0; i < 50000; i++) { cur.n = {}; cur = cur.n; }
    assert.throws(() => U.safeDeepClone(deep), RangeError);
    // maxDepth 옵션이 엔진 스택 한계가 아니라 라이브러리 자체 제한으로 동작하는지 확인
    const nest = (n) => { const r = {}; let c = r; for (let i = 0; i < n; i++) { c.n = {}; c = c.n; } return r; };
    assert.throws(() => U.safeDeepClone(nest(10), 5), /maximum depth/);
    assert.doesNotThrow(() => U.safeDeepClone(nest(10), 20));
    let ok = {}; cur = ok;
    for (let i = 0; i < 500; i++) { cur.n = {}; cur = cur.n; }
    assert.doesNotThrow(() => U.safeDeepClone(ok));
  });

  T('formatBytes', () => {
    const table = [
      [0, '0 Bytes'], [-5, '0 Bytes'], [NaN, '0 Bytes'], [Infinity, '0 Bytes'], ['5', '0 Bytes'], [null, '0 Bytes'],
      [1, '1 Bytes'], [0.5, '0.5 Bytes'], [1023, '1023 Bytes'], [1023.999, '1 KB'], [1024, '1 KB'], [1536, '1.5 KB'],
      [1048575, '1 MB'], [1048576, '1 MB'], [1073741824, '1 GB'], [1024 ** 5, '1 PB'], [1024 ** 6, '1024 PB']
    ];
    for (const [input, want] of table) assert.equal(U.formatBytes(input), want, String(input));
    assert.equal(U.formatBytes(1536, 0), '2 KB');
    assert.equal(U.formatBytes(1536, -1), '2 KB');
    assert.equal(U.formatBytes(1536, NaN), '1.5 KB');
    assert.doesNotThrow(() => U.formatBytes(1536, 200));
    assert.doesNotThrow(() => U.formatBytes(1536, Infinity));
    assert.doesNotThrow(() => U.formatBytes(Number.MAX_VALUE));
    for (const b of [0.1, 1e-9, 5e-324, 1, 1e3, 1e30]) assert.doesNotMatch(U.formatBytes(b), /undefined|NaN|Infinity/);
  });

  T('공개 API 변조 방지', () => {
    if (fmt === 'umd') assert.equal(Object.isFrozen(U), true);
    assert.throws(() => { U.escapeHTML = () => 'pwn'; }, TypeError); // 둘 다 strict 컨텍스트에서 TypeError
    assert.equal(U.escapeHTML('<'), '&lt;');
    const original = JSON.parse;
    JSON.parse = () => ({ tampered: true });
    try { assert.deepEqual(U.safeJSONParse('{"a":1}'), { a: 1 }); } finally { JSON.parse = original; }
  });

  T('debounce', async () => {
    assert.throws(() => U.debounce('x'), TypeError);

    const calls = [];
    const d = U.debounce(function (x) { calls.push([x, this && this.t]); }, 40);
    d.call({ t: 'T' }, 1); d.call({ t: 'T' }, 2); d.call({ t: 'T' }, 3);
    await sleep(120);
    assert.deepEqual(calls, [[3, 'T']]);

    const cancelled = [];
    const dc = U.debounce((x) => cancelled.push(x), 40);
    dc(1); dc.cancel();
    await sleep(100);
    assert.deepEqual(cancelled, []);

    const lead = [];
    const dl = U.debounce((x) => lead.push(x), 40, { leading: true });
    dl(1); dl(2); dl(3);
    await sleep(100);
    dl(4);
    await sleep(100);
    assert.deepEqual(lead, [1, 4]);

    const huge = []; // 상한(2^31-1) 초과 delay 가 즉시 실행되지 않아야 함
    const dh = U.debounce(() => huge.push(1), 1e12);
    dh(); await sleep(50);
    assert.deepEqual(huge, []);
    dh.cancel();
  });
}

// debounce 에서 fn 이 예외를 던져도 이후 호출이 정상 동작해야 함 (프로세스 전역 핸들러를 쓰므로 루프 밖에서 1회만)
test('debounce: fn 예외 후에도 상태가 꼬이지 않는다 (자식 프로세스에서 검증)', async () => {
  // node:test 는 uncaughtException 을 테스트 실패로 처리하므로 별도 프로세스에서 실행한다
  const { spawnSync } = await import('node:child_process');
  const script = `
    const { debounce } = require(${JSON.stringify(path.join(ROOT, 'dist', 'easy-secure-utils.js'))});
    let n = 0; const errors = [];
    process.on('uncaughtException', (e) => errors.push(e.message));
    const d = debounce(() => { n++; if (n === 1) throw new Error('boom'); }, 10);
    d();
    setTimeout(() => d(), 50);
    setTimeout(() => { console.log(JSON.stringify({ n, errors })); }, 120);
  `;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { n: 2, errors: ['boom'] });
});
