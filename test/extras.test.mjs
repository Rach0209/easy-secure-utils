import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const umd = require('../dist/easy-secure-utils.js');
const esm = await import('../dist/easy-secure-utils.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 오염 여부 검사 도우미
function polluted() {
  return ({}).pwn !== undefined || Object.pwn !== undefined || Function.prototype.pwn !== undefined || Array.prototype.pwn !== undefined;
}
function cleanPollution() { for (const o of [Object.prototype, Object, Function.prototype, Array.prototype]) delete o.pwn; }

const POLLUTION_PAYLOADS = [
  '{"__proto__":{"pwn":1}}',
  '{"a":{"b":{"__proto__":{"pwn":1}}}}',
  '{"constructor":{"prototype":{"pwn":1}}}',
  '{"constructor":{"pwn":1}}',
  '{"prototype":{"pwn":1}}',
  '[{"__proto__":{"pwn":1}}]'
];

for (const [fmt, U] of [['umd', umd], ['esm', esm]]) {
  const T = (name, fn) => test(`[${fmt}] ${name}`, fn);

  // -------------------------------------------------------------------------
  T('sanitizeURL: 안전하면 그대로, 아니면 fallback', () => {
    assert.equal(U.sanitizeURL('https://example.com/a?b=1'), 'https://example.com/a?b=1');
    assert.equal(U.sanitizeURL('/relative'), '/relative');
    assert.equal(U.sanitizeURL('javascript:alert(1)'), '#');
    assert.equal(U.sanitizeURL('javascript:alert(1)', '/home'), '/home');
    assert.equal(U.sanitizeURL('//evil.com', 'about:blank'), 'about:blank');
    assert.equal(U.sanitizeURL('/' + String.fromCharCode(9) + '/evil.com'), '#');
    assert.equal(U.sanitizeURL(null), '#');
    assert.equal(U.sanitizeURL(123, 'x'), 'x');
    // 옵션 전달
    assert.equal(U.sanitizeURL('https://evil.com', '#', undefined, { allowedHosts: ['ok.com'] }), '#');
    assert.equal(U.sanitizeURL('https://ok.com', '#', undefined, { allowedHosts: ['ok.com'] }), 'https://ok.com');
    assert.equal(U.sanitizeURL('ftp://a.com', '#', ['ftp:']), 'ftp://a.com');
  });

  // -------------------------------------------------------------------------
  T('escapeRegExp: 모든 특수문자를 문자 그대로 매칭', () => {
    const specials = '.*+?^${}()|[]\\/-a1 ';
    assert.ok(new RegExp('^' + U.escapeRegExp(specials) + '$').test(specials));
    assert.ok(new RegExp('^' + U.escapeRegExp(specials) + '$', 'u').test(specials)); // u 플래그에서도 유효
    assert.equal(new RegExp('^' + U.escapeRegExp('a.c') + '$').test('abc'), false);
    assert.equal(new RegExp('^' + U.escapeRegExp('(a+)+$') + '$').test('(a+)+$'), true);
    // 문자 클래스 안의 '-' 가 범위로 해석되지 않음
    const cls = new RegExp('[' + U.escapeRegExp('a-z') + ']');
    assert.equal(cls.test('-'), true);
    assert.equal(cls.test('b'), false);
    assert.equal(U.escapeRegExp(12.5), '12\\.5');
    assert.equal(U.escapeRegExp(null), '');
    assert.equal(U.escapeRegExp({}), '');
  });

  // -------------------------------------------------------------------------
  T('safeMerge: 기본 동작 (깊은 병합, 배열 교체, 반환값, 다중 source)', () => {
    const target = { a: 1, nested: { x: 1, keep: true }, arr: [1, 2, 3] };
    const result = U.safeMerge(target, { b: 2, nested: { x: 9, y: 2 }, arr: [4] }, { c: 3 });
    assert.equal(result, target);
    assert.deepEqual(target, { a: 1, b: 2, c: 3, nested: { x: 9, keep: true, y: 2 }, arr: [4] });
    assert.deepEqual(U.safeMerge({}, { a: 1 }, null, undefined, 5, 'str', { b: 2 }), { a: 1, b: 2 });
    assert.deepEqual(U.safeMerge({ a: { b: 1 } }, { a: 5 }), { a: 5 }); // 객체 → 원시값 덮어쓰기
    assert.deepEqual(U.safeMerge({ a: 5 }, { a: { b: 1 } }), { a: { b: 1 } });
  });

  T('safeMerge: source 를 변경하지 않고 참조를 공유하지 않는다', () => {
    const source = { nested: { list: [1, { deep: true }] } };
    const snapshot = JSON.stringify(source);
    const merged = U.safeMerge({}, source);
    merged.nested.list[1].deep = false;
    merged.nested.list.push(2);
    assert.equal(JSON.stringify(source), snapshot);
    assert.notEqual(merged.nested, source.nested);
  });

  T('safeMerge: Prototype Pollution 페이로드(JSON.parse 원본)를 병합해도 오염되지 않는다', () => {
    try {
      for (const payload of POLLUTION_PAYLOADS) {
        for (const makeTarget of [() => ({}), () => class Target {}, () => []]) {
          const target = makeTarget();
          U.safeMerge(target, JSON.parse(payload));
          assert.equal(polluted(), false, payload);
          assert.equal(target.pwn, undefined, payload);
          if (typeof target === 'function') assert.equal(target.prototype.pwn, undefined, payload);
          cleanPollution();
        }
      }
    } finally { cleanPollution(); }
  });

  T('safeMerge: 위험 키 규칙 (원시값 constructor 는 유지, 객체값은 무시), getter/setter 미실행', () => {
    assert.equal(U.safeMerge({}, JSON.parse('{"constructor":"Acme","prototype":"v2"}')).constructor, 'Acme');
    assert.deepEqual(Object.keys(U.safeMerge({}, JSON.parse('{"constructor":{"prototype":{"pwn":1}},"ok":1}'))), ['ok']);

    let getterRan = false;
    const src = { get boom() { getterRan = true; return 1; }, fine: 1 };
    assert.deepEqual(U.safeMerge({}, src), { fine: 1 });
    assert.equal(getterRan, false);

    let setterRan = false;
    const target = Object.create({ set x(v) { setterRan = true; } });
    U.safeMerge(target, { x: 5 });
    assert.equal(setterRan, false);
    assert.equal(Object.getOwnPropertyDescriptor(target, 'x').value, 5);

    const sym = Symbol('s');
    assert.equal(U.safeMerge({}, { [sym]: 1 })[sym], 1);
  });

  T('safeMerge: 잘못된 target, 동결 target, 순환/깊이 폭탄', () => {
    for (const bad of [null, undefined, 1, 'str', true]) assert.throws(() => U.safeMerge(bad, {}), TypeError);
    assert.throws(() => U.safeMerge(Object.freeze({}), { a: 1 }), TypeError);

    const cyc = { n: 1 }; cyc.self = cyc;
    const merged = U.safeMerge({}, cyc);
    assert.equal(merged.self, merged.self.self); // 순환 구조를 무한 루프 없이 복제

    const nest = (n) => { const r = {}; let c = r; for (let i = 0; i < n; i++) { c.n = {}; c = c.n; } return r; };
    assert.throws(() => U.safeMerge({}, nest(50000)), RangeError);
    // 양쪽이 모두 순수 객체일 때의 재귀 병합 경로. 엔진의 스택 한계(수천 단계)보다 작은 깊이로 라이브러리 자체 제한(1000)을 검증
    assert.throws(() => U.safeMerge(nest(1200), nest(1200)), /maximum depth/);
    assert.doesNotThrow(() => U.safeMerge(nest(500), nest(500)));
    assert.doesNotThrow(() => U.safeMerge({}, nest(500)));
  });

  // -------------------------------------------------------------------------
  T('debounce.flush: 대기 중인 호출을 즉시 실행하고 중복 실행하지 않는다', async () => {
    const calls = [];
    const d = U.debounce(function (x) { calls.push([x, this && this.t]); }, 40);
    d.call({ t: 'T' }, 1);
    d.call({ t: 'T' }, 2);
    d.flush();
    assert.deepEqual(calls, [[2, 'T']]);
    await sleep(100);
    assert.deepEqual(calls, [[2, 'T']]); // 타이머가 취소되어 재실행 없음
    d.flush(); // 대기 중인 게 없으면 no-op
    assert.equal(calls.length, 1);

    d(3); d.cancel(); d.flush();
    assert.equal(calls.length, 1); // cancel 후 flush 는 no-op

    const lead = [];
    const dl = U.debounce((x) => lead.push(x), 40, { leading: true });
    dl(1); dl(2); dl.flush();
    assert.deepEqual(lead, [1]); // leading 모드에서는 flush 할 대기 호출이 없음
    dl.cancel();
  });

  // -------------------------------------------------------------------------
  T('throttle: 인자 검증', () => {
    assert.throws(() => U.throttle('x'), TypeError);
    assert.throws(() => U.throttle(() => {}, 10, { leading: false, trailing: false }), TypeError);
    assert.equal(typeof U.throttle(() => {}).cancel, 'function');
    assert.equal(typeof U.throttle(() => {}).flush, 'function');
  });

  T('throttle: leading + trailing (기본) — 첫 호출 즉시, 구간 끝에 마지막 인자로 1회', async () => {
    const calls = [];
    const t = U.throttle(function (x) { calls.push([x, this && this.t]); return x * 10; }, 60);
    assert.equal(t.call({ t: 'T' }, 1), 10); // leading 은 반환값 전달
    t.call({ t: 'T' }, 2);
    t.call({ t: 'T' }, 3);
    assert.deepEqual(calls, [[1, 'T']]);
    await sleep(150);
    assert.deepEqual(calls, [[1, 'T'], [3, 'T']]);
    await sleep(120);
    assert.equal(calls.length, 2); // 호출이 없으면 더 실행되지 않음
    t(4); // 새 구간의 leading
    assert.equal(calls.length, 3);
    t.cancel();
  });

  T('throttle: leading 만 / trailing 만', async () => {
    const lead = [];
    const tl = U.throttle((x) => lead.push(x), 60, { trailing: false });
    tl(1); tl(2); tl(3);
    await sleep(120);
    assert.deepEqual(lead, [1]);
    tl(4);
    assert.deepEqual(lead, [1, 4]);
    tl.cancel();

    const trail = [];
    const tt = U.throttle((x) => trail.push(x), 60, { leading: false });
    tt(1); tt(2); tt(3);
    assert.deepEqual(trail, []);
    await sleep(120);
    assert.deepEqual(trail, [3]);
    tt.cancel();
  });

  T('throttle: 고빈도 호출에서도 실행 횟수가 구간당 1회 이하로 제한됨', async () => {
    let count = 0;
    const t = U.throttle(() => { count++; }, 100);
    const start = Date.now();
    while (Date.now() - start < 350) { t(); await sleep(5); }
    t.cancel();
    assert.ok(count >= 2 && count <= 6, 'count=' + count); // 약 350/100 + leading/trailing 여유
  });

  T('throttle: cancel / flush', async () => {
    const calls = [];
    const t = U.throttle((x) => calls.push(x), 60);
    t(1); t(2);
    t.flush();
    assert.deepEqual(calls, [1, 2]);
    await sleep(100);
    assert.deepEqual(calls, [1, 2]);

    const c = [];
    const t2 = U.throttle((x) => c.push(x), 60);
    t2(1); t2(2); t2.cancel();
    await sleep(100);
    assert.deepEqual(c, [1]);
    t2.flush(); // 대기 없음 → no-op
    assert.deepEqual(c, [1]);
  });

  // -------------------------------------------------------------------------
  T('randomToken: 길이·문자집합·유일성', () => {
    assert.match(U.randomToken(), /^[0-9a-f]{64}$/);
    assert.match(U.randomToken(1), /^[0-9a-f]{2}$/);
    assert.match(U.randomToken(16, 'hex'), /^[0-9a-f]{32}$/);
    assert.match(U.randomToken(32, 'base64url'), /^[A-Za-z0-9_-]{43}$/);
    assert.match(U.randomToken(1024), /^[0-9a-f]{2048}$/);
    const seen = new Set();
    for (let i = 0; i < 500; i++) seen.add(U.randomToken(16));
    assert.equal(seen.size, 500);
    assert.notEqual(U.randomToken(32), '0'.repeat(64));
  });

  T('randomToken: 인코딩이 정확함 (Buffer 로 디코딩하면 정확히 bytes 길이, 재인코딩하면 동일)', () => {
    for (let bytes = 1; bytes <= 40; bytes++) {
      const b64 = U.randomToken(bytes, 'base64url');
      const decoded = Buffer.from(b64, 'base64url');
      assert.equal(decoded.length, bytes, 'base64url bytes=' + bytes);
      assert.equal(decoded.toString('base64url'), b64, 'roundtrip bytes=' + bytes);
      assert.equal(Buffer.from(U.randomToken(bytes, 'hex'), 'hex').length, bytes, 'hex bytes=' + bytes);
    }
  });

  T('randomToken: 잘못된 인자와 Math.random 비의존', () => {
    for (const bad of [0, -1, 1.5, 1025, NaN, Infinity, '8', null]) assert.throws(() => U.randomToken(bad), RangeError, String(bad));
    assert.throws(() => U.randomToken(8, 'base32'), TypeError);
    assert.throws(() => U.randomToken(8, 'HEX'), TypeError);
    const original = Math.random;
    Math.random = () => { throw new Error('Math.random must not be used'); };
    try { assert.equal(U.randomToken(8).length, 16); } finally { Math.random = original; }
  });
}

// 안전한 난수원이 없는 환경에서는 절대 약한 난수로 대체하지 않고 Error 를 던진다 (crypto 가 없는 vm 컨텍스트)
test('randomToken: crypto 가 없으면 Math.random 으로 대체하지 않고 Error', () => {
  const code = fs.readFileSync(path.join(ROOT, 'dist', 'easy-secure-utils.js'), 'utf8');
  const ctx = vm.createContext({});
  vm.runInContext(code, ctx);
  assert.equal(vm.runInContext('typeof crypto', ctx), 'undefined');
  assert.throws(() => vm.runInContext('SecureWebUtils.randomToken(8)', ctx), /secure random source/);
  // 같은 환경에서도 난수와 무관한 함수는 정상 동작
  assert.equal(vm.runInContext("SecureWebUtils.html`<p>${'<'}</p>`.toString()", ctx), '<p>&lt;</p>');
});
