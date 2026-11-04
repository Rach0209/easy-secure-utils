/**
 * SecureWebUtils v1.1.0
 * Zero-dependency, Secure, High-Performance Web Utility Library.
 *
 * @license MIT
 */

// ---------------------------------------------------------------------------
// 0. 내장 함수 사전 캡처 (로드 이후 Object/JSON 등의 변조에 대한 방어)
// ---------------------------------------------------------------------------
const nativeJSONParse = JSON.parse;
const nativeDefineProperty = Object.defineProperty;
const nativeGetProto = Object.getPrototypeOf;
const nativeGetDescriptor = Object.getOwnPropertyDescriptor;
const nativeOwnKeys = Reflect.ownKeys;
const nativeApply = Reflect.apply;
const nativeDateGetTime = Date.prototype.getTime;
const nativeMapForEach = Map.prototype.forEach;
const nativeSetForEach = Set.prototype.forEach;
const nativeStructuredClone = typeof structuredClone === 'function' ? structuredClone : null;
const nativeWeakMapGet = WeakMap.prototype.get;
const nativeWeakMapSet = WeakMap.prototype.set;
const nativeHasOwn = Object.prototype.hasOwnProperty;
const nativeCrypto = typeof globalThis.crypto === 'object' && globalThis.crypto !== null ? globalThis.crypto : null;
const nativeGetRandomValues = nativeCrypto !== null ? nativeCrypto.getRandomValues : null;

// 값이 문자열이 아니어도 안전하게 텍스트로 변환 (객체는 toString 호출을 피하기 위해 빈 문자열)
function toText(value) {
  const t = typeof value;
  if (t === 'string') return value;
  if (t === 'number' || t === 'boolean' || t === 'bigint') return String(value);
  return '';
}

// ---------------------------------------------------------------------------
// 1. XSS & HTML Encoding (Fast-path 적용)
// ---------------------------------------------------------------------------
const HTML_ESCAPES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;'
});

const FAST_HTML_REGEX = /[&<>"'`]/;
const HTML_REPLACE_REGEX = /[&<>"'`]/g;
const ATTR_UNSAFE_REGEX = /[^A-Za-z0-9,._-]/gu;

/**
 * HTML 텍스트 노드 및 따옴표로 감싼 속성값("..." / '...')용 인코딩.
 * <script>, <style>, 이벤트 핸들러(onclick=...), URL 속성(href/src), 따옴표 없는 속성에는
 * 안전하지 않으므로 각각 isSafeURL / escapeAttribute 를 사용하거나 textContent 를 사용하세요.
 * 문자열/숫자/불리언/bigint 만 변환하며 그 외(null, 객체 등)는 빈 문자열을 반환합니다.
 * @param {string} str
 * @returns {string}
 */
function escapeHTML(str) {
  return escapeTextString(typeof str === 'string' ? str : toText(str));
}

// 문자열 전용 내부 구현 (html 템플릿에서도 사용)
function escapeTextString(text) {
  if (!FAST_HTML_REGEX.test(text)) return text;
  return text.replace(HTML_REPLACE_REGEX, (match) => HTML_ESCAPES[match]);
}

function escapeAttributeString(text) {
  if (text === '') return text;
  return text.replace(ATTR_UNSAFE_REGEX, (ch) => '&#x' + ch.codePointAt(0).toString(16).toUpperCase() + ';');
}

/**
 * HTML 속성값 전용 엄격 인코딩 (OWASP 규칙): 영숫자와 , . _ - 를 제외한 모든 문자를 &#xHH; 로 변환합니다.
 * 따옴표 없는 속성(<div title=VALUE>)에서도 속성 탈출이 불가능합니다.
 * @param {string} value
 * @returns {string}
 */
function escapeAttribute(value) {
  return escapeAttributeString(toText(value));
}

const REGEXP_SPECIAL_REGEX = /[.*+?^${}()|[\]\\-]/g;

/**
 * 사용자 입력을 정규식 안에 "문자 그대로" 넣을 수 있도록 특수문자를 이스케이프합니다
 * (문자 클래스 안의 `-` 포함). new RegExp(escapeRegExp(userInput)) 형태로 사용하세요.
 * @param {string} str
 * @returns {string}
 */
function escapeRegExp(str) {
  return toText(str).replace(REGEXP_SPECIAL_REGEX, (ch) => (ch === '-' ? '\\x2d' : '\\' + ch));
}

// ---------------------------------------------------------------------------
// 2. URL 안전성 검증 (dangerous scheme / Open Redirect / 자격증명 URL 방지)
// ---------------------------------------------------------------------------
const DEFAULT_ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:', 'mailto:', 'tel:']);
// 호출자가 allowedProtocols 에 실수로 넣어도 항상 차단되는 스킴
const BLOCKED_PROTOCOLS = new Set([
  'javascript:', 'data:', 'vbscript:', 'blob:', 'file:', 'filesystem:', 'about:', 'view-source:'
]);
const MAX_URL_LENGTH = 8192;
// 브라우저는 URL 내부의 탭/개행을 제거한 뒤 해석하므로 C0/C1 제어문자는 전부 거부
const CONTROL_CHARS_REGEX = /[\x00-\x1F\x7F-\x9F]/;
const SCHEME_PREFIX_REGEX = /^[A-Za-z][A-Za-z0-9+.\-]*:/;
const RELATIVE_BASE = 'https://relative-check.invalid';

/**
 * URL 이 안전한지 검증합니다 (fail-closed: 의심스러우면 false).
 *  - 허용 프로토콜 화이트리스트 (javascript:, data:, vbscript:, blob:, file: 등은 항상 차단)
 *  - 탭/개행/제어문자/백슬래시/앞뒤 공백이 포함된 URL 거부 (브라우저 정규화 우회 방지)
 *  - protocol-relative(//host), /\host 거부, 상대경로는 동일 출처로 해석될 때만 허용
 *  - http(s)의 user:pass@host 자격증명 URL 거부
 * @param {string} url
 * @param {readonly string[]} [allowedProtocols] 소문자 + 콜론 형식 (예: 'https:')
 * @param {{allowRelative?: boolean, allowedHosts?: readonly string[]}} [options]
 *        allowedHosts 지정 시 http(s) 절대 URL 은 해당 호스트(정확히 일치)만 허용 → Open Redirect 방지
 * @returns {boolean}
 */
function isSafeURL(url, allowedProtocols = DEFAULT_ALLOWED_PROTOCOLS, options) {
  if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL_LENGTH) return false;
  if (!Array.isArray(allowedProtocols)) return false;
  if (url !== url.trim() || CONTROL_CHARS_REGEX.test(url) || url.indexOf('\\') !== -1) return false;

  const opts = options !== null && typeof options === 'object' ? options : {};
  const allowedHosts = opts.allowedHosts;
  if (allowedHosts !== undefined && !Array.isArray(allowedHosts)) return false;

  try {
    // 스킴이 없는 상대 URL
    if (!SCHEME_PREFIX_REGEX.test(url)) {
      if (opts.allowRelative === false) return false;
      if (url.startsWith('//')) return false;
      // 제어문자/백슬래시는 위에서 이미 거부됨 → "/x" 형태는 항상 동일 출처이므로 URL 파싱 생략(fast-path)
      if (url.charCodeAt(0) === 47) return true;
      return new URL(url, RELATIVE_BASE).origin === RELATIVE_BASE;
    }

    const parsed = new URL(url);
    const protocol = parsed.protocol;
    if (BLOCKED_PROTOCOLS.has(protocol) || !allowedProtocols.includes(protocol)) return false;

    if (protocol === 'http:' || protocol === 'https:') {
      if (!parsed.hostname || parsed.username || parsed.password) return false;
      if (allowedHosts !== undefined && !allowedHosts.includes(parsed.hostname)) return false;
    }
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * 안전한 URL 이면 그대로, 아니면 fallback 을 반환합니다 (`el.href = sanitizeURL(userUrl)` 한 줄 사용).
 * 검증 규칙은 isSafeURL 과 동일합니다. fallback 은 개발자가 지정하는 값이므로 검증하지 않습니다.
 * @param {string} url
 * @param {string} [fallback='#']
 * @param {readonly string[]} [allowedProtocols]
 * @param {{allowRelative?: boolean, allowedHosts?: readonly string[]}} [options]
 * @returns {string}
 */
function sanitizeURL(url, fallback = '#', allowedProtocols, options) {
  return isSafeURL(url, allowedProtocols, options) ? url : fallback;
}

// ---------------------------------------------------------------------------
// 3. Prototype Pollution 방지 & 안전한 객체 조작
// ---------------------------------------------------------------------------
// 위험 키 규칙 (병합 유틸의 target.constructor.prototype 경로 / target.__proto__ 대입을 차단):
//  - "__proto__" 는 값과 무관하게 항상 위험
//  - "constructor" / "prototype" 은 값이 객체·함수일 때만 위험 (문자열 등 원시값은 병합 코드가 따라 들어갈 수 없어 안전)
function isDangerousEntry(key, value) {
  if (key === '__proto__') return true;
  if (key !== 'constructor' && key !== 'prototype') return false;
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

// 키는 유니코드 이스케이프(백슬래시 + u)로만 위장할 수 있으므로(\x5C = 백슬래시),
// 위험 키워드/이스케이프가 없는 입력은 reviver 를 생략한다 (fast-path)
const MAYBE_DANGEROUS_JSON_REGEX = /__proto__|constructor|prototype|\x5Cu/;
const DEFAULT_MAX_JSON_LENGTH = 5 * 1024 * 1024; // 5MB

function stripDangerousKeys(key, value) {
  return isDangerousEntry(key, value) ? undefined : value;
}

/**
 * Prototype Pollution 요소를 제거하고 JSON 을 파싱합니다 (모든 깊이, 이스케이프로 위장한 키 포함).
 * 제거 대상: "__proto__" 키 전부, 값이 객체/배열인 "constructor"/"prototype" 키.
 * 문자열 등 원시값을 가진 "constructor"/"prototype" 키는 정상 데이터로 유지됩니다.
 * @template T
 * @param {string} text
 * @param {T} [fallback=null]
 * @param {number} [maxLength=5242880] 이 길이를 초과하는 입력은 파싱하지 않고 fallback 반환 (메모리/CPU DoS 방지)
 * @returns {T | null}
 */
function safeJSONParse(text, fallback = null, maxLength = DEFAULT_MAX_JSON_LENGTH) {
  if (typeof text !== 'string') return fallback;
  if (typeof maxLength !== 'number' || !(maxLength >= 0)) maxLength = DEFAULT_MAX_JSON_LENGTH;
  if (text.length > maxLength) return fallback;
  try {
    return MAYBE_DANGEROUS_JSON_REGEX.test(text)
      ? nativeJSONParse(text, stripDangerousKeys)
      : nativeJSONParse(text);
  } catch (_) {
    return fallback;
  }
}

const DEFAULT_MAX_DEPTH = 1000;

function cloneValue(value, seen, depth, maxDepth) {
  if (value === null || typeof value !== 'object') return value; // 원시값/함수는 그대로 반환
  if (seen.has(value)) return seen.get(value);
  if (depth > maxDepth) throw new RangeError('safeDeepClone: maximum depth exceeded');

  if (value instanceof Date) {
    const d = new Date(nativeApply(nativeDateGetTime, value, []));
    seen.set(value, d);
    return d;
  }
  if (value instanceof RegExp) {
    const r = new RegExp(value.source, value.flags);
    seen.set(value, r);
    return r;
  }
  if (value instanceof Map) {
    const m = new Map();
    seen.set(value, m);
    nativeApply(nativeMapForEach, value, [(v, k) => {
      m.set(cloneValue(k, seen, depth + 1, maxDepth), cloneValue(v, seen, depth + 1, maxDepth));
    }]);
    return m;
  }
  if (value instanceof Set) {
    const s = new Set();
    seen.set(value, s);
    nativeApply(nativeSetForEach, value, [(v) => { s.add(cloneValue(v, seen, depth + 1, maxDepth)); }]);
    return s;
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value) || value instanceof Error) {
    if (!nativeStructuredClone) throw new TypeError('safeDeepClone: structuredClone is required for this type');
    const c = nativeStructuredClone(value);
    seen.set(value, c);
    return c;
  }
  if (value instanceof WeakMap || value instanceof WeakSet || value instanceof Promise) {
    throw new TypeError('safeDeepClone: unsupported type');
  }

  const isArray = Array.isArray(value);
  const clone = isArray ? new Array(value.length) : Object.create(nativeGetProto(value));
  seen.set(value, clone);

  const keys = nativeOwnKeys(value);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    // 디스크립터로 읽어 getter(악성 코드 실행)를 호출하지 않고, 대입 대신 defineProperty 로 setter 를 우회
    const desc = nativeGetDescriptor(value, key);
    if (desc === undefined || !desc.enumerable || !('value' in desc)) continue;
    if (typeof key === 'string' && isDangerousEntry(key, desc.value)) continue;
    nativeDefineProperty(clone, key, {
      value: cloneValue(desc.value, seen, depth + 1, maxDepth),
      writable: true,
      enumerable: true,
      configurable: true
    });
  }
  return clone;
}

/**
 * 순환 참조 안전 + Prototype Pollution 차단 Deep Clone.
 *  - "__proto__" 키, 값이 객체/함수인 "constructor"/"prototype" 키는 복사하지 않음 (safeJSONParse 와 동일 규칙)
 *  - getter 는 호출하지 않고 건너뜀 (데이터 속성만 복사), 비열거 속성은 복사하지 않음
 *  - Date/RegExp/Map/Set/ArrayBuffer/TypedArray/Error 지원, WeakMap/WeakSet/Promise 는 TypeError
 *  - 중첩이 maxDepth 를 넘으면 RangeError (스택 오버플로 DoS 방지)
 * @template T
 * @param {T} obj
 * @param {number} [maxDepth=1000]
 * @returns {T}
 */
function safeDeepClone(obj, maxDepth = DEFAULT_MAX_DEPTH) {
  if (typeof maxDepth !== 'number' || !(maxDepth >= 0)) maxDepth = DEFAULT_MAX_DEPTH;
  return cloneValue(obj, new WeakMap(), 0, maxDepth);
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = nativeGetProto(value);
  return proto === Object.prototype || proto === null;
}

function mergeInto(target, source, seen, depth, maxDepth) {
  if (depth > maxDepth) throw new RangeError('safeMerge: maximum depth exceeded');
  const keys = nativeOwnKeys(source);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const desc = nativeGetDescriptor(source, key);
    if (desc === undefined || !desc.enumerable || !('value' in desc)) continue; // getter 미실행
    const incoming = desc.value;
    if (typeof key === 'string' && isDangerousEntry(key, incoming)) continue;

    const existing = nativeGetDescriptor(target, key);
    // 양쪽이 모두 순수 객체일 때만 재귀 병합 (배열은 병합하지 않고 통째로 교체)
    if (existing !== undefined && 'value' in existing && isPlainObject(incoming) && isPlainObject(existing.value)) {
      mergeInto(existing.value, incoming, seen, depth + 1, maxDepth);
      continue;
    }
    nativeDefineProperty(target, key, {
      value: cloneValue(incoming, seen, depth + 1, maxDepth),
      writable: true,
      enumerable: true,
      configurable: true
    });
  }
}

/**
 * Prototype Pollution 에 안전한 깊은 병합 (Object.assign 처럼 target 을 변경하고 반환).
 *  - "__proto__" 키, 값이 객체/함수인 "constructor"/"prototype" 키는 무시 (safeJSONParse 와 동일 규칙)
 *  - 대입 대신 defineProperty 를 사용해 setter/프로토타입 접근을 일으키지 않고, getter 는 실행하지 않음
 *  - source 값은 깊은 복사되어 원본 객체와 참조를 공유하지 않음. 배열은 병합하지 않고 교체
 *  - null/undefined/원시값 source 는 무시, 중첩이 maxDepth(1000) 를 넘으면 RangeError
 * 원본을 보존하려면 safeMerge({}, a, b) 처럼 빈 객체를 target 으로 사용하세요.
 * @template T
 * @param {T} target
 * @param {...object} sources
 * @returns {T}
 */
function safeMerge(target, ...sources) {
  if (target === null || (typeof target !== 'object' && typeof target !== 'function')) {
    throw new TypeError('safeMerge: target must be an object');
  }
  const seen = new WeakMap();
  for (let i = 0; i < sources.length; i++) {
    const source = sources[i];
    if (source === null || typeof source !== 'object') continue;
    mergeInto(target, source, seen, 0, DEFAULT_MAX_DEPTH);
  }
  return target;
}

// ---------------------------------------------------------------------------
// 4. 성능 & 유틸리티 함수
// ---------------------------------------------------------------------------
const BYTE_UNITS = Object.freeze(['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']);
const MAX_DECIMALS = 20;

/**
 * 파일 크기(Byte)를 읽기 쉬운 단위로 변환합니다.
 * @param {number} bytes
 * @param {number} [decimals=2] 0 ~ 20 으로 보정됩니다.
 * @returns {string}
 */
function formatBytes(bytes, decimals = 2) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes <= 0) return '0 Bytes';

  const dm = Number.isFinite(decimals) ? Math.min(Math.max(Math.trunc(decimals), 0), MAX_DECIMALS) : 2;
  const last = BYTE_UNITS.length - 1;
  let unit = 0;
  let value = bytes;
  while (value >= 1024 && unit < last) {
    value /= 1024;
    unit++;
  }

  let text = value.toFixed(dm);
  // 반올림으로 "1024 KB" 처럼 경계가 어긋나는 경우 다음 단위로 승급
  if (unit < last && parseFloat(text) >= 1024) {
    value /= 1024;
    unit++;
    text = value.toFixed(dm);
  }
  return `${parseFloat(text)} ${BYTE_UNITS[unit]}`;
}

const MAX_TIMEOUT = 2147483647; // setTimeout 상한 (초과 시 즉시 실행되는 브라우저 동작 방지)

function normalizeWait(delay) {
  return typeof delay === 'number' && delay >= 0 ? Math.min(delay, MAX_TIMEOUT) : 250;
}

/**
 * Debounce 함수 (취소·즉시 실행 옵션 포함)
 * @param {Function} fn
 * @param {number} [delay=250]
 * @param {{leading?: boolean}} [options] leading:true 면 첫 호출을 즉시 실행하고 delay 동안의 이후 호출은 무시(타이머만 연장)
 * @returns {Function & { cancel: () => void, flush: () => void }}
 *          cancel(): 대기 중인 호출 취소, flush(): 대기 중인 호출을 지금 즉시 실행
 */
function debounce(fn, delay = 250, options) {
  if (typeof fn !== 'function') throw new TypeError('debounce: fn must be a function');
  const wait = normalizeWait(delay);
  const leading = options !== null && typeof options === 'object' && options.leading === true;
  let timerId = null;
  let pendingArgs = null;
  let pendingThis;

  function runPending() {
    const args = pendingArgs;
    const ctx = pendingThis;
    pendingArgs = null; // fn 이 예외를 던져도 상태가 꼬이지 않도록 먼저 초기화
    pendingThis = undefined;
    nativeApply(fn, ctx, args);
  }

  function onTimer() {
    timerId = null;
    if (pendingArgs !== null) runPending();
  }

  function debounced(...args) {
    const callNow = leading && timerId === null;
    if (timerId !== null) clearTimeout(timerId);
    if (!leading) {
      pendingArgs = args;
      pendingThis = this;
    }
    timerId = setTimeout(onTimer, wait);
    if (callNow) return nativeApply(fn, this, args);
  }

  debounced.cancel = () => {
    if (timerId !== null) clearTimeout(timerId);
    timerId = null;
    pendingArgs = null;
    pendingThis = undefined;
  };

  debounced.flush = () => {
    if (timerId !== null && pendingArgs !== null) {
      clearTimeout(timerId);
      timerId = null;
      runPending();
    }
  };

  return debounced;
}

/**
 * Throttle 함수: wait(ms) 동안 최대 1번만 실행 (스크롤·리사이즈 등 고빈도 이벤트용)
 * @param {Function} fn
 * @param {number} [wait=250]
 * @param {{leading?: boolean, trailing?: boolean}} [options] 기본 leading:true, trailing:true.
 *        leading: 구간의 첫 호출을 즉시 실행, trailing: 구간 중 마지막 호출을 구간 끝에 실행
 * @returns {Function & { cancel: () => void, flush: () => void }}
 */
function throttle(fn, wait = 250, options) {
  if (typeof fn !== 'function') throw new TypeError('throttle: fn must be a function');
  const interval = normalizeWait(wait);
  const opts = options !== null && typeof options === 'object' ? options : {};
  const leading = opts.leading !== false;
  const trailing = opts.trailing !== false;
  if (!leading && !trailing) throw new TypeError('throttle: leading and trailing cannot both be false');
  let timerId = null;
  let pendingArgs = null;
  let pendingThis;

  function runPending() {
    const args = pendingArgs;
    const ctx = pendingThis;
    pendingArgs = null;
    pendingThis = undefined;
    return nativeApply(fn, ctx, args);
  }

  function onTimer() {
    timerId = null;
    if (trailing && pendingArgs !== null) {
      timerId = setTimeout(onTimer, interval); // 트레일링 실행 뒤 새 구간 시작
      runPending();
    } else {
      pendingArgs = null;
      pendingThis = undefined;
    }
  }

  function throttled(...args) {
    pendingArgs = args;
    pendingThis = this;
    if (timerId === null) {
      timerId = setTimeout(onTimer, interval);
      if (leading) return runPending();
    }
  }

  throttled.cancel = () => {
    if (timerId !== null) clearTimeout(timerId);
    timerId = null;
    pendingArgs = null;
    pendingThis = undefined;
  };

  throttled.flush = () => {
    if (timerId !== null && pendingArgs !== null) {
      clearTimeout(timerId);
      timerId = null;
      runPending();
    }
  };

  return throttled;
}

// ---------------------------------------------------------------------------
// 5. 보안 난수
// ---------------------------------------------------------------------------
const HEX_TABLE = Array.from({ length: 256 }, (_, i) => (i < 16 ? '0' : '') + i.toString(16));
const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function toBase64URL(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += BASE64URL_CHARS[n >> 18] + BASE64URL_CHARS[(n >> 12) & 63] + BASE64URL_CHARS[(n >> 6) & 63] + BASE64URL_CHARS[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += BASE64URL_CHARS[n >> 18] + BASE64URL_CHARS[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += BASE64URL_CHARS[n >> 18] + BASE64URL_CHARS[(n >> 12) & 63] + BASE64URL_CHARS[(n >> 6) & 63];
  }
  return out;
}

/**
 * 암호학적으로 안전한 난수 토큰 (crypto.getRandomValues). Math.random 으로 절대 대체되지 않으며,
 * 안전한 난수원이 없으면 Error 를 던집니다. 세션 ID·CSRF 토큰·nonce 등에 사용하세요.
 * @param {number} [bytes=32] 1 ~ 1024
 * @param {'hex' | 'base64url'} [encoding='hex'] hex 는 길이 bytes*2, base64url 은 패딩 없는 URL-safe 문자열
 * @returns {string}
 */
function randomToken(bytes = 32, encoding = 'hex') {
  if (!Number.isInteger(bytes) || bytes < 1 || bytes > 1024) throw new RangeError('randomToken: bytes must be an integer between 1 and 1024');
  if (encoding !== 'hex' && encoding !== 'base64url') throw new TypeError("randomToken: encoding must be 'hex' or 'base64url'");
  if (nativeGetRandomValues === null) throw new Error('randomToken: a secure random source (crypto.getRandomValues) is not available');

  const buf = new Uint8Array(bytes);
  nativeApply(nativeGetRandomValues, nativeCrypto, [buf]);
  if (encoding === 'base64url') return toBase64URL(buf);
  let out = '';
  for (let i = 0; i < buf.length; i++) out += HEX_TABLE[buf[i]];
  return out;
}

// ---------------------------------------------------------------------------
// 6. html`` 태그드 템플릿: 보간(${})을 위치(문맥)에 맞게 자동 이스케이프
// ---------------------------------------------------------------------------
// SafeHTML 은 "이미 안전한 HTML" 표식입니다. 표식은 이 모듈만 아는 Symbol 키(Symbol.for 가 아님)에 저장됩니다.
//  - JSON·폼·URL 파라미터 같은 "데이터"에는 Symbol 키를 넣을 수 없으므로 데이터로는 위조할 수 없습니다.
//  - WeakMap 방식보다 10~40배 빠릅니다 (WeakMap.set 은 호출당 약 400ns).
//  - 인스턴스는 동결되고, 프로토타입의 constructor 를 무력화해서 `real.constructor('...')` 로 새 인스턴스를 만들 수 없습니다.
const SAFE_HTML_KEY = Symbol('easy-secure-utils.safeHTML');

class SafeHTML {
  constructor(text) {
    this[SAFE_HTML_KEY] = text;
    Object.freeze(this);
  }

  toString() {
    return nativeApply(nativeHasOwn, this, [SAFE_HTML_KEY]) ? this[SAFE_HTML_KEY] : '';
  }
}
Object.defineProperty(SafeHTML.prototype, 'constructor', { value: Object, writable: false, configurable: false });
Object.freeze(SafeHTML.prototype);

function makeSafeHTML(text) {
  return new SafeHTML(text);
}

/**
 * html`` 가 만든(또는 unsafeHTML 로 명시한) "이미 안전한 HTML" 인지 확인합니다.
 * @param {unknown} value
 * @returns {boolean}
 */
function isSafeHTML(value) {
  return value !== null && typeof value === 'object' && nativeApply(nativeHasOwn, value, [SAFE_HTML_KEY]);
}

/**
 * 이스케이프 없이 그대로 삽입할 "신뢰할 수 있는" HTML 문자열을 표시합니다 (명시적 탈출구).
 * 사용자 입력에 쓰지 마세요. DOMPurify 등으로 정제한 결과처럼 이미 신뢰할 수 있는 값에만 사용합니다.
 * @param {string} text
 * @returns {object} SafeHTML
 */
function unsafeHTML(text) {
  if (typeof text !== 'string') throw new TypeError('unsafeHTML: text must be a string');
  return makeSafeHTML(text);
}

// 보간 위치를 판별하기 위한 최소 HTML 토크나이저 (정적 문자열만 분석하며 템플릿 호출 지점마다 1회만 수행)
//  원칙: 판단이 애매하면 "허용"이 아니라 "예외(throw)" 방향으로 동작한다.
const RAW_TEXT_TAGS = new Set(['script', 'style', 'noscript', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext', 'textarea', 'title']);
const RCDATA_ESCAPABLE_TAGS = new Set(['textarea', 'title']); // 이 두 태그의 본문에만 보간 허용
const NO_ATTR_INTERPOLATION_TAGS = new Set(['script', 'style', 'link', 'object', 'embed', 'base', 'meta', 'iframe', 'frame', 'frameset', 'applet', 'param']);
const NO_INTERPOLATION_ATTRS = new Set(['style', 'srcdoc', 'srcset']);
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'poster', 'background', 'cite', 'data', 'longdesc', 'xlink:href', 'ping', 'manifest', 'codebase', 'icon']);
const MAX_RENDER_DEPTH = 64;

function isHtmlSpace(c) {
  return c === ' ' || c === '\t' || c === '\n' || c === '\f' || c === '\r';
}

function isAsciiAlpha(c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

function newScanState() {
  return { mode: 'text', tag: '', closing: false, attr: '', valueStart: false, dashes: 0, rawTag: '', rawEscaped: false };
}

function finishTag(st) {
  if (!st.closing && RAW_TEXT_TAGS.has(st.tag)) {
    st.mode = 'rawtext';
    st.rawTag = st.tag;
    st.rawEscaped = false;
  } else {
    st.mode = 'text';
  }
}

function scanStatic(str, st) {
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    switch (st.mode) {
      case 'text':
        if (c === '<') st.mode = 'tagopen';
        break;
      case 'tagopen':
        if (isAsciiAlpha(c)) { st.mode = 'tagname'; st.tag = c.toLowerCase(); st.closing = false; st.attr = ''; }
        else if (c === '/') st.mode = 'endtagopen';
        else if (c === '!') st.mode = 'bang';
        else if (c === '?') st.mode = 'bogus';
        else if (c !== '<') st.mode = 'text';
        break;
      case 'endtagopen':
        if (isAsciiAlpha(c)) { st.mode = 'tagname'; st.tag = c.toLowerCase(); st.closing = true; st.attr = ''; }
        else if (c === '>') st.mode = 'text';
        else st.mode = 'bogus';
        break;
      case 'bang':
        st.mode = c === '-' ? 'bangdash' : (c === '>' ? 'text' : 'bogus');
        break;
      case 'bangdash':
        if (c === '-') { st.mode = 'comment'; st.dashes = 0; } else st.mode = c === '>' ? 'text' : 'bogus';
        break;
      case 'comment': // 보수적으로 정확한 "-->" 에서만 종료 (이보다 일찍 끝났다고 오판하지 않기 위함)
        if (c === '-') st.dashes++;
        else if (c === '>' && st.dashes >= 2) st.mode = 'text';
        else st.dashes = 0;
        break;
      case 'bogus':
        if (c === '>') st.mode = 'text';
        break;
      case 'tagname':
        if (isHtmlSpace(c) || c === '/') st.mode = 'beforeattr';
        else if (c === '>') finishTag(st);
        else st.tag += c.toLowerCase();
        break;
      case 'beforeattr':
        if (c === '>') finishTag(st);
        else if (!isHtmlSpace(c) && c !== '/') { st.mode = 'attrname'; st.attr = c.toLowerCase(); }
        break;
      case 'attrname':
        if (c === '=') st.mode = 'beforevalue';
        else if (isHtmlSpace(c)) st.mode = 'afterattrname';
        else if (c === '/') st.mode = 'beforeattr';
        else if (c === '>') finishTag(st);
        else st.attr += c.toLowerCase();
        break;
      case 'afterattrname':
        if (c === '=') st.mode = 'beforevalue';
        else if (c === '>') finishTag(st);
        else if (c === '/') st.mode = 'beforeattr';
        else if (!isHtmlSpace(c)) { st.mode = 'attrname'; st.attr = c.toLowerCase(); }
        break;
      case 'beforevalue':
        if (isHtmlSpace(c)) break;
        if (c === '"') { st.mode = 'valuedq'; st.valueStart = true; }
        else if (c === "'") { st.mode = 'valuesq'; st.valueStart = true; }
        else if (c === '>') finishTag(st);
        else { st.mode = 'valueunq'; st.valueStart = false; }
        break;
      case 'valuedq':
        if (c === '"') st.mode = 'beforeattr'; else st.valueStart = false;
        break;
      case 'valuesq':
        if (c === "'") st.mode = 'beforeattr'; else st.valueStart = false;
        break;
      case 'valueunq':
        if (isHtmlSpace(c)) st.mode = 'beforeattr';
        else if (c === '>') finishTag(st);
        else st.valueStart = false;
        break;
      case 'rawtext': {
        if (c !== '<') break;
        const rest = str.slice(i, i + 12).toLowerCase();
        if (rest.startsWith('<!--')) { st.rawEscaped = true; break; } // script 의 이중 이스케이프 상태는 종료 판정을 포기(계속 raw 로 간주)
        if (!st.rawEscaped && st.rawTag !== 'plaintext' && rest.startsWith('</' + st.rawTag)) {
          const after = rest.charAt(2 + st.rawTag.length);
          if (after === '' || isHtmlSpace(after) || after === '/' || after === '>') {
            st.mode = 'tagname'; st.tag = st.rawTag; st.closing = true; st.attr = '';
            i += 1 + st.rawTag.length; // "</tag" 소비 후 일반 태그 상태 머신으로 끝(>)까지 처리
          }
        }
        break;
      }
      default:
        break;
    }
  }
}

function attributeContext(st) {
  if (NO_ATTR_INTERPOLATION_TAGS.has(st.tag)) {
    throw new Error('html: <' + st.tag + '> 태그의 속성에는 보간(${})을 사용할 수 없습니다');
  }
  const name = st.attr;
  if (name.startsWith('on') || NO_INTERPOLATION_ATTRS.has(name)) {
    throw new Error('html: "' + name + '" 속성에는 보간(${})을 사용할 수 없습니다 (이벤트 핸들러/style/srcdoc/srcset)');
  }
  if (URL_ATTRS.has(name)) return { kind: 'url', atStart: st.valueStart };
  return { kind: 'attr' };
}

function contextAt(st) {
  switch (st.mode) {
    case 'text':
      return { kind: 'text' };
    case 'rawtext':
      if (RCDATA_ESCAPABLE_TAGS.has(st.rawTag)) return { kind: 'rcdata' };
      throw new Error('html: <' + st.rawTag + '> 내부에는 보간(${})을 사용할 수 없습니다');
    case 'valuedq':
    case 'valuesq':
      return attributeContext(st);
    case 'beforevalue': // `href=${x}`
    case 'valueunq': // `data-x=a${x}`
      // 따옴표 없는 값은 허용하지 않는다: 빈 값이면 다음 속성이 값으로 먹히는 등(`value= class="c"`) 구조가 깨지고,
      // 공백·`=`·`/` 등 인코딩하지 않은 문자로 속성이 추가될 위험이 있다. 항상 따옴표로 감싸야 한다.
      throw new Error('html: 속성 값의 보간(${})은 반드시 따옴표로 감싸야 합니다: name="${value}"');
    default:
      throw new Error('html: 보간(${})을 사용할 수 없는 위치입니다 (태그 이름, 속성 이름, 주석 등)');
  }
}

function afterInterpolation(st) {
  st.valueStart = false;
}

const templateContexts = new WeakMap();

function analyzeTemplate(strings) {
  const cached = nativeApply(nativeWeakMapGet, templateContexts, [strings]);
  if (cached !== undefined) return cached;
  const st = newScanState();
  const contexts = [];
  for (let i = 0; i < strings.length - 1; i++) {
    scanStatic(strings[i], st);
    contexts.push(contextAt(st));
    afterInterpolation(st);
  }
  nativeApply(nativeWeakMapSet, templateContexts, [strings, contexts]);
  return contexts;
}

function renderText(value, depth) {
  if (typeof value === 'string') return escapeTextString(value); // 가장 흔한 경우를 먼저 처리
  if (isSafeHTML(value)) return String(value);
  if (Array.isArray(value)) {
    if (depth > MAX_RENDER_DEPTH) throw new RangeError('html: array nesting too deep');
    let out = '';
    for (let i = 0; i < value.length; i++) out += renderText(value[i], depth + 1);
    return out;
  }
  if (value === null || value === undefined || value === false) return '';
  return escapeTextString(toText(value));
}

function plainText(value, depth) {
  if (typeof value === 'string') return value;
  if (isSafeHTML(value)) return String(value);
  if (Array.isArray(value)) {
    if (depth > MAX_RENDER_DEPTH) throw new RangeError('html: array nesting too deep');
    const parts = [];
    for (let i = 0; i < value.length; i++) parts.push(plainText(value[i], depth + 1));
    return parts.join(' ');
  }
  if (value === null || value === undefined || value === false) return '';
  return toText(value);
}

function encodeComponent(text) {
  try {
    return encodeURIComponent(text);
  } catch (_) {
    return ''; // 짝이 맞지 않는 서로게이트 등
  }
}

function renderValue(value, ctx) {
  switch (ctx.kind) {
    case 'text':
      return renderText(value, 0);
    case 'rcdata':
      return escapeAttributeString(plainText(value, 0));
    case 'attr': // 항상 따옴표로 감싼 값 → " ' 를 포함한 HTML 인코딩으로 충분
      return escapeTextString(plainText(value, 0));
    default: { // 'url': 속성값 맨 앞의 보간은 URL 전체로 검증하고, 고정 문자열 뒤의 보간은 경로/쿼리 조각으로 인코딩
      const text = plainText(value, 0);
      return escapeTextString(ctx.atStart ? sanitizeURL(text) : encodeComponent(text));
    }
  }
}

/**
 * 보간(${})을 위치에 맞게 자동 이스케이프하는 태그드 템플릿. 결과는 SafeHTML 이며 `el.innerHTML = html\`...\`` 로 바로 사용합니다.
 *  - 텍스트·따옴표로 감싼 속성(name="${v}" / name='${v}'): HTML 인코딩. 따옴표 없는 속성 값의 보간은 Error
 *  - href·src 등 URL 속성: 값 전체가 보간이면 sanitizeURL('#' 대체), URL 중간 조각이면 encodeURIComponent
 *  - 중첩된 html`` 결과(SafeHTML)와 그 배열은 이중 인코딩 없이 삽입 (목록: ${items.map(i => html`<li>${i}</li>`)})
 *  - null/undefined/false 는 '', 객체는 '' (SafeHTML 제외)
 *  - 예외(템플릿 정의 시점에 데이터와 무관하게 발생): on* 이벤트·style·srcdoc·srcset 속성, <script>/<style> 등 본문,
 *    script/link/iframe 등의 속성, 태그 이름·속성 이름·주석 안의 보간
 * @param {TemplateStringsArray} strings
 * @param {...unknown} values
 * @returns {object} SafeHTML (toString() 으로 문자열)
 */
function html(strings, ...values) {
  if (!Array.isArray(strings) || !Array.isArray(strings.raw) || !Object.isFrozen(strings)) {
    throw new TypeError('html: must be used as a tagged template: html`...`');
  }
  for (let i = 0; i < strings.length; i++) {
    if (typeof strings[i] !== 'string') throw new TypeError('html: invalid escape sequence in template');
  }
  if (values.length === 0) return makeSafeHTML(strings[0]);

  const contexts = analyzeTemplate(strings);
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += renderValue(values[i], contexts[i]) + strings[i + 1];
  return makeSafeHTML(out);
}

export {
  escapeHTML, escapeAttribute, escapeRegExp, html, unsafeHTML, isSafeHTML,
  isSafeURL, sanitizeURL,
  safeJSONParse, safeDeepClone, safeMerge,
  formatBytes, debounce, throttle, randomToken
};
