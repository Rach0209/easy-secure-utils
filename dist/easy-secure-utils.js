/**
 * SecureWebUtils v1.0.0
 * Zero-dependency, Secure, High-Performance Web Utility Library.
 *
 * @license MIT
 */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
  typeof define === 'function' && define.amd ? define(['exports'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.SecureWebUtils = {}));
})(this, (function (exports) {
  'use strict';

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
    const text = typeof str === 'string' ? str : toText(str);
    if (!FAST_HTML_REGEX.test(text)) return text;
    return text.replace(HTML_REPLACE_REGEX, (match) => HTML_ESCAPES[match]);
  }

  /**
   * HTML 속성값 전용 엄격 인코딩 (OWASP 규칙): 영숫자와 , . _ - 를 제외한 모든 문자를 &#xHH; 로 변환합니다.
   * 따옴표 없는 속성(<div title=VALUE>)에서도 속성 탈출이 불가능합니다.
   * @param {string} value
   * @returns {string}
   */
  function escapeAttribute(value) {
    const text = toText(value);
    if (text === '') return text;
    return text.replace(ATTR_UNSAFE_REGEX, (ch) => '&#x' + ch.codePointAt(0).toString(16).toUpperCase() + ';');
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

  /**
   * Debounce 함수 (취소 및 즉시 실행 옵션 포함)
   * @param {Function} fn
   * @param {number} [delay=250]
   * @param {{leading?: boolean}} [options] leading:true 면 첫 호출을 즉시 실행하고 delay 동안의 이후 호출은 무시(타이머만 연장)
   * @returns {Function & { cancel: Function }}
   */
  function debounce(fn, delay = 250, options) {
    if (typeof fn !== 'function') throw new TypeError('debounce: fn must be a function');
    const wait = typeof delay === 'number' && delay >= 0 ? Math.min(delay, MAX_TIMEOUT) : 250;
    const leading = options !== null && typeof options === 'object' && options.leading === true;
    let timerId = null;

    function debounced(...args) {
      const callNow = leading && timerId === null;
      if (timerId !== null) clearTimeout(timerId);
      timerId = setTimeout(() => {
        timerId = null; // fn 이 예외를 던져도 상태가 꼬이지 않도록 먼저 초기화
        if (!leading) nativeApply(fn, this, args);
      }, wait);
      if (callNow) return nativeApply(fn, this, args);
    }

    debounced.cancel = () => {
      if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
      }
    };

    return debounced;
  }

  exports.escapeHTML = escapeHTML;
  exports.escapeAttribute = escapeAttribute;
  exports.isSafeURL = isSafeURL;
  exports.safeJSONParse = safeJSONParse;
  exports.safeDeepClone = safeDeepClone;
  exports.formatBytes = formatBytes;
  exports.debounce = debounce;

  Object.defineProperty(exports, '__esModule', { value: true });
  Object.freeze(exports); // 로드 후 API 덮어쓰기(monkey-patching) 방지
}));
