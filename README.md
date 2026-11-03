# 🛡️ SecureWebUtils

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Formats](https://img.shields.io/badge/formats-ESM%20%7C%20UMD-blue.svg)]()

**SecureWebUtils**는 프론트엔드 개발 시 자주 발생하는 **XSS, Prototype Pollution, 위험 URL 스킴/Open Redirect**를 완화하고, 성능에 도움이 되는 유틸리티를 제공하는 **Zero-Dependency** JavaScript 라이브러리입니다. (UMD 기준 압축 전 약 15KB, gzip 약 5.5KB — 미니파이 없음)

> ⚠️ 이 라이브러리는 **방어 계층 중 하나**입니다. 서버 측 검증, CSP, 프레임워크의 자동 이스케이프를 대체하지 않습니다. ([보안 모델과 한계](#-보안-모델과-한계) 참고)

---

## 🌟 주요 특징

- **🔒 Fail-closed 설계**: 의심스러운 입력은 허용하지 않고 거부/제거합니다.
- **⚡ Fast-path**: 위험 요소가 없는 일반 입력은 정규식 1회 검사 후 즉시 반환합니다 (`escapeHTML`, `safeJSONParse`, 상대경로 `isSafeURL`).
- **📦 Zero-Dependencies**, **ESM + UMD(CommonJS/AMD/`<script>`)** 동시 제공, TypeScript 선언 포함
- **🧊 변조 방어**: 내장 함수(`JSON.parse` 등)를 로드 시점에 캡처하고, UMD 공개 객체는 `Object.freeze` 됩니다 (ESM 은 export 바인딩이 읽기 전용).

---

## 📦 설치 및 사용 방법

### 1. GitHub 에서 설치 (npm / pnpm / yarn)

```bash
npm install github:Rach0209/easy-secure-utils#v1.0.0
```

`#v1.0.0` 은 릴리스 태그입니다 (생략하면 기본 브랜치 최신). 설치 후에는 패키지 이름 `easy-secure-utils` 로 불러옵니다.

```javascript
import { escapeHTML, safeJSONParse, debounce } from 'easy-secure-utils';   // ESM
const { escapeHTML } = require('easy-secure-utils');                        // CommonJS
```

### 2. CDN 으로 바로 로드 (jsDelivr)

```html
<!-- UMD: 전역 SecureWebUtils -->
<script src="https://cdn.jsdelivr.net/gh/Rach0209/easy-secure-utils@v1.0.0/dist/easy-secure-utils.js"></script>

<!-- 네이티브 ESM -->
<script type="module">
  import { escapeHTML } from 'https://cdn.jsdelivr.net/gh/Rach0209/easy-secure-utils@v1.0.0/dist/easy-secure-utils.mjs';
</script>
```
> 외부 CDN 스크립트는 `integrity`(SRI) 속성으로 고정하거나, 보안이 중요하면 아래 3번처럼 파일을 직접 복사해 자체 호스팅하세요.

### 3. 파일 복사 (가장 단순)

`dist/easy-secure-utils.js` (UMD) 또는 `dist/easy-secure-utils.mjs` (ESM) 한 파일만 프로젝트에 복사합니다.

```html
<script src="./easy-secure-utils.js"></script>
<script>
  const { escapeHTML } = SecureWebUtils;   // UMD 전역 이름
  el.innerHTML = escapeHTML(userInput);
</script>
```

```html
<script type="module">
  import { escapeHTML } from './easy-secure-utils.mjs';
</script>
```
> 네이티브 ESM 은 `file://` 에서 CORS 로 차단됩니다. 로컬 서버(`python -m http.server` 등)로 여세요. 예제: [`examples/esm.html`](examples/esm.html)

### 4. CSP 권장 설정

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'">
```

### 5. 데모

`index.html` 을 브라우저로 열면 각 함수를 직접 시험할 수 있습니다 (`demo.js` + `dist/easy-secure-utils.js` 사용).

---

## 📖 API Reference

### `escapeHTML(str): string`
`& < > " ' \`` 를 인코딩합니다. **HTML 텍스트 노드와 따옴표로 감싼 속성값**에서만 안전합니다.
- 문자열·숫자·불리언·bigint 는 문자열로 변환, 그 외(`null`, 객체 등)는 `''` 를 반환합니다 (객체의 `toString` 을 호출하지 않음).
- `<script>`/`<style>` 내부, 이벤트 핸들러 속성(`onclick`), URL 속성(`href`/`src`), 따옴표 없는 속성에는 **사용하지 마세요.**
- `textContent` 로 넣는 값에는 필요 없습니다 (이중 인코딩이 됩니다).

### `escapeAttribute(value): string`
영숫자와 `, . _ -` 를 제외한 **모든 문자**를 `&#xHH;` 로 변환하는 엄격 인코딩입니다. 따옴표 없는 속성에서도 속성 탈출이 불가능합니다.

### `isSafeURL(url, allowedProtocols?, options?): boolean`
```js
isSafeURL('https://example.com');                                                          // true
isSafeURL('javascript:alert(1)');                                                          // false
isSafeURL('https://app.example.com/x', undefined, { allowedHosts: ['app.example.com'] }); // true
isSafeURL('https://evil.com/x',        undefined, { allowedHosts: ['app.example.com'] }); // false
```
- 기본 허용 프로토콜: `http:` `https:` `mailto:` `tel:` (`allowedProtocols` 는 **배열**, 소문자+콜론 형식)
- `javascript:` `data:` `vbscript:` `blob:` `file:` `filesystem:` `about:` `view-source:` 는 `allowedProtocols` 에 넣어도 **항상 차단**
- 탭/개행/제어문자(브라우저가 제거 후 해석하는 우회 수법), 백슬래시, 앞뒤 공백이 있으면 거부
- `//host`, `/\host` 등 protocol-relative 거부. 상대경로는 같은 출처로 해석될 때만 허용 (`options.allowRelative: false` 로 상대경로 자체를 금지 가능)
- `https://user:pass@host` 형태(자격증명 URL) 거부
- `options.allowedHosts` 를 지정하면 http(s) 절대 URL 은 **호스트가 정확히 일치**할 때만 허용 → 실질적인 **Open Redirect 방지**는 이 옵션을 사용해야 합니다.
- 길이 8192자 초과, 문자열이 아닌 입력, 배열이 아닌 `allowedProtocols` → `false`

### `safeJSONParse(text, fallback = null, maxLength = 5242880)`
Prototype Pollution 키를 **모든 깊이에서** 제거합니다 (JSON 유니코드 이스케이프 표기 — 백슬래시+`u`+16진수 4자리 — 로 키 이름을 위장한 경우 포함).

| 키 | 값 | 처리 |
|---|---|---|
| `__proto__` | 무엇이든 | **제거** |
| `constructor`, `prototype` | 객체 / 배열 | **제거** (`target.constructor.prototype` 병합 경로 차단) |
| `constructor`, `prototype` | 문자열·숫자 등 원시값 | **유지** (정상 데이터, 오염 경로가 될 수 없음) |

- 파싱 실패, 문자열이 아닌 입력, `maxLength` 초과 시 `fallback` 반환
- 위험 키워드/이스케이프가 없는 일반 JSON 은 reviver 없이 네이티브 파서를 사용합니다 (fast-path).
- `fallback` 에 `undefined` 를 넘기면 기본값 `null` 이 적용됩니다. 구분이 필요하면 고유 값(예: `Symbol()`)을 사용하세요.
- 정당한 데이터라도 `{"constructor": {...}}` 처럼 **객체 값**을 가진 `constructor`/`prototype` 키는 제거됩니다.

### `safeDeepClone(obj, maxDepth = 1000)`
- 순환 참조 지원. 위험 키 규칙은 `safeJSONParse` 와 동일
- **getter 는 실행하지 않고 건너뜀**, 비열거 속성은 복사하지 않음, 값은 `defineProperty` 로 정의 (프로토타입의 setter 우회)
- 지원: 일반 객체/배열(희소 배열 포함)/`Date`/`RegExp`/`Map`/`Set`/`ArrayBuffer`/TypedArray/`Error`/Symbol 키
- 함수는 복제하지 않고 참조를 그대로 유지합니다. 클래스 인스턴스는 프로토타입을 유지합니다.
- `WeakMap`/`WeakSet`/`Promise` → `TypeError`, 중첩이 `maxDepth` 초과 → `RangeError` (스택 오버플로 DoS 방지)
- 디스크립터 기반 복사이므로 단순 대입 방식보다 약 2배 느립니다 (보안과 맞바꾼 비용).

### `formatBytes(bytes, decimals = 2): string`
`Bytes`/`KB`/`MB`/`GB`/`TB`/`PB` 로 변환합니다. 숫자가 아니거나 `NaN`/`Infinity`/0 이하이면 `'0 Bytes'`. `decimals` 는 0~20 으로 보정됩니다. 반올림 경계(`1048575` → `1 MB`)도 올바르게 승급합니다.

### `debounce(fn, delay = 250, options?)`
- `fn` 이 함수가 아니면 즉시 `TypeError`
- `delay` 는 `0 ~ 2147483647` 로 보정 (유효하지 않으면 250)
- `options.leading: true` → 첫 호출을 즉시 실행하고 `delay` 동안의 이후 호출은 무시(타이머 연장)
- `.cancel()` 제공. 호출 시점의 `this` 와 마지막 인자가 보존됩니다.
- `fn` 의 예외/비동기 reject 는 처리하지 않고 그대로 전파됩니다.

---

## 🔐 보안 모델과 한계

**막는 것**: 위험 URL 스킴, 탭/개행·백슬래시 기반 정규화 우회, 자격증명 URL, `__proto__` 계열 키(이스케이프 위장 포함), getter/setter 를 통한 복제 중 코드 실행, 깊은 중첩·초대형 JSON·초장문 URL 로 인한 DoS, 로드 후 API 덮어쓰기.

**막지 못하는 것 (사용자의 책임)**
- 이미 페이지에서 임의 스크립트가 실행되는 상태(= XSS 성립 후)의 공격. 이 경우 어떤 클라이언트 라이브러리도 방어할 수 없습니다 → **CSP** 사용.
- `escapeHTML` 을 부적절한 컨텍스트(`<script>`, `onclick`, `href`, 따옴표 없는 속성)에 사용하는 경우.
- `isSafeURL` 을 통과한 뒤 URL 을 **재조합/변형**해서 쓰는 경우. 검증한 문자열을 그대로 사용하세요.
- `allowedHosts` 없이 `isSafeURL` 을 쓰면 임의의 `https://외부사이트` 로의 이동은 허용됩니다.
- 서버 측 검증(SSRF, 인가, 입력 검증). 클라이언트 검사는 우회 가능하므로 서버에서도 반드시 검증하세요.
- 순수 `JSON.parse` 자체는 오염을 일으키지 않습니다. 위험은 그 결과를 **재귀 병합(deep merge)·경로 대입 유틸**에 넘길 때 생깁니다. 이 라이브러리는 입력 단계에서 위험 키를 제거하지만, 병합 함수 자체에서도 `__proto__`/`constructor`/`prototype` 키를 차단하는 것이 권장됩니다.

---

## 🛠️ 개발

```bash
npm run build   # src/easy-secure-utils.mjs → dist/ (ESM + UMD) 생성
npm test        # Node 18+ 내장 테스트 러너 (UMD/ESM 양쪽 + dist 최신 여부 검사)
```

`src/easy-secure-utils.mjs` 가 **단일 소스**이며 `dist/` 는 빌드 산출물입니다 (CDN 용으로 커밋). 소스를 수정하면 반드시 `npm run build` 후 커밋하세요 (테스트가 불일치를 감지합니다).

변경 내역은 [CHANGELOG.md](CHANGELOG.md) 를 참고하세요.

---

## 📄 License

[MIT](LICENSE)
