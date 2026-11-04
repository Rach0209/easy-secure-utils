# 🛡️ SecureWebUtils

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Formats](https://img.shields.io/badge/formats-ESM%20%7C%20UMD-blue.svg)]()

**SecureWebUtils**는 프론트엔드 개발 시 자주 발생하는 **XSS, Prototype Pollution, 위험 URL 스킴/Open Redirect**를 완화하고, 성능에 도움이 되는 유틸리티를 제공하는 **Zero-Dependency** JavaScript 라이브러리입니다. (UMD 기준 주석 포함 약 37KB, gzip 약 11KB — 미니파이 없음)

> ⚠️ 이 라이브러리는 **방어 계층 중 하나**입니다. 서버 측 검증, CSP, 프레임워크의 자동 이스케이프를 대체하지 않습니다. ([보안 모델과 한계](#-보안-모델과-한계) 참고)

---

## 🌟 주요 특징

- **🧩 `html` 태그드 템플릿**: ``html`<a href="${url}">${name}</a>` `` 처럼 쓰면 보간(`${}`)이 **위치에 맞게 자동 이스케이프**됩니다. 이스케이프를 깜빡하는 실수를 구조적으로 막습니다.
- **🔒 Fail-closed 설계**: 의심스러운 입력은 허용하지 않고 거부/제거하며, 안전하지 않은 템플릿 위치는 **데이터와 무관하게 즉시 Error** 입니다.
- **⚡ Fast-path & 캐시**: 위험 요소가 없는 일반 입력은 정규식 1회 검사 후 즉시 반환하고, `html` 의 템플릿 분석은 호출 지점마다 1회만 수행합니다.
- **📦 Zero-Dependencies**, **ESM + UMD(CommonJS/AMD/`<script>`)** 동시 제공, TypeScript 선언 포함, SRI 해시 제공
- **🧊 변조 방어**: 내장 함수(`JSON.parse` 등)를 로드 시점에 캡처하고, UMD 공개 객체는 `Object.freeze` 됩니다 (ESM 은 export 바인딩이 읽기 전용).

---

## 🧭 상황별 레시피 — 무엇을 써야 하나요?

| 하고 싶은 일 | 사용 | 예시 |
|---|---|---|
| 사용자 입력을 **HTML 로** 화면에 넣기 | `html` | ``el.innerHTML = html`<p>${input}</p>` `` |
| 단순 텍스트만 표시 | (라이브러리 불필요) | `el.textContent = input` |
| 사용자가 준 URL 을 링크에 넣기 | `sanitizeURL` | `a.href = sanitizeURL(userUrl)` |
| URL 이 안전한지만 검사 / 외부 이동 제한 | `isSafeURL` | `isSafeURL(url, undefined, { allowedHosts: ['app.example.com'] })` |
| 서버·사용자가 준 JSON 읽기 | `safeJSONParse` | `safeJSONParse(text, {})` |
| 설정/옵션 병합 (사용자 입력이 섞일 때) | `safeMerge` | `safeMerge({}, defaults, userOptions)` |
| 객체 복사 | `safeDeepClone` | `safeDeepClone(state)` |
| 세션 ID·CSRF 토큰·nonce 생성 | `randomToken` | `randomToken(32)` / `randomToken(16, 'base64url')` |
| 검색어로 정규식 만들기 | `escapeRegExp` | `new RegExp(escapeRegExp(query), 'i')` |
| 입력창 자동완성·검색 | `debounce` | `debounce(search, 300)` |
| 스크롤·리사이즈·마우스 이동 | `throttle` | `throttle(onScroll, 100)` |
| 파일 크기 표시 | `formatBytes` | `formatBytes(1536)` → `"1.5 KB"` |

---

## 📦 설치 및 사용 방법

npm 레지스트리에는 올리지 않고 **GitHub 에서 직접 받아** 사용합니다 (`dist/` 가 저장소에 커밋되어 있어 빌드가 필요 없습니다).

### 1. GitHub Releases 에서 파일 받기 (가장 단순)

[Releases](https://github.com/Rach0209/easy-secure-utils/releases) 페이지에서 `easy-secure-utils.js`(UMD) 또는 `easy-secure-utils.mjs`(ESM) 를 받아 프로젝트에 복사합니다. 릴리스에는 `integrity.json`(SRI 해시)과 전체 zip 이 함께 첨부됩니다.

```html
<script src="./easy-secure-utils.js"></script>
<script>
  const { html } = SecureWebUtils;   // UMD 전역 이름
  el.innerHTML = html`<p>${userInput}</p>`;
</script>
```

```html
<script type="module">
  import { html } from './easy-secure-utils.mjs';
</script>
```
> 네이티브 ESM 은 `file://` 에서 CORS 로 차단됩니다. 로컬 서버(`python -m http.server` 등)로 여세요. 예제: [`examples/esm.html`](examples/esm.html)

### 2. GitHub 에서 설치 (npm / pnpm / yarn)

```bash
npm install github:Rach0209/easy-secure-utils#v1.1.0
```

`#v1.1.0` 은 릴리스 태그입니다 (생략하면 기본 브랜치 최신). 설치 후에는 패키지 이름 `easy-secure-utils` 로 불러옵니다.

```javascript
import { html, safeJSONParse, debounce } from 'easy-secure-utils';   // ESM
const { html } = require('easy-secure-utils');                        // CommonJS
```

### 3. CDN 으로 바로 로드 (jsDelivr — SRI 로 고정 권장)

```html
<!-- UMD: 전역 SecureWebUtils -->
<script src="https://cdn.jsdelivr.net/gh/Rach0209/easy-secure-utils@v1.1.0/dist/easy-secure-utils.js"
        integrity="sha384-(dist/integrity.json 의 easy-secure-utils.js 값)"
        crossorigin="anonymous"></script>

<!-- 네이티브 ESM -->
<script type="module">
  import { html } from 'https://cdn.jsdelivr.net/gh/Rach0209/easy-secure-utils@v1.1.0/dist/easy-secure-utils.mjs';
</script>
```
> `integrity` 값은 [`dist/integrity.json`](dist/integrity.json) 과 Release 노트에 있습니다. 해시가 다르면 브라우저가 스크립트를 실행하지 않으므로 CDN 이 변조되어도 안전합니다. (태그를 `@main` 처럼 움직이는 대상에 쓰면 해시가 맞지 않을 수 있으니 **항상 태그로 고정**하세요.) 저장소가 **공개**일 때만 jsDelivr 가 동작합니다.

### 4. CSP 권장 설정

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'">
```

### 5. 데모

`index.html` 을 브라우저로 열면 각 함수를 직접 시험할 수 있습니다 (`demo.js` + `dist/easy-secure-utils.js` 사용).

### 6. 브라우저 호환성 점검

[`examples/browser-check.html`](examples/browser-check.html) 을 **점검하려는 브라우저에서** 열면 라이브러리의 핵심 동작 43개를 그 자리에서 실행해 통과/실패를 보여줍니다. 특히 `html` 템플릿의 출력을 **그 브라우저 자신의 HTML 파서**(`DOMParser`)로 다시 해석해 구조 불변·값 왕복·URL 안전성을 약 5천 번 대조합니다. 외부로 아무것도 전송하지 않으며, 맨 아래 JSON 으로 결과를 복사할 수 있습니다. (GitHub Pages 를 켜면 휴대폰·Safari 에서도 URL 하나로 열 수 있습니다.)

| 브라우저 | 상태 |
|---|---|
| Chrome 156 (Windows) | ✅ 통과 (`file://` 42/42 · `http://` 43/43, ESM 포함) |
| Edge 156 (Windows) | ✅ 통과 (동일) |
| Brave · Opera · Samsung Internet 등 Chromium 계열 | 같은 엔진(Blink)이라 동일 결과가 예상되나 **직접 확인하지는 않음** |
| Firefox · Safari(macOS/iOS) · 모바일 | ⚠️ **아직 확인하지 않음** — 위 점검 페이지로 확인해 주세요 |

> 네이티브 ESM 점검은 `http(s)` 에서만 동작합니다. `file://` 에서는 모든 브라우저가 모듈을 막으므로 "건너뜀" 으로 표시됩니다.

---

## 📖 API Reference

### 🧩 `html` — 문맥 인식 자동 이스케이프 템플릿

```js
import { html, unsafeHTML } from 'easy-secure-utils';

const user = { name: '<img src=x onerror=alert(1)>', site: 'javascript:alert(1)' };

el.innerHTML = html`
  <div class="card" title="${user.name}">
    <a href="${user.site}">${user.name}</a>
    <ul>${items.map((i) => html`<li>${i}</li>`)}</ul>
  </div>`;
// → 이름은 &lt;img ...&gt; 로 인코딩, href 는 "#" 으로 대체, 목록은 이중 인코딩 없이 삽입
```

결과는 `SafeHTML` 객체이며 `String(result)`, `` `${result}` ``, `el.innerHTML = result` 모두 동작합니다.

| 보간 위치 | 처리 |
|---|---|
| 텍스트 (`<p>${v}</p>`) | HTML 인코딩 |
| 따옴표로 감싼 속성값 (`title="${v}"`, `title='${v}'`) | HTML 인코딩 |
| URL 속성 (`href` `src` `action` `formaction` `poster` `xlink:href` 등) — **값 전체**가 보간 | `sanitizeURL` 검증 (위험하면 `#`) |
| URL 속성 — 고정 문자열 **뒤**의 보간 (`href="/u/${id}"`) | `encodeURIComponent` (경로 이동·`//` 합성 불가) |
| `<textarea>`·`<title>` 본문 | 엄격 인코딩 (닫는 태그 탈출 불가) |
| 중첩된 `html` 결과 / 그 배열 | 이중 인코딩 없이 그대로 삽입 |
| `null` `undefined` `false` | 빈 문자열 |
| 객체·함수·Symbol | 빈 문자열 (`SafeHTML` 제외) |

**다음 위치의 보간은 `Error` 를 던집니다.** 템플릿을 처음 실행하는 순간(= 개발 중) 데이터와 무관하게 발생하므로, 운영 중 특정 입력에서만 터지는 일은 없습니다.
- 이벤트 핸들러 속성 `on*`, `style`, `srcdoc`, `srcset`
- **따옴표 없는 속성값** (`value=${v}` → 반드시 `value="${v}"`; 빈 값이 다음 속성을 삼키는 문제를 원천 차단)
- `<script>` `<style>` `<noscript>` `<iframe>` `<xmp>` 등의 본문
- `<script>` `<link>` `<iframe>` `<object>` `<embed>` `<base>` `<meta>` 의 속성
- 태그 이름·속성 이름·주석(`<!-- ${x} -->`)·`<!`·`<?` 안

그 밖에:
- `html(문자열)` 처럼 **태그드 템플릿이 아닌 호출**은 `TypeError` 입니다.
- `SafeHTML` 표식은 모듈 내부 Symbol 키로 저장되어 **JSON·폼·URL 파라미터 같은 데이터로는 위조할 수 없고**, 인스턴스는 동결되어 있으며 `constructor` 로 새 인스턴스를 만들 수 없습니다.
- `unsafeHTML(text)` 는 **이스케이프 없이** 삽입하는 명시적 탈출구입니다. DOMPurify 로 정제한 결과처럼 이미 신뢰할 수 있는 값에만 쓰세요. 사용자 입력에 쓰면 이 라이브러리의 보호가 무력화됩니다.
- `isSafeHTML(value)` 로 `SafeHTML` 여부를 확인할 수 있습니다.
- `html` 은 **sanitizer 가 아닙니다.** 사용자가 입력한 HTML 을 "허용"하지 않고 문자 그대로 보여줍니다. 리치 텍스트를 렌더링해야 하면 DOMPurify 같은 검증된 sanitizer 로 정제한 뒤 `unsafeHTML` 로 감싸세요.

### `escapeHTML(str): string`
`&` `<` `>` `"` `'` 그리고 백틱(`` ` ``)을 인코딩합니다. **HTML 텍스트 노드와 따옴표로 감싼 속성값**에서만 안전합니다. (`html` 템플릿을 쓰면 직접 호출할 필요가 거의 없습니다.)
- 문자열·숫자·불리언·bigint 는 문자열로 변환, 그 외(`null`, 객체 등)는 `''` 를 반환합니다 (객체의 `toString` 을 호출하지 않음).
- `<script>`/`<style>` 내부, 이벤트 핸들러 속성(`onclick`), URL 속성(`href`/`src`), 따옴표 없는 속성에는 **사용하지 마세요.**
- `textContent` 로 넣는 값에는 필요 없습니다 (이중 인코딩이 됩니다).

### `escapeAttribute(value): string`
영숫자와 `, . _ -` 를 제외한 **모든 문자**를 `&#xHH;` 로 변환하는 엄격 인코딩입니다. 따옴표 없는 속성에서도 속성 탈출이 불가능합니다.

### `escapeRegExp(str): string`
정규식 특수문자(문자 클래스 안의 `-` 포함)를 이스케이프해 사용자 입력을 **문자 그대로** 매칭합니다.

```js
new RegExp(escapeRegExp(userQuery), 'i')   // "a.c" 가 "abc" 와 매칭되지 않음
```

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

### `sanitizeURL(url, fallback = '#', allowedProtocols?, options?): string`
`isSafeURL` 이 `true` 이면 `url` 그대로, 아니면 `fallback` 을 반환합니다. 검증 규칙은 `isSafeURL` 과 같습니다.

```js
a.href = sanitizeURL(userProvidedUrl);              // 위험하면 '#'
a.href = sanitizeURL(userProvidedUrl, '/home');     // 대체 경로 지정
```

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

### `safeMerge(target, ...sources)`
Prototype Pollution 에 안전한 **깊은 병합**입니다. `Object.assign` 처럼 `target` 을 변경하고 그대로 반환합니다. 원본을 보존하려면 `safeMerge({}, a, b)` 로 사용하세요.

```js
const options = safeMerge({}, DEFAULTS, JSON.parse(untrustedJson));   // JSON.parse 결과를 그대로 넘겨도 안전
```
- `safeJSONParse` 와 **동일한 위험 키 규칙** (`__proto__` 는 항상, `constructor`/`prototype` 은 객체·함수 값일 때만 무시)
- 대입 대신 `defineProperty` 를 사용해 setter·프로토타입 접근을 일으키지 않고, **getter 는 실행하지 않습니다.**
- 양쪽이 모두 순수 객체이면 재귀 병합하고, **배열은 병합하지 않고 통째로 교체**합니다.
- `source` 값은 깊게 복사되어 원본과 참조를 공유하지 않습니다. `null`/`undefined`/원시값 source 는 무시합니다.
- `target` 이 객체가 아니면 `TypeError`, 중첩이 1000단계를 넘으면 `RangeError`.
- 성능: 작은 설정 객체 병합에 약 8µs (디스크립터 기반이라 단순 재귀 병합보다 느림). 설정·옵션·JSON 병합용이며 초당 수십만 번 호출되는 핫 루프용은 아닙니다.

### `safeDeepClone(obj, maxDepth = 1000)`
- 순환 참조 지원. 위험 키 규칙은 `safeJSONParse` 와 동일
- **getter 는 실행하지 않고 건너뜀**, 비열거 속성은 복사하지 않음, 값은 `defineProperty` 로 정의 (프로토타입의 setter 우회)
- 지원: 일반 객체/배열(희소 배열 포함)/`Date`/`RegExp`/`Map`/`Set`/`ArrayBuffer`/TypedArray/`Error`/Symbol 키
- 함수는 복제하지 않고 참조를 그대로 유지합니다. 클래스 인스턴스는 프로토타입을 유지합니다.
- `WeakMap`/`WeakSet`/`Promise` → `TypeError`, 중첩이 `maxDepth` 초과 → `RangeError` (스택 오버플로 DoS 방지)
- 디스크립터 기반 복사이므로 단순 대입 방식보다 약 2배 느립니다 (보안과 맞바꾼 비용).

### `randomToken(bytes = 32, encoding = 'hex'): string`
`crypto.getRandomValues` 기반의 **암호학적으로 안전한** 난수 토큰입니다. 세션 ID·CSRF 토큰·nonce 용입니다.

```js
randomToken();                    // 64자 hex
randomToken(16, 'base64url');     // 22자, URL-safe, 패딩 없음
```
- `bytes` 는 1~1024 정수 (아니면 `RangeError`), `encoding` 은 `'hex'` 또는 `'base64url'` (아니면 `TypeError`)
- 안전한 난수원이 없으면 **`Math.random` 으로 대체하지 않고 `Error`** 를 던집니다.

### `formatBytes(bytes, decimals = 2): string`
`Bytes`/`KB`/`MB`/`GB`/`TB`/`PB` 로 변환합니다. 숫자가 아니거나 `NaN`/`Infinity`/0 이하이면 `'0 Bytes'`. `decimals` 는 0~20 으로 보정됩니다. 반올림 경계(`1048575` → `1 MB`)도 올바르게 승급합니다.

### `debounce(fn, delay = 250, options?)`
- `fn` 이 함수가 아니면 즉시 `TypeError`
- `delay` 는 `0 ~ 2147483647` 로 보정 (유효하지 않으면 250)
- `options.leading: true` → 첫 호출을 즉시 실행하고 `delay` 동안의 이후 호출은 무시(타이머 연장)
- `.cancel()` 대기 중인 호출 취소, `.flush()` 대기 중인 호출을 **지금 즉시** 실행 (예: 페이지를 떠나기 직전 저장)
- 호출 시점의 `this` 와 마지막 인자가 보존됩니다. `fn` 의 예외/비동기 reject 는 처리하지 않고 그대로 전파됩니다.

### `throttle(fn, wait = 250, options?)`
`wait`(ms) 동안 **최대 1번**만 실행합니다 (스크롤·리사이즈·마우스 이동용).
- 기본은 `leading: true, trailing: true`: 첫 호출은 즉시 실행하고, 구간 중 마지막 호출은 구간이 끝날 때 마지막 인자로 1회 실행합니다.
- `{ trailing: false }` 처음만 / `{ leading: false }` 구간 끝에만. 둘 다 `false` 는 `TypeError`.
- `.cancel()`, `.flush()` 제공. 호출 시점의 `this` 와 인자가 보존됩니다.

---

## 🔐 보안 모델과 한계

**막는 것**: 위험 URL 스킴, 탭/개행·백슬래시 기반 정규화 우회, 자격증명 URL, `__proto__` 계열 키(이스케이프 위장 포함), getter/setter 를 통한 복제·병합 중 코드 실행, 깊은 중첩·초대형 JSON·초장문 URL·깊은 배열로 인한 DoS, 로드 후 API 덮어쓰기, 약한 난수 사용, `html` 템플릿에서의 속성 탈출·태그 주입·`on*` 핸들러·`javascript:` URL.

**검증 방법**: 모든 보호 장치는 테스트(UMD/ESM 양쪽)로 확인하며, 보호 장치를 하나씩 일부러 망가뜨려 테스트가 실패하는지 확인하는 변형(mutation) 검사를 거쳤습니다. `html` 은 실제 브라우저의 HTML 파서를 기준으로, 22개 템플릿 × 약 5천 개의 적대적 입력에서 구조 불변·데이터 왕복·URL 안전성을 확인했습니다. 다만 이는 **증명이 아니라 검증**이며 sanitizer 가 아닙니다.

**막지 못하는 것 (사용자의 책임)**
- 이미 페이지에서 임의 스크립트가 실행되는 상태(= XSS 성립 후)의 공격. 이 경우 어떤 클라이언트 라이브러리도 방어할 수 없습니다 → **CSP** 사용.
- `escapeHTML` 을 부적절한 컨텍스트(`<script>`, `onclick`, `href`, 따옴표 없는 속성)에 사용하는 경우. → `html` 템플릿을 쓰면 이런 위치는 에러로 막힙니다.
- `unsafeHTML` 로 신뢰 표시한 값 안의 악성 콘텐츠.
- `isSafeURL` 을 통과한 뒤 URL 을 **재조합/변형**해서 쓰는 경우. 검증한 문자열을 그대로 사용하세요.
- `allowedHosts` 없이 `isSafeURL` 을 쓰면 임의의 `https://외부사이트` 로의 이동은 허용됩니다.
- 서버 측 검증(SSRF, 인가, 입력 검증). 클라이언트 검사는 우회 가능하므로 서버에서도 반드시 검증하세요.
- 순수 `JSON.parse` 자체는 오염을 일으키지 않습니다. 위험은 그 결과를 **재귀 병합(deep merge)·경로 대입 유틸**에 넘길 때 생깁니다. 이 라이브러리의 `safeJSONParse` + `safeMerge` 는 이를 막지만, 다른 병합 라이브러리를 쓴다면 그쪽에서도 위험 키를 차단하세요.

취약점을 발견하셨다면 [SECURITY.md](SECURITY.md) 의 절차로 비공개 신고해 주세요.

---

## 🛠️ 개발

```bash
npm run build       # src/easy-secure-utils.mjs → dist/ (ESM + UMD + integrity.json) 생성
npm test            # Node 20+ 내장 테스트 러너 (UMD/ESM 양쪽 + dist·SRI 최신 여부 검사)
npm run typecheck   # TypeScript 컴파일러로 타입 선언 검증 (npx 로 임시 설치, 프로젝트에 의존성 추가 없음)
```

`src/easy-secure-utils.mjs` 가 **단일 소스**이며 `dist/` 는 빌드 산출물입니다 (CDN 용으로 커밋). 소스를 수정하면 반드시 `npm run build` 후 커밋하세요 (테스트가 불일치를 감지합니다).

**릴리스**: `package.json` 의 `version` 과 `src` 배너·`CHANGELOG.md` 를 올리고 커밋한 뒤 태그를 push 하면(`git tag v1.2.3 && git push origin v1.2.3`) GitHub Actions 가 테스트 → 버전 일치 확인 → Release 생성(파일·SRI·zip 첨부)을 자동으로 수행합니다.

변경 내역은 [CHANGELOG.md](CHANGELOG.md) 를 참고하세요.

---

## 📄 License

[MIT](LICENSE)
