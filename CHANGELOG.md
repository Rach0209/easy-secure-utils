# Changelog

## 1.1.0

### 추가 (Added)
- **`html` 태그드 템플릿**: 보간(`${}`)을 위치(텍스트 / 따옴표 속성 / URL 속성 / `<textarea>`·`<title>` 본문)에 맞게 자동 이스케이프. 중첩 `html` 결과와 배열은 이중 인코딩 없이 삽입. 안전하지 않은 위치(`on*`·`style`·`srcdoc`·`srcset`, 따옴표 없는 속성값, `<script>`·`<style>` 등의 본문, 태그·속성 이름, 주석)의 보간은 데이터와 무관하게 `Error`. `unsafeHTML`(명시적 탈출구), `isSafeHTML` 함께 제공
- **`safeMerge`**: Prototype Pollution 에 안전한 깊은 병합 (`safeJSONParse` 와 동일한 위험 키 규칙, getter·setter 미실행, source 깊은 복사, 배열 교체)
- **`sanitizeURL`**: 안전하면 그대로, 아니면 대체값(기본 `'#'`) 반환
- **`throttle`** (leading / trailing, `cancel` / `flush`), **`debounce.flush()`**
- **`randomToken`**: `crypto.getRandomValues` 기반 hex / base64url 토큰. 안전한 난수원이 없으면 `Math.random` 으로 대체하지 않고 `Error`
- **`escapeRegExp`**
- **SRI**: 빌드 시 `dist/integrity.json`(sha384) 생성, 릴리스 노트에 포함
- **GitHub Release 자동화**: `v*` 태그 push 시 테스트 → 태그·버전 일치 확인 → 파일(UMD / ESM / `integrity.json` / zip)을 첨부한 Release 생성
- `SECURITY.md`(취약점 비공개 신고 절차), 타입 선언을 실제 TypeScript 컴파일러로 검증하는 `npm run typecheck` 와 CI 잡
- **브라우저 호환성 점검 페이지** `examples/browser-check.html`: 열고 있는 브라우저에서 핵심 동작 43개와 `html` × 해당 브라우저 HTML 파서 대조를 실행하고 결과 JSON 을 제공

### 변경 (Changed)
- 지원 Node.js 를 `>=20` 으로 상향 (18 은 지원 종료, CI 는 20 / 22 / 24)
- 성능: `SafeHTML` 표식을 WeakMap 에서 모듈 내부 Symbol 키로 변경해 `html` 호출당 고정 비용을 약 1.5µs → 약 0.06µs 로 감소. 데이터(JSON·폼·URL 파라미터)로는 여전히 위조할 수 없음

### 검증 (Verification)
- 테스트 98개 (UMD / ESM 양쪽), 보호 장치를 하나씩 망가뜨리는 변형 검사 41종 모두 검출
- 실제 설치된 Chrome 156 · Edge 156 (Windows)에서 `examples/browser-check.html` 전부 통과 (`file://` / `http://` 양쪽, 파서 대조 5,472회 렌더). 일부러 보호 장치를 망가뜨린 라이브러리에서는 같은 페이지가 실패(8건)함을 확인. Firefox · Safari · 모바일은 미확인
- 실제 브라우저의 HTML 파서를 기준으로 22개 템플릿 × 약 5천 개 적대적 입력(약 11만 회 렌더)에서 구조 불변 · 데이터 왕복 · URL 안전성 확인. 이 과정에서 발견된 "빈 값의 따옴표 없는 속성이 다음 속성을 삼키는" 문제는 따옴표 없는 속성 보간을 금지하는 것으로 근본 해결

## 1.0.0

첫 공개 릴리스 (아래는 공개 전 내부 초안 대비 변경 사항).

### 수정 (Fixed)
- `isSafeURL` 의 구문 오류로 파일 전체가 로드되지 않던 문제
- `formatBytes(0.5)` → `"512 undefined"`, `formatBytes(1048575)` → `"1024 KB"`, `formatBytes(Infinity)`, `decimals > 100` 예외
- `safeDeepClone` 이 `Map` / `Set` / TypedArray 를 사용 불가능한 객체로 복제하던 문제
- `debounce` 에 함수가 아닌 값을 넘기면 타이머 안에서 뒤늦게 예외가 나던 문제, 잘못된 `delay` 처리

### 보안 (Security)
- `isSafeURL`: 탭/개행/제어문자 삽입(`/\t/evil.com`) Open Redirect 우회 차단, 백슬래시·앞뒤 공백 거부, 자격증명 URL(`user:pass@host`) 거부, 문자열 `allowedProtocols` 부분일치 우회 차단, `javascript:` 등 위험 스킴은 허용 목록에 넣어도 항상 차단
- `safeJSONParse`: 유니코드 이스케이프로 위장한 `__proto__` 키 제거, 입력 길이 제한(기본 5MB)
- `safeDeepClone`: getter 미실행, setter 우회(`defineProperty`), 깊이 제한(DoS 방지)
- 공개 API `Object.freeze` 및 내장 함수 사전 캡처

### 변경 (Changed)
- 위험 키 규칙 정밀화: `__proto__` 는 항상 제거, `constructor` / `prototype` 은 **값이 객체·함수일 때만** 제거. 원시값(`{"constructor":"Acme"}`)은 정상 데이터로 유지. (취약한 병합 유틸 3종 × 대상 2종 실험에서 오염 0건 확인)
- `safeDeepClone` 의 두 번째 인자가 `WeakMap` 에서 `maxDepth` 로 변경
- `escapeHTML`: 숫자·불리언·bigint 는 문자열로 변환, 그 외는 `''`

### 추가 (Added)
- 네이티브 ESM 빌드 `dist/easy-secure-utils.mjs` (UMD 는 `dist/easy-secure-utils.js`), TypeScript 선언(`types/`), `package.json` `exports`
- `escapeAttribute`, `isSafeURL` 옵션(`allowedHosts`, `allowRelative`), `debounce` `leading` 옵션
- 테스트 스위트(`npm test`), GitHub Actions CI
