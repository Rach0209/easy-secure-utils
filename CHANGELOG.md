# Changelog

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
