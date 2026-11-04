# 보안 정책 (Security Policy)

## 지원 버전

| 버전 | 보안 수정 |
|---|---|
| 최신 릴리스 (`1.x`) | ✅ |
| 이전 버전 | ❌ 최신 버전으로 업데이트해 주세요 |

## 취약점 신고

이 라이브러리는 보안을 목적으로 하므로, 우회 방법이나 취약점을 발견하셨다면 **공개 이슈로 올리지 말고** 비공개로 알려주세요.

1. GitHub 저장소의 **Security** 탭 → **Report a vulnerability** (Private vulnerability reporting)를 사용합니다.
2. 아래 내용을 포함해 주세요.
   - 영향을 받는 함수와 버전 (`html`, `isSafeURL`, `safeJSONParse` 등)
   - 재현 가능한 최소 코드 (입력값과 기대 결과 / 실제 결과)
   - 가능하면 사용한 브라우저/Node.js 버전

확인 후 수정 버전을 릴리스하고, 신고자 동의 하에 `CHANGELOG.md` 에 크레딧을 남깁니다.

## 이 정책이 다루는 범위

**범위 안:**
- 문서에 "막는다"고 적힌 보호가 우회되는 경우 (예: `isSafeURL` 이 위험 URL 을 통과시킴, `html` 템플릿이 허용 문맥에서 스크립트 주입을 허용함, `safeJSONParse`/`safeMerge` 후 `Object.prototype` 오염)
- 입력만으로 라이브러리를 멈추게 하는 경우 (스택 오버플로, 과도한 CPU/메모리 사용)

**범위 밖 (README 의 "보안 모델과 한계" 참고):**
- 이미 스크립트가 실행되는 환경(XSS 성립 후)에서의 공격
- 지원하지 않는 문맥에 함수를 잘못 사용한 경우 (예: `escapeHTML` 결과를 `<script>` 안이나 `onclick` 에 삽입)
- 서버 측 검증 부재로 인한 문제
- 사용자가 `unsafeHTML` 로 명시적으로 신뢰 표시한 값 안의 악성 콘텐츠

## 무결성 확인 (공급망)

릴리스 파일의 SRI 해시는 `dist/integrity.json` 과 GitHub Releases 에 함께 게시됩니다. CDN 으로 로드할 때는 `integrity` 속성으로 고정하세요.
