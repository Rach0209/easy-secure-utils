// browser-check.html 의 ESM 점검. 네이티브 ESM 을 지원하는 http(s) 환경에서만 로드됩니다.
import * as E from '../dist/easy-secure-utils.mjs';

try {
  const names = Object.keys(E);
  const problems = [];
  if (names.length !== 15) problems.push('export 개수 ' + names.length + ' (기대 15)');
  if (String(E.html`<p>${'<'}</p>`) !== '<p>&lt;</p>') problems.push('html 결과 불일치');
  if (E.isSafeURL('javascript:alert(1)') !== false) problems.push('isSafeURL 이 javascript: 를 통과시킴');
  if (typeof E.randomToken(8) !== 'string') problems.push('randomToken');
  window.__reportEsm(problems.length === 0, problems.join('; '));
} catch (e) {
  window.__reportEsm(false, String(e));
}
