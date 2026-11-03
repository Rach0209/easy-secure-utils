(function () {
  'use strict';

  if (typeof SecureWebUtils === 'undefined') {
    document.getElementById('loadError').style.display = 'block';
    return;
  }

  const { escapeHTML, debounce, formatBytes, isSafeURL, safeJSONParse } = SecureWebUtils;
  const $ = (id) => document.getElementById(id);
  const INVALID_JSON = Symbol('invalid-json');

  // 1. XSS 방지: innerHTML 에는 반드시 escapeHTML 결과만 넣는다 (textContent 는 그 자체로 안전)
  const xssOutput = $('xssOutput');
  const xssEncoded = $('xssEncoded');
  $('xssInput').addEventListener('input', (e) => {
    const value = e.target.value;
    xssOutput.innerHTML = '[innerHTML 렌더링]: ' + escapeHTML(value);
    xssEncoded.textContent = '[인코딩된 원문]: ' + escapeHTML(value);
  });

  // 2. 디바운스 검색: textContent 는 자동으로 이스케이프되므로 값에 escapeHTML 을 중복 적용하지 않는다
  const searchOutput = $('searchOutput');
  const handleSearch = debounce((query) => {
    if (!query.trim()) {
      searchOutput.textContent = '대기 중...';
      return;
    }
    searchOutput.textContent = '[API Request Sent] 검색어: "' + query + '" (' + new Date().toLocaleTimeString() + ')';
  }, 300);
  $('searchInput').addEventListener('input', (e) => handleSearch(e.target.value));

  // 3. 파일 용량 변환
  const fileOutput = $('fileOutput');
  $('fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      fileOutput.textContent = '파일명: ' + file.name + '\n용량: ' + formatBytes(file.size);
    }
  });

  // 4. URL 검증: 안전할 때만 href 를 설정한다
  const urlOutput = $('urlOutput');
  $('urlInput').addEventListener('input', (e) => {
    const value = e.target.value;
    urlOutput.textContent = '';
    if (!value) {
      urlOutput.className = 'result';
      urlOutput.textContent = 'URL 을 입력하세요.';
      return;
    }
    if (isSafeURL(value)) {
      urlOutput.className = 'result ok';
      const a = document.createElement('a');
      a.href = value;
      a.textContent = value;
      a.rel = 'noopener noreferrer';
      a.target = '_blank';
      urlOutput.append('✅ 안전한 URL: ', a);
    } else {
      urlOutput.className = 'result bad';
      urlOutput.textContent = '⛔ 차단됨: ' + JSON.stringify(value);
    }
  });

  // 5. JSON 파싱
  const jsonOutput = $('jsonOutput');
  $('jsonInput').addEventListener('input', (e) => {
    // fallback 에 undefined 를 넘기면 기본값(null)이 적용되므로 고유 센티널을 사용한다
    const parsed = safeJSONParse(e.target.value, INVALID_JSON);
    if (parsed === INVALID_JSON) {
      jsonOutput.textContent = '유효하지 않은 JSON 입니다.';
      return;
    }
    jsonOutput.textContent =
      '파싱 결과: ' + JSON.stringify(parsed) +
      '\n({}).isAdmin (오염 여부): ' + String(({}).isAdmin);
  });
  $('jsonInput').dispatchEvent(new Event('input'));
})();
