import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const umd = require('../dist/easy-secure-utils.js');
const esm = await import('../dist/easy-secure-utils.mjs');

// 공격 페이로드 모음 (정규식/속성 탈출/태그 주입/URL 우회 등)
const PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "' onmouseover='alert(1)",
  ' onfocus=alert(1) autofocus ',
  'x onmouseover=alert(1)',
  'javascript:alert(1)',
  'JaVaScRiPt:alert(1)',
  '</textarea><script>alert(1)</script>',
  '</title><script>alert(1)</script>',
  '--><img src=x onerror=1>',
  '&#x3C;script&#x3E;',
  '%3Cscript%3E',
  '`onmouseover=alert(1)`',
  'a\tb\nc\rd',
  '//evil.com/x',
  'data:text/html,<script>alert(1)</script>',
  '\x00<script>',
  '= / > < " \' ` & ;',
  'a'.repeat(5000)
];

for (const [fmt, U] of [['umd', umd], ['esm', esm]]) {
  const { html, unsafeHTML, isSafeHTML, escapeHTML, isSafeURL } = U;
  const T = (name, fn) => test(`[${fmt}] html: ${name}`, fn);
  const str = (v) => String(v);

  T('텍스트 문맥은 HTML 인코딩', () => {
    assert.equal(str(html`<p>${'<b>&"\''}</p>`), '<p>&lt;b&gt;&amp;&quot;&#39;</p>');
    assert.equal(str(html`<i>${0}${5n}${true}</i>`), '<i>05true</i>');
    assert.equal(str(html`<i>${null}${undefined}${false}</i>`), '<i></i>');
    assert.equal(str(html`<i>${{ toString() { return '<x>'; } }}${() => 1}${Symbol('s')}</i>`), '<i></i>');
  });

  T('따옴표 속성(", \')은 HTML 인코딩', () => {
    assert.equal(str(html`<a title="${'" onmouseover="x'}">`), '<a title="&quot; onmouseover=&quot;x">');
    assert.equal(str(html`<a title='${"' x='"}'>`), "<a title='&#39; x=&#39;'>");
    assert.equal(str(html`<div class="${['a', 'b<', null, 3]}">`), '<div class="a b&lt;  3">');
    assert.equal(str(html`<input value="${''}" class="c">`), '<input value="" class="c">'); // 빈 값도 구조 유지
  });

  T('따옴표 없는 속성 값의 보간은 데이터와 무관하게 Error (빈 값이 다음 속성을 삼키는 문제 방지)', () => {
    assert.throws(() => html`<input value=${'a'} class="c">`, /따옴표/);
    assert.throws(() => html`<input value=${''} class="c">`, /따옴표/);
    assert.throws(() => html`<div data-x=a${'b'}>`, /따옴표/);
    assert.throws(() => html`<a href=${'https://e.com'}>`, /따옴표/);
    assert.throws(() => html`<a title= ${'x'}>`, /따옴표/);
    // 보간 없는 정적 따옴표 없는 속성은 문제 없음
    assert.equal(str(html`<input data-z=1 value="${'v'}">`), '<input data-z=1 value="v">');
  });

  T('URL 속성: 값 전체 보간은 sanitizeURL, 고정 문자열 뒤 보간은 encodeURIComponent', () => {
    assert.equal(str(html`<a href="${'https://example.com/a?b=1&c=2'}">`), '<a href="https://example.com/a?b=1&amp;c=2">');
    assert.equal(str(html`<a href="${'javascript:alert(1)'}">`), '<a href="#">');
    assert.equal(str(html`<a href="${'//evil.com'}">`), '<a href="#">');
    assert.equal(str(html`<a href="${''}">`), '<a href="#">');
    assert.equal(str(html`<a href="/u/${'a/b c'}?q=${'1&2'}">`), '<a href="/u/a%2Fb%20c?q=1%262">');
    assert.equal(str(html`<a href="/${'/evil.com'}">`), '<a href="/%2Fevil.com">'); // "//evil.com" 으로 합쳐지지 않음
    assert.equal(str(html`<a href="${'https://x.com/'}${'p q'}">`), '<a href="https://x.com/p%20q">');
    assert.equal(str(html`<a href='${'javascript:1'}'>`), '<a href=\'#\'>');
    assert.equal(str(html`<A HREF="${'javascript:1'}">`), '<A HREF="#">');
    assert.equal(str(html`<form action="${'javascript:1'}">`), '<form action="#">');
    assert.equal(str(html`<svg><use xlink:href="${'javascript:1'}"/></svg>`), '<svg><use xlink:href="#"/></svg>');
    assert.equal(str(html`<a href="/x/${'\ud800'}">`), '<a href="/x/">'); // 짝 없는 서로게이트 → URIError 대신 빈 문자열
  });

  T('중첩 html``·배열은 이중 인코딩 없이 삽입, 속성 안에서는 일반 문자열로 인코딩', () => {
    assert.equal(str(html`<ul>${[1, 2].map((i) => html`<li>${i}</li>`)}</ul>`), '<ul><li>1</li><li>2</li></ul>');
    assert.equal(str(html`<p>${html`<i>${'<'}</i>`}</p>`), '<p><i>&lt;</i></p>');
    assert.equal(str(html`<p>${[]}${[[], [html`<b>x</b>`]]}</p>`), '<p><b>x</b></p>');
    assert.equal(str(html`<a title="${html`<b>`}">`), '<a title="&lt;b&gt;">');
    assert.equal(str(html`<p>${unsafeHTML('<b>ok</b>')}</p>`), '<p><b>ok</b></p>');
    assert.throws(() => unsafeHTML(5), TypeError);
  });

  T('SafeHTML 은 위조할 수 없다', () => {
    const fake = { toString() { return '<script>alert(1)</script>'; } };
    assert.equal(isSafeHTML(fake), false);
    assert.equal(str(html`<p>${fake}</p>`), '<p></p>');
    const spoof = Object.create(Object.getPrototypeOf(html`x`));
    assert.equal(isSafeHTML(spoof), false);
    assert.equal(str(spoof), '');
    assert.equal(str(html`<p>${spoof}</p>`), '<p></p>');
    for (const v of [null, undefined, 'x', 1, {}, []]) assert.equal(isSafeHTML(v), false);
    // JSON 등 "데이터"로 만든 객체는 어떤 키를 써도 SafeHTML 이 될 수 없다
    for (const json of ['{"value":"<script>"}', '{"__proto__":{"value":"x"}}', '{"toString":"x","safe":true,"html":"<b>"}']) {
      assert.equal(isSafeHTML(JSON.parse(json)), false);
      assert.equal(str(html`<p>${JSON.parse(json)}</p>`), '<p></p>');
    }
    // 실제 인스턴스의 constructor 로 새 인스턴스를 만들 수 없다
    const forged = new (html`x`.constructor)('<script>alert(1)</script>');
    assert.equal(isSafeHTML(forged), false);
    assert.equal(str(html`<p>${forged}</p>`), '<p></p>');
    assert.throws(() => { html`x`.constructor = Object; }, TypeError); // 동결된 인스턴스
    const real = html`<b>x</b>`;
    assert.equal(isSafeHTML(real), true);
    assert.equal(Object.isFrozen(real), true);
    assert.equal(Object.isFrozen(Object.getPrototypeOf(real)), true);
    assert.equal('value' in real, false); // 내부 문자열이 속성으로 노출되지 않음
  });

  T('textarea/title 본문은 엄격 인코딩(보간 허용), 닫는 태그로 탈출 불가', () => {
    const out = str(html`<textarea>${'</textarea><script>alert(1)</script>'}</textarea>`);
    assert.equal(out.split('<').length - 1, 2); // 정적 <textarea>, </textarea> 만 남음
    assert.equal(str(html`<title>${'a b'}</title>`), '<title>a&#x20;b</title>');
  });

  T('허용되지 않는 위치의 보간은 데이터와 무관하게 Error', () => {
    const x = 'ok'; // 무해한 값으로도 던져야 한다 (데이터 의존 예외 금지)
    const cases = {
      'on* 속성(따옴표 없음)': () => html`<img onerror=${x}>`,
      'on* 속성(큰따옴표)': () => html`<a onclick="${x}">`,
      'on* 속성(대문자·작은따옴표)': () => html`<a ONCLICK='${x}'>`,
      'style 속성': () => html`<div style="${x}">`,
      'srcdoc 속성': () => html`<iframe srcdoc="${x}"></iframe>`,
      'srcset 속성': () => html`<img srcset="${x}">`,
      'script 본문': () => html`<script>${x}</script>`,
      'script 본문(대문자)': () => html`<SCRIPT>${x}</SCRIPT>`,
      'style 본문': () => html`<style>${x}</style>`,
      'noscript 본문': () => html`<noscript>${x}</noscript>`,
      'xmp 본문': () => html`<xmp>${x}</xmp>`,
      'iframe 본문': () => html`<iframe>${x}</iframe>`,
      'script src': () => html`<script src="${x}"></script>`,
      'link href': () => html`<link href="${x}">`,
      'iframe src': () => html`<iframe src="${x}"></iframe>`,
      'meta content': () => html`<meta content="${x}">`,
      'object data': () => html`<object data="${x}"></object>`,
      'base href': () => html`<base href="${x}">`,
      '태그 이름': () => html`<${x}>`,
      '태그 이름 일부': () => html`<a${x}>`,
      '닫는 태그': () => html`</${x}>`,
      '속성 이름 위치': () => html`<div ${x}>`,
      '기존 속성 뒤': () => html`<div class="a" ${x}>`,
      '속성 이름 자체': () => html`<div ${x}="v">`,
      '따옴표 없는 값 뒤': () => html`<div data-x=1 ${x}>`,
      'URL 속성 뒤': () => html`<a href=${x} ${x}>`,
      '주석': () => html`<!-- ${x} -->`,
      '--!> 로 끝나는 주석(보수적 판정)': () => html`<!-- a --!> <p>${x}</p>`,
      '<! 선언': () => html`<!${x}>`,
      '<? 처리 명령': () => html`<?${x}>`,
      'CDATA': () => html`<![CDATA[${x}]]>`,
      '이중 이스케이프된 script(보수적 판정)': () => html`<script><!-- </script><p>${x}</p>`,
      'noscript 안의 태그': () => html`<noscript><p>${x}</p></noscript>`,
      "'<' 직후 보간": () => html`a<${x}`
    };
    for (const [name, fn] of Object.entries(cases)) {
      assert.throws(fn, (e) => e instanceof Error && !(e instanceof TypeError), name);
    }
  });

  T('올바르게 닫힌 뒤에는 다시 보간 가능, 정적 마크업을 올바르게 해석', () => {
    const x = '<i>';
    assert.equal(str(html`<script>var a = 1;</script><p>${x}</p>`), '<script>var a = 1;</script><p>&lt;i&gt;</p>');
    assert.equal(str(html`<style>p{}</style><p>${x}</p>`), '<style>p{}</style><p>&lt;i&gt;</p>');
    assert.equal(str(html`<SCRIPT>1</SCRIPT ><p>${x}</p>`), '<SCRIPT>1</SCRIPT ><p>&lt;i&gt;</p>');
    assert.equal(str(html`<a title=">" href="${'https://e.com'}">`), '<a title=">" href="https://e.com">');
    assert.equal(str(html`<div title='a"b' class="${x}">`), '<div title=\'a"b\' class="&lt;i&gt;">');
    assert.equal(str(html`<!-- " ' --><b title="${x}">`), '<!-- " \' --><b title="&lt;i&gt;">');
    assert.equal(str(html`<!DOCTYPE html><p>${x}</p>`), '<!DOCTYPE html><p>&lt;i&gt;</p>');
    assert.equal(str(html`<br/><img src="a.png"/><p>${x}</p>`), '<br/><img src="a.png"/><p>&lt;i&gt;</p>');
    assert.equal(str(html`1 < 2 <p>${x}</p>`), '1 < 2 <p>&lt;i&gt;</p>');
    assert.equal(str(html`<input disabled value="a" data-x="${'y'}" title='t'>`), '<input disabled value="a" data-x="y" title=\'t\'>');
  });

  T('공격 페이로드 코퍼스: 모든 안전 문맥에서 구조가 깨지지 않는다', () => {
    for (const p of PAYLOADS) {
      const label = JSON.stringify(p.slice(0, 40));
      const text = str(html`<p>${p}</p>`);
      assert.ok(!/[<>]/.test(text.slice(3, -4)), 'text ' + label);

      const dq = str(html`<a title="${p}">`);
      assert.ok(!/"/.test(dq.slice(10, -2)), 'dq ' + label);

      const sq = str(html`<a title='${p}'>`);
      assert.ok(!/'/.test(sq.slice(10, -2)), 'sq ' + label);

      const href = str(html`<a href="${p}">`).slice(9, -2);
      assert.equal(href, isSafeURL(p) ? escapeHTML(p) : '#', 'href ' + label);

      const mid = str(html`<a href="/p/${p}">`).slice(12, -2);
      assert.match(mid, /^[A-Za-z0-9\-_.!~*'()%&#;]*$/, 'href-mid ' + label);
      assert.ok(!mid.includes('/') && !mid.includes('"'), 'href-mid-slash ' + label);

      const area = str(html`<textarea>${p}</textarea>`).slice(10, -11);
      assert.match(area, /^[A-Za-z0-9,._\-&#;]*$/, 'textarea ' + label);
    }
  });

  T('올바른 사용 방법 강제: 태그드 템플릿이 아니면 TypeError', () => {
    assert.throws(() => html('<b>' + '<script>'), TypeError);
    assert.throws(() => html(['a', 'b'], 'x'), TypeError);
    assert.throws(() => html(null), TypeError);
    // .raw 를 갖췄지만 동결되지 않은(= 런타임에 만든) 배열은 템플릿 리터럴이 아니므로 거부
    const fake = ['<b>', '</b>'];
    fake.raw = fake.slice();
    assert.throws(() => html(fake, 'x'), TypeError);
    assert.throws(() => html`\xZ`, TypeError); // 잘못된 이스케이프(cooked 가 undefined)
  });

  T('같은 호출 지점을 반복 호출해도(분석 캐시) 항상 올바르게 인코딩', () => {
    const render = (v) => html`<p title="${v}">${v}</p>`;
    for (let i = 0; i < 5; i++) {
      assert.equal(str(render('<' + i)), `<p title="&lt;${i}">&lt;${i}</p>`);
    }
    assert.equal(str(render('"')), '<p title="&quot;">&quot;</p>');
  });

  T('정적 템플릿(보간 없음)과 배열 중첩 깊이 제한', () => {
    assert.equal(str(html`<b>static "text" & stuff</b>`), '<b>static "text" & stuff</b>');
    let deep = 'x';
    for (let i = 0; i < 100; i++) deep = [deep];
    assert.throws(() => html`<p>${deep}</p>`, RangeError);
    assert.throws(() => html`<p title="${deep}"></p>`, RangeError);
    let ok = 'x';
    for (let i = 0; i < 10; i++) ok = [ok];
    assert.equal(str(html`<p>${ok}</p>`), '<p>x</p>');
  });

  T('el.innerHTML 에 바로 대입 가능한 문자열 변환(toString/템플릿 리터럴)', () => {
    const v = html`<b>${'<'}</b>`;
    assert.equal('' + v, '<b>&lt;</b>');
    assert.equal(`${v}`, '<b>&lt;</b>');
    assert.equal(v.toString(), '<b>&lt;</b>');
  });
}
