// 타입 선언(.d.ts)을 실제 TypeScript 컴파일러로 검증하기 위한 파일입니다 (npm run typecheck). 실행되지 않습니다.
import {
  escapeHTML, escapeAttribute, escapeRegExp, html, unsafeHTML, isSafeHTML, isSafeURL, sanitizeURL,
  safeJSONParse, safeDeepClone, safeMerge, formatBytes, debounce, throttle, randomToken,
  type SafeHTML, type IsSafeURLOptions, type Debounced
} from '../types/easy-secure-utils';

const s: string = escapeHTML('<b>') + escapeAttribute(1) + escapeRegExp('a.b');

const fragment: SafeHTML = html`<p title="${s}">${['a', 1, null]}</p>`;
const text: string = fragment.toString();
const wrapped: SafeHTML = unsafeHTML('<b>trusted</b>');
const maybe: unknown = fragment;
if (isSafeHTML(maybe)) {
  const narrowed: SafeHTML = maybe;
  void narrowed;
}

const opts: IsSafeURLOptions = { allowedHosts: ['example.com'], allowRelative: false };
const ok: boolean = isSafeURL('https://example.com', ['https:'], opts);
const href: string = sanitizeURL('javascript:1');
const href2: string = sanitizeURL('x', '/home', undefined, opts);

const parsed = safeJSONParse<{ a: number }>('{"a":1}');
const a: number | null = parsed === null ? null : parsed.a;
const parsedWithFallback = safeJSONParse<{ a: number }, string>('{', 'FB');
const fbOrObj: { a: number } | string = parsedWithFallback;

const cloned: { x: number[] } = safeDeepClone({ x: [1, 2] }, 50);
const merged: { a: number } & { b: number } = safeMerge({ a: 1 } as { a: number } & { b: number }, { b: 2 }, null);
const size: string = formatBytes(1536, 1);

const d: Debounced<[string, number], void> = debounce((x: string, n: number) => { void x; void n; }, 100, { leading: true });
d('a', 1);
d.cancel();
d.flush();
const t = throttle((n: number) => n * 2, 100, { trailing: false });
const doubled: number | undefined = t(2);

const token: string = randomToken(16, 'base64url') + randomToken();

// @ts-expect-error html 은 태그드 템플릿으로만 호출할 수 있다
html('plain string');
// @ts-expect-error encoding 은 'hex' | 'base64url' 만 허용
randomToken(8, 'base32');
// @ts-expect-error bytes 는 number
randomToken('8');
// @ts-expect-error unsafeHTML 은 문자열만 받는다
unsafeHTML(123);

void [text, wrapped, ok, href, href2, a, fbOrObj, cloned, merged, size, doubled, token];
