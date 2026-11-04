/**
 * easy-secure-utils v1.1.0 type declarations
 */

/** html`` 가 만든(또는 unsafeHTML 로 명시한) "이미 안전한 HTML". toString() 으로 문자열을 얻습니다. */
export interface SafeHTML {
  /** 타입 구분용 표식 (런타임에는 존재하지 않음) */
  readonly __brand: 'SafeHTML';
  toString(): string;
}

// ---------------------------------------------------------------------------
// XSS / 인코딩
// ---------------------------------------------------------------------------

/** HTML 텍스트 노드 / 따옴표로 감싼 속성값용 인코딩. string·number·boolean·bigint 외에는 '' 반환. */
export function escapeHTML(str: unknown): string;

/** 속성값 전용 엄격 인코딩 (영숫자와 `, . _ -` 외 전부 &#xHH; 로 변환). */
export function escapeAttribute(value: unknown): string;

/** 사용자 입력을 정규식 안에 문자 그대로 넣을 수 있도록 특수문자를 이스케이프. */
export function escapeRegExp(str: unknown): string;

/**
 * 보간(${})을 위치(텍스트/속성/URL 속성)에 맞게 자동 이스케이프하는 태그드 템플릿.
 * 허용되지 않는 위치(on* 속성, 따옴표 없는 속성값, <script> 본문, 태그·속성 이름, 주석 등)의 보간은
 * 데이터와 무관하게 Error 를 던집니다. 속성값은 항상 따옴표로 감싸세요: title="${v}"
 */
export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHTML;

/** 이스케이프 없이 삽입할 "신뢰할 수 있는" HTML 문자열을 표시 (명시적 탈출구, 사용자 입력 금지). */
export function unsafeHTML(text: string): SafeHTML;

/** html`` / unsafeHTML 이 만든 값인지 확인. */
export function isSafeHTML(value: unknown): value is SafeHTML;

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

export interface IsSafeURLOptions {
  /** false 면 상대 URL(`/path`, `?q`, `#h` 등)도 거부. 기본 true */
  allowRelative?: boolean;
  /** 지정 시 http(s) 절대 URL 은 이 호스트(소문자, 정확히 일치)만 허용 */
  allowedHosts?: readonly string[];
}

/** URL 안전성 검증 (fail-closed). allowedProtocols 는 'https:' 처럼 소문자 + 콜론 형식의 배열. */
export function isSafeURL(
  url: unknown,
  allowedProtocols?: readonly string[],
  options?: IsSafeURLOptions
): boolean;

/** 안전하면 url 그대로, 아니면 fallback(기본 '#') 반환. */
export function sanitizeURL(
  url: unknown,
  fallback?: string,
  allowedProtocols?: readonly string[],
  options?: IsSafeURLOptions
): string;

// ---------------------------------------------------------------------------
// Prototype Pollution 방지
// ---------------------------------------------------------------------------

/**
 * Prototype Pollution 키를 제거하며 JSON 파싱. 실패·길이 초과·비문자열 입력이면 fallback 반환.
 * (fallback 에 undefined 를 넘기면 기본값 null 이 적용됩니다)
 */
export function safeJSONParse<T = unknown, F = null>(
  text: unknown,
  fallback?: F,
  maxLength?: number
): T | F;

/** 순환 참조 안전 / getter 미실행 / 위험 키 제거 Deep Clone. 깊이 초과 시 RangeError. */
export function safeDeepClone<T>(obj: T, maxDepth?: number): T;

/**
 * Prototype Pollution 에 안전한 깊은 병합. target 을 변경하고 반환합니다 (Object.assign 과 동일).
 * 원본을 보존하려면 safeMerge({}, a, b) 로 사용하세요.
 */
export function safeMerge<T extends object>(target: T, ...sources: unknown[]): T;

// ---------------------------------------------------------------------------
// 유틸리티
// ---------------------------------------------------------------------------

/** 바이트를 'KB', 'MB' ... 'PB' 단위 문자열로 변환. */
export function formatBytes(bytes: unknown, decimals?: number): string;

export interface DebounceOptions {
  /** true 면 첫 호출을 즉시 실행하고 delay 동안의 이후 호출은 무시 */
  leading?: boolean;
}

export interface ThrottleOptions {
  /** 구간의 첫 호출을 즉시 실행. 기본 true */
  leading?: boolean;
  /** 구간 중 마지막 호출을 구간 끝에 실행. 기본 true (leading 과 동시에 false 는 불가) */
  trailing?: boolean;
}

export interface Debounced<A extends unknown[], R> {
  (this: unknown, ...args: A): R | undefined;
  /** 대기 중인 호출 취소 */
  cancel(): void;
  /** 대기 중인 호출을 지금 즉시 실행 */
  flush(): void;
}

export function debounce<A extends unknown[], R>(
  fn: (this: any, ...args: A) => R,
  delay?: number,
  options?: DebounceOptions
): Debounced<A, R>;

export function throttle<A extends unknown[], R>(
  fn: (this: any, ...args: A) => R,
  wait?: number,
  options?: ThrottleOptions
): Debounced<A, R>;

/**
 * crypto.getRandomValues 기반 난수 토큰 (안전한 난수원이 없으면 Error).
 * bytes: 1~1024 (기본 32), encoding: 'hex'(길이 bytes*2) | 'base64url'(패딩 없음)
 */
export function randomToken(bytes?: number, encoding?: 'hex' | 'base64url'): string;

/** <script> 태그로 로드했을 때의 전역 이름 */
export as namespace SecureWebUtils;
