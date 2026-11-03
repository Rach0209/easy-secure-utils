/**
 * SecureWebUtils v1.0.0 type declarations
 */

/** HTML 텍스트 노드 / 따옴표로 감싼 속성값용 인코딩. string·number·boolean·bigint 외에는 '' 반환. */
export function escapeHTML(str: unknown): string;

/** 속성값 전용 엄격 인코딩 (영숫자와 `, . _ -` 외 전부 &#xHH; 로 변환). */
export function escapeAttribute(value: unknown): string;

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

/** 바이트를 'KB', 'MB' ... 'PB' 단위 문자열로 변환. */
export function formatBytes(bytes: unknown, decimals?: number): string;

export interface DebounceOptions {
  /** true 면 첫 호출을 즉시 실행하고 delay 동안의 이후 호출은 무시 */
  leading?: boolean;
}

export interface Debounced<A extends unknown[], R> {
  (this: unknown, ...args: A): R | undefined;
  cancel(): void;
}

export function debounce<A extends unknown[], R>(
  fn: (this: any, ...args: A) => R,
  delay?: number,
  options?: DebounceOptions
): Debounced<A, R>;

/** <script> 태그로 로드했을 때의 전역 이름 */
export as namespace SecureWebUtils;
