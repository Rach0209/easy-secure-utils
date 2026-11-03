'use strict';
/**
 * src/easy-secure-utils.mjs (단일 소스) → dist/easy-secure-utils.mjs (ESM) + dist/easy-secure-utils.js (UMD)
 * 의존성 없는 Node 스크립트입니다.  사용: npm run build
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src', 'easy-secure-utils.mjs');
const DIST = path.join(ROOT, 'dist');

function build() {
  const src = fs.readFileSync(SRC, 'utf8').replace(/\r\n/g, '\n');

  const exportMatch = src.match(/^export \{([^}]*)\};\s*$/m);
  if (!exportMatch) throw new Error('build: final `export { ... };` statement not found');
  const names = exportMatch[1].split(',').map((s) => s.trim()).filter(Boolean);

  const bannerMatch = src.match(/^(\/\*\*[\s\S]*?\*\/)\n/);
  if (!bannerMatch) throw new Error('build: leading /** banner */ not found');

  const code = src.slice(bannerMatch[0].length, exportMatch.index).trim();
  if (/^\s*(import|export)\s/m.test(code)) throw new Error('build: unexpected import/export in module body');

  const indented = code.split('\n').map((line) => (line ? '  ' + line : line)).join('\n');
  const assignments = names.map((n) => `  exports.${n} = ${n};`).join('\n');

  const umd = [
    bannerMatch[1],
    '(function (global, factory) {',
    "  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :",
    "  typeof define === 'function' && define.amd ? define(['exports'], factory) :",
    "  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.SecureWebUtils = {}));",
    '})(this, (function (exports) {',
    "  'use strict';",
    '',
    indented,
    '',
    assignments,
    '',
    "  Object.defineProperty(exports, '__esModule', { value: true });",
    '  Object.freeze(exports); // 로드 후 API 덮어쓰기(monkey-patching) 방지',
    '}));',
    ''
  ].join('\n');

  return { umd, esm: src, names };
}

module.exports = { build };

if (require.main === module) {
  const { umd, esm } = build();
  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(path.join(DIST, 'easy-secure-utils.js'), umd);
  fs.writeFileSync(path.join(DIST, 'easy-secure-utils.mjs'), esm);
  console.log('built dist/easy-secure-utils.js (UMD) and dist/easy-secure-utils.mjs (ESM)');
}
