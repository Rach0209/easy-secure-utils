import { escapeHTML, isSafeURL, safeJSONParse, formatBytes } from '../dist/easy-secure-utils.mjs';

const lines = [
  'escapeHTML:    ' + escapeHTML('<img src=x onerror=alert(1)>'),
  'isSafeURL(javascript:...): ' + isSafeURL('javascript:alert(1)'),
  'isSafeURL(https://example.com): ' + isSafeURL('https://example.com'),
  'safeJSONParse: ' + JSON.stringify(safeJSONParse('{"user":"kim","__proto__":{"isAdmin":true}}')),
  'formatBytes(1048575): ' + formatBytes(1048575)
];
document.getElementById('out').textContent = lines.join('\n');
