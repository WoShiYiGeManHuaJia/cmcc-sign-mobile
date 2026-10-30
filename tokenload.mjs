// 凭证解析：接受裸 App 票据 / 整个 appTokenLogin 请求体 JSON / 混杂文本
import fs from 'fs';

export function loadToken(input) {
  let raw = String(input || '');
  try { if (fs.existsSync(raw.trim())) raw = fs.readFileSync(raw.trim(), 'utf8'); } catch {}
  raw = raw.trim();
  if (!raw) return null;
  const out = { token: '', provinceCode: '', cityCode: '', source: '' };
  try {
    const j = JSON.parse(raw);
    if (j && typeof j === 'object' && j.token) {
      out.token = String(j.token).trim();
      out.provinceCode = j.provinceCode || '';
      out.cityCode = j.cityCode || '';
      out.source = 'JSON 请求体';
      return out;
    }
  } catch {}
  let m = raw.match(/"token"\s*:\s*"([^"]+)"/);
  if (m) {
    out.token = m[1].trim();
    const p = raw.match(/"provinceCode"\s*:\s*"?([^",}]+)"?/);
    const c = raw.match(/"cityCode"\s*:\s*"?([^",}]+)"?/);
    out.provinceCode = p ? p[1].trim() : '';
    out.cityCode = c ? c[1].trim() : '';
    out.source = '文本中的 token 字段';
    return out;
  }
  m = raw.match(/JSESSIONID=[^"'\n\r]+/);
  if (m) { out.token = m[0].trim().replace(/[;,]\s*$/, ''); out.source = '文本中的 JSESSIONID 串'; return out; }
  out.token = raw.replace(/^["'`]+/, '').replace(/["'`]+$/, '').trim();
  out.source = '裸 token';
  return out;
}
