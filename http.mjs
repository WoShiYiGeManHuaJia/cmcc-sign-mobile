// 极简 HTTP 封装（Node 内置 fetch，无第三方依赖）
export const UA_APP = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148/wkwebview leaddon/12.5.4/CMCCIT';

export async function httpGet(url, headers = {}) {
  const r = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': UA_APP, ...headers } });
  const body = await r.text();
  let cookies = [];
  try { cookies = r.headers.getSetCookie ? r.headers.getSetCookie() : []; } catch { cookies = []; }
  return { status: r.status, headers: r.headers, cookies, body, location: r.headers.get('location') || '' };
}

export async function httpPost(url, headers = {}, body = '') {
  const r = await fetch(url, { method: 'POST', redirect: 'manual', headers: { 'User-Agent': UA_APP, ...headers }, body });
  const txt = await r.text();
  let cookies = [];
  try { cookies = r.headers.getSetCookie ? r.headers.getSetCookie() : []; } catch { cookies = []; }
  return { status: r.status, headers: r.headers, cookies, body: txt };
}
