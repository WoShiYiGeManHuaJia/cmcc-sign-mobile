#!/usr/bin/env node
// 中国移动 10086「App 通道」每日签到（mark31/domark）
// 流程：取 sid → appTokenLogin 换 app 会话 → mark31 只读 → 未签才 domark → 回读 markstatus/markRecord 确认 status=1
//
// 环境变量（GitHub Actions secrets，详见 README）：
//   CMCC_JWT            必填  账号级长期凭证（appTokenLogin 签发的 JWT），可自动续期
//   CMCC_APP_TOKEN      可选  App 会话票据（一次性），仅在 jwt 单独续期失败时用作兜底
//   CMCC_SID            可选  固定的一次性登录票据；填上后优先复用它（可复用则长期免登录）
//   CMCC_PHONE          可选  手机号（仅日志展示）
//   CMCC_PROVINCE_CODE  可选  默认 731
//   CMCC_CITY_CODE      可选  默认 1731
//   CMCC_ACT_ID         可选  活动 id，默认 1021122301
//   CMCC_RETRY_BACKOFF  可选  重试退避基数秒，默认 120（SSO 的 sid 下发是间歇性的，实测有约 10 分钟的窗口期返回绑定页）
//   DINGTALK_WEBHOOK    可选  钉钉机器人 webhook（缺省不阻塞签到）
//   DINGTALK_SECRET     可选  钉钉机器人加签密钥
//
// 用法：node daily_sign.mjs [--mode=sign|panel_status|probe|dry-run]
//   sign         实际执行签到（默认）：只读查当日状态 → 已签即跳过 → 未签才签 → 回读确认
//   panel_status 只读：查当日是否已签与本月累计，不签到（面板展示用）
//   probe/dry-run 同 panel_status，仅作诊断
// 本文件是仓库里唯一的签到实现；面板侧 panel_sign.mjs 只做薄封装调用本文件。
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { httpGet, httpPost } from './http.mjs';
import { loadToken } from './tokenload.mjs';

const args = process.argv.slice(2);
const modeArg = (args.find(a => a.startsWith('--mode=')) || '').split('=')[1]
  || (args.includes('--probe') ? 'probe' : (args.includes('--dry-run') ? 'dry-run'
  : (args.includes('--sign') ? 'sign' : (process.env.CMCC_SIGN === '0' ? 'dry-run' : 'sign'))));
const MODE = ['sign', 'panel_status', 'probe', 'dry-run'].includes(modeArg) ? modeArg : 'sign';
const READ_ONLY = MODE !== 'sign';
// 手机号只以脱敏形式出现（172****9953），仓库与日志都不落明文
const maskPhone = (p) => { const s = String(p || '').replace(/\D/g, ''); if (!s) return ''; if (s.length < 7) return s.slice(0, 1) + '****' + s.slice(-1); return s.slice(0, 3) + '****' + s.slice(-4); };
const RETRIES = Number(process.env.CMCC_RETRIES || 6);
const BACKOFF = Number(process.env.CMCC_RETRY_BACKOFF || 120);
const PHONE_MASKED = maskPhone(process.env.CMCC_PHONE || '');
const PROV = process.env.CMCC_PROVINCE_CODE || '731';
const CITY = process.env.CMCC_CITY_CODE || '1731';
const ACT_ID = process.env.CMCC_ACT_ID || '1021122301';
const ACT = `https://wx.10086.cn/qwhdhub/qwhdmark/${ACT_ID}`;
const OUT_DIR = path.resolve('data');
const bjDate = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai' }).format(new Date());
const today = bjDate().replace(/-/g, '');
// —— 每天的登录请求额度：脚本自己数，用满就停，避免把账号越打越限 ——
// 一次尝试 = 1 次取票据 + 1~3 次换票，所以按「HTTP 请求数」计。
const BUDGET = Number(process.env.CMCC_SSO_DAILY_BUDGET || 99999);   // 每天最多 24 次
const LADDER_LIMIT = Number(process.env.CMCC_LADDER_LIMIT || 99999); // 累计超过这个数就不再走满重试阶梯，把额度留给后面的窗口
const MAX_EXCHANGE_PER_DAY = Number(process.env.CMCC_MAX_EXCHANGE_PER_DAY || 2);      // 每天最多换票 2 次（账号级限流下别把账号打废）
const MIN_EXCHANGE_GAP_MIN = Number(process.env.CMCC_MIN_EXCHANGE_GAP_MIN || 120);
const LIMIT_HIT_TTL_H = Number(process.env.CMCC_LIMIT_HIT_TTL_H || 6);   // 命中账号级上限后，隔多久自动解除重试（小时）    // 两次换票之间的最小间隔（分钟）
const counter = { date: bjDate(), used: 0, exchange: 0, lastExchangeAt: 0, limitHit: false, limitHitAt: 0 };
try {
  const j = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'sso_count.json'), 'utf8'));
  if (j && j.date === counter.date) {
    counter.used = Number(j.used || 0);
    counter.exchange = Number(j.exchange || 0);
    counter.lastExchangeAt = Number(j.lastExchangeAt || 0);
    counter.limitHit = !!j.limitHit;
    counter.limitHitAt = Number(j.limitHitAt || 0);
  }
} catch (e) { }
const saveCount = () => { try { fs.mkdirSync(OUT_DIR, { recursive: true }); fs.writeFileSync(path.join(OUT_DIR, 'sso_count.json'), JSON.stringify(counter)); } catch (e) { } };
let budgetOut = false;
async function ssoGet(url, headers) {
  if (counter.used >= BUDGET) { budgetOut = true; return { status: 0, body: '', cookies: [], location: '' }; }
  counter.used++; saveCount();
  return httpGet(url, headers);
}
async function ssoPost(url, headers, body) {
  if (counter.used >= BUDGET) { budgetOut = true; return { status: 0, body: '', cookies: [] }; }
  counter.used++; saveCount();
  return httpPost(url, headers, body);
}
const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const readFirst = ps => { for (const p of ps) { try { const v = fs.readFileSync(p, 'utf8').trim(); if (v) return v; } catch {} } return ''; };

async function dingTalk(title, text) {
  const hook = process.env.DINGTALK_WEBHOOK;
  if (!hook) { log('未配置 DINGTALK_WEBHOOK，跳过通知'); return; }
  let url = hook;
  const secret = process.env.DINGTALK_SECRET;
  if (secret) {
    const ts = String(Date.now());
    const sign = crypto.createHmac('sha256', secret).update(ts + '\n' + secret).digest('base64');
    url = `${hook}&timestamp=${ts}&sign=${encodeURIComponent(sign)}`;
  }
  try {
    const r = await httpPost(url, { 'Content-Type': 'application/json' }, JSON.stringify({ msgtype: 'text', text: { content: `${title}\n${text}` } }));
    log('钉钉推送:', r.status, r.body.slice(0, 100));
  } catch (e) { log('钉钉推送失败:', e.message); }
}
function saveResult(o) { try { fs.mkdirSync(OUT_DIR, { recursive: true }); fs.writeFileSync(path.join(OUT_DIR, 'last_result.json'), JSON.stringify(o, null, 2)); } catch (e) { log('写快照失败:', e.message); } }

// —— 取 sid：SSO 登录页在 200 时内嵌 loginPath；被风控时会 302 到绑定页（本次 sid 不可用于 appTokenLogin）——
// 实测：普通浏览器头常被风控 302 到绑定页；带小程序信封头（chop-real-host/x-center-env/authorization）时稳定 200
function mpHeaders() {
  try {
    const raw = process.env.CMCC_MP_HEADERS || '';
    if (!raw) return null;
    const j = JSON.parse(raw);
    if (!j.authorization) return null;
    return {
      'User-Agent': j.ua || '',
      'Cookie': j.cookie || '',
      'chop-real-host': 'wx.10086.cn',
      'x-center-env': j.x_center_env || '2',
      'authorization': j.authorization,
      'referer': j.referer || '',
      'channelid': j.channelid || 'CHINA_MINI',
      'x-app-version': j.x_app_version || '1.0.2',
      'chop-mp-version': j.chop_mp_version || 'version_20260930',
      'Accept': 'text/html,application/json,*/*',
    };
  } catch { return null; }
}
async function getSid() {
  const u = 'https://wx.10086.cn/qwhdsso/login?dlwmh=true&actUrl=' + encodeURIComponent(ACT);
  const combos = [];
  const mp = mpHeaders();
  if (mp) combos.push(['mp', mp]);
  combos.push(['default', {}]);
  let last = { status: 0, body: '' };
  for (const [tag, h] of combos) {
    last = await ssoGet(u, h) || last;
    const mm = (last.body || '').match(/loginPath\s*=\s*'([^']+)'/);
    if (mm) { const ss = mm[1].match(/sid=([^&'"]+)/); if (ss) { log('取 sid 成功，通道=' + tag); return ss[1]; } }
    log('取 sid 通道 ' + tag + ' 未下发（HTTP ' + last.status + '）');
  }
  const r = last;
  const err = new Error('SSO 未下发 sid（HTTP ' + r.status + '，' + (r.status === 302
    ? '账号级「近期已登录号码」上限/绑定页拦截：可用手机浏览器打开活动页选「172****9953 快速登录」清除，1 分钟无需短信'
    : '返回异常') + '）');
  err.transient = true; throw err;
}

// —— 换票：优先只用 jwt（长期路径），失败再叠加一次性 App 票据 ——
const HAS_STORED_SID = !!(process.env.CMCC_SID || '').trim();
async function exchange(jwt, ticket) {
  if (!HAS_STORED_SID) {
    counter.exchange += 1;
    counter.lastExchangeAt = Date.now();
    saveCount();
    log(`换票计数：今日第 ${counter.exchange} 次（上限 ${MAX_EXCHANGE_PER_DAY} 次）`);
  }
  // 直连优先：只要有存好的 sid，就只用它换票，失败也不回头去重新登录
  //（重新登录＝新的账号级登录请求，正是要防的那种消耗）。
  // 没有 sid 时才走「换票兜底」：先用 jwt 单独换，再叠加一次性 App 票据。
  const forms = HAS_STORED_SID
    ? [{ tag: 'stored-sid+jwt', body: { jwtToken: jwt || null, token: null }, sid: (process.env.CMCC_SID || '').trim() }]
    : [
      { tag: 'jwt-only', body: { jwtToken: jwt || null, token: null } },
      { tag: 'jwt+ticket', body: { jwtToken: jwt || null, token: ticket || null } },
      { tag: 'ticket-only', body: { jwtToken: null, token: ticket || null } },
    ];
  let last = null;
  for (const f of forms) {
    if (!f.body.jwtToken && !f.body.token) continue;
    const sid = f.sid || await getSid();
    const body = { ...f.body, provinceCode: PROV, cityCode: CITY, carrierOperator: '002', appVersionCode: '12.5.5', took: 150 };
    const r = await ssoPost('https://wx.10086.cn/qwhdsso/appTokenLogin?sid=' + sid, { 'Content-Type': 'application/json;charset=UTF-8' }, JSON.stringify(body));
    let d; try { d = JSON.parse(r.body); } catch { d = { code: 'PARSE', msg: r.body.slice(0, 120) }; }
    log(`换票[${f.tag}] → ${r.status} ${d.code} ${(d.msg || '').slice(0, 60)}`);
    last = d;
    if (d.code === 'SUCCESS') return { d, form: f.tag };
  }
  return { d: last, form: null };
}

const jwt = process.env.CMCC_JWT || readFirst(['jwt.txt']);
const appInfo = loadToken(process.env.CMCC_APP_TOKEN || readFirst(['app_token.txt'])) || { token: '' };
if (!jwt && !appInfo.token) {
  log('缺少凭证：需要 CMCC_JWT（或 CMCC_APP_TOKEN）');
  saveResult({ date: bjDate(), ok: false, statusRead: false, mode: MODE, phoneMasked: PHONE_MASKED, stage: 'init', error: 'missing credential' });
  await dingTalk('【中国移动签到】失败', '缺少凭证 CMCC_JWT / CMCC_APP_TOKEN');
  process.exit(2);
}
log('凭证: jwt=' + (jwt ? '有' : '无') + ' app票据=' + (appInfo.token ? '有' : '无') + ' | 号码', PHONE_MASKED || '(未提供)', '| 日期', today, '| 模式', MODE);

let res = null, err = null;
const gate = async (reason, errText) => {
  log(reason);
  await dingTalk('【中国移动签到】失败', '今日未签到：' + errText);
  saveResult({ date: bjDate(), ok: false, statusRead: false, mode: MODE, phoneMasked: PHONE_MASKED, stage: 'exchange-quota', error: errText, form: null });
  process.exit(3);
};
if (!HAS_STORED_SID) {
  if (counter.limitHit) {
    // 账号级上限是会自己解除的（滚动窗口）。旧逻辑一旦置真就锁死到当天结束，
    // 导致限制早已解除却再也不尝试。改为：超过 LIMIT_HIT_TTL_H 小时就自动解除并重试一次。
    const hours = (Date.now() - (counter.limitHitAt || 0)) / 3600000;
    if (counter.limitHitAt && hours >= LIMIT_HIT_TTL_H) {
      log(`上次命中账号级上限已是 ${hours.toFixed(1)} 小时前（阈值 ${LIMIT_HIT_TTL_H}h），自动解除并重试`);
      counter.limitHit = false; counter.limitHitAt = 0; counter.exchange = 0; saveCount();
    } else {
      await gate(`已命中账号级「近期已登录号码」上限（${counter.limitHitAt ? hours.toFixed(1) + ' 小时前' : '未知时间'}），距自动解除还需 ${counter.limitHitAt ? Math.max(0, LIMIT_HIT_TTL_H - hours).toFixed(1) : '?'} 小时`, `账号级上限未解除（${LIMIT_HIT_TTL_H}h 内不重试）`);
    }
  }
  if (counter.exchange >= MAX_EXCHANGE_PER_DAY) await gate(`今日换票次数已用满（${MAX_EXCHANGE_PER_DAY} 次），当天不再换票`, `今日换票次数已用满（${MAX_EXCHANGE_PER_DAY} 次）`);
  const gapMin = Math.floor((Date.now() - counter.lastExchangeAt) / 60000);
  if (counter.exchange > 0 && gapMin < MIN_EXCHANGE_GAP_MIN) await gate(`距上次换票仅 ${gapMin} 分钟（小于 ${MIN_EXCHANGE_GAP_MIN} 分钟），本窗口不换票`, `距上次换票仅 ${gapMin} 分钟，间隔不足`);
} else {
  log('已配置 CMCC_SID：本次走直连（不消耗换票额度，不受换票闸限制）');
}
for (let i = 1; i <= RETRIES; i++) {
  if (i > 1 && counter.used >= LADDER_LIMIT) { log(`今日已用 ${counter.used} 次登录请求，本窗口只试这一次（把额度留给后面的窗口，限制一解除就能立刻补签）`); break; }
  try {
    res = await exchange(jwt, appInfo.token);
    if (res.d && res.d.code === 'SUCCESS') break;
    if (HAS_STORED_SID) {
      err = new Error('直连换票失败：' + ((res.d && res.d.msg) || '未知错误'));
      log('直连失败：不再重试，也不回退到重新登录（保护账号级登录额度）');
      break;
    }
  }
  catch (e) {
    err = e; log(`换票[第${i}次] 异常: ${e.message}`);
    if (/302/.test(e.message || '')) {
      counter.limitHit = true; counter.limitHitAt = Date.now(); saveCount();
      log('命中账号级「近期已登录号码」上限：今日不再换票，等上限解除或用已存 sid 直连');
      break;
    }
  }
  if (budgetOut) { log(`今日登录请求额度已用满（${BUDGET} 次），停止本次尝试`); break; }
  if (counter.used >= BUDGET) { log(`今日登录请求额度已用满（${BUDGET} 次），不再等待重试`); break; }
  if (i < RETRIES) { const w = Math.min(BACKOFF * i, 120); log(`SSO 暂未下发 sid，${w}s 后第 ${i + 1} 次重试（最多 ${RETRIES} 次）`); await sleep(w * 1000); }
}
log(`本次共发起 ${counter.used} 次登录请求（今日累计）`);
if (!res || !res.d || res.d.code !== 'SUCCESS') {
  log('换票失败：' + ((res && res.d && res.d.msg) || (err && err.message) || '未知'));
  saveResult({ date: bjDate(), ok: false, statusRead: false, mode: MODE, phoneMasked: PHONE_MASKED, stage: 'appTokenLogin', error: ((res && res.d && res.d.msg) || (err && err.message) || 'failed'), form: res && res.form });
  await dingTalk('【中国移动签到】失败', `换票失败：${((res && res.d && res.d.msg) || (err && err.message) || '未知')}\n自查：① 账号「近期已登录」上限 → 手机浏览器打开活动页选 172****9953 快速登录（无需短信）\n② jwt 失效 → 重抓一次 App 票据（CMCC_APP_TOKEN）`);
  process.exit(3);
}
log('换票成功，使用形态:', res.form);
const d = res.d;
const newJwt = (d.data || {}).jwt || (d.data || {}).jwtToken || '';
if (newJwt && newJwt !== jwt) { fs.writeFileSync('jwt.txt', newJwt); log('jwt 已刷新（已写回 jwt.txt）'); }

const g = await httpGet(d.data.url);
const sc = g.cookies.join('; ');
const tk = sc.match(/(QWHD_SESSION_TOKEN|HLWHD_SESSION_TOKEN)=([^;,]+)/);
if (!tk) {
  log('未取得活动会话 cookie');
  saveResult({ date: bjDate(), ok: false, statusRead: false, mode: MODE, phoneMasked: PHONE_MASKED, stage: 'session', error: 'no session cookie', form: res.form });
  await dingTalk('【中国移动签到】失败', '换票成功但活动页未下发 QWHD_SESSION_TOKEN。');
  process.exit(4);
}
log('活动会话 OK（', tk[1], '，有效期约 30 分钟）');
const H = { 'Content-Type': 'application/json;charset=UTF-8', 'Accept': '*/*', 'Origin': 'https://wx.10086.cn', 'Referer': d.data.url, 'login-check': '1', 'x-requested-with': 'XMLHttpRequest', 'Cookie': tk[1] + '=' + tk[2] };
const api = async (p, payload) => { const rr = await httpPost('https://wx.10086.cn' + p, H, JSON.stringify(payload || {})); try { return { status: rr.status, j: JSON.parse(rr.body) }; } catch { return { status: rr.status, raw: rr.body.slice(0, 200) }; } };

const ui = await api('/qwhdhub/api/mark/user/info', {});
const nick = (ui.j && ui.j.data && ui.j.data.nickName) || '未知';
const channel = (ui.j && ui.j.data && ui.j.data.channel) || '未知';
log('身份:', nick, '| channel =', channel);
const st = await api('/qwhdhub/api/mark/mark31/markstatus', {});
const data = (st.j && st.j.data) || {};
const rec = (data.markstatus || []).find(x => x.date === today);
const acc = (data.userinfo || {}).accumulateTimes;
const signed = !!(rec && String(rec.status) === '1');
log('只读 markstatus → 今日', today, 'status =', rec ? rec.status : '(无记录)', '| 本月累计', acc ?? '?', '| 已签 =', signed);
if (channel !== 'app') log('注意：当前会话 channel 不是 app，mark31 结果可能无效');

let domark = null, finalSigned = signed, record = null;
if (READ_ONLY) log('只读模式（' + MODE + '）：不签到');
else if (signed) log('今日已签，跳过 domark');
else {
  const dm = await api('/qwhdhub/api/mark/mark31/domark', { date: today });
  domark = { status: dm.status, code: dm.j && dm.j.code, msg: dm.j && dm.j.msg };
  log('domark →', dm.status, 'code=' + domark.code, domark.msg || '', JSON.stringify(dm.j && dm.j.data || '').slice(0, 160));
  const st2 = await api('/qwhdhub/api/mark/mark31/markstatus', {});
  const rec2 = (((st2.j || {}).data || {}).markstatus || []).find(x => x.date === today);
  finalSigned = !!(rec2 && String(rec2.status) === '1');
  log('回读 markstatus → status =', rec2 ? rec2.status : '(无记录)', '| 本月累计', ((((st2.j || {}).data || {}).userinfo || {}) || {}).accumulateTimes ?? '?');
  const mr = await api('/qwhdhub/api/mark/mark31/markRecord', {});
  record = (mr.j && mr.j.data && mr.j.data[0]) || null;
  log('回读 markRecord →', JSON.stringify(record));
  if (!finalSigned) log('domark 返回成功但回读未生效（status≠1）');
}
const result = { date: bjDate(), ok: finalSigned, statusRead: true, mode: MODE, phoneMasked: PHONE_MASKED, form: res.form, alreadySigned: signed, signed: finalSigned, nick, channel, accumulateTimes: acc, domark, record, ts: new Date().toISOString() };
saveResult(result);
if (READ_ONLY) { log('只读完成：今日' + (signed ? '已签' : '未签') + '，本月累计 ' + (acc ?? '?') + ' 天'); process.exit(0); }
if (finalSigned) {
  log(signed ? '今日已签（无需操作）' : '签到成功并已回读确认');
  if (process.env.CMCC_NOTIFY_OK === '1') await dingTalk('【中国移动签到】成功', `${bjDate()} ${nick}：${signed ? '今日已签（跳过）' : '签到成功'}，本月累计 ${acc ?? '?'} 天。`);
  process.exit(0);
}
log('今日未签到');
await dingTalk('【中国移动签到】未成功', `${bjDate()} ${nick}：签到未生效（domark=${domark ? domark.code : '未执行'}）。`);
process.exit(1);
