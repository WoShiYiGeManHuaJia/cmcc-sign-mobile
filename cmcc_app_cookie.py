#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmcc_app_cookie.py — 中国移动 App 端凭证获取工具（手机号 + 短信验证码 → App 会话 Cookie / app_token）

链路（全部由本工具自己完成，不依赖用户手动抓包、不需要用户提供任何票据）：
    1) send-code : App 网关 /biz-orange/LN/uamrandcode/sendMsgLogin      → 下发短信验证码
    2) login     : App 网关 /biz-orange/LN/uamrandcodelogin/*（验证码登录 / autoLogin 免密登录）
    3) appTokenLogin : https://wx.10086.cn/qwhdsso/appTokenLogin（用 App 会话票据换 app_token / jwt）
    4) 输出：完整 Cookie 串（JSESSIONID/UID/ticketID）+ app_token(jwt) + 账号基本信息

依赖：Python 3.8+（仅标准库）+ 系统 openssl 命令行（AES-128-CBC 加解密）。
用法：
    python3 cmcc_app_cookie.py send-code --phone 13xxxxxxxxx
    python3 cmcc_app_cookie.py login     --phone 13xxxxxxxxx --code 123456
    python3 cmcc_app_cookie.py session   --phone 13xxxxxxxxx            # 复用本地票据刷新
    python3 cmcc_app_cookie.py probe                                # 诊断各网关/档位可用性
    python3 cmcc_app_cookie.py selftest                             # 离线自检（加解密/签名一致性）
"""
import argparse, base64, hashlib, json, os, random, re, ssl, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------- 加密常量（移动 App 网关）
KEY_14   = "tVkdaRWRY0ZkV1Vr"   # x-qen=14 档 body AES-128 key
IV_14    = "VjFSQ1ZtVkQxRTlP"   # x-qen=14 档 body AES-128 iv
KEY_2    = "bAIgvwAuA4tbDr9d"   # x-token AES-128 key
IV_2     = "9791027341711819"   # x-token / 2 档 AES-128 iv
RESP_14  = "RYV0hCV1lV25KYVJ"   # 14 档响应 key
RESP_2   = "GS7VelkJl5IT1uwQ"   # 2 档响应 key
SIGN_SALT = "_Leadeon/SecurityOrganization"   # xs 签名盐
RSA_N = int("968E9ACF9E59B4E2E1BB24266EE39043788A45F788ECDC5C971F4964C3267CF20AFD3B7F029B68A9A9B65D77D0306B8319DF0C174F3DD82EF3894A6C38E23634F6095A81901AD7E6650911C0910F12C7DE50A6FCEE3AE3563CC5985C46A965DB2AF49E94F69B62F67FF3D5C0F79782572375E5F8B44AA43C0CA6D48E8A969BEB", 16)
RSA_E = 0x10001
CN_TZ = timezone(timedelta(hours=8))

DEFAULT_PROFILE = {
    "host": "apm.app.coc.10086.cn",
    "sign_salt": SIGN_SALT,
    "ua": "ChinaMobile/12.5.5 (iPhone; iOS 27.0.1; Scale/3.00)",
    "qen": 14,
    "province_code": "731",
    "city_code": "1731",
    "device": {},
    "paths": {
        "send_code":  "/biz-orange/LN/uamrandcode/sendMsgLogin",
        "code_login": "/biz-orange/LN/uamrandcodelogin/threenetworklogin",
        "auto_login": "/biz-orange/LN/uamrandcodelogin/autoLogin"
    }
}

# ---------------------------------------------------------------- TLS：老网关要求 unsafe legacy renegotiation
def _ensure_legacy_tls():
    """OpenSSL 3.x 默认禁用 legacy renegotiation，登录后端会直接断连。
    若当前解释器没有 ssl.OP_LEGACY_SERVER_CONNECT，则写入一份 openssl.cnf 并带 OPENSSL_CONF 重启自身。"""
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        return
    if os.environ.get("CMCC_LEGACY_TLS_READY") == "1":
        return
    cfg = os.path.join(tempfile.gettempdir(), "cmcc_legacy_openssl.cnf")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write("openssl_conf = openssl_init\n\n[openssl_init]\nssl_conf = ssl_sect\n\n"
                "[ssl_sect]\nsystem_default = system_default_sect\n\n"
                "[system_default_sect]\nOptions = UnsafeLegacyRenegotiation\n")
    env = dict(os.environ); env["OPENSSL_CONF"] = cfg; env["CMCC_LEGACY_TLS_READY"] = "1"
    try:
        os.execve(sys.executable, [sys.executable] + sys.argv, env)
    except Exception:
        pass

def _ssl_ctx():
    ctx = ssl.create_default_context()
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        try:
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        except Exception:
            pass
    return ctx

# ---------------------------------------------------------------- 基础密码学
def md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def _openssl(args, data: bytes) -> bytes:
    p = subprocess.run(["openssl", "enc", "-aes-128-cbc"] + args, input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("openssl 失败: " + p.stderr.decode("utf-8", "replace")[:200])
    return p.stdout

def aes_enc_b64(plaintext: str, key: str, iv: str) -> str:
    ct = _openssl(["-K", key.encode().hex(), "-iv", iv.encode().hex()], plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode("ascii")

def aes_dec_b64(cipher_b64: str, key: str, iv: str) -> str:
    raw = base64.b64decode(cipher_b64.strip())
    pt = _openssl(["-d", "-K", key.encode().hex(), "-iv", iv.encode().hex()], raw)
    return pt.decode("utf-8", "replace")

def rsa_encrypt(text: str) -> str:
    """PKCS#1 v1.5 公钥加密（移动 App 用 RSA 加密手机号明文），返回 base64"""
    k = (RSA_N.bit_length() + 7) // 8
    msg = text.encode("utf-8")
    if len(msg) > k - 11:
        raise ValueError("RSA 明文过长")
    ps = bytearray()
    while len(ps) < k - len(msg) - 3:
        b = random.randrange(1, 256)
        ps += bytes([b])
    em = b"\x00\x02" + bytes(ps) + b"\x00" + msg
    m = int.from_bytes(em, "big")
    c = pow(m, RSA_E, RSA_N)
    cb = c.to_bytes(k, "big")
    return base64.b64encode(cb).decode("ascii")

def ts14() -> str:
    return datetime.now(CN_TZ).strftime("%Y%m%d%H%M%S")

# ---------------------------------------------------------------- HTTP
def http(url, method="GET", headers=None, body=None, timeout=30):
    _ensure_legacy_tls()
    req = urllib.request.Request(url, data=body.encode("utf-8") if isinstance(body, str) else body,
                                 headers=headers or {}, method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=_ssl_ctx()))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, "CLIENT_ERROR: %s: %s" % (type(e).__name__, str(e)[:200])

# ---------------------------------------------------------------- App 网关信封
def build_envelope(profile, phone, extra_req_body=None):
    dev = dict(profile.get("device") or {})
    req = dict(dev.get("reqBody") or {})
    req.setdefault("sendSmsFlag", "0")
    req.setdefault("imei", dev.get("imei", ""))
    req["sysTime"] = str(int(time.time()))
    req["cellNum"] = rsa_encrypt("leaddon" + phone + ts14())
    if extra_req_body:
        req.update(extra_req_body)
    body_obj = {k: v for k, v in dev.items() if k != "reqBody"}
    body_obj["reqBody"] = req
    body_obj["tel"] = phone
    return body_obj, json.dumps(body_obj, ensure_ascii=False, separators=(",", ":"))

def app_request(profile, path, body_obj, body_json, jsessionid=None, qen=None):
    """按移动 App 的信封格式向 App 网关发一个请求（xs/x-token/x-sign 全部现场生成）"""
    host = profile.get("host", "apm.app.coc.10086.cn")
    url = "https://" + host + path
    qen = qen or profile.get("qen", 14)
    xk = (profile.get("device") or {}).get("xk", "")
    salt = profile.get("sign_salt", SIGN_SALT)
    now = str(int(time.time() * 1000))
    nonce = str(random.randrange(10000000, 99999999))
    token = aes_enc_b64("%s_%s_%s_%s" % (xk, path, now, nonce), KEY_2, IV_2)
    xs = md5("%s_%s_%s" % (url, body_json, salt))
    xsign = md5("%s_%s_%s_%s" % (token, now, nonce, jsessionid or "null"))
    headers = {
        "Content-Type": "application/Json",
        "x-qen": str(qen),
        "x-time": now,
        "x-nonce": nonce,
        "xs": xs,
        "x-token": token,
        "x-sign": xsign,
        "User-Agent": profile.get("ua", DEFAULT_PROFILE["ua"]),
        "Accept": "*/*",
    }
    body = aes_enc_b64(body_json, KEY_14, IV_14) if qen == 14 else aes_enc_b64(body_json, KEY_2, IV_2)
    status, hdrs, text = http(url, "POST", headers, body)
    return status, hdrs, text, {"xs": xs, "x_token": token, "x_sign": xsign, "x_time": now, "x_nonce": nonce}

def decode_app_response(text, qen=14):
    """网关响应可能是明文 JSON，也可能是 AES 加密串"""
    t = (text or "").strip()
    if t.startswith("{"):
        return t
    for key, iv in ((RESP_14, IV_14), (RESP_2, IV_2)):
        try:
            pt = aes_dec_b64(t, key, iv)
            if pt.lstrip().startswith("{"):
                return pt
        except Exception:
            continue
    return t

def biz_result(status, hdrs, text, qen=14):
    """把网关响应整理成 {ok, retCode, retDesc, data}"""
    raw = decode_app_response(text, qen)
    if status != 200:
        return {"ok": False, "http": status, "error": (hdrs.get("error") or "").strip(),
                "raw": raw[:400]}
    try:
        j = json.loads(raw)
    except Exception:
        return {"ok": False, "http": status, "raw": raw[:400]}
    code = str(j.get("retCode", ""))
    desc = j.get("retDesc", "")
    return {"ok": code in ("000000", "000100"), "http": status, "retCode": code, "retDesc": desc,
            "rspBody": j.get("rspBody"), "raw": raw[:400]}

# ---------------------------------------------------------------- 业务：下发验证码
def send_code(profile, phone):
    path = profile["paths"]["send_code"]
    body_obj, body_json = build_envelope(profile, phone)
    st, hdrs, text, sig = app_request(profile, path, body_obj, body_json)
    res = biz_result(st, hdrs, text)
    res["path"] = path
    res["host"] = profile.get("host")
    return res

# ---------------------------------------------------------------- 业务：验证码登录 / 免密登录
def code_login(profile, phone, code):
    path = profile["paths"]["code_login"]
    body_obj, body_json = build_envelope(profile, phone, {"smsCode": code, "code": code})
    st, hdrs, text, sig = app_request(profile, path, body_obj, body_json)
    res = biz_result(st, hdrs, text)
    res["path"] = path
    res["set_cookie"] = hdrs.get("Set-Cookie", "") or hdrs.get("set-cookie", "")
    return res

def auto_login(profile, phone):
    path = profile["paths"]["auto_login"]
    body_obj, body_json = build_envelope(profile, phone)
    st, hdrs, text, sig = app_request(profile, path, body_obj, body_json)
    res = biz_result(st, hdrs, text)
    res["path"] = path
    res["set_cookie"] = hdrs.get("Set-Cookie", "") or hdrs.get("set-cookie", "")
    return res

# ---------------------------------------------------------------- 业务：appTokenLogin（换 app_token）
def app_token_login(profile, phone, ticket, jwt=None):
    base = "https://wx.10086.cn"
    act = base + "/qwhdhub/qwhdmark/1021122301?channelId=P00000057578"
    st, hdrs, text = http(base + "/qwhdsso/login?dlwmh=true&actUrl=" +
                          urllib.parse.quote(act, safe=""),
                          "GET", {"User-Agent": profile.get("ua", DEFAULT_PROFILE["ua"])})
    m = re.search(r"loginPath\s*=\s*'([^']+)'", text or "")
    if not m:
        return {"ok": False, "stage": "sso_login", "http": st, "msg": "登录页未返回 sid"}
    login_url = base + "/qwhdsso" + m.group(1)
    body = {
        "jwtToken": jwt,
        "token": ticket,
        "provinceCode": profile.get("province_code", ""),
        "cityCode": profile.get("city_code", ""),
        "userCheckId": str(int(phone)),
        "carrierOperator": "002",
        "appVersionCode": "12.5.5",
        "took": 150,
    }
    st2, hdrs2, text2 = http(login_url, "POST", {
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": profile.get("ua", DEFAULT_PROFILE["ua"])}, json.dumps(body))
    try:
        j = json.loads(text2)
    except Exception:
        return {"ok": False, "stage": "appTokenLogin", "http": st2, "msg": text2[:300]}
    data = j.get("data") or {}
    jwt_new = data.get("jwt") or data.get("token") or ""
    return {"ok": j.get("code") == "SUCCESS", "stage": "appTokenLogin", "http": st2,
            "code": j.get("code"), "msg": j.get("msg"), "jwt": jwt_new,
            "set_cookie": hdrs2.get("Set-Cookie", "") or hdrs2.get("set-cookie", "")}

# ---------------------------------------------------------------- 会话存档
def session_path(profile):
    d = os.path.join(os.path.dirname(os.path.abspath(profile.get("__path__", "cmcc_app_cookie.py"))), "cmcc_session.json")
    return d

def save_session(profile, data):
    p = session_path(profile)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass
    return p

def load_session(profile):
    p = session_path(profile)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return None

# ---------------------------------------------------------------- 命令
def cmd_send_code(args, profile):
    r = send_code(profile, args.phone)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if r.get("ok") and r.get("retCode") == "000000":
        print("✅ 短信验证码已下发（status 0）", file=sys.stderr)
        return 0
    print("❌ 下发失败：" + str(r.get("retDesc") or r.get("raw") or r.get("error")), file=sys.stderr)
    return 2

def cmd_login(args, profile):
    out = {"phone": args.phone}
    if args.code:
        r = code_login(profile, args.phone, args.code)
        out["code_login"] = r
        ticket = r.get("set_cookie") or ""
        if not ticket:
            print("❌ 验证码登录未返回票据：" + str(r.get("retDesc") or r.get("raw")), file=sys.stderr)
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 2
    else:
        r = auto_login(profile, args.phone)
        out["auto_login"] = r
        ticket = r.get("set_cookie") or ""
        if not ticket:
            print("❌ autoLogin 未返回票据：" + str(r.get("retDesc") or r.get("raw")), file=sys.stderr)
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 2
    out["ticket_present"] = True
    tr = app_token_login(profile, args.phone, ticket)
    out["appTokenLogin"] = {k: v for k, v in tr.items() if k != "jwt"}
    if tr.get("jwt"):
        out["app_token"] = tr["jwt"]
    sess = save_session(profile, {"phone": args.phone, "ticket": ticket, "jwt": tr.get("jwt", ""),
                                  "saved_at": datetime.now(CN_TZ).isoformat(timespec="seconds")})
    out["session_file"] = sess
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if tr.get("ok"):
        print("✅ 已获取 app_token（app 通道凭证）", file=sys.stderr)
        return 0
    print("❌ appTokenLogin 失败：" + str(tr.get("msg") or tr.get("code")), file=sys.stderr)
    return 2

def cmd_session(args, profile):
    s = load_session(profile)
    if not s:
        print("❌ 本地没有会话存档，请先执行 login", file=sys.stderr)
        return 2
    tr = app_token_login(profile, args.phone or s.get("phone"), s.get("ticket"), jwt=s.get("jwt") or None)
    print(json.dumps({"ok": tr.get("ok"), "code": tr.get("code"), "msg": tr.get("msg"),
                      "app_token": tr.get("jwt", "")}, ensure_ascii=False, indent=2))
    return 0 if tr.get("ok") else 2

def cmd_probe(args, profile):
    """诊断：各网关主机 / 路径 / 加密档位 的可达性"""
    hosts = profile.get("probe_hosts") or [profile.get("host", "apm.app.coc.10086.cn")]
    paths = [profile["paths"][k] for k in ("send_code", "code_login", "auto_login")]
    rows = []
    for h in hosts:
        p2 = dict(profile); p2["host"] = h
        for path in paths:
            body_obj, body_json = build_envelope(p2, args.phone)
            for qen in (14, 2):
                try:
                    st, hdrs, text, _ = app_request(p2, path, body_obj, body_json, qen=qen)
                    rows.append({"host": h, "path": path, "qen": qen, "http": st,
                                 "error": (hdrs.get("error") or "").strip(),
                                 "resp": decode_app_response(text, qen)[:160]})
                except Exception as e:
                    rows.append({"host": h, "path": path, "qen": qen, "http": "ERR", "resp": str(e)[:120]})
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0

def cmd_selftest(args, profile):
    ok = True
    p = "hello-cmcc-selftest"
    enc = aes_enc_b64(p, KEY_14, IV_14)
    dec = aes_dec_b64(enc, KEY_14, IV_14)
    r1 = dec == p
    ok &= r1
    r2 = md5("abc") == "900150983cd24fb0d6963f7d28e17f72"
    ok &= r2
    r3 = aes_dec_b64(aes_enc_b64("x", KEY_2, IV_2), KEY_2, IV_2) == "x"
    ok &= r3
    body = {"tel": "13800000000", "reqBody": {"sysTime": "1"}}
    bj = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    url = "https://example.invalid/p"
    sig = md5("%s_%s_%s" % (url, bj, SIGN_SALT))
    r4 = len(sig) == 32 and re.fullmatch(r"[0-9a-f]{32}", sig) is not None
    ok &= r4
    print(json.dumps({"aes_roundtrip": r1, "md5": r2, "tier2_roundtrip": r3, "xs_format": r4,
                      "all_ok": bool(ok)}, ensure_ascii=False, indent=2))
    return 0 if ok else 1

def main():
    ap = argparse.ArgumentParser(description="中国移动 App 端凭证获取工具")
    ap.add_argument("--profile", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_profile.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("send-code", help="下发短信验证码")
    p.add_argument("--phone", required=True)
    p = sub.add_parser("login", help="验证码登录 / 免密登录并换 app_token")
    p.add_argument("--phone", required=True)
    p.add_argument("--code", default="")
    p = sub.add_parser("session", help="用本地票据刷新 app_token")
    p.add_argument("--phone", default="")
    p = sub.add_parser("probe", help="诊断网关/路径/档位可用性")
    p.add_argument("--phone", required=True)
    sub.add_parser("selftest", help="离线自检")
    args = ap.parse_args()
    try:
        with open(args.profile, encoding="utf-8") as f:
            profile = json.load(f)
    except FileNotFoundError:
        print("❌ 找不到配置文件：" + args.profile, file=sys.stderr)
        return 2
    profile["__path__"] = args.profile
    profile = {**DEFAULT_PROFILE, **profile}
    profile["device"] = {**DEFAULT_PROFILE["device"], **(profile.get("device") or {})}
    profile["paths"] = {**DEFAULT_PROFILE["paths"], **(profile.get("paths") or {})}
    fn = {"send-code": cmd_send_code, "login": cmd_login, "session": cmd_session,
          "probe": cmd_probe, "selftest": cmd_selftest}[args.cmd]
    return fn(args, profile)

if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
