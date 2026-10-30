#!/bin/bash
# 手机端（太墟/Termux）移动签到 一键安装 + 运行
set -e
BIN="$HOME/cmcc"; mkdir -p "$BIN"; cd "$BIN"
BASE="https://raw.githubusercontent.com/WoShiYiGeManHuaJia/cmcc-sign-mobile/main"
for f in daily_sign.mjs http.mjs tokenload.mjs cmcc_app_cookie.py device_profile.json package.json; do
  curl -sSL "$BASE/$f" -o "$f"
done
echo "下载完成 -> $BIN"
echo
echo "下一步："
echo "  cd $BIN"
echo "  export CMCC_PHONE=你的手机号"
echo "  python3 cmcc_app_cookie.py send-code --phone 你的手机号"
