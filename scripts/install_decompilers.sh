#!/usr/bin/env bash
# 反编译工具一键安装脚本（升级阶段 2）
# 支持环境：Kali / Debian / Ubuntu；工具统一放 tools/decompilers/
# 已配置：cfr(Java 反编译)、jadx(APK/DEX)、apktool(APK 资源)
# 可选：ilspycmd(.NET，需 dotnet-sdk)、pycdc(.pyc，需编译)、redress(Go 二进制)
# 说明：GitHub 直连被阻断时，优先走 apt 镜像源（jadx/apktool 有包），cfr 走 Maven 镜像
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)/tools/decompilers"
mkdir -p "$DIR"

# GitHub 加速代理（直连超时/SSL 失败时使用），可通过 GH_PROXY 环境变量覆盖
GH_PROXY="${GH_PROXY:-}"
proxy_url() { if [ -n "$GH_PROXY" ]; then echo "${GH_PROXY}https://github.com$1"; else echo "https://github.com$1"; fi; }

echo "== [1/6] 检查 Java 运行时 =="
if ! command -v java >/dev/null; then
  echo "安装 openjdk-17-jdk ..."
  apt-get update -qq && apt-get install -y -qq openjdk-17-jdk-headless
fi

echo "== [2/6] jadx（apk/dex → Java 源码；优先 apt 镜像源）=="
if [ ! -x "$DIR/jadx/bin/jadx" ]; then
  if apt-cache show jadx >/dev/null 2>&1; then
    echo "通过 apt 安装 jadx（镜像源）..."
    apt-get install -y -qq jadx
    rm -rf "$DIR/jadx" && mkdir -p "$DIR/jadx"
    cp -r /usr/share/jadx/* "$DIR/jadx/" 2>/dev/null || true
    cp -f /usr/bin/jadx "$DIR/jadx/bin/jadx" 2>/dev/null || true
    chmod +x "$DIR/jadx/bin/jadx" 2>/dev/null || true
  else
    echo "apt 无 jadx 包，从 GitHub 下载..."
    curl -sL --retry 3 -o /tmp/jadx.zip "$(proxy_url /skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip)"
    rm -rf "$DIR/jadx" && mkdir -p "$DIR/jadx"
    unzip -qo /tmp/jadx.zip -d "$DIR/jadx" && chmod +x "$DIR/jadx/bin/jadx" || echo "WARN: jadx 解压失败"
  fi
fi
"$DIR/jadx/bin/jadx" --version 2>/dev/null || echo "WARN: jadx 不可用"

echo "== [3/6] apktool（APK 资源/manifest；优先 apt 镜像源）=="
if [ ! -s "$DIR/apktool.jar" ]; then
  if apt-cache show apktool >/dev/null 2>&1; then
    echo "通过 apt 安装 apktool（镜像源）..."
    apt-get install -y -qq apktool
    JAR=$(find /usr/share/apktool -maxdepth 1 -name 'apktool-cli.jar' 2>/dev/null | head -1)
    if [ -n "$JAR" ]; then
      # apt 拆分版合并为可独立运行 fat jar
      mkdir -p /tmp/apktool_fat/classes && cd /tmp/apktool_fat/classes
      find /usr/share/apktool /usr/share/java -name '*.jar' -type f 2>/dev/null | while read -r j; do unzip -o -q "$j" -d . 2>/dev/null || true; done
      rm -rf META-INF/*.SF META-INF/*.RSA META-INF/*.DSA 2>/dev/null || true
      printf 'Manifest-Version: 1.0\nMain-Class: brut.apktool.Main\n\n' > META-INF/MANIFEST.MF
      jar cfm "$DIR/apktool.jar" META-INF/MANIFEST.MF . 2>/dev/null || echo "WARN: apktool fat jar 合并失败"
    fi
  else
    curl -sL --retry 3 -o "$DIR/apktool.jar" \
      "$(proxy_url /iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar)" || true
  fi
fi
[ -s "$DIR/apktool.jar" ] && java -jar "$DIR/apktool.jar" --version 2>/dev/null | head -1 || echo "WARN: apktool 不可用"

echo "== [4/6] cfr（jar/war/class → Java 源码；Maven 镜像）=="
if [ ! -s "$DIR/cfr.jar" ]; then
  curl -sL --retry 3 -o "$DIR/cfr.jar" \
    "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar" \
  || curl -sL --retry 3 -o "$DIR/cfr.jar" \
    "https://maven.aliyun.com/repository/central/org/benf/cfr/0.152/cfr-0.152.jar"
fi
java -jar "$DIR/cfr.jar" --version 2>/dev/null | head -1 || echo "WARN: cfr 下载校验失败"

echo "== [5/6] 可选工具 =="
# .NET 反编译：需要 dotnet-sdk（Kali: apt install dotnet-sdk；或参考 https://dot.net）
command -v dotnet >/dev/null && { dotnet tool install --global ilspycmd 2>/dev/null || true; } \
  || echo "SKIP: ilspycmd 需先安装 dotnet-sdk（.NET 审计将走降级扫描）"
# pyc 反编译：pycdc 需 cmake/g++ 编译，或使用 pypi 的 decompyle3（仅 3.8 字节码）
pip3 install -q decompyle3 2>/dev/null || echo "SKIP: decompyle3（.pyc 审计将走降级扫描）"
if ! command -v pycdc >/dev/null && command -v cmake >/dev/null && command -v g++ >/dev/null; then
  echo "编译 pycdc（.pyc → Python 源码）..."
  cd /tmp && rm -rf pycdc && mkdir pycdc && cd pycdc
  curl -sL --retry 3 -o pycdc.zip "https://codeload.github.com/zrax/pycdc/zip/refs/heads/master" && unzip -qo pycdc.zip -d .
  cd pycdc-master && cmake -DCMAKE_BUILD_TYPE=Release . >/dev/null 2>&1 && make -j2 >/dev/null 2>&1
  cp -f pycdc pycdas /usr/local/bin/ 2>/dev/null || true
  cp -f pycdc pycdas "$DIR/" 2>/dev/null || true
fi
# Go 二进制反编译：redress（需 go 工具链，走 goproxy 镜像）
if ! command -v redress >/dev/null && command -v go >/dev/null; then
  echo "安装 redress（Go 二进制反编译）..."
  export GOPROXY=https://goproxy.cn,direct
  go install github.com/goretk/redress@latest 2>/dev/null || true
  cp -f "$HOME/go/bin/redress" /usr/local/bin/ 2>/dev/null || true
  cp -f "$HOME/go/bin/redress" "$DIR/" 2>/dev/null || true
fi

echo
echo "== 工具状态 =="
for f in cfr.jar apktool.jar; do
  [ -s "$DIR/$f" ] && echo "OK  $f ($(stat -c%s "$DIR/$f") bytes)" || echo "MISS $f"
done
[ -x "$DIR/jadx/bin/jadx" ] && echo "OK  jadx" || echo "MISS jadx"
command -v ilspycmd >/dev/null && echo "OK  ilspycmd" || echo "MISS ilspycmd（降级：字符串特征扫描）"
command -v pycdc >/dev/null && echo "OK  pycdc" || { command -v decompyle3 >/dev/null && echo "OK  decompyle3" || echo "MISS pycdc/decompyle3（降级：字符串特征扫描）"; }
command -v redress >/dev/null && echo "OK  redress" || echo "MISS redress（原生 ELF 审计将走字符串特征扫描）"
echo "安装完成。"

