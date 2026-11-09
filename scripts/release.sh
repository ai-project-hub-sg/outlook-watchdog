#!/usr/bin/env bash
# 交叉编译发布：产出 dist/ 下全部目标二进制（Windows 自测 + Linux 部署）
# 用法：bash scripts/release.sh   （在仓库根目录，git-bash/Linux 均可）
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "==> version: ${VERSION}"
mkdir -p dist

build() {
  local goos=$1 goarch=$2 out=$3
  echo "==> ${goos}/${goarch} -> dist/${out}"
  CGO_ENABLED=0 GOOS=${goos} GOARCH=${goarch} \
    go build -trimpath -ldflags="${LDFLAGS}" -o "dist/${out}" ./cmd/watchdog
}

build windows amd64 watchdog-windows-amd64.exe
build linux   amd64 watchdog-linux-amd64
build linux   arm64 watchdog-linux-arm64

echo "==> done. artifacts in dist/"
ls -lh dist/
