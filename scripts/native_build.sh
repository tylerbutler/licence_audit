#!/usr/bin/env bash
set -euo pipefail

target=${1:?Usage: native_build.sh TARGET}
export PYTHONUTF8=1
export XDG_CACHE_HOME="$PWD/build/release-cache"
queso_cache="$XDG_CACHE_HOME/queso"
mkdir -p build/release-tmp build/native-tools
export TMPDIR="$PWD/build/release-tmp"
export TMP="$TMPDIR" TEMP="$TMPDIR"

case "$(uname -s)" in
  Linux)
    # The container is native to the runner, including libc. Queso does not
    # cross-compile the esqlite NIF copied by gleam export erlang-shipment.
    if [ -f /etc/alpine-release ]; then
      apk add --no-cache bash build-base ca-certificates curl git linux-headers \
        ncurses-libs openssl-dev perl pkgconf python3 py3-pip
    else
      apt-get update -qq
      apt-get install -y --no-install-recommends build-essential ca-certificates \
        curl git libssl-dev pkg-config python3 python3-venv
    fi
    arch=$(uname -m)
    case "$target" in
      "$arch-linux-musl") test -f /etc/alpine-release ;;
      "$arch-linux-glibc") test ! -f /etc/alpine-release ;;
      *) echo "Target does not match the native Linux host: $target" >&2; exit 1 ;;
    esac
    gleam_version=$(python3 -c 'import tomllib; print(tomllib.load(open(".mise.toml", "rb"))["tools"]["gleam"])')
    rebar_version=$(python3 -c 'import tomllib; print(tomllib.load(open(".mise.toml", "rb"))["tools"]["rebar"])')
    otp=$(python3 -c 'import tomllib; print(tomllib.load(open(".mise.toml", "rb"))["tools"]["erlang"])')
    actual_otp=$(erl -noshell -eval 'io:format("~s", [string:trim(element(2, file:read_file(filename:join([code:root_dir(), "releases", erlang:system_info(otp_release), "OTP_VERSION"]))))]), halt().')
    test "$actual_otp" = "$otp"
    curl --fail --location --retry 3 \
      "https://github.com/gleam-lang/gleam/releases/download/v${gleam_version}/gleam-v${gleam_version}-${arch}-unknown-linux-musl.tar.gz" \
      -o build/native-tools/gleam.tar.gz
    tar -xzf build/native-tools/gleam.tar.gz -C build/native-tools
    curl --fail --location --retry 3 \
      "https://github.com/erlang/rebar3/releases/download/${rebar_version}/rebar3" \
      -o build/native-tools/rebar3
    chmod +x build/native-tools/rebar3
    export PATH="$PWD/build/native-tools:$PATH"
    export CARGO_HOME="$PWD/build/native-tools/cargo"
    export RUSTUP_HOME="$PWD/build/native-tools/rustup"
    curl --fail --location --retry 3 https://sh.rustup.rs -o build/native-tools/rustup-init.sh
    sh build/native-tools/rustup-init.sh -y --no-modify-path --profile minimal
    export PATH="$CARGO_HOME/bin:$PATH"
    python3 -m venv build/native-tools/python
    export PATH="$PWD/build/native-tools/python/bin:$PATH"
    queso_platform="${arch}-unknown-linux-musl"
    ;;
  Darwin)
    arch=$(uname -m)
    [ "$arch" != arm64 ] || arch=aarch64
    test "$target" = "$arch-macos"
    queso_platform="${arch}-apple-darwin"
    # ProjectDirs ignores XDG_CACHE_HOME on macOS and Windows.
    queso_cache="$HOME/Library/Caches/queso"
    python3 -m venv build/native-tools/python
    export PATH="$PWD/build/native-tools/python/bin:$PATH"
    ;;
  MINGW*|MSYS*)
    test "$target" = x86_64-windows
    queso_platform=x86_64-pc-windows-msvc
    queso_cache=$(python3 -c 'import os; from pathlib import Path; print((Path(os.environ["LOCALAPPDATA"]) / "queso/cache").as_posix())')
    TMPDIR=$(python3 -c 'from pathlib import Path; print(Path("build/release-tmp").resolve().as_posix())')
    export TMPDIR TMP="$TMPDIR" TEMP="$TMPDIR"
    ;;
  *)
    echo "Unsupported native build host" >&2
    exit 1
    ;;
esac

python3 -m pip install 'ziglang==0.14.1'
cargo install --locked cargo-zigbuild --version 0.23.4
cargo install --locked cargo-about --version 0.9.2 --features cli
cargo about --version
rustup component add rust-docs
case "$target" in
  *-linux-glibc) rust_target="${target%%-linux-*}-unknown-linux-gnu" ;;
  *-linux-musl) rust_target="${target%%-linux-*}-unknown-linux-musl" ;;
  *-macos) rust_target="${target%%-macos}-apple-darwin" ;;
  x86_64-windows) rust_target=x86_64-pc-windows-gnu ;;
  *) echo "Unsupported native target: $target" >&2; exit 1 ;;
esac
rustup target add "$rust_target"

queso_version=$(python3 -c 'import tomllib; print(tomllib.load(open(".mise.toml", "rb"))["tools"]["github:jtdowney/queso"])')
if [ "$target" = x86_64-windows ]; then
  curl --fail --location --retry 3 \
    "https://github.com/jtdowney/queso/releases/download/v${queso_version}/queso-${queso_platform}.zip" \
    -o build/native-tools/queso.zip
  python3 -m zipfile -e build/native-tools/queso.zip build/native-tools
else
  curl --fail --location --retry 3 \
    "https://github.com/jtdowney/queso/releases/download/v${queso_version}/queso-${queso_platform}.tar.gz" \
    -o build/native-tools/queso.tar.gz
  tar -xzf build/native-tools/queso.tar.gz -C build/native-tools
fi
export PATH="$PWD/build/native-tools:$PATH"
gleam deps download
if [ "$target" = x86_64-windows ]; then
  # Gleam cannot copy cvss's licence symlink on Windows.
  python3 -c "from pathlib import Path; p = Path('build/packages/cvss/LICENSE.txt'); text = Path('build/packages/cvss/LICENSES/Apache-2.0.txt').read_bytes(); p.unlink(); p.write_bytes(text)"
fi
gleam build --target erlang --warnings-as-errors
mkdir -p build/native-logs
queso build --target "$target" 2>&1 | tee "build/native-logs/$target.log"
python3 -B scripts/sqlite_native.py \
  --destination "build/escript-sidecars/$target/esqlite"
python3 -B scripts/runtime_notices.py --target "$target" --cache "$queso_cache" \
  --build-log "build/native-logs/$target.log"

gleam export escript
mkdir -p build/escript
cp licence_audit build/escript/
python3 -B scripts/sqlite_native.py \
  --destination "build/escript/sqlite_native/$target/esqlite"
test ! -e build/escript/sqlite_native/esqlite
python3 -B test/native_cache_smoke.py build/escript/licence_audit --escript
if [ "$target" = x86_64-linux-glibc ]; then
  python3 -B test/native_cache_smoke.py build/escript/licence_audit --bare-escript
fi
