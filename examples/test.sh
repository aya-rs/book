#!/usr/bin/env bash

set -euxo pipefail

for dir in *; do
  if [ ! -d "${dir}" ]; then
    continue;
  fi

  pushd "${dir}"

  cargo +nightly fmt --check

  # `-C panic=abort` because "unwinding panics are not supported without std"; ebpf programs are
  # `#[no_std]` binaries.
  cargo clippy "$@" -- --deny warnings -C panic=abort

  popd
done

for dir in *; do
  if [ ! -d "${dir}" ]; then
    continue;
  fi

  pushd "${dir}"

  cargo build "$@"
  cargo build "$@" --release

  popd
done
