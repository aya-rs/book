#!/usr/bin/env bash

set -euxo pipefail

for dir in *; do
  if [ ! -d "${dir}" ]; then
    continue;
  fi

  pushd "${dir}"

  cargo +nightly fmt --check
  cargo +nightly clippy "$@" --workspace --all-targets -- --deny warnings -C panic=abort -Zpanic_abort_tests

  cargo build "$@"
  cargo build "$@" --release

  popd
done
