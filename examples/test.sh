#!/usr/bin/env bash

set -euxo pipefail

for dir in *; do
  if [ ! -d "${dir}" ]; then
    continue;
  fi

  pushd "${dir}"

  cargo +nightly fmt --check

  bpf_crate=$dir-ebpf
  if [ "${dir}" == "aya-tool" ]; then
    bpf_crate=myapp-ebpf
  fi

  # We can't run clippy over the entire workspace all at once because we need panic=abort for the
  # ${bpf_crate} crate.
  #
  # We can't use --all-targets on ${bpf_crate} because building tests with panic=abort isn't
  # supported without -Zpanic_abort_tests.
  cargo clippy "$@" --exclude "${bpf_crate}" --all-targets --workspace -- --deny warnings
  cargo clippy "$@" --package "${bpf_crate}" -- --deny warnings -C panic=abort

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
