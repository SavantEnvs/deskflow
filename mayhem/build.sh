#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Both build trees live under build/, which upstream's .gitignore already ignores (/build), so
# `git clean -ffdX` removes them and the graded rebuild starts clean.
FUZZ_TARGETS=(
  fuzz_server_proxy fuzz_client_proxy fuzz_clipboard_unmarshall fuzz_clipboard_chunk
  fuzz_unicode fuzz_keyboard_layouts fuzz_server_config fuzz_fingerprint_db
)

# 1) Sanitized + coverage-instrumented build of the deskflow libraries, with the fuzz harnesses added as
#    targets of upstream's own CMake (mayhem/harnesses/fuzz-targets.cmake, injected after project()).
#    -fsanitize=fuzzer-no-link puts SanitizerCoverage on the project code, not only on the harness.
#    The standalone driver is a C object so its LLVMFuzzerTestOneInput reference keeps C linkage.
mkdir -p build/fuzz
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o
# LeakSanitizer off in every fuzz and -standalone binary (mayhem/lsan_off.cc); ASan/UBSan stay on.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake -S . -B build/fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1" \
  -DBUILD_TESTS=OFF -DBUILD_INSTALLER=OFF \
  -DCMAKE_PROJECT_deskflow_INCLUDE="$SRC/mayhem/harnesses/fuzz-targets.cmake" \
  -DMAYHEM_FUZZ_ENGINE="$LIB_FUZZING_ENGINE" \
  -DMAYHEM_STANDALONE_OBJ="$SRC/build/fuzz/standalone_main.o" \
  -DMAYHEM_LSAN_OFF_OBJ="$SRC/build/fuzz/lsan_off.o"
targets=()
for t in "${FUZZ_TARGETS[@]}"; do targets+=("$t" "$t-standalone"); done
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target "${targets[@]}"
for t in "${FUZZ_TARGETS[@]}"; do
  cp -f "build/fuzz/fuzz/$t" "/mayhem/$t"
  cp -f "build/fuzz/fuzz/$t-standalone" "/mayhem/$t-standalone"
done

# 2) Upstream's own Qt Test suite (src/unittests), NORMAL flags, separate tree; mayhem/test.sh runs it.
cmake -S . -B build/tests -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DBUILD_TESTS=ON -DSKIP_BUILD_TESTS=ON -DBUILD_INSTALLER=OFF
cmake --build build/tests -j"$MAYHEM_JOBS"
