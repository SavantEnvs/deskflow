#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's Qt Test suite (src/unittests, 32 executables), built by mayhem/build.sh in build/tests.
# ctest runs them; each QtTest executable prints "Totals: P passed, F failed, S skipped, ..." and we
# sum those per-function counts. A test executable that prints no Totals line (it did not run its
# test functions) counts as one failure, so a neutered binary cannot pass. A few upstream tests are
# timing-sensitive under load, so ctest retries a failing executable up to 3 times; the LAST attempt's
# Totals line per test number is what counts.
TESTDIR="$SRC/build/tests/src/unittests"
if [ ! -f "$TESTDIR/CTestTestfile.cmake" ]; then
  echo "test suite not built: $TESTDIR missing (mayhem/build.sh builds it)" >&2
  emit_ctrf "qtest-ctest" 0 1 0
  exit 1
fi

log="$(mktemp)"
# QtTest GUI tests need a platform plugin; offscreen needs no display. Settings go to a private dir.
cfg="$(mktemp -d)"
( cd "$TESTDIR" && QT_QPA_PLATFORM=offscreen XDG_CONFIG_HOME="$cfg" XDG_STATE_HOME="$cfg" \
    ctest -V -j"$MAYHEM_JOBS" --repeat until-pass:3 ) > "$log" 2>&1
ctest_rc=$?

total_tests="$(cd "$TESTDIR" && ctest -N | sed -n 's/^Total Tests: \([0-9]*\)$/\1/p')"
: "${total_tests:=0}"
passed=0; failed=0; skipped=0; with_totals=0
while read -r p f s; do
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + s)); with_totals=$((with_totals + 1))
done < <(sed -n 's/^\([0-9]*\): Totals: \([0-9]*\) passed, \([0-9]*\) failed, \([0-9]*\) skipped.*/\1 \2 \3 \4/p' "$log" \
          | awk '{ last[$1] = $2 " " $3 " " $4 } END { for (t in last) print last[t] }')

missing=$((total_tests - with_totals))
[ "$missing" -gt 0 ] && failed=$((failed + missing))
if [ "$ctest_rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ "$total_tests" -eq 0 ]; then failed=$((failed + 1)); fi

echo "ctest rc=$ctest_rc, executables=$total_tests, with Totals=$with_totals"
grep -E "^[0-9]+: (FAIL!|   Loc:|Totals:)" "$log" | grep -v " 0 failed" || true
rm -rf "$log" "$cfg"
emit_ctrf "qtest-ctest" "$passed" "$failed" "$skipped"
