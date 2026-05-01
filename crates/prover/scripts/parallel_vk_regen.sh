#!/usr/bin/env bash
# parallel_vk_regen.sh — Layer 1 of #81: parallel partition runner for
# build_compress_vks. Splits the [0, total_shapes) index range into N
# equal partitions, spawns N worker processes (one per CPU), waits
# for all to complete, then invokes merge_vk_maps to union the
# partials into a single vk_map.bin.
#
# Usage:
#   parallel_vk_regen.sh <total_shapes> <workers> <output_dir>
#
# Example (full enumeration, 8 workers, results into ./vk_out/):
#   ./parallel_vk_regen.sh 47000 8 ./vk_out
#
# Notes:
#   * Each worker gets its own --build-dir <output_dir>/partial_<i>/
#     so the per-worker `vk_map.bin` files don't collide.
#   * If any worker exits non-zero, the merge is still attempted (the
#     successful partials still contribute) but the script returns 1.
#   * Run from the Ziren repo root; the script invokes
#     `cargo run --release --bin {build_compress_vks,merge_vk_maps}`.
#   * Intended for use AFTER #80 (silent crash fix) lands.

set -u  # but NOT -e so partial failures don't abort the merge

if [ $# -lt 3 ]; then
    echo "Usage: $0 <total_shapes> <workers> <output_dir>" >&2
    exit 2
fi

TOTAL_SHAPES=$1
WORKERS=$2
OUT_DIR=$3

mkdir -p "$OUT_DIR"

# Compute per-worker chunk size. Last worker absorbs the remainder.
CHUNK=$(( (TOTAL_SHAPES + WORKERS - 1) / WORKERS ))

echo "[parallel] total=$TOTAL_SHAPES workers=$WORKERS chunk=$CHUNK"
echo "[parallel] output dir: $OUT_DIR"

PIDS=()
LOGS=()
START_TIME=$(date +%s)
for i in $(seq 0 $(($WORKERS - 1))); do
    START=$(( i * CHUNK ))
    END=$(( START + CHUNK ))
    if [ $END -gt $TOTAL_SHAPES ]; then
        END=$TOTAL_SHAPES
    fi
    if [ $START -ge $TOTAL_SHAPES ]; then
        echo "[parallel] worker $i: range empty — skipping"
        continue
    fi
    PARTIAL_DIR="$OUT_DIR/partial_$i"
    LOG="$OUT_DIR/worker_$i.log"
    mkdir -p "$PARTIAL_DIR"
    echo "[parallel] worker $i: --start $START --end $END -> $PARTIAL_DIR (log: $LOG)"
    cargo run --release --bin build_compress_vks -- \
        --build-dir "$PARTIAL_DIR" \
        --start "$START" \
        --end "$END" \
        --num-compiler-workers 1 \
        --count-setup-workers 1 \
        > "$LOG" 2>&1 &
    PIDS+=($!)
    LOGS+=("$LOG")
done

# Wait for all workers, recording exit codes.
FAILED=0
for i in "${!PIDS[@]}"; do
    PID=${PIDS[$i]}
    if wait "$PID"; then
        echo "[parallel] worker $i (pid $PID) OK"
    else
        EXITCODE=$?
        echo "[parallel] worker $i (pid $PID) FAILED with exit code $EXITCODE — see ${LOGS[$i]}" >&2
        FAILED=$(( FAILED + 1 ))
    fi
done

WORK_END=$(date +%s)
echo "[parallel] all workers finished in $(( WORK_END - START_TIME ))s ($FAILED failed of ${#PIDS[@]})"

# Collect all partial vk_map.bin files (skip missing — those are
# from failed workers).
INPUTS=()
for i in $(seq 0 $(($WORKERS - 1))); do
    PARTIAL="$OUT_DIR/partial_$i/vk_map.bin"
    if [ -f "$PARTIAL" ]; then
        INPUTS+=( --input "$PARTIAL" )
    else
        echo "[parallel] note: $PARTIAL missing (worker $i did not produce a vk_map.bin)" >&2
    fi
done

if [ ${#INPUTS[@]} -eq 0 ]; then
    echo "[parallel] no partials to merge — every worker failed" >&2
    exit 1
fi

# Merge into the final output.
MERGED="$OUT_DIR/vk_map.bin"
echo "[parallel] merging into $MERGED"
cargo run --release --bin merge_vk_maps -- "${INPUTS[@]}" --output "$MERGED"
MERGE_EXIT=$?

TOTAL_END=$(date +%s)
echo "[parallel] total wall time: $(( TOTAL_END - START_TIME ))s"

if [ $FAILED -gt 0 ] || [ $MERGE_EXIT -ne 0 ]; then
    exit 1
fi
