#!/bin/bash
# Test double for /usr/sbin/colatrl, used only by the systemd-lifecycle CI job.
#
# Real "colatrl start" needs a genuine IPv6-only NAT64/DNS64 network and BPF,
# neither of which exist on a CI runner. This stub honors the same CLI and
# /run/colatrl/state contract (see colatrl's cmd_start/process) so the
# *systemd unit's* orchestration (ExecStartPre, Restart=on-failure,
# RemainAfterExit) can be exercised deterministically, without asserting
# anything about real CLAT functionality.
set -euo pipefail

state_dir=/run/colatrl
state_file="$state_dir/state"
log_file="$state_dir/lifecycle-test.log"
fail_sentinel="$state_dir/fail-next-start"

mkdir -p "$state_dir"

case "${1:-}" in
  start)
    if [[ -f "$fail_sentinel" ]]; then
      rm -f "$fail_sentinel"
      echo "start: simulated failure" >> "$log_file"
      exit 1
    fi
    printf 'stub-dev\nstub-dev4\nstub-dev6\n' > "$state_file"
    echo "start: ok" >> "$log_file"
    ;;
  stop)
    if [[ -f "$state_file" ]]; then
      echo "stop: state-file $(tr '\n' ',' < "$state_file")" >> "$log_file"
      rm -f "$state_file"
    else
      echo "stop: fallback" >> "$log_file"
    fi
    ;;
  *)
    echo "Need start, stop, or status." >&2
    exit 1
    ;;
esac
