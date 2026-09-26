#!/bin/sh
# Alert when the reorg-watch page stops updating. Runs from cron on its own,
# because the generator is what sends every other alert: if it stops, nothing
# else would say so. Sends one alert when the page goes stale and one when it
# is fresh again, not one every run.
#
# Usage: freshness-check.sh --page PATH [--max-age SECONDS] --notify CMD
#   CMD gets the message on stdin, like reorg-watch.py --notify.
set -eu
PAGE= MAX_AGE=600 NOTIFY=
while [ $# -gt 0 ]; do
	case "$1" in
		--page) PAGE=$2; shift 2 ;;
		--max-age) MAX_AGE=$2; shift 2 ;;
		--notify) NOTIFY=$2; shift 2 ;;
		*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ -n "$PAGE" ] && [ -n "$NOTIFY" ] || { echo "--page and --notify are required" >&2; exit 2; }
FLAG="${REORG_WATCH_STATE:-$HOME/.reorg-watch}/stale.alerted"

now=$(date +%s)
if [ -e "$PAGE" ]; then age=$((now - $(stat -c %Y "$PAGE"))); else age=$((MAX_AGE + 1)); fi
stamp=$(date -u +%FT%TZ)

if [ "$age" -gt "$MAX_AGE" ]; then
	[ -e "$FLAG" ] && exit 0
	if [ -e "$PAGE" ]; then what="was last written $((age / 60)) minutes ago"; else what="is missing"; fi
	printf '%s: %s %s. The generator has stopped or is failing; check cron and ~/reorg-watch.log.\n' "$stamp" "$PAGE" "$what" | sh -c "$NOTIFY"
	: > "$FLAG"
elif [ -e "$FLAG" ]; then
	printf '%s: %s is updating again.\n' "$stamp" "$PAGE" | sh -c "$NOTIFY"
	rm -f "$FLAG"
fi
