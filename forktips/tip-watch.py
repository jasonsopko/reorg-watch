#!/usr/bin/env python3
"""tip-watch.py - regenerate the page as soon as a block lands, not on the minute.

reorg-watch.py runs in about 1.5 s, so there is no reason for a new block to wait up to a
minute to appear. This polls the node's REST tip a few times a minute and regenerates only
when the height actually changes. reorg-watch takes a non-blocking lock, so overlapping with
its own cron run is harmless: whichever is second exits immediately.

Meant to be run once a minute from cron; it loops for just under a minute and exits.

Usage: tip-watch.py [--rest URL] [--page PATH] [--every S] [--for S] [--cmd ...]
"""
import argparse, json, os, socket, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# Refresh the branch view first, so a block and the block that lost to it appear in the
# same reload rather than a minute apart.
TIPS_CMD = [os.path.join(HERE, "chain-tips.py")]

# Must match the crontab line exactly, --notify included: a reorg detected by this path
# has to raise the same alert it would have raised on the minute. The address lives in
# ~/.reorg-watch/mailto (one line); without that file no alert is mailed.
DEFAULT_CMD = [os.path.join(HERE, "..", "reorg-watch.py"),
               "--html", "/var/www/reorg.watch/index.html",
               "--tz", "America/New_York"]
try:
    with open(os.path.expanduser("~/.reorg-watch/mailto")) as _f:
        _to = _f.read().strip()
    if _to:
        DEFAULT_CMD += ["--notify", 'mail -s "reorg-watch ALERT on %s" %s' % (socket.gethostname().split(".")[0], _to)]
except OSError:
    pass


def rest_tip(base):
    with urllib.request.urlopen(base.rstrip("/") + "/chaininfo.json", timeout=8) as r:
        return json.load(r)["blocks"]


def page_tip(page):
    try:
        with open(os.path.join(os.path.dirname(page) or ".", "tip.json")) as f:
            return json.load(f).get("height")
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--page", default="/var/www/reorg.watch/index.html")
    ap.add_argument("--every", type=float, default=2.0)
    ap.add_argument("--for", dest="dur", type=float, default=57.0)
    ap.add_argument("--cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.cmd or DEFAULT_CMD

    deadline = time.monotonic() + args.dur
    while time.monotonic() < deadline:
        try:
            node, shown = rest_tip(args.rest), page_tip(args.page)
            if shown is not None and node != shown:
                # branches first: a losing block is only visible once getchaintips is re-read
                try:
                    subprocess.run(TIPS_CMD, timeout=90,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                except Exception as e:
                    print("%s chain-tips failed: %s"
                          % (time.strftime("%H:%M:%SZ", time.gmtime()), e), flush=True)
                subprocess.run(cmd, timeout=120,
                               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                print("%s block %s -> regenerated (page was at %s)"
                      % (time.strftime("%H:%M:%SZ", time.gmtime()), node, shown), flush=True)
        except Exception as e:
            print("%s %s" % (time.strftime("%H:%M:%SZ", time.gmtime()), e), flush=True)
        time.sleep(args.every)
    return 0


if __name__ == "__main__":
    sys.exit(main())
