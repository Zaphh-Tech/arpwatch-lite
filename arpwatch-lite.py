#!/usr/bin/env python3
"""
arpwatch-lite — learn the devices on your LAN and alert when something changes.

A small, dependency-free take on the classic `arpwatch`. It builds a baseline of
the (IP, MAC) pairs on your network, then tells you when:

  * a NEW device appears (a MAC it has never seen)
  * an IP flip-flops to a DIFFERENT MAC — the classic signature of ARP spoofing
    / a man-in-the-middle attempt on the LAN

Two ways to observe the network:

  --table  (default, no root)  read the kernel's ARP cache from /proc/net/arp.
           The kernel fills this in passively from normal traffic. Great for a
           one-shot check or a polling watch loop.

  --sniff  (needs root)        open a raw AF_PACKET socket and passively capture
           ARP frames off the wire in real time. Truly passive — sends nothing.

Usage:
    sudo python3 arpwatch-lite.py --sniff
    python3 arpwatch-lite.py --table
    python3 arpwatch-lite.py --watch 30        # re-check the ARP table every 30s
    python3 arpwatch-lite.py --table --json
    python3 arpwatch-lite.py --table --reset    # forget the baseline and relearn

State (the learned devices) is stored as JSON in ~/.arpwatch-lite.json.
Standard library only — no pip install required.
"""

import argparse
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ETH_P_ALL = 0x0003
ARP_PROTO = 0x0806


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


def color(t, c, on=True):
    return f"{c}{t}{C.END}" if on else t


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---- observation sources -------------------------------------------------

def read_arp_table(path="/proc/net/arp"):
    """Return a list of (ip, mac, iface) for COMPLETE ARP entries only."""
    out = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as e:
        sys.exit(f"error: cannot read ARP table at {path}: {e}")
    for line in lines[1:]:  # skip header
        cols = line.split()
        if len(cols) < 6:
            continue
        ip, _htype, flags, mac, _mask, iface = cols[:6]
        # flags 0x2 = complete; skip incomplete / all-zero entries.
        if flags != "0x2" or mac == "00:00:00:00:00:00":
            continue
        out.append((ip, mac.lower(), iface))
    return out


def parse_arp_frame(frame):
    """Decode one Ethernet frame; return (ip, mac, None) if it's ARP, else None."""
    if len(frame) < 42:
        return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != ARP_PROTO:
        return None
    arp = frame[14:]
    # ARP: htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
    sha = arp[8:14]
    spa = arp[14:18]
    mac = ":".join(f"{b:02x}" for b in sha)
    ip = ".".join(str(b) for b in spa)
    return (ip, mac, None)


def sniff(store, state_path, on, emit):
    """Continuously capture ARP frames on a raw socket (root required)."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        sys.exit("error: --sniff needs root (raw socket). try: sudo python3 ...")
    except AttributeError:
        sys.exit("error: --sniff is Linux-only (AF_PACKET). use --table elsewhere.")
    print(color("sniffing ARP passively — Ctrl-C to stop\n", C.GREY, on))
    while True:
        frame = s.recv(65535)
        obs = parse_arp_frame(frame)
        if not obs:
            continue
        ip, mac, iface = obs
        events = process([(ip, mac, "sniff")], store)
        for ev in events:
            emit(ev, on)
        if events:
            save_state(state_path, store)


# ---- core: learn + detect ------------------------------------------------

def process(observations, store):
    """Update the store with observations; return a list of alert events."""
    devices = store["devices"]      # mac -> {ip, iface, first_seen, last_seen}
    bindings = store["bindings"]    # ip  -> mac
    events = []
    ts = now_iso()

    for ip, mac, iface in observations:
        if mac not in devices:
            devices[mac] = {"ip": ip, "iface": iface,
                            "first_seen": ts, "last_seen": ts}
            events.append({"type": "new_device", "mac": mac,
                           "ip": ip, "iface": iface})
        else:
            devices[mac]["ip"] = ip
            devices[mac]["iface"] = iface
            devices[mac]["last_seen"] = ts

        prev = bindings.get(ip)
        if prev and prev != mac:
            events.append({"type": "mac_changed", "ip": ip,
                           "old_mac": prev, "new_mac": mac})
        bindings[ip] = mac

    return events


# ---- state ---------------------------------------------------------------

def default_state_path():
    return str(Path.home() / ".arpwatch-lite.json")


def load_state(path):
    try:
        data = json.loads(Path(path).read_text())
        data.setdefault("devices", {})
        data.setdefault("bindings", {})
        return data
    except (OSError, json.JSONDecodeError):
        return {"devices": {}, "bindings": {}}


def save_state(path, store):
    Path(path).write_text(json.dumps(store, indent=2))


# ---- output --------------------------------------------------------------

def emit_human(ev, on):
    if ev["type"] == "new_device":
        print(color(
            f"[NEW]   {ev['mac']}  {ev['ip']}  ({ev['iface']})",
            C.GREEN + C.BOLD, on))
    elif ev["type"] == "mac_changed":
        print(color(
            f"[ALERT] {ev['ip']} moved {ev['old_mac']} -> {ev['new_mac']}"
            f"  (possible ARP spoofing)", C.RED + C.BOLD, on))


def emit_json(ev, _on):
    print(json.dumps({"time": now_iso(), **ev}))


# ---- main ----------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Learn LAN devices and alert on new ones / ARP spoofing."
    )
    ap.add_argument("--sniff", action="store_true",
                    help="passively capture ARP frames on a raw socket (root)")
    ap.add_argument("--table", action="store_true",
                    help="read the kernel ARP cache once (default, no root)")
    ap.add_argument("--watch", type=int, metavar="SECONDS",
                    help="re-read the ARP table every N seconds in a loop")
    ap.add_argument("--arp-file", default="/proc/net/arp",
                    help="ARP table path (override for testing)")
    ap.add_argument("--state", default=default_state_path(),
                    help="where to store learned devices")
    ap.add_argument("--reset", action="store_true",
                    help="forget the saved baseline before running")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON object per event")
    args = ap.parse_args()

    on = sys.stdout.isatty() and not args.json
    emit = emit_json if args.json else emit_human

    if args.reset and os.path.exists(args.state):
        os.remove(args.state)

    store = load_state(args.state)
    first_run = not store["devices"]

    if not args.json:
        mode = "sniff" if args.sniff else "table"
        print(color(f"\n== arpwatch-lite ({mode}) ==", C.BOLD + C.CYAN, on))
        if first_run:
            print(color("no baseline yet — learning current devices", C.GREY, on))

    if args.sniff:
        try:
            sniff(store, args.state, on, emit)
        except KeyboardInterrupt:
            save_state(args.state, store)
            sys.exit(130)
        return

    def one_pass():
        obs = read_arp_table(args.arp_file)
        events = process(obs, store)
        # On the very first run everything is "new" — that's the baseline, not
        # an incident. Record it silently unless JSON is requested.
        if first_run and not args.json:
            print(color(f"learned {len(obs)} device(s).", C.GREY, on))
        else:
            for ev in events:
                emit(ev, on)
            if not events and not args.json:
                print(color("no changes.", C.GREY, on))
        save_state(args.state, store)

    if args.watch:
        one_pass()  # first pass establishes / reconciles the baseline
        if not args.json:
            print(color(f"watching every {args.watch}s — Ctrl-C to stop", C.GREY, on))
        try:
            while True:
                time.sleep(args.watch)
                obs = read_arp_table(args.arp_file)
                for ev in process(obs, store):
                    emit(ev, on)
                save_state(args.state, store)
        except KeyboardInterrupt:
            save_state(args.state, store)
            sys.exit(130)
    else:
        one_pass()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
