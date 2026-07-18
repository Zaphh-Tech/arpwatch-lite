# arpwatch-lite

Learn the devices on your LAN and get alerted when something changes — a
small, dependency-free take on the classic [`arpwatch`](https://ee.lbl.gov/).

`arpwatch-lite` builds a baseline of the `(IP, MAC)` pairs on your network, then
tells you when:

- a **new device** appears (a MAC it has never seen), and
- an **IP flip-flops to a different MAC** — the classic signature of ARP
  spoofing / a man-in-the-middle attempt on the local network.

## Demo

<!-- Record a baseline run, then a new-device + spoofing alert, and drop the
     file here. Replace this line with:  ![arpwatch-lite demo](demo.gif) -->

_Demo GIF coming soon._

## Why

Everything on a LAN trusts ARP, and ARP has no authentication — which is exactly
why ARP spoofing is still one of the easiest ways to MITM a local network.
arpwatch-lite gives you a passive early-warning tripwire: it never sends a
packet, it just watches who's talking and notices when a known IP suddenly
answers from a new MAC.

## Two ways to watch

| Mode | Root? | How it observes |
|---|---|---|
| `--table` (default) | no | reads the kernel ARP cache (`/proc/net/arp`), which the kernel fills in passively from normal traffic |
| `--sniff` | yes | opens a raw `AF_PACKET` socket and captures ARP frames off the wire in real time (Linux) |

Both feed the same "learn + detect" core. `--table` is perfect for a cron job or
a polling watch loop; `--sniff` catches things the moment they hit the wire.

## Install

```bash
git clone https://github.com/<you>/arpwatch-lite
cd arpwatch-lite
```

No pip install — Python 3 standard library only.

## Usage

```bash
# one-shot check of the kernel ARP table (no root)
python3 arpwatch-lite.py --table

# re-check every 30 seconds and stream alerts
python3 arpwatch-lite.py --watch 30

# real-time passive capture (needs root)
sudo python3 arpwatch-lite.py --sniff

# machine-readable event stream (one JSON object per alert)
python3 arpwatch-lite.py --table --json

# forget the baseline and relearn from scratch
python3 arpwatch-lite.py --table --reset
```

## Example

```
== arpwatch-lite (table) ==
[NEW]   de:ad:be:ef:00:75  192.168.1.75  (eth0)
[ALERT] 192.168.1.1 moved aa:bb:cc:00:00:01 -> 66:66:66:66:66:66  (possible ARP spoofing)
```

The first run is silent about individual devices — it just learns the current
network as the baseline. Every run after that reports only what changed.

## How it works

1. **Observe** — pull `(ip, mac)` pairs from `/proc/net/arp` (complete entries
   only) or decode ARP frames from a raw socket.
2. **Learn** — the first pass records everything to `~/.arpwatch-lite.json`.
3. **Detect** — later passes compare against the baseline: an unseen MAC is a
   new device; an IP that changes MAC is a spoofing signal.

The state file is plain JSON, so you can inspect or edit the learned inventory.

## Notes

- `--sniff` is Linux-only (`AF_PACKET`) and needs root or `CAP_NET_RAW`. Use
  `--table` on other platforms or when you can't run as root.
- Only monitor networks you own or are authorized to observe.

## License

MIT
