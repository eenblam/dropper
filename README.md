# dropper
...this name may not stick.

A simple Linux firewall using Go and eBPF to hook XDP.

```bash
go generate
go build .
sudo ./dropper
```
Debug logs: `sudo cat /sys/kernel/debug/tracing/trace_pipe`.
(You may need to `sudo mount -t debugfs none /sys/kernel/debug` if it's not already there.)

Currently, rules are just received via STDIN:
* `+1.2.3.4` will block all that pesky incoming traffic from `1.2.3.4`.
* `+1.0.0.0/8` will add a rule to block a rather large network.
* `-1.0.0.0/8` wlil remove the previous rule.
* Rules are stored a longest-prefix-match trie, so redundant rules are ignored, but overlapping rules are not. (e.g. `+1.2.3.4` and `+1.2.3.0/24` can be added and removed independently.)
* I'm currently only hooking into XDP, so I'm not blocking outbound packets yet.

(It's rather annoying to try and type rules into STDIN while data is spewing out.
I'll add a different input soon, and also reduce the log spray.
A lot of the current logs are just stand-ins for things that aren't being otherwise used yet.)