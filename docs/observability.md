# Validator Observability

The default validator run now records Docker resource samples for every matrix
entry and publishes these artifacts:

- `resource-usage.json`: calculated CPU, memory, PID, and network summary
- `docker-stats.jsonl`: raw `docker stats --no-stream --format '{{json .}}'` samples
- `log-events.json`: timestamped stdout/stderr lines for timeline annotations
- `timeline.json`: dashboard-ready 10 second resource buckets, log annotations,
  DNS queries, and network flows
- `ebpf/tooling.json` and `ebpf/tooling.log`: non-invasive preflight showing whether capture tools were available
- `ebpf/capture-status.json` and `ebpf/capture.log`: capture process status and startup/cleanup log
- `ebpf/dns-queries.tsv`: derived DNS query report, when collected
- `ebpf/network-flows.json`: packet-derived per-flow RX/TX bytes plus min/max rates over time, when collected
- `ebpf/tcp-flows.json`: BCC-derived per-flow RX/TX bytes plus min/max rates over time, when collected
- `ebpf/tcp-bps.log` and `ebpf/tcp-life.log`: best-effort BPF byte/connection reports, when collected
- `ebpf/syscalls.log` and `ebpf/memory-allocations.log`: syscall and allocation traces, when collected

The dashboard surfaces peak processor cores and peak RAM for each validator,
plus one timeline chart per validator below the validator table. Each chart
uses `timeline.json` as its browser-facing source for resource graphs,
Gantt-style network-flow overlays, DNS labels, and hoverable stdout/stderr
event dots.
Use `resource-usage.json` as the sizing input for routine capacity planning:

- `peakMemoryBytes`: minimum RAM headroom for the observed run
- `meanMemoryBytes`: steady-state RAM estimate
- `peakProcessorCores`: peak CPU core demand, derived from Docker CPU percent
- `meanProcessorCores`: steady-state CPU core demand
- `meanNetworkRxBps` and `meanNetworkTxBps`: average container network rate during the sampled window

## Privileged eBPF Capture

The GitHub Actions workflow attempts this automatically when the tooling
preflight reports `canAttemptCapture=true`. It requires passwordless `sudo`
or root privileges plus kernel tracing support.

Install tools on Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y bpfcc-tools bpftrace tcpdump tshark linux-tools-common linux-tools-generic
```

Start one validator in a terminal:

```sh
python3 scripts/run_validator.py --config validators.yml --entry-id routinator-0_15_2 --output out/routinator-0_15_2
```

In another terminal, find the running container and init PID:

```sh
container="$(docker ps --format '{{.Names}}' | awk '/^rpki-routinator-0_15_2-/ {print; exit}')"
pid="$(docker inspect -f '{{.State.Pid}}' "$container")"
container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")"
mkdir -p "out/routinator-0_15_2/ebpf"
```

Capture DNS queries and responses:

```sh
sudo tcpdump -i any -nn -s 0 -w "out/routinator-0_15_2/ebpf/dns.pcap" "((udp port 53 or tcp port 53) and host $container_ip)"
tshark -r "out/routinator-0_15_2/ebpf/dns.pcap" -Y dns -T fields -E separator=/t \
  -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport \
  -e dns.qry.name -e dns.a -e dns.aaaa -e dns.cname \
  -e dns.flags.response -e dns.qry.type \
  > "out/routinator-0_15_2/ebpf/dns-queries.tsv"
```

Keep `dns.pcap` local for investigation only. The workflow uploads
`dns-queries.tsv`, not the full packet capture. DNS response flags and query
types are used for timeline labels, while DNS answer fields are used to
annotate packet-derived network flows with `candidateDnsNames`.

Capture packet headers for protocol, host, port, byte, and rate accounting:

```sh
sudo tcpdump -i any -nn -s 128 -w "out/routinator-0_15_2/ebpf/network.pcap" "((tcp or udp) and host $container_ip)"
tshark -r "out/routinator-0_15_2/ebpf/network.pcap" -Y 'tcp or udp' -T fields -E header=y -E separator=/t \
  -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e dns.qry.name \
  > "out/routinator-0_15_2/ebpf/network-packets.tsv"
python3 scripts/observability.py summarize-packets \
  --input "out/routinator-0_15_2/ebpf/network-packets.tsv" \
  --output "out/routinator-0_15_2/ebpf/network-flows.json" \
  --container-ip "$container_ip" \
  --dns-input "out/routinator-0_15_2/ebpf/dns-queries.tsv"
```

Keep `network.pcap` and `network-packets.tsv` local for investigation only.
The workflow uploads `network-flows.json`, not the raw packet capture.

Capture per-IP/port TCP throughput and lifetimes:

```sh
sudo tcptop-bpfcc -p "$pid" -C 1 > "out/routinator-0_15_2/ebpf/tcp-bps.log"
python3 scripts/observability.py summarize-tcptop \
  --input "out/routinator-0_15_2/ebpf/tcp-bps.log" \
  --output "out/routinator-0_15_2/ebpf/tcp-flows.json"
sudo tcplife-bpfcc -p "$pid" > "out/routinator-0_15_2/ebpf/tcp-life.log"
```

Capture syscall volume:

```sh
sudo syscount-bpfcc -p "$pid" -L > "out/routinator-0_15_2/ebpf/syscalls.log"
```

Capture allocation stacks. This is best effort: stripped binaries, static
linking, allocator choice, and missing symbols can limit stack quality.

```sh
sudo memleak-bpfcc -p "$pid" -a > "out/routinator-0_15_2/ebpf/memory-allocations.log"
```

The eBPF output is intentionally not enabled in the default daily workflow:
host kernel permissions, BCC availability, and packet capture policy vary
across runners. Use it for focused profiling runs, then compare against the
always-published `resource-usage.json` sizing numbers.
