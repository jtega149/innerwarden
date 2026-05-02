Raw Ethernet packet corpus for the sensor collector harness.

Each `.hex` file stores one complete Ethernet frame encoded as lowercase
hexadecimal with whitespace ignored by the test loader. The fixtures avoid
pcap parser dependencies while still exercising the same packet parsers used by
the AF_PACKET collectors.

Run:

```sh
cargo test -p innerwarden-sensor --test collector_packet_corpus
```

The privileged end-to-end variant still requires a Linux host or VM with
CAP_NET_RAW for DNS/HTTP/TLS capture and CAP_BPF/CAP_PERFMON for eBPF syscall
capture. Use this corpus first for deterministic CI coverage, then run the live
collector smoke manually on a capable Linux test host.
