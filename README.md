# elos-bpf-scanner

This is currently a proof of concept to attach a BPF and create events inside
the Linux kernel and publish them through a BPF-scanner.

This example demonstrates:

* How to write and build a BPF program.
* How to load BPF programs from a elos plugin
* How to send elos events from kernel space back to an elos-scanner in the
  user space

# Build

Install dependencies

* libbpf
* elos
* clang (to compile BPF programs)

```sh
cmake -B build -DCMAKE_INSTALL_PREFIX:PATH=/usr
make -C build
sudo make -C build install
```

# Run

* Add BPF-Plugin in elosd config.

```json
...
"Scanner": {
    "Plugins": {
        "BPF": {
          "File": "scanner_bpf.so",
          "Run": "always"
        },
        ...
    }
...
```

* Run elosd as root

```sh
sudo elosd
```

* subscribe to elos event created by the BPF running in the kernel space.

```sh
elosc -s ".e.messageCode 2700 EQ"
```

* trace BPF printks 

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
