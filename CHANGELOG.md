# Changelog

All notable changes to the DNSFlux project will be documented in this file.

---

## [v1.3.0] - 2026-06-17

This release introduces significant bug fixes, new features for the Linux eBPF monitor, and package refactoring for better encapsulation.

### Added
- **Linux DNS Response Monitoring**: Added DNS response packet parsing (`QR=1`) in the Linux collector. It can now extract resolved IPv4 (A), IPv6 (AAAA), and CNAME answers.
- **Process-Response Correlation**: Implemented IP/port swapping in the eBPF socket filter for response packets. This links incoming DNS answers back to the originating process details (PID, Process Name, and Path) in real-time.
- **ASCII Startup Logo**: Integrated a beautiful ASCII startup logo and dynamic version display at program startup.

### Fixed
- **eBPF Compilation & Go 1.20 Compatibility**: Resolved Go compilation errors and library dependency conflicts on older host environments by downgrading `cilium/ebpf` to `v0.11.0`, removing the `toolchain` directive, and targeting Go 1.20 in `go.mod`.
- **UDP Autobind Logic**: Fixed the logic error where unbound client UDP DNS queries were labeled as `"unknown"` processes. It now temporarily registers sockets using a `kprobe` + `kretprobe` pattern on `udp_sendmsg` and matches them once ports are allocated.
- **BPF Verifier Error (`invalid zero-sized read`)**: Resolved bounds-checking verifier errors by applying a bitwise AND boundary check (`len &= 0x1FF`) and calling `bpf_skb_load_bytes()` before structure truncation.
- **BPF Verifier Error (`no space left on device`)**: Fixed `ENOSPC` errors during loading by removing verbose `LogLevelInstruction` logging from the default eBPF collection options.
- **TCP DNS Length Parsing**: Corrected TCP packet offset extraction by skipping the 2-byte message length prefix required by the TCP DNS protocol.
- **Duplicate Collector Declaration**: Removed duplicate definitions of `NewPlatformCollector()` in `interface.go` to fix compile-time redeclaration errors.

### Refactored
- **Internal Configuration Encapsulation**: Refactored the codebase by moving versioning and startup flags logic from the public `pkg/version` and `pkg/flag` directories to the internal `internal/config` module, cleaning up public packages.

---

## [v1.2.0] - 2024-01-15

Initial cross-platform release with Windows ETW DNS monitoring support.

### Added
- **Windows ETW Collector**: Added support for Windows DNS monitoring using ETW (`Microsoft-Windows-DNS-Client` provider). Runs with standard user privileges.
- **Linux eBPF Collector**: Initial eBPF collector implementation using Kprobes on `udp_sendmsg` and `tcp_sendmsg`.
- **Web Interface Dashboard**: Integrated a web server providing a responsive, real-time data table, statistics, and domain search filters.
- **Output & Storage**: Supported real-time console formatting and automated background JSON log archiving.
