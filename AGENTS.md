# Working on niflhel

These instructions apply to this repository and its subdirectories.

## Context and sources

Niflhel provides a Docker-style CLI for running one OCI application container per Firecracker microVM. Phase one uses runc inside the VM. Keep the implementation small and preserve the separation between application images and the guest infrastructure base.

Read [README.md](README.md) for setup and supported commands, and [docs/implementation-notes.md](docs/implementation-notes.md) for current implementation choices and qualification gaps. The original design lives in the sibling [../design](../design/README.md) directory, particularly architecture.md, cli.md, images.md, and implementation.md. That directory may be absent in a standalone checkout. Some design text describes the repository before implementation; do not treat proposed layouts or behavior as existing code. Resolve discrepancies using the code and implementation notes, and document intentional changes.

The sibling Ignite checkout is a reference for OCI packaging and VM lifecycle concepts. Do not introduce its historical host runtime, device-mapper, GitOps, or Kubernetes API machinery. Implementation belongs here; avoid changing sibling repositories unless the task calls for it.

## Repository map

| Location | Responsibility |
| --- | --- |
| `cmd/niflhel`, `internal/cli` | Cobra CLI, sessions, registry credentials, BuildKit orchestration |
| `cmd/niflheld`, `internal/daemon` | Host service, lifecycle coordination, admission, recovery, result retention |
| `cmd/niflhel-agent`, `internal/guest` | Guest PID 1, OCI unpacking, container supervision and IO |
| `internal/runtime` | Guest runc configuration and application process identity |
| `internal/api`, `internal/wire` | Shared validation/models and bounded JSON RPC/stream transport |
| `internal/state` | SQLite metadata, state transitions, durable operation intents |
| `internal/oci`, `internal/base` | Application content cache and signed VM base bundles |
| `internal/firecracker` | Jailer/VMM setup, process identity, authenticated vsock |
| `internal/network`, `internal/storage` | Owned network resources and ext4 disks/volumes |
| `internal/fsutil`, `internal/filecopy`, `internal/journal` | Confined filesystem operations, transfers, bounded logs |
| `cmd/niflhel-pack`, `cmd/niflhel-pack-ssh` | Isolated base packaging and SSH worker transport |
| `images/base`, `packaging` | Base recipes, service configuration and systemd unit |
| `tests/integration` | Explicitly enabled real Firecracker smoke test |

Keep lifecycle sequencing and durable state changes in the coordinator. Resource adapters should manage resources by sandbox identity and generation, rather than independently driving lifecycle transitions. Keep shared protocol changes compatible across CLI, daemon, and guest, or explicitly version and reject incompatible peers.

## Invariants to preserve

- Each sandbox owns one VM and one application container. Both the initial application command and exec processes run in that container, never as host processes or unrestricted guest commands. The guest agent is infrastructure and requires PID 1.
- The local service socket grants administrative access. Preserve restrictive socket permissions and explicit optional group access; this is not a remote or hostile-local-user multi-tenant API.
- Run Firecracker through jailer with the intended namespaces, UID and cgroups. Confirm process identity and termination before deleting resources or reusing leases. Cleanup must only touch resources owned by the sandbox.
- Persist operation intent and support recovery across allocation/start/remove boundaries. Preserve daemon-restart adoption, generation checks, volume exclusivity and idempotent cleanup. Report unknown exits honestly after lost state or host reboot.
- Keep application layers opaque on the host; unpack and verify them in the guest. Never mount guest-written filesystems on the host. Base unpacking belongs on an isolated packaging worker. Its environment guard is not itself isolation.
- Verify content digests, signed base descriptors, trusted keys, platform, protocol and declared VMM compatibility. Local base identity is the signed-envelope digest, not the registry manifest digest. Preserve references when removing shared cache content.
- Preserve per-boot TLS 1.3 mutual authentication over vsock. Do not expose bootstrap credentials, control sockets or AF_VSOCK to the application container. Keep registry credentials and publisher private keys out of guest state and logs.
- Preserve container namespaces, no_new_privileges, seccomp, capability/device restrictions and resource bounds. Do not solve compatibility failures by silently disabling isolation.
- Bound RPC frames, archive expansion, file counts, transfers, disks, logs and waits. Confine filesystem access with directory descriptors/openat2; lexical path checks alone do not protect against symlinks.
- Stop/start preserves writable disk state, not process memory. Named volumes survive container removal. Writable disks reserve physical space; jail/image/state hard links require a shared filesystem.
- Bridge networking provides public IPv4 NAT with host/private/metadata/peer isolation and explicit TCP publication, defaulting to loopback. No-network mode must still support exec over vsock. Preserve IPv6 blocking.

## CLI and scope

Preserve literal argv and OCI Entrypoint/Cmd, environment, user and workdir semantics. Keep stdout/stderr distinct without a PTY, propagate exit status, and distinguish detach/disconnect from stopping the workload. Do not replay an exec when its outcome is uncertain.

Implement the documented Docker subset. Reject unsupported flags and security features before boot instead of ignoring them. Current deliberate differences include directory-destination file copy with no symlinks/special files, a 512 MiB/10,000-entry copy limit, record-based log tails, no anonymous image-volume creation, and unsupported image health checks. Update CLI help, tests and documentation together when changing these contracts.

Phase two adds gVisor **inside Firecracker** and host-enforced DNS/domain policy, a TLS-aware proxy and credential injection. Do not implement or claim those features as an incidental phase-one change. Requests for unsupported runtime/policy options must fail explicitly, with no fallback to weaker enforcement. Phase-one NAT does not restrict websites. Remote orchestration, managed builders, snapshots and VM pooling are later work.

Builds use an explicitly configured BuildKit endpoint and isolated base packager. Running existing images must not acquire a host Docker/containerd daemon dependency. Example base recipes and registry placeholders are not published, qualified release artifacts.

## Development and validation

Use Linux amd64 and the Go toolchain declared in `go.mod` (currently 1.26.8). Keep dependency changes intentional and commit matching `go.sum` changes. Follow existing package conventions, format Go changes, and add meaningful regression tests for behavior changes, including failure paths at trust and lifecycle boundaries.

Run from the repository root for implementation changes:

```sh
make fmt
make test
make race
make vet
make build
```

The build produces five binaries in `bin/`; the guest binary is statically built with CGO disabled. Unit/RPC tests run without root or KVM. Use temporary directories and injected adapters for ordinary tests. Do not require real registry credentials, a live daemon, or privileged host mutation in the unit suite. Documentation-only changes need link/content checks rather than a full runtime test run.

For dependency changes, also run the vulnerability check documented in README.md and distinguish reachable findings from unused-module advisories. Do not commit generated binaries, caches, ext4 images, credentials or signing keys.

Real integration tests require a disposable Linux worker with a configured privileged daemon, usable KVM, matching Firecracker/jailer, cgroups v2, networking/storage tools and a trusted base:

```sh
NIFLHEL_INTEGRATION_SOCKET=/run/niflhel/niflhel.sock \
NIFLHEL_INTEGRATION_BASE=YOUR_TRUSTED_BASE_REFERENCE \
make integration
```

Without both variables, the integration test skips. A skipped test or passing mocks is not evidence of VM isolation. Changes to boot, guest mounts, networking, cgroups, PTYs or VMM recovery need real KVM qualification; clearly report when that validation cannot run. The original implementation environment lacked jailer and usable KVM permissions, so existing unit/build results do not establish real-VM correctness.

When reporting work, state what changed, the checks actually run, and remaining limitations. Keep README.md and implementation notes aligned with behavior; do not claim full Docker compatibility, security qualification or performance measurements without supporting evidence.
