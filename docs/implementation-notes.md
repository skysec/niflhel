# Phase-one implementation notes

## Implemented boundaries

The runtime path is CLI → root-owned Unix socket → niflheld → jailer/Firecracker → authenticated vsock → guest init/agent → runc → one application container. Exec creates another process in that existing container. The guest executable refuses to run unless it is PID 1.

Host image download leaves application layer contents opaque. Before privileged decoding, registry and layout index/manifest/application-config metadata is limited to 4 MiB per object with aggregate JSON token, depth, and string budgets; signed base metadata is limited to 1 MiB. The guest verifies compressed digests and uncompressed DiffIDs, bounds expansion/inodes, and uses containerd's maintained archive package to apply OCI whiteouts and metadata. The host never mounts guest-written filesystems.

Firecracker runs in a separate PID namespace and a jailer mount namespace, with an assigned UID, cgroups, and a private network namespace in bridge mode. Host boot ID plus PID start identity, pidfds, and an exact sandbox-cgroup check before signaling protect lifecycle cleanup from cross-boot aliases, PID reuse, and the launch/persist crash window. Legacy start-tick-only records are adopted only through the same cgroup check. The Unix service socket is an administrative capability; this is not a hostile-local-user multi-tenant API.

Each boot generates a unique TLS CA and host/guest key pair. The guest receives its own certificate/key and public CA only. Control uses TLS 1.3 mutual authentication over the Firecracker vsock CONNECT transport. Container socket syscalls exclude AF_VSOCK, and the container has no bootstrap/device/control-socket mounts.

The application OCI spec uses separate namespaces, no_new_privileges, a default-deny syscall profile, bounded memory/CPU/PIDs, a limited capability/device set, and read-only protected kernel paths. Optional named volumes are explicitly mounted. The guest runtime remains runc; requesting runsc fails.

## Concrete choices relative to the proposal

- **RPC:** bounded, versioned JSON RPC with duplex frame streams over Unix sockets/vsock. This initial implementation uses JSON rather than generated protobuf. Control uses /v1/call and IO uses a niflhel HTTP upgrade at /v1/session. Frames are limited to 1 MiB.
- **Base signing:** Ed25519 signs the canonical configuration containing component digests, sizes, platform, protocol, runtime, and qualified VMM versions. The signed envelope is the OCI artifact config; non-canonical base64 signatures are rejected before identity is computed. Pull verifies that manifest descriptors match signed descriptors. The local base identity is the canonical signed-envelope digest; it is distinct from the registry manifest digest.
- **Storage:** ext4 raw disks. Writable disks reserve physical space with fallocate; immutable carrier/base files are read-only. All jail/image/state files must reside on one filesystem for hard linking. Stop/start preserves the upper layer, not memory/process state.
- **Resource admission:** memory checks conservatively compare all active VM reservations against currently available memory, with an additional host reserve. Failed sandboxes retain VM-memory and named-volume reservations when VMM termination or cleanup was not confirmed; recovery and removal release them only after confirmed cleanup. Legacy failed records default to this quarantined state. This may reject a workload earlier than a more sophisticated allocator.
- **File copy:** regular files/directories only, destination-directory semantics, no symlinks/special files, running containers only, 512 MiB/10,000-entry cap. openat2 confines traversal to an open root descriptor.
- **Logs:** stdout/stderr are distinct without a PTY. Journals rotate and expose sequence gaps. --tail counts retained stream records rather than reconstructed text lines. Auto-removed results/logs are retained for up to 24 hours, at most 128 results and 256 MiB, so late wait/attach can receive output/status. Expiry is enforced at startup, before retained-result lookup, after saves, and by periodic maintenance; reads reject expired records even if physical deletion fails.
- **Builds:** an explicit BuildKit endpoint and isolated filesystem packaging worker are dependencies only for builders. Publisher keys must be outside both original BuildKit local roots. Base builds pin the key inode and copy both roots into a private directory under protected `/tmp` (ignoring `TMPDIR`); only those copies are passed to BuildKit. Source entries are opened relative to pinned directory descriptors without following symlinks, and their actual inode is compared with the pinned key before any bytes are copied. Each root is bounded to 512 MiB, 10,000 entries and 128 directory levels before `.dockerignore`; only regular files, directories and relative symlinks resolving within the staged root are accepted. This closes the reported export-root replacement and late hard-link race. Snapshot preparation is not an atomic filesystem snapshot: concurrent ordinary file edits may produce mixed build inputs, but later source changes cannot alter the exported copies. Publisher-account processes and root remain trusted. An included SSH wrapper performs worker transport. Build/load archives share the copy size cap. No managed build service or published default base is provisioned by this repository.
- **DNS admission:** the fixed-upstream proxy shares UDP/TCP token and concurrency admission per sandbox and across the daemon. UDP receives into a reused fixed buffer and allocates retained work only after admission. These bounds protect daemon resources; they are not destination policy.
- **Images:** the image/base rm commands remove the selected digest and its local aliases after checking sandbox references. Shared blobs are retained while other cached images reference them.
- **Metadata:** image health checks are reported as unsupported. Image-declared volume paths remain in the writable root unless explicitly mounted; no anonymous volume creation/copy-up occurs.
- **Security updates:** component versions are pinned in go.mod. A base's own kernel and runc packages require separate release qualification and patching.

## Failure handling

SQLite stores durable sandbox metadata and operation intents. Per-sandbox locks serialize lifecycle actions; allocation locks guard names, slots, ports, and volume ownership. The daemon reconnects to surviving VMMs and resumes guest log cursors after restart. Interrupted incomplete operations are terminated/cleaned and retained as failed for inspection/removal. Host reboot produces an unknown application exit reason; it does not fabricate success or auto-restart workloads.

Missing artifacts, signature mismatches, unsupported options, wrong platform, failed KVM/jailer checks, port/route conflicts, and resource exhaustion produce errors. Failed creation removes partial writable disks. Removal refuses live VMMs unless forced and confirms termination before releasing network/storage ownership.

Guest exit is journaled before VM shutdown. The host asks for guest sync/shutdown before using a bounded forced-stop fallback. A forced stop can report unknown workload status. Console output is consumed by an independent rotating-log helper so it remains bounded across daemon restarts.

## Qualification still required

The checked-in unit/RPC tests and build checks do not prove host isolation or application compatibility under real Firecracker. A root-capable disposable KVM worker is required to validate the integration test, nftables behavior on supported hosts, guest kernel configuration, PTYs, runc startup, base builds, and load/fault scenarios.

In the implementation environment, Firecracker was installed but jailer was absent, the current user could not open /dev/kvm, and noninteractive sudo was unavailable. Real VM boot/network tests were therefore not run there. The example base is a build recipe, not a prequalified published release artifact.

Further release qualification should cover sustained/concurrent workloads, every allocation crash boundary, disk corruption recovery, runtime-specific syscall compatibility, and measured performance. Do not infer those results from passing unit tests. Phase-two proxy/DNS policy and gVisor are intentionally outside this implementation.

The [2026-09-16 security report follow-up](security-review-2026-09-16.md) records the BuildKit export-root race fix, regression coverage, and validation limits.
