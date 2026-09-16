# niflhel

Niflhel runs one OCI application container inside one Firecracker microVM. It provides a Docker-style local CLI, a host service, and a minimal guest agent. Application code runs through runc inside the guest; neither the host service nor the guest agent executes application commands directly.

This is the phase-one implementation. gVisor, TLS interception, destination policy, and credential injection remain phase two and are rejected when requested.

## Build and test

A Linux amd64 host and Go 1.26.8 or newer are required. Go's automatic toolchain selection can download the version pinned in `go.mod`.

```sh
make test
make race
make vet
make build
```

The build produces:

| Binary | Purpose |
| --- | --- |
| `bin/niflhel` | User CLI |
| `bin/niflheld` | Local privileged host service |
| `bin/niflhel-agent` | Statically linked guest init/agent |
| `bin/niflhel-pack` | Base filesystem packager, for an isolated build worker |
| `bin/niflhel-pack-ssh` | Transport packaging inputs/outputs to that worker |

Unit tests run without KVM or root. They cover argument semantics, image integrity, signature trust, OCI layers/whiteouts, path confinement, state transitions, RPC/streams, resource plans, and lifecycle recovery. Tests also exercise the coordinator against a simulated guest through real Unix-socket RPC; those tests do not establish Firecracker isolation.

## Host setup

Running microVMs requires root, `/dev/kvm`, cgroups v2, matching Firecracker/jailer binaries, `ip`, `nft`, and `mkfs.ext4`. Bridge networking requires host IPv4 forwarding. The filesystem holding niflhel state must support hard links, ext4 image files, and allocation of writable disks.

```sh
bin/niflhel doctor
sudo install -m 0755 bin/niflhel bin/niflheld /usr/local/bin/
sudo install -d -m 0755 /etc/niflhel
sudo install -m 0600 packaging/config.example.json /etc/niflhel/config.json
sudo install -m 0644 packaging/systemd/niflheld.service /etc/systemd/system/
```

Edit the configuration before starting the service. Set the installed Firecracker/jailer paths, a default signed base reference, and trusted publisher public keys:

```json
{
  "Root": "/var/lib/niflhel",
  "Socket": "/run/niflhel/niflhel.sock",
  "Firecracker": "/usr/local/bin/firecracker",
  "Jailer": "/usr/local/bin/jailer",
  "DefaultBase": "registry.example.com/team/niflhel-base:1",
  "TrustedKeys": {
    "team-release": "BASE64_ED25519_PUBLIC_KEY"
  },
  "DNSUpstream": "1.1.1.1:53",
  "BootTimeoutSeconds": 60
}
```

The registry and public key above are placeholders. This repository does not publish a stock base or silently trust an arbitrary publisher. An operator must publish/select a trusted base; the next section describes building one.

The socket defaults to mode 0600. To grant trusted local administrators access without running the CLI through sudo, optionally set `"SocketGroup": "niflhel"` and manage that group's membership. This group grants administrative access to the sandbox service.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now niflheld
sudo niflhel info
```

A daemon restart preserves existing VMMs. A host reboot does not automatically restart containers.

## Run applications

Once the service has a trusted default base, missing base/application artifacts download automatically.

```sh
niflhel run --rm python:3.13 python -c 'print("hello")'

niflhel run -d --name web --cpus 2 --memory 512m \
  -p 127.0.0.1:8080:80 nginx:stable
niflhel exec -it web sh
niflhel logs -f web
niflhel stop web
niflhel start web
niflhel rm -f web

niflhel run --rm --network none busybox:1.37 echo offline-network
```

Use `sudo niflhel` when the current user does not have socket access. `NIFLHEL_SOCKET` or `--socket` selects a different local service.

`--memory` limits application memory; the guest adds the base's infrastructure reserve and the host bounds VMM overhead. `--cpus` accepts whole numbers. `--network none` omits the data NIC while exec still uses authenticated vsock.

Bridge mode supplies public IPv4 NAT, a fixed-upstream DNS forwarder, explicit TCP publication, and host/private/metadata/peer isolation. DNS forwarding admits a burst of 512 queries per sandbox and 8,192 process-wide, then limits forwarding to 256 queries/second per sandbox and 4,096 process-wide, with 64 concurrent queries per sandbox and 256 process-wide. Port publication defaults to loopback; `-p 0.0.0.0:8080:80` publishes externally. IPv6 is blocked. Phase one does not implement website filtering.

## Files and volumes

```sh
niflhel volume create --size 4g workspace
niflhel run -d --name dev --network none \
  --mount type=volume,src=workspace,dst=/workspace python:3.13 sleep infinity
niflhel cp ./src/. dev:/workspace/
niflhel exec -w /workspace dev python main.py
niflhel cp dev:/workspace/results/. ./results/
niflhel rm -f dev
niflhel volume rm workspace
```

Writable roots persist across stop/start and are deleted by rm. Named volumes survive container removal and are exclusive to one active sandbox. A failed sandbox retains its volume and VM-memory reservations when VMM termination or cleanup was not confirmed; recovery or `rm` releases them only after confirming cleanup. Writable disks reserve their physical capacity rather than overcommit host free space. Live host bind mounts are unsupported.

In this release, `cp` copies regular files/directories **into a destination directory**, requires a running container, and rejects symlinks/special files. Transfers are capped at 512 MiB and 10,000 entries. This is a narrower contract than Docker's complete cp behavior.

## Application builds and registry authentication

Builds use an explicitly configured BuildKit service. Running prebuilt images requires no Docker/containerd daemon or BuildKit service on the host.

```sh
export BUILDKIT_HOST=unix:///run/buildkit/buildkitd.sock
niflhel build -f Dockerfile -t local/my-agent:dev .
niflhel run --rm local/my-agent:dev
```

For TCP BuildKit endpoints, configure `BUILDKIT_TLS_CA_CERT`, `BUILDKIT_TLS_CERT`, and `BUILDKIT_TLS_KEY`. Build arguments are passed as literal argv, and BuildKit handles Dockerfile stages and .dockerignore. OCI-layout build/load archives share the 512 MiB transfer limit; index, manifest, and application-config metadata are each limited to 4 MiB before privileged parsing. Registry pulls allow larger layer data while applying the same metadata limit.

Existing Docker credential helpers are used for registry pulls. For niflhel-managed login/logout, set `NIFLHEL_CREDENTIAL_HELPER` to an installed helper such as `pass`:

```sh
niflhel login --username USER --password-stdin registry.example.com
niflhel pull registry.example.com/team/app:1
niflhel logout registry.example.com
```

Login reads the password from stdin and stores it through the helper. Registry credentials are never placed in the guest bootstrap or persisted in sandbox metadata.

## Build the first VM base

1. Build the guest binary with `make guest`.
2. Generate a publisher key outside every directory that will be exported to BuildKit: `bin/niflhel base keygen --output ../niflhel-signing-keys --key-id local`. Keep the generated private key on the publisher machine and add the printed public key to the service's `TrustedKeys`.
3. Prepare an isolated Linux build worker with root privileges inside that worker, `mkfs.ext4`, and the built `niflhel-pack` installed at `/usr/local/bin/niflhel-pack`. Configure SSH access to that worker.
4. Configure BuildKit and the packaging transport, then build using an approved amd64 ELF vmlinux:

```sh
export BUILDKIT_HOST=unix:///run/buildkit/buildkitd.sock
export NIFLHEL_BUILD_SSH=root@build-worker
export NIFLHEL_BASE_PACKAGER="$PWD/bin/niflhel-pack-ssh"

niflhel base build -f images/base/Dockerfile \
  --config images/base/base.yaml \
  --kernel /path/to/approved/vmlinux \
  --signing-key ../niflhel-signing-keys/publisher.key --key-id local \
  --firecracker-version 1.16.1 \
  -t registry.example.com/team/niflhel-base:1 .
niflhel base push registry.example.com/team/niflhel-base:1
```

The Firecracker version is a declared qualification target, not a claim that every kernel works with it. The kernel must support virtio block/net/vsock, ext4, OverlayFS, namespaces, cgroups v2, seccomp, and guest routing/NAT. Essential drivers must be built in. Use a kernel whose inputs and configuration your release process records.

Alternatively, replace the kernel reference in the recipe with an approved digest-pinned OCI image containing a **regular** `/boot/vmlinux`, and omit `--kernel`. Essential modules must be included in the rootfs if your kernel needs them.

Base build runs the Dockerfile through BuildKit, packages its filesystem on the isolated worker, signs component descriptors locally, uploads it to the host cache, and runs a VM/exec/stop smoke validation. A failed validation leaves a staged artifact and reports failure. `niflhel base validate REFERENCE` reruns this check. The smoke image is `busybox:1.37`, pinned to its resolved digest during creation.

The base-build command exports private copies of both BuildKit local roots, checking each opened source file against the pinned publisher key before copying. Root replacement and aliases added after staging cannot expose the key to BuildKit. Staging uses a private directory under root-owned, sticky-protected `/tmp`, ignoring `TMPDIR`, and is removed when the command returns.

Each local root is limited to 512 MiB, 10,000 entries and 128 directory levels before `.dockerignore` filtering. Regular-file and directory permission bits are preserved; relative symlinks must resolve within their staged root. Absolute, escaping, dangling or cyclic symlinks and special files are rejected. Keep the key outside both original local roots and keep its directory protected; processes with the publisher's own account privileges remain trusted.

The SSH packager transfers rootfs/kernel data, never the publisher key or host service socket. `NIFLHEL_ISOLATED_BUILD_WORKER=1` is an explicit worker-operation guard, not an isolation mechanism by itself. Release builders should pin the guest distro/package sources and runtime binaries rather than rely on the example Dockerfile's floating distribution tag.

## Validation and implementation notes

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

A real KVM smoke test is available for a disposable configured worker:

```sh
NIFLHEL_INTEGRATION_SOCKET=/run/niflhel/niflhel.sock \
NIFLHEL_INTEGRATION_BASE=registry.example.com/team/niflhel-base:1 \
go test -tags=integration -v ./tests/integration
```

See [implementation notes](docs/implementation-notes.md) for the concrete protocol, security boundaries, and release qualification limits. The original design is in [../design](../design/README.md).
