# Experimental Clang/ASan container candidate

**Scope:** The native IHB fuzzer's opt-in local synthetic fixture tests only.
The container is **not** an independently admitted sandbox, not connected to
Tronix, and not authorization for third-party fuzz targets. This Dockerfile
was exercised on Butcher on 2026-10-20; never grant a Tronix daemon or Celix
worker the Docker socket to reproduce these checks.

## Build and pin locally

Requirements: operator-controlled Docker with cgroup v2 memory controller,
network access to the Ubuntu package archive for the *build only*, and space
for the toolchain. The `FROM` line pins the exact Ubuntu 24.04 manifest used
during testing, but apt package versions are **not** pinned to a snapshot.
Subsequent builds may therefore differ; always record the final image ID.

```sh
docker build --pull=false -t ihb/native-fuzz-clang:local \
  -f native_fuzz/container/Dockerfile native_fuzz/container
IMAGE_ID="$(docker image inspect ihb/native-fuzz-clang:local --format '{{.Id}}')"
printf 'Locally built immutable image: %s\n' "$IMAGE_ID"
```

Do not use a mutable image tag for the campaign itself. `isolated.py`
accepts the local `sha256:<image-id>` or an exact
`repository@sha256:<manifest>` and specifies `--pull=never`. The host
operator is responsible for reviewing the image, the Docker daemon, the
fixture scope and the container policy before execution.

## Synthetic acceptance

All output roots below must not exist before running the command.

```sh
mkdir -p /tmp/ihb-seeds-accepted
printf '\000' > /tmp/ihb-seeds-accepted/zero

python3 native_fuzz/isolated.py \
  --image "$IMAGE_ID" --source native_fuzz/fixtures/safe.c \
  --corpus /tmp/ihb-seeds-accepted --out /tmp/ihb-cgroup-safe \
  --runs 96 --seed 17 --seconds 15

# Exit 1 is expected for a discovered, intentionally synthetic ASan failure.
python3 native_fuzz/isolated.py \
  --image "$IMAGE_ID" --source native_fuzz/fixtures/buggy.c \
  --corpus /tmp/ihb-seeds-accepted --out /tmp/ihb-cgroup-buggy \
  --runs 1000 --seed 17 --seconds 15
```

**Never execute the deliberate `fixtures/oom.c` outside a memory-bounded
disposable container.** It touches approximately 1 GiB of physical memory
and can disrupt an unconfined host. An operator can exercise the negative
control with `--memory-mb 512 --runs 1` and a fresh output root.
The exact expected classification is `cgroup_oom_kill` only when the
dedicated, finite cgroup v2 `memory.events.local` counter shows an OOM kill
and the target failed via SIGKILL. Direct host execution does not enable this
classification. A mere SIGKILL without that evidence remains a generic
failure, not an asserted OOM.

The wrapper applies cgroup memory/swap, pids and CPU budgets, denies networking,
drops Linux capabilities, selects a read-only container root and input mounts,
and writes to a private new output directory. These options do **not** prevent
every possible host escape or guarantee disk quota, image trust, target authority,
daemon integrity or cleanup on every infrastructure failure. The controller's
Docker privileges remain outside Tronix. Run only synthetic fixtures until
independently reviewed.

## Local acceptance evidence (2026-10-20)

A separate `acceptance-container-20261020.json` records the Butcher test
image identity, fixture hashes, statuses and local evidence manifest digests.
The raw proof directories remain on the Butcher host, not in Git history.
The result is **local, unsigned validation**, not hosted CI or security attestation.
The operator also ran `container/restrictions_probe.py` in the same restricted
container profile with a 512 MiB memory ceiling, confirming at the time of
the test: nonroot UID, zero effective capabilities, read-only root,
non-routable external networking, an absent host SSH directory mount,
and the configured memory and PID cgroup ceilings. These are **negative smoke
checks**, not a complete sandbox security review or guarantee that another
kernel/container setup behaves identically.

The original engine still uses `fork` as a state-reset mechanism; that is not
a sandbox. AddressSanitizer reserves substantial virtual address space, so
the container's cgroup physical memory ceiling is **not** interchangeable
with a small `RLIMIT_AS`. Tronix's existing 1 GiB virtual address-space worker
limit must not be applied directly to ASan campaigns.

The next gate is admission of a separate, unprivileged executor and immutable,
reviewed campaign profiles before any Tronix broker/adapter starts a campaign.
