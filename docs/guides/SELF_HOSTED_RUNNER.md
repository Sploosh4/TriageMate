# TriageMate self-hosted GitHub Actions runner

**Installed:** 13 July 2026
**Status at handoff:** Online and validated
**GitHub runner:** `triagemate-vm`
**Workflow routing:** Merged to `main`; TriageMate CI uses this runner selector

## What was installed

TriageMate CI has a repository-scoped GitHub Actions runner hosted in an isolated Ubuntu 24.04 KVM virtual machine on the development computer. The VM prevents workflow code and Docker jobs from receiving direct access to the desktop operating system and personal files.

```text
GitHub Actions
      | outbound HTTPS
      v
triagemate-runner VM
  - GitHub runner service
  - Docker Engine
  - 8 vCPUs / 12 GiB RAM
  - 60 GiB sparse disk
      |
      v
KVM/libvirt on the Ubuntu host
```

The VM uses libvirt's `default` NAT network. It initiates its connection to GitHub; no router port forwarding or inbound Internet exposure was configured.

## Host changes

Installed Ubuntu packages: `qemu-kvm`, `libvirt-daemon-system`, `libvirt-clients`, `virtinst`, and `cloud-image-utils`.

The local user `jpc` was added to the `libvirt` group. A sign-out/sign-in is required once to refresh group membership in the desktop session.

| Purpose | Location |
|---|---|
| Management command | `~/.local/bin/triagemate-runner` |
| SSH private key | `~/.ssh/triagemate_runner_ed25519` |
| SSH public key | `~/.ssh/triagemate_runner_ed25519.pub` |
| Download and cloud-init workspace | `~/.local/share/triagemate-runner/` |
| VM disk | `/var/lib/libvirt/images/triagemate-runner.qcow2` |
| Cloud-init seed | `/var/lib/libvirt/images/triagemate-runner-seed.iso` |

The downloaded Ubuntu cloud image was checked against Ubuntu's published SHA-256 checksum before the VM was created.

## Guest configuration

| Setting | Value |
|---|---|
| VM name and hostname | `triagemate-runner` |
| Login user | `runner` |
| vCPUs | 8 |
| Memory | 12 GiB |
| Virtual disk | 60 GiB sparse qcow2 |
| VM autostart | Enabled |
| Guest SSH password login | Disabled |
| Docker | Enabled and started |
| GitHub runner directory | `/opt/actions-runner` |
| Runner service | `actions.runner.Sploosh4-TriageMate.triagemate-vm.service` |

The runner is scoped only to the private `Sploosh4/TriageMate` repository and carries labels `self-hosted`, `Linux`, `X64`, and `triagemate`.

## Routine operation

After signing out and back in:

```bash
triagemate-runner status
triagemate-runner ssh
triagemate-runner stop
triagemate-runner start
triagemate-runner restart
```

Stopping the VM takes the runner offline. Jobs requiring its labels remain queued until it returns. The VM and runner service otherwise start automatically with the host.

Run the read-only diagnostic from the repository root:

```bash
bash .opencode/skills/triagemate-runner-ops/scripts/runner-doctor.sh
```

## Workflow routing

The merged workflow changes each CI job from `runs-on: ubuntu-latest` to:

```yaml
runs-on: [self-hosted, Linux, X64, triagemate]
```

With one local runner, matrix and independent jobs execute sequentially rather than in parallel. Use `github-basics` for branch, PR, CI-evidence, and merge workflow; this guide covers VM/runner operation only.

## Validation evidence

The clean validation run against the latest Sprint 26b head produced:

| Check | Result |
|---|---|
| Python 3.11 tests | Passed |
| Python 3.12 tests | Passed |
| Ruff lint | Passed |
| Frontend JavaScript syntax | Passed |
| TriageMate Docker image build | Passed when run directly in the VM |

The Docker workflow job was skipped on the PR because the workflow intentionally runs it only for qualifying push events; the equivalent `docker build .` completed successfully inside the VM.

## Troubleshooting

If management commands return libvirt permission errors immediately after setup, sign out and back in. Do not loosen permissions on `/var/run/libvirt/libvirt-sock`.

If GitHub reports the runner offline:

```bash
triagemate-runner status
triagemate-runner ssh
sudo systemctl status actions.runner.Sploosh4-TriageMate.triagemate-vm.service
sudo journalctl -u actions.runner.Sploosh4-TriageMate.triagemate-vm.service -n 100 --no-pager
```

If Docker fails inside the VM:

```bash
systemctl status docker
docker info
df -h /
id
```

The VM's DHCP address may change after a reboot. Always discover it with `triagemate-runner status` or `virsh domifaddr`; do not rely on the installation-time address.

## Security and recovery

- Keep the repository private while using a persistent self-hosted runner.
- Review workflow changes carefully because workflow code executes inside the VM.
- Never print or copy runner credential files from `/opt/actions-runner`.
- Never commit the SSH private key or cloud-init workspace.
- Prefer restarting the runner service or VM before considering re-registration.
- Re-registration requires a short-lived repository token and should only be done when the GitHub runner record or credentials are invalid.
- Docker access is powerful inside the guest but does not grant Docker control over the physical host.

The OpenCode troubleshooting skill is `.opencode/skills/triagemate-runner-ops/SKILL.md`.
