---
name: triagemate-runner-ops
description: Operate and troubleshoot TriageMate's repository-scoped GitHub Actions self-hosted runner in its local Ubuntu KVM/libvirt VM. Use for runner offline or queued jobs, VM lifecycle, SSH access, Docker failures, GitHub runner service failures, runner labels, disk pressure, networking, registration, or CI routing questions involving triagemate-vm.
---

# TriageMate runner operations

Follow `github-basics`: only the user creates the task workspace through OpenCode; use its existing shared worktree and branch, and never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Treat the VM as CI infrastructure, not as a development checkout or OpenCode workspace; it does not replace the assigned GUI workspace. Start with read-only diagnostics and obtain explicit approval before deleting a runner, re-registering it, changing workflow YAML, reverting the VM disk, or merging a PR.

## Known topology

- Host: Ubuntu 24.04, KVM/libvirt system connection `qemu:///system`.
- VM: `triagemate-runner`, autostart enabled, 8 vCPUs, 12 GiB RAM, 60 GiB sparse qcow2 disk.
- Network: libvirt `default` NAT; the address is dynamic. Discover it from the DHCP lease.
- Guest login: `runner`, SSH key `~/.ssh/triagemate_runner_ed25519`.
- GitHub runner: `triagemate-vm`, scoped to private repository `Sploosh4/TriageMate`.
- Labels: `self-hosted`, `Linux`, `X64`, `triagemate`.
- Guest runner directory: `/opt/actions-runner`.
- Guest service: `actions.runner.Sploosh4-TriageMate.triagemate-vm.service`.
- Host disk: `/var/lib/libvirt/images/triagemate-runner.qcow2`.
- Host seed ISO: `/var/lib/libvirt/images/triagemate-runner-seed.iso`.
- Host management command: `triagemate-runner {start|stop|restart|status|ssh}`.
- Operator guide: `docs/guides/SELF_HOSTED_RUNNER.md`.

## Diagnose

1. Run `bash .opencode/skills/triagemate-runner-ops/scripts/runner-doctor.sh` from the repository root.
2. If libvirt denies access, explain that the interactive desktop session may predate membership in the `libvirt` group. Ask the user to sign out and back in; do not weaken socket permissions.
3. If the VM is stopped, use `triagemate-runner start` only when the user wants CI capacity online.
4. If the VM has no lease, inspect `virsh -c qemu:///system net-list --all`, `domiflist`, and the `default` network. Do not hard-code the historical address.
5. If SSH works but GitHub reports offline, inspect the guest service:

   ```bash
   triagemate-runner ssh
   sudo systemctl status actions.runner.Sploosh4-TriageMate.triagemate-vm.service
   sudo journalctl -u actions.runner.Sploosh4-TriageMate.triagemate-vm.service -n 100 --no-pager
   ```

6. If jobs stay queued while the runner is online, compare workflow `runs-on` labels exactly. The intended selector is:

   ```yaml
   runs-on: [self-hosted, Linux, X64, triagemate]
   ```

7. If Docker fails, check `systemctl is-active docker`, `docker info`, guest free disk, and membership of `runner` in `docker`. Docker access is intentionally confined to the VM.
8. Separate infrastructure failures from repository failures. Checkout, tool setup, and dependency installation passing proves the runner path works; pytest or coverage failures belong to the checked-out revision.

## Recovery order

Use the least disruptive action that fits the evidence:

1. Restart only the runner service.
2. Reboot the guest with `triagemate-runner restart`.
3. Restart libvirt networking only if DHCP/NAT is the confirmed failure.
4. Re-register only if credentials are invalid or the GitHub runner record was deleted. Generate the one-hour repository registration token through `gh api`; never print or persist it.
5. Rebuild the VM only after preserving logs and receiving explicit approval.

Do not expose SSH private keys, runner credentials, `.credentials*` files, registration tokens, or GitHub tokens in output.

## Verify after repair

- Confirm `gh api repos/Sploosh4/TriageMate/actions/runners` reports `triagemate-vm` online and not unexpectedly busy.
- Confirm `docker run --rm hello-world` works inside the guest when Docker was involved.
- Trigger or re-run only the specifically authorized workflow.
- Report job-level evidence and distinguish skipped jobs from passes.
