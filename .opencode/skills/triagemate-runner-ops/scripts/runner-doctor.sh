#!/usr/bin/env bash
set -uo pipefail

VM="triagemate-runner"
URI="qemu:///system"
KEY="$HOME/.ssh/triagemate_runner_ed25519"
REPO="Sploosh4/TriageMate"
SERVICE="actions.runner.Sploosh4-TriageMate.triagemate-vm.service"

heading() { printf '\n== %s ==\n' "$1"; }

if virsh -c "$URI" uri >/dev/null 2>&1; then
  VIRSH=(virsh -c "$URI")
elif getent group libvirt | grep -qE "[:,]${USER}(,|$)"; then
  VIRSH=(sg libvirt -c)
else
  echo "Cannot access system libvirt. Sign out and back in to refresh libvirt group membership." >&2
  exit 2
fi

vcall() {
  if [[ "${VIRSH[0]}" == "sg" ]]; then
    local quoted=""
    printf -v quoted '%q ' virsh -c "$URI" "$@"
    sg libvirt -c "$quoted"
  else
    "${VIRSH[@]}" "$@"
  fi
}

heading "Host"
printf 'User: %s\n' "$USER"
printf 'Groups: %s\n' "$(id -nG)"
printf 'KVM: '
[[ -e /dev/kvm ]] && echo present || echo missing

heading "VM"
if ! vcall dominfo "$VM" 2>/dev/null | awk '/^(Name|State|CPU\(s\)|Max memory|Autostart):/'; then
  echo "VM $VM is not defined or libvirt is unavailable."
  exit 1
fi

IP="$(vcall domifaddr "$VM" --source lease 2>/dev/null | awk '/ipv4/ {sub("/.*", "", $4); print $4; exit}')"
printf 'Lease IP: %s\n' "${IP:-none}"

heading "GitHub"
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh api "repos/$REPO/actions/runners" \
    --jq '.runners[] | select(.name=="triagemate-vm") | {name,status,busy,labels:[.labels[].name]}' || true
else
  echo "gh is unavailable or unauthenticated."
fi

heading "Guest"
if [[ -z "$IP" ]]; then
  echo "No DHCP lease; guest checks skipped."
  exit 1
fi
if [[ ! -f "$KEY" ]]; then
  echo "SSH key missing: $KEY"
  exit 1
fi

ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "runner@$IP" \
  "printf 'Runner service: '; systemctl is-active '$SERVICE'; printf 'Docker: '; systemctl is-active docker; printf 'Disk: '; df -h / | awk 'NR==2 {print \$3 \" used / \" \$2 \" (\" \$5 \")\"}'; printf 'Load: '; uptime | sed 's/.*load average: //'"
