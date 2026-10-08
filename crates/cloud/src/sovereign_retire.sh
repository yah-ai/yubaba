# R605-F37 — retire yubaba's literal --sovereign-* flags. Runs ON the node as
# root-capable `bash -s`, with SUDO set by the caller's prologue. Shipped as
# cloud::sovereign_unit::RETIRE_LITERALS_SCRIPT and printed by
# `yah cloud sovereign-dropin --retire-script`; every roll path pipes this one
# copy. Does NOT restart yubaba: the caller's restart picks the result up.
#
# GATE: only when the INSTALLED /usr/local/bin/yubaba reads YUBABA_SOVEREIGN_*
# (its `serve --help` names the env var). An older binary keeps its literal
# flags — stripping them would leave it with no sovereign group at all.
#
# Sequence: (1) require 90-sovereign.conf; (2) strip --sovereign-{group,
# participation,voters} from every ExecStart= line in every yubaba drop-in,
# keeping every other flag, with a .pre-f37 copy beside each edited file;
# (3) delete 95-sovereign-group.conf only if doing so leaves the effective
# argv unchanged — it re-declares the whole ExecStart (R911-T6), so where it
# is the only carrier of some other flag it is kept, stripped; (4) assert the
# effective argv carries no literal sovereign flag. Prints RETIRED, NOOP or
# SKIP on its last line.
set -euo pipefail
S="${SUDO:-}"
D=/etc/systemd/system/yubaba.service.d
argv() { systemctl show yubaba.service -p ExecStart --value | sed -nE 's/.*argv\[\]=([^;]*) ;.*/\1/p' | head -1; }

if ! /usr/local/bin/yubaba serve --help 2>/dev/null | grep -q YUBABA_SOVEREIGN_VOTERS; then
  echo "SKIP: installed yubaba does not read YUBABA_SOVEREIGN_*; literal flags kept"
  exit 0
fi
if [ ! -f "$D/90-sovereign.conf" ]; then
  # A machine that declares no group has no drop-in and should carry no flag.
  if argv | grep -q -- '--sovereign-'; then
    echo "REFUSED: literal --sovereign-* flags but no $D/90-sovereign.conf — install the render first" >&2
    exit 1
  fi
  echo NOOP
  exit 0
fi

changed=0
for f in "$D"/*.conf; do
  [ -f "$f" ] || continue
  grep -qE '^ExecStart=.*--sovereign-' "$f" || continue
  $S cp -p "$f" "$f.pre-f37"
  $S sed -i -E '/^ExecStart=/ s/[[:space:]]+--sovereign-(group|participation|voters)(=|[[:space:]]+)[^[:space:]]+//g' "$f"
  echo "  stripped literal sovereign flags from $f"
  changed=1
done
$S systemctl daemon-reload

if [ -f "$D/95-sovereign-group.conf" ]; then
  before="$(argv)"
  $S mv "$D/95-sovereign-group.conf" "$D/95-sovereign-group.conf.pre-f37-removed"
  $S systemctl daemon-reload
  if [ "$(argv)" = "$before" ]; then
    echo "  removed 95-sovereign-group.conf (effective argv unchanged)"
    changed=1
  else
    $S mv "$D/95-sovereign-group.conf.pre-f37-removed" "$D/95-sovereign-group.conf"
    $S systemctl daemon-reload
    echo "  KEPT 95-sovereign-group.conf (stripped): it is the only carrier of other flags"
  fi
fi

if argv | grep -q -- '--sovereign-'; then
  echo "REFUSED: the effective ExecStart still passes a literal --sovereign-* flag: $(argv)" >&2
  exit 1
fi
[ "$changed" = 1 ] && echo RETIRED || echo NOOP
