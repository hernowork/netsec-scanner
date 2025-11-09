import subprocess
from pathlib import Path
import shlex
import time
import os

# Hardcoded nuclei path (per your request)
NUCLEI_BIN = "/Users/hernowo/.pdtm/go/bin/nuclei"

def run_cmd(cmd, timeout=None, cwd=None, env=None):
    """Run a shell command, return (rc, stdout, stderr)."""
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=(env or os.environ.copy()),
        executable="/bin/bash",
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out.decode(errors="ignore"), err.decode(errors="ignore") + "\n[timeout]"
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

def masscan_scan(targets_cidr, ports, out_dir, rate=2000, timeout=300):
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    fname = out_dir / f"masscan_{int(time.time())}.json"
    cmd = (
        f"sudo masscan {shlex.quote(targets_cidr)} "
        f"-p{shlex.quote(ports)} --rate {int(rate)} "
        f"--output-format json --output-file {shlex.quote(str(fname))}"
    )
    rc, out, err = run_cmd(cmd, timeout=timeout)
    return rc, str(fname), out, err

def nmap_vuln_scan(host, ports_csv, out_dir, timing="3", timeout=900, proxies=None, env=None):
    """
    timing accepts '0'-'5' or 'Paranoid'/'Sneaky'/'Polite'/'Normal'/'Aggressive'/'Insane' or 'T3'.
    We'll normalize to '-T<digit or word>'.
    'proxies' is a comma-separated list of proxy URLs for NSE HTTP (e.g., http://127.0.0.1:8080,...).
    """
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    safe_host = host.replace(":", "_")
    fname = out_dir / f"nmap_{safe_host}_{int(time.time())}.xml"
    port_arg = f"-p {ports_csv}" if ports_csv else ""

    t = str(timing).strip()
    if t.upper().startswith("T"):  # e.g., "T3"
        t = t[1:]
    tflag = f"-T{t}"  # becomes -T3, -T4, etc.

    proxies_arg = f"--proxies {shlex.quote(proxies)}" if proxies else ""

    cmd = (
        f"nmap {port_arg} -sV --script vuln "
        f"{proxies_arg} "
        f"-oX {shlex.quote(str(fname))} {tflag} {shlex.quote(host)}"
    )
    rc, out, err = run_cmd(cmd, timeout=timeout, env=env)
    return rc, str(fname), out, err

def nuclei_scan_host(target_host, out_dir, timeout=300, proxy=None, env=None):
    """
    Run nuclei against a raw host/IP using -target (better for IPs than -u).
    Autodetect common templates locations on macOS/Homebrew.
    'proxy' is a single proxy URL (http/https/socks5), sqlmap-style.
    """
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = target_host.replace('://','_').replace('/','_').replace(':','_')
    fname = out_dir / f"nuclei_{safe_name}_{int(time.time())}.json"

    # Try common templates dirs (mac-friendly, incl. Homebrew)
    tmpl_candidates = [
        Path.home() / "nuclei-templates",
        Path.home() / ".local" / "share" / "nuclei-templates",
        Path("/usr/local/share/nuclei-templates"),
        Path("/opt/homebrew/share/nuclei-templates"),
    ]
    tmpl_arg = ""
    for p in tmpl_candidates:
        if p.exists():
            tmpl_arg = f"-t {shlex.quote(str(p))}"
            break

    proxy_arg = f"-proxy {shlex.quote(proxy)}" if proxy else ""

    cmd = (
        f"{shlex.quote(NUCLEI_BIN)} "
        f"-target {shlex.quote(target_host)} "
        f"{tmpl_arg} "
        f"{proxy_arg} "
        f"-severity info,low,medium,high,critical "
        f"-c 50 -rl 500 "
        f"-silent "
        f"-jsonl -o {shlex.quote(str(fname))}"
    )
    rc, out, err = run_cmd(cmd, timeout=timeout, env=env)
    return rc, str(fname), out, err
