import argparse
import yaml
from pathlib import Path
from runners import masscan_scan, nmap_vuln_scan, nuclei_scan_host, NUCLEI_BIN, run_cmd
from parsers import parse_masscan_json, parse_nmap_xml
import json
import time
import os, re
from reporter import generate_report

def load_config(path="config.yml"):
    with open(path) as f:
        return yaml.safe_load(f)

def merge_ports(defaults_csv, manual_csv):
    """Merge comma-separated port strings into a de-duplicated, sorted CSV."""
    def norm(s):
        return [x.strip() for x in (s or "").split(",") if x.strip()]
    a = set(norm(defaults_csv))
    b = set(norm(manual_csv))
    def sort_key(x):
        return (not x.isdigit(), int(x) if x.isdigit() else x)
    merged = sorted(a.union(b), key=sort_key)
    return ",".join(merged)

def banner_header(targets, ports, all_ports, rate, outfile, out_dir, timing, no_nmap, no_nuclei, proxy):
    line = "=" * 74
    txt = f"""
{line}
  Network Security Scan Orchestrator
{line}
  Scope        : {targets}
  Ports        : {"ALL (1-65535)" if all_ports else ports}
  Masscan rate : {rate} pps
  Nmap timing  : {timing} {'(DISABLED)' if no_nmap else ''}
  Nuclei bin   : {NUCLEI_BIN} {'(DISABLED)' if no_nuclei else ''}
  Proxy        : {proxy or '-'}
  Output dir   : {out_dir}
  Report file  : {outfile}

  Steps:
    1) masscan whole network on selected ports
    2) nmap -sV --script vuln on discovered host:port (can disable with --no-nmap)
    3) nuclei (universal, by host/IP) (can disable with --no-nuclei)
    4) generate simple HTML report

  Safety:
    • Only scan assets you own or have explicit written permission to test.
    • Start with conservative rates; increase gradually if needed.
{line}
"""
    print(txt)

def main():
    ap = argparse.ArgumentParser(description="masscan -> nmap(--script vuln) -> nuclei (IP) -> HTML report")
    ap.add_argument("-t", "--targets", required=True, help="Target CIDR(s)")
    ap.add_argument("-p", "--ports", required=False, help="Extra ports to merge with defaults")
    ap.add_argument("--all-ports", action="store_true", help="Scan ALL ports (1-65535) with masscan")
    ap.add_argument("-o", "--outfile", required=True, help="Output HTML report filename")
    ap.add_argument("-c", "--config", default="config.yml", help="Config file path")
    ap.add_argument("--no-nmap", action="store_true", help="Skip the nmap stage")
    ap.add_argument("--no-nuclei", action="store_true", help="Skip the nuclei stage")
    # sqlmap-style proxy flags
    ap.add_argument("--proxy", help="Proxy URL (sqlmap-style), e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050")
    ap.add_argument("--proxy-cred", help="Proxy credentials user:pass (sqlmap-style)")
    ap.add_argument("--ignore-proxy", action="store_true", help="Ignore system proxies (like sqlmap --ignore-proxy)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    out_dir = Path(cfg.get("output_dir", "./scans")); out_dir.mkdir(parents=True, exist_ok=True)

    if args.all_ports:
        ports_for_masscan = cfg["masscan"].get("ports_default", "1-65535")
    else:
        ports_for_masscan = merge_ports(cfg["masscan"].get("ports_common",""), args.ports or "")

    timing = cfg["nmap"].get("timing", "3")

    # Build sqlmap-style effective proxy (inject creds if provided and not already present)
    effective_proxy = args.proxy
    if effective_proxy and args.proxy_cred and '@' not in effective_proxy:
        m = re.match(r'^(?P<sch>[\w+]+://)(?P<rest>.+)$', effective_proxy)
        if m:
            effective_proxy = f"{m.group('sch')}{args.proxy_cred}@{m.group('rest')}"

    # Prepare environment; optionally strip system proxies
    env = os.environ.copy()
    if args.ignore_proxy:
        for k in ["HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy","ALL_PROXY","all_proxy","NO_PROXY","no_proxy"]:
            env.pop(k, None)

    banner_header(args.targets, ports_for_masscan, args.all_ports, cfg["masscan"].get("rate",2000),
                  args.outfile, out_dir, timing, args.no_nmap, args.no_nuclei, effective_proxy)

    # Optional templates preflight (common macOS locations)
    if not args.no_nuclei:
        tmpl_candidates = [
            Path.home() / "nuclei-templates",
            Path.home() / ".local" / "share" / "nuclei-templates",
            Path("/usr/local/share/nuclei-templates"),
            Path("/opt/homebrew/share/nuclei-templates"),
        ]
        if not any(p.exists() for p in tmpl_candidates):
            print("[warn] nuclei templates directory not found in common locations.")
            print("       Run once: /Users/<username>/.pdtm/go/bin/nuclei -update && -update-templates")

    # Preflight nuclei version (only warn on failure)
    if not args.no_nuclei:
        rc, so, se = run_cmd(f"{NUCLEI_BIN} -version", timeout=10, env=env)
        if rc != 0:
            print(f"[warn] nuclei preflight failed rc={rc}. stderr: {se.strip()[:300]}")

    # MASSCAN
    rc, masscan_file, so, se = masscan_scan(
        args.targets, ports_for_masscan, out_dir,
        rate=cfg["masscan"].get("rate",2000),
        timeout=cfg["masscan"].get("timeout",300)
    )
    print(f"[+] masscan finished rc={rc}, file={masscan_file}")
    if rc != 0 and se:
        print("[masscan stderr]", se)

    # Parse masscan -> {host: ports}
    hits = parse_masscan_json(masscan_file)
    host_ports = {}
    for h in hits:
        if not h.get("host") or not h.get("port"):
            continue
        host_ports.setdefault(h["host"], set()).add(int(h["port"]))
    print(f"[+] masscan discovered {len(host_ports)} host(s) with open ports)")

    results = {"run_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "masscan_file": str(masscan_file), "hosts": {}}

    # Per-host pipeline
    for host, ports_set in host_ports.items():
        host_result = {"nmap_file": None, "nmap": [], "nuclei": []}

        # NMAP (optional)
        if not args.no_nmap:
            ports_csv = ",".join(map(str, sorted(ports_set)))
            print(f"[+] nmap (vuln) -> host {host} ports {ports_csv}")
            rc, nmap_file, so, se = nmap_vuln_scan(
                host, ports_csv, out_dir,
                timing=timing,
                timeout=cfg["nmap"].get("timeout",900),
                proxies=effective_proxy,   # sqlmap-style proxy
                env=env                    # honors --ignore-proxy
            )
            print(f"[+] nmap finished rc={rc}, file={nmap_file}")
            if rc != 0 and se:
                print("[nmap stderr]", se)
            host_result["nmap_file"] = str(nmap_file)
            host_result["nmap"] = parse_nmap_xml(nmap_file)

        # NUCLEI (optional)
        if not args.no_nuclei:
            print(f"[+] nuclei (host) -> {host}")
            rc, nuc_file, so, se = nuclei_scan_host(
                host, out_dir,
                timeout=cfg["nuclei"].get("timeout", 900),
                proxy=effective_proxy,     # sqlmap-style proxy
                env=env                    # honors --ignore-proxy
            )
            print(f"[+] nuclei rc={rc}, file={nuc_file}")
            if rc != 0 and se:
                print("[nuclei stderr]", se)
                # Save stderr to file for post-mortem
                try:
                    Path(nuc_file + ".stderr.txt").write_text(se)
                except Exception:
                    pass
            if rc == 0 and Path(nuc_file).exists():
                try:
                    with open(nuc_file) as f:
                        lines = [json.loads(l) for l in f.read().splitlines() if l.strip()]
                        host_result["nuclei"].extend(lines)
                except Exception:
                    pass

        results["hosts"][host] = host_result

    # Write summary + HTML report
    base = Path(args.outfile).with_suffix("")
    summary_file = out_dir / f"{base.name}.summary.json"
    with open(summary_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] summary written to {summary_file}")

    report_path = out_dir / args.outfile
    generate_report(str(summary_file), str(report_path))
    print(f"[+] HTML report generated at {report_path}")

if __name__ == "__main__":
    main()
