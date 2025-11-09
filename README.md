
# NetSec Orchestrator (nuclei-only, hardcoded nuclei path)

Workflow: masscan whole network → parse → nmap `-sV --script vuln` → **nuclei by IP/host (universal)** → HTML report.

> Use only on assets you own or have explicit permission to test.

## Requirements

System: `masscan`, `nmap`, `nuclei`.
**Nuclei path is hardcoded to**:
```
/Users/<username>/.pdtm/go/bin/nuclei
```

Python: `pyyaml`, `xmltodict`, `jinja2`
```
python -m pip install pyyaml xmltodict jinja2
```

## Quick start

Focused scan (default common ports + extras):
```
python scan_manager.py -t "192.168.111.0/24" -p "9200,11211" -o "oct14-scan.html"
```
All ports:
```
python scan_manager.py -t "192.168.111.0/16" --all-ports -o "full-net-allports.html"
```

### Optional skip flags
- `--no-nmap`   : skip the nmap stage entirely (masscan → nuclei → report)
- `--no-nuclei` : skip the nuclei stage (masscan → nmap → report)
