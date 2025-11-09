
import json
from pathlib import Path
import xmltodict

def parse_masscan_json(path):
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text()
    lines = [l for l in text.splitlines() if l.strip()]
    objs = []
    if len(lines) == 1 and (lines[0].startswith("[") or lines[0].startswith("{")):
        try:
            parsed = json.loads(lines[0])
            if isinstance(parsed, list):
                objs = parsed
            else:
                objs = [parsed]
        except:
            pass
    else:
        for l in lines:
            try:
                objs.append(json.loads(l))
            except:
                continue
    results = []
    for e in objs:
        ip = e.get("ip") or e.get("address") or e.get("target")
        for p in e.get("ports", []):
            results.append({"host": ip, "port": int(p.get("port")), "proto": p.get("proto")})
    return results

def parse_nmap_xml(path):
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = xmltodict.parse(p.read_text())
    except Exception:
        return []
    hosts = []
    nmaprun = doc.get("nmaprun", {})
    host_nodes = nmaprun.get("host") or []
    if isinstance(host_nodes, dict):
        host_nodes = [host_nodes]
    for h in host_nodes:
        addr = None
        addrs = h.get("address")
        if isinstance(addrs, list):
            addr = addrs[0].get("@addr")
        elif isinstance(addrs, dict):
            addr = addrs.get("@addr")
        host_entry = {"address": addr, "ports": []}
        ports_block = h.get("ports", {}).get("port") or []
        if isinstance(ports_block, dict):
            ports_block = [ports_block]
        for port in ports_block:
            portid = int(port.get("@portid"))
            proto = port.get("@protocol")
            service = port.get("service") or {}
            service_info = {
                "name": service.get("@name"),
                "product": service.get("@product"),
                "version": service.get("@version"),
                "extrainfo": service.get("@extrainfo")
            }
            scripts = port.get("script") or []
            if isinstance(scripts, dict):
                scripts = [scripts]
            script_results = []
            for s in scripts:
                script_results.append({"id": s.get("@id"), "output": s.get("@output")})
            host_entry["ports"].append({"port": portid, "protocol": proto, "service": service_info, "scripts": script_results})
        hosts.append(host_entry)
    return hosts
