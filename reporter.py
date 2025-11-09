
import json
from jinja2 import Template
from pathlib import Path

TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Scan Report</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Arial;background:#0b1220;color:#e8eef7;padding:20px;}
h1{font-size:22px}
.card{background:#111a2a;padding:12px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.35);margin-bottom:12px}
.small{font-size:12px;color:#9fb0c9}
.code{font-family:monospace;background:#0f1a30;padding:6px;border-radius:4px;display:inline-block;color:#a8c6ff}
table{width:100%;border-collapse:collapse}
th,td{padding:6px;border-bottom:1px solid #1e2a42;text-align:left}
.bad{color:#ff8f8f;font-weight:600}
.mid{color:#ffd27a}
.ok{color:#84f7a8}
</style>
</head>
<body>
<h1>Scan Report</h1>
<p class="small">Generated: {{ summary.run_time }}</p>

<div class="card">
  <h2>Masscan output</h2>
  <p class="small">masscan file: <span class="code">{{ summary.masscan_file }}</span></p>
  <p class="small">Hosts discovered: {{ summary.hosts|length }}</p>
</div>

{% for host, data in summary.hosts.items() %}
<div class="card">
  <h3>{{ host }}</h3>
  {% if data.nmap_file %}<p class="small">Nmap: <span class="code">{{ data.nmap_file }}</span></p>{% endif %}

  {% if data.nmap %}
  <h4>Open ports & services</h4>
  <table>
    <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Script findings</th></tr></thead>
    <tbody>
    {% for h in data.nmap %}
      {% for p in h.ports %}
      <tr>
        <td>{{ p.port }}</td>
        <td>{{ p.protocol }}</td>
        <td>{{ p.service.name or '-' }}</td>
        <td>{{ (p.service.product or '') ~ (' ' ~ p.service.version if p.service.version else '') }}</td>
        <td>{% if p.scripts %}{% for s in p.scripts %}<div class="small"><strong>{{ s.id }}</strong>: {{ s.output }}</div>{% endfor %}{% else %}-{% endif %}</td>
      </tr>
      {% endfor %}
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h4>Nuclei (host/IP) findings</h4>
  <p class="small">Nuclei findings: {{ data.nuclei|length }}</p>
  {% if data.nuclei %}
    <ul>
    {% for n in data.nuclei %}
      <li><strong>{{ n.get("template") or (n.get("info",{}).get("name") or "template") }}</strong> - severity: {{ n.get("info",{}).get("severity") or "n/a" }}</li>
    {% endfor %}
    </ul>
  {% endif %}
</div>
{% endfor %}
</body>
</html>
"""

def generate_report(summary_json_path, out_html_path):
    summary = json.load(open(summary_json_path))
    tpl = Template(TEMPLATE)
    html = tpl.render(summary=summary)
    Path(out_html_path).write_text(html)
    print("Report written to", out_html_path)
