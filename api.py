from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap
import re

app = Flask(__name__)
CORS(app)  # Permite acesso do frontend

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    subnet_mask = data.get('subnet_mask')
    option = data.get('option')

    try:
        results = run_scan(target, subnet_mask, option)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_scan(target, subnet_mask, option):
    nm = nmap.PortScanner()

    # Monta o alvo com CIDR
    target_cidr = f"{target}/{subnet_mask}" if '/' not in subnet_mask else f"{target}{subnet_mask}"

    # Define argumentos com base na opção
    if option == "quick":
        arguments = "-T4 -sV --script vulners"
    elif option == "standard":
        arguments = "-T4 -sV -p- --script vulners"
    elif option == "comprehensive":
        arguments = "-T4 -p- -A --script vulners"
    else:
        arguments = "-T4 -F --script vulners"

    # Executa o scan
    nm.scan(hosts=target_cidr, arguments=arguments)

    results = []
    for host in nm.all_hosts():
        services = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                cves = []

                # Se o script 'vulners' rodou, extrai CVEs
                script_output = service.get('script', {})
                if 'vulners' in script_output:
                    cves = extract_cves(script_output['vulners'])

                services.append({
                    "port": port,
                    "name": service.get('name', 'unknown'),
                    "state": service.get('state', 'unknown'),
                    "cves": cves
                })

        results.append({
            "ip": host,
            "services": services
        })

    return results

def extract_cves(vulners_output):
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})')
    return cve_pattern.findall(vulners_output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
