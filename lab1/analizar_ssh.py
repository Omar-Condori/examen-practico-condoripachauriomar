import re
import json
from collections import defaultdict, Counter

def parsear_log_ssh(ruta_archivo):
    patron = re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<mensaje>.*)'
    )
    intentos_bruteforce = defaultdict(list)
    logs_procesados = []
    reporte = {
        "total_logs": 0,
        "intentos_fallidos": 0,
        "autenticaciones_exitosas": 0,
        "ips_mas_frecuentes": [],
        "alertas": []
    }

    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            for linea in f:
                match = patron.match(linea.strip())
                if match:
                    datos = match.groupdict()
                    reporte["total_logs"] += 1
                    logs_procesados.append(datos)
                    
                    if 'Failed password' in datos['mensaje']:
                        reporte["intentos_fallidos"] += 1
                        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', datos['mensaje'])
                        if ip_match:
                            ip = ip_match.group(1)
                            intentos_bruteforce[ip].append(datos)
                            
                            if len(intentos_bruteforce[ip]) >= 5:
                                alerta = {
                                    "tipo": "BRUTE_FORCE",
                                    "ip": ip,
                                    "intentos": len(intentos_bruteforce[ip]),
                                    "timestamp": f"{datos['mes']} {datos['dia']} {datos['hora']}"
                                }
                                if alerta not in reporte["alertas"]:
                                    reporte["alertas"].append(alerta)
                                    print(f"[ALERTA] Brute force detectado desde {ip} ({len(intentos_bruteforce[ip])} intentos)")
                    
                    elif 'Accepted password' in datos['mensaje'] or 'Accepted publickey' in datos['mensaje']:
                        reporte["autenticaciones_exitosas"] += 1

        # Calcular IPs más frecuentes
        conteo_ips = Counter()
        for ip in intentos_bruteforce:
            conteo_ips[ip] = len(intentos_bruteforce[ip])
        reporte["ips_mas_frecuentes"] = [{"ip": ip, "intentos": cnt} for ip, cnt in conteo_ips.most_common(10)]

        return reporte
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {ruta_archivo}")
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python analizar_ssh.py <ruta_al_log_ssh>")
        sys.exit(1)
    
    ruta_log = sys.argv[1]
    reporte = parsear_log_ssh(ruta_log)
    
    if reporte:
        with open('reporte_ssh.json', 'w', encoding='utf-8') as f:
            json.dump(reporte, f, indent=4, ensure_ascii=False)
        print("Reporte generado exitosamente en reporte_ssh.json")
