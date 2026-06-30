import re
import json
from collections import defaultdict
from datetime import datetime

def parsear_log_ssh(ruta_archivo):
    # Patrón para parsear líneas de auth.log
    patron = re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<mensaje>.*)'
    )
    
    intentos_por_ip = defaultdict(int)
    total_intentos_fallidos = 0
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": 0,
        "ips_sospechosas": []
    }

    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
            for linea in f:
                match = patron.match(linea.strip())
                if match:
                    datos = match.groupdict()
                    
                    if 'Failed password' in datos['mensaje']:
                        total_intentos_fallidos += 1
                        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', datos['mensaje'])
                        if ip_match:
                            ip = ip_match.group(1)
                            intentos_por_ip[ip] += 1

        # Obtener top 10 IPs y generar alertas
        top_ips = sorted(intentos_por_ip.items(), key=lambda x: x[1], reverse=True)[:10]
        
        for ip, intentos in top_ips:
            es_alerta = intentos >= 50
            if es_alerta:
                print(f"[ALERTA] IP: {ip} — {intentos} intentos fallidos — Posible ataque de fuerza bruta")
            
            reporte["ips_sospechosas"].append({
                "ip": ip,
                "intentos": intentos,
                "alerta": es_alerta
            })
        
        reporte["total_intentos_fallidos"] = total_intentos_fallidos
        
        # Imprimir ranking top 10
        print("\nRanking de IPs con más intentos fallidos:")
        for i, (ip, intentos) in enumerate(top_ips, 1):
            print(f"{i}. {ip} — {intentos} intentos")

        return reporte
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {ruta_archivo}")
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python analizar_ssh.py lab1/auth.log")
        sys.exit(1)
    
    ruta_log = sys.argv[1]
    reporte = parsear_log_ssh(ruta_log)
    
    if reporte:
        with open('reporte_ssh.json', 'w', encoding='utf-8') as f:
            json.dump(reporte, f, indent=4, ensure_ascii=False)
        print("\nReporte generado exitosamente en reporte_ssh.json")
