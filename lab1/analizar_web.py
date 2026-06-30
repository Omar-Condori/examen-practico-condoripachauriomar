import re
import json
from collections import defaultdict, Counter

def parsear_log_web(ruta_archivo):
    patron = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<metodo>\S+)\s+(?P<ruta>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
    )
    escaneos = defaultdict(int)
    sqli = defaultdict(list)
    reporte = {
        "total_peticiones": 0,
        "codigos_status": {},
        "escaneos_detectados": [],
        "sqli_detectados": [],
        "alertas": []
    }

    patrones_sqli = [
        r"('|\"|;|--|#|/\*|\*/|UNION|SELECT|INSERT|DELETE|DROP|OR\s+1=1|AND\s+1=1)",
        r"(\.\./|\.\.\\|/etc/passwd|/bin/sh)"
    ]

    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            for linea in f:
                match = patron.match(linea.strip())
                if match:
                    datos = match.groupdict()
                    reporte["total_peticiones"] += 1
                    
                    status = datos['status']
                    reporte["codigos_status"][status] = reporte["codigos_status"].get(status, 0) + 1
                    
                    if status in ['404', '403']:
                        escaneos[datos['ip']] += 1
                        if escaneos[datos['ip']] >= 10:
                            alerta_escaneo = {
                                "tipo": "ESCANNER",
                                "ip": datos['ip'],
                                "peticiones": escaneos[datos['ip']]
                            }
                            if alerta_escaneo not in reporte["alertas"]:
                                reporte["alertas"].append(alerta_escaneo)
                                print(f"[ALERTA] Escaneo detectado desde {datos['ip']} ({escaneos[datos['ip']]} peticiones)")
                    
                    for patron_sqli in patrones_sqli:
                        if re.search(patron_sqli, datos['ruta'], re.IGNORECASE):
                            sqli[datos['ip']].append(datos)
                            alerta_sqli = {
                                "tipo": "SQL_INJECTION",
                                "ip": datos['ip'],
                                "ruta": datos['ruta'],
                                "timestamp": datos['timestamp']
                            }
                            if alerta_sqli not in reporte["alertas"]:
                                reporte["alertas"].append(alerta_sqli)
                                print(f"[ALERTA] SQL Injection detectado desde {datos['ip']} en ruta {datos['ruta']}")
                            break

        reporte["escaneos_detectados"] = [{"ip": ip, "peticiones": cnt} for ip, cnt in escaneos.items() if cnt >= 10]
        reporte["sqli_detectados"] = [{"ip": ip, "intentos": len(intentos)} for ip, intentos in sqli.items()]

        return reporte
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {ruta_archivo}")
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python analizar_web.py <ruta_al_log_web>")
        sys.exit(1)
    
    ruta_log = sys.argv[1]
    reporte = parsear_log_web(ruta_log)
    
    if reporte:
        with open('reporte_web.json', 'w', encoding='utf-8') as f:
            json.dump(reporte, f, indent=4, ensure_ascii=False)
        print("Reporte generado exitosamente en reporte_web.json")
