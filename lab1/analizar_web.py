import re
import json
from collections import defaultdict
from datetime import datetime, timedelta

def parsear_log_web(ruta_archivo):
    # Patrón para Combined Log Format de Apache
    patron = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<metodo>\S+)\s+(?P<ruta>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
    )
    
    # Almacenar peticiones por IP y timestamp
    peticiones_por_ip = defaultdict(list)
    errores_por_ip = defaultdict(int)
    sqli_detectados = []
    escaneos_detectados = []
    
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones": 0,
        "errores_4xx_5xx": {},
        "escaneos_detectados": [],
        "sqli_detectados": []
    }

    # Patrones de SQL Injection
    patrones_sqli = [
        r"UNION", r"SELECT", r"--", r"OR\s+1=1", r"'", r";", r"DROP", r"INSERT"
    ]

    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
            for linea in f:
                match = patron.match(linea.strip())
                if match:
                    datos = match.groupdict()
                    reporte["total_peticiones"] += 1
                    
                    ip = datos['ip']
                    status = datos['status']
                    ruta = datos['ruta']
                    
                    # Parsear timestamp
                    try:
                        ts_str = datos['timestamp'].split()[0]
                        ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                    except:
                        ts = datetime.now()
                    
                    # Almacenar petición
                    peticiones_por_ip[ip].append({
                        "timestamp": ts,
                        "ruta": ruta,
                        "status": status
                    })
                    
                    # Contar errores 4xx y 5xx
                    if status.startswith('4') or status.startswith('5'):
                        errores_por_ip[ip] += 1
                    
                    # Detectar SQL Injection
                    for patron_sqli in patrones_sqli:
                        if re.search(patron_sqli, ruta, re.IGNORECASE):
                            sqli_detectados.append({
                                "ip": ip,
                                "ruta": ruta,
                                "timestamp": ts_str
                            })
                            print(f"[ALERTA] SQL Injection detectado desde {ip} en ruta: {ruta}")
                            break

        # Detectar escaneos (>20 rutas distintas en <60 segundos)
        for ip, peticiones in peticiones_por_ip.items():
            # Ordenar peticiones por timestamp
            peticiones_ordenadas = sorted(peticiones, key=lambda x: x["timestamp"])
            
            for i in range(len(peticiones_ordenadas)):
                ventana = []
                for j in range(i, len(peticiones_ordenadas)):
                    if peticiones_ordenadas[j]["timestamp"] - peticiones_ordenadas[i]["timestamp"] <= timedelta(seconds=60):
                        ventana.append(peticiones_ordenadas[j])
                    else:
                        break
                
                # Contar rutas distintas en la ventana
                rutas_distintas = set(p["ruta"] for p in ventana)
                if len(rutas_distintas) > 20:
                    escaneos_detectados.append({
                        "ip": ip,
                        "peticiones_60s": len(ventana),
                        "rutas_distintas": len(rutas_distintas)
                    })
                    print(f"[ALERTA] Escaneo detectado desde {ip}: {len(rutas_distintas)} rutas distintas en 60 segundos")
                    break

        # Preparar reporte
        reporte["errores_4xx_5xx"] = dict(errores_por_ip)
        reporte["escaneos_detectados"] = escaneos_detectados
        reporte["sqli_detectados"] = sqli_detectados

        return reporte
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {ruta_archivo}")
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python analizar_web.py lab1/access.log")
        sys.exit(1)
    
    ruta_log = sys.argv[1]
    reporte = parsear_log_web(ruta_log)
    
    if reporte:
        with open('lab1/reporte_web.json', 'w', encoding='utf-8') as f:
            json.dump(reporte, f, indent=4, ensure_ascii=False)
        print("\nReporte generado exitosamente en lab1/reporte_web.json")
