import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import re
from datetime import datetime

def generar_graficas(ruta_reporte_ssh, ruta_reporte_web, ruta_log_web):
    # Cargar reportes
    with open(ruta_reporte_ssh, 'r') as f:
        reporte_ssh = json.load(f)
    
    with open(ruta_reporte_web, 'r') as f:
        reporte_web = json.load(f)
    
    # Gráfica 1: Top 10 IPs SSH
    ips = [item['ip'] for item in reporte_ssh['ips_mas_frecuentes']]
    intentos = [item['intentos'] for item in reporte_ssh['ips_mas_frecuentes']
    
    plt.figure(figsize=(12, 6))
    sns.barplot(x=ips, y=intentos, palette='viridis')
    plt.title('Top 10 IPs con más intentos fallidos SSH')
    plt.xlabel('IP')
    plt.ylabel('Intentos')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('graficas/top10_ssh.png')
    plt.close()
    print("Gráfica top10_ssh.png generada")
    
    # Gráfica 2: Timeline HTTP
    # Parsear log web para timestamps
    timestamps = []
    patron = re.compile(r'\[(?P<dia>\d+/\w+/\d+:\d+:\d+:\d+)')
    try:
        with open(ruta_log_web, 'r', encoding='utf-8') as f:
            for linea in f:
                match = patron.search(linea)
                if match:
                    try:
                        ts = datetime.strptime(match.group(1), '%d/%b/%Y:%H:%M:%S')
                        timestamps.append(ts.replace(minute=0, second=0))
                    except ValueError:
                        continue
    except FileNotFoundError:
        print("No se encontró el log web para timeline")
    
    if timestamps:
        conteo_horas = Counter(timestamps)
        horas = sorted(conteo_horas.keys())
        valores = [conteo_horas[h] for h in horas]
        
        plt.figure(figsize=(12, 6))
        plt.plot(horas, valores, marker='o', linestyle='-')
        plt.title('Peticiones HTTP por hora')
        plt.xlabel('Hora')
        plt.ylabel('Número de peticiones')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('graficas/timeline_http.png')
        plt.close()
        print("Gráfica timeline_http.png generada")
    
    # Gráfica 3: Heatmap HTTP (simplificado)
    if timestamps:
        dias_semana = [ts.weekday() for ts in timestamps]
        horas_dia = [ts.hour for ts in timestamps]
        import numpy as np
        heatmap_data = np.zeros((7, 24))
        for d, h in zip(dias_semana, horas_dia):
            heatmap_data[d][h] += 1
        
        plt.figure(figsize=(15, 8))
        sns.heatmap(heatmap_data, cmap='YlOrRd', annot=True, fmt='.0f')
        plt.title('Heatmap de peticiones HTTP')
        plt.xlabel('Hora del día')
        plt.ylabel('Día de la semana (0=Lunes)')
        plt.tight_layout()
        plt.savefig('graficas/heatmap_http.png')
        plt.close()
        print("Gráfica heatmap_http.png generada")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Uso: python visualizar.py <reporte_ssh.json <reporte_web.json <log_web>")
        sys.exit(1)
    generar_graficas(sys.argv[1], sys.argv[2], sys.argv[3])
