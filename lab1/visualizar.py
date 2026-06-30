import json
import matplotlib.pyplot as plt
import seaborn as sns
import re
from collections import Counter
from datetime import datetime
import pandas as pd
import numpy as np

def generar_graficas(ruta_reporte_ssh, ruta_log_web):
    # Cargar reporte SSH
    with open(ruta_reporte_ssh, 'r') as f:
        reporte_ssh = json.load(f)
    
    # --- Gráfica 1: Top 10 IPs con más intentos fallidos SSH ---
    ips = [item['ip'] for item in reporte_ssh['ips_sospechosas']]
    intentos = [item['intentos'] for item in reporte_ssh['ips_sospechosas']]
    
    plt.figure(figsize=(12, 6))
    sns.barplot(x=ips, y=intentos, palette='viridis')
    plt.title('Top 10 IPs con más intentos fallidos SSH')
    plt.xlabel('Dirección IP')
    plt.ylabel('Número de intentos fallidos')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('lab1/graficas/top10_ssh.png')
    plt.close()
    print("Gráfica lab1/graficas/top10_ssh.png generada")
    
    # --- Parsear log web para gráficas 2 y 3 ---
    timestamps = []
    status_codes = []
    
    patron = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<metodo>\S+)\s+(?P<ruta>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
    )
    
    try:
        with open(ruta_log_web, 'r', encoding='utf-8', errors='ignore') as f:
            for linea in f:
                match = patron.match(linea.strip())
                if match:
                    datos = match.groupdict()
                    try:
                        ts_str = datos['timestamp'].split()[0]
                        ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                        timestamps.append(ts)
                        status_codes.append(datos['status'])
                    except:
                        continue
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {ruta_log_web}")
        return
    
    # --- Gráfica 2: Línea de tiempo de peticiones HTTP por hora ---
    if timestamps:
        # Agrupar por hora
        horas = [ts.replace(minute=0, second=0, microsecond=0) for ts in timestamps]
        conteo_horas = Counter(horas)
        horas_ordenadas = sorted(conteo_horas.keys())
        valores = [conteo_horas[h] for h in horas_ordenadas]
        
        plt.figure(figsize=(14, 6))
        plt.plot(horas_ordenadas, valores, marker='o', linestyle='-', color='b')
        plt.title('Peticiones HTTP por hora')
        plt.xlabel('Hora')
        plt.ylabel('Número de peticiones')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig('lab1/graficas/timeline_http.png')
        plt.close()
        print("Gráfica lab1/graficas/timeline_http.png generada")
        
        # --- Gráfica 3: Heatmap de peticiones HTTP por hora y código de respuesta ---
        if status_codes:
            # Preparar datos para heatmap
            df = pd.DataFrame({
                'hora': [ts.hour for ts in timestamps],
                'status': status_codes
            })
            
            # Filtrar códigos comunes
            codigos_comunes = ['200', '301', '404', '500']
            df = df[df['status'].isin(codigos_comunes)]
            
            # Crear tabla de frecuencia
            heatmap_data = pd.crosstab(df['hora'], df['status']).reindex(range(24), fill_value=0)
            
            plt.figure(figsize=(12, 8))
            sns.heatmap(heatmap_data, cmap='YlOrRd', annot=True, fmt='d', cbar_kws={'label': 'Número de peticiones'})
            plt.title('Heatmap: Peticiones HTTP por hora y código de respuesta')
            plt.xlabel('Código de respuesta')
            plt.ylabel('Hora del día')
            plt.tight_layout()
            plt.savefig('lab1/graficas/heatmap_http.png')
            plt.close()
            print("Gráfica lab1/graficas/heatmap_http.png generada")

if __name__ == "__main__":
    import os
    # Crear carpeta de gráficas si no existe
    os.makedirs('lab1/graficas', exist_ok=True)
    
    generar_graficas('lab1/reporte_ssh.json', 'lab1/access.log')
