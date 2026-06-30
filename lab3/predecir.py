import pandas as pd
import joblib
import sys

def predecir_anomalias(ruta_archivo):
    try:
        # Cargar modelo y scaler
        modelo = joblib.load('modelo_anomalias.pkl')
        scaler = joblib.load('scaler.pkl')
        
        # Cargar datos nuevos
        datos = pd.read_csv(ruta_archivo)
        
        # Preprocesar
        X = datos[['duracion', 'bytes_enviados', 'paquetes', 'puerto_destino']]
        X_scaled = scaler.transform(X)
        
        # Predecir
        predicciones = modelo.predict(X_scaled)
        predicciones = [1 if p == -1 else 0 for p in predicciones]
        scores = modelo.decision_function(X_scaled)
        
        # Agregar resultados al dataframe
        datos['anomalia'] = predicciones
        datos['score'] = scores
        
        # Mostrar resultados
        print("Resultados de la predicción:")
        print(datos)
        print(f"\nTotal de registros: {len(datos)}")
        print(f"Anomalías detectadas: {sum(predicciones)}")
        
        # Guardar resultados
        datos.to_csv('resultados_prediccion.csv', index=False)
        print("\nResultados guardados en resultados_prediccion.csv")
        
        return datos
        
    except FileNotFoundError as e:
        print(f"Error: Archivo no encontrado - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error en la predicción: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python predecir.py <nuevo_trafico.csv>")
        sys.exit(1)
    predecir_anomalias(sys.argv[1])
