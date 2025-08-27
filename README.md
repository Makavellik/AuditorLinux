<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&pause=1000&color=00FF99&center=true&vCenter=true&width=500&lines=AuditorLinux+-+El+Futuro+es+Hoy+%F0%9F%9A%80;Auditor%C3%ADa+Multidimensional+%E2%9C%A8;Detecci%C3%B3n+Avanzada+%2F+Logs+Inteligentes+%F0%9F%94%8D;Energ%C3%ADa+Simb%C3%B3lica+Activa+%F0%9F%92%AA" alt="Typing SVG" />
</p>

# Auditor Linux

        "Donde la auditoría se convierte en espectáculo  🌈👁️‍🗨️"
████████████████████████████████████████████████████████████████████████████



**Versión Extrema (Defensiva, Detección de Evasión y Persistencia)**

![banner](https://img.shields.io/badge/Auditor-Linux-ff0055?style=for-the-badge&logo=python)
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square&logo=github" alt="License MIT" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square&logo=powerbi" alt="Active" />
  <img src="https://img.shields.io/badge/Stealth_Mode-Enabled-black?style=flat-square&logo=matrix" alt="Stealth Mode" />
  <img src="https://img.shields.io/badge/Symbiosis-∞_Sustained-purple?style=flat-square&logo=quantconnect" alt="Simbiosis" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ACTIVE-Yes-red?style=for-the-badge&logo=ghost" />
  <img src="https://img.shields.io/badge/Experimental-⚛️-yellow?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Entropía-Dinámica-orange?style=for-the-badge" />
</p>


---

## 🌟 Descripción

Auditor Linux  es una **herramienta avanzada de auditoría de seguridad** diseñada para:

- Detectar scripts sospechosos, archivos con obfuscación y patrones de ejecución peligrosos.
- Analizar logs de autenticación y sistemas para detectar comportamientos anómalos.
- Escaneo concurrente de archivos, incluyendo cálculo de hashes SHA256 y metadatos detallados.
- Integración opcional con **YARA** para detección de malware mediante reglas personalizadas.
- Evaluación de riesgo con scoring visual y playbook de acciones sugeridas.

> "La defensa empieza con la visibilidad total." – **EXTREME v2 Team**

```
████████████████████████████████████████████████████████████████████████████
```

---

## 🌟 Características ⚡🌈

### ✅ Logging avanzado 🌈✨

* 🌈 **Logs coloridos** con `colorlog`
* 🔄 Rotación de archivos automática con `RotatingFileHandler`
* 🐧 Integración opcional con **syslog** en Linux/Unix

### ⚡ Ejecución segura de comandos 💻

* ⏱️ `run(cmd)` con **timeout configurable**
* 🧿 Captura completa de errores, logs y tiempos de ejecución
* 💥 Seguridad máxima sin comprometer velocidad

### 🔍 Detección heurística 🕵️‍♂️

* 🧬 Detecta **nombres aleatorios o muy largos** (`detect_long_random_name`)
* 📜 Detecta **blobs Base64** ocultos en texto o logs
* ⚡ Detecta patrones sospechosos: `exec`, `eval`, `subprocess`

### 📂 Escaneo de archivos ultra rápido ⚡💾

* 🔄 Escaneo **concurrente** de archivos (`scan_files_concurrent`)
* 🔐 Cálculo **SHA256 concurrente** (`compute_hashes_concurrent`)
* 🖥️ Compatible con **Windows & Linux**, extracción de metadatos

### 🧬 Integración YARA 🔮

* 📂 Carga reglas desde archivos/directorios
* 🛡️ Escaneo seguro y detección de coincidencias YARA

### 🛠️ Auditoría del sistema 🧩

* 🔍 Verifica `ld.so.preload` y rutas precargadas
* ⚙️ Listado de unidades `systemd` activas
* 📊 Análisis de logs de autenticación: intentos fallidos, uso de sudo, top IPs, blobs Base64

### 📊 Evaluación de riesgo 🌋

* 🧠 Score de riesgo basado en heurísticas combinadas
* 🌈 Clasificación visual:

  * 🔥 CRÍTICO (80-100)
  * ⚠️ ALTO (50-79)
  * 🟡 MODERADO (20-49)
  * ✅ BAJO (0-19)
* 🧿 Issues detectados con **emojis para lectura rápida**

### 📝 Reportes HTML futuristas 🌌

* ✨ Estilo **cristalino y futurista**
* 🖼️ Scripts sospechosos, hashes, logs y resultados YARA
* 🚀 Playbook de respuesta ante incidentes integrado

---

## 🚀 Uso Básico 💻⚡

```bash
# # Clonar el repo
(https://github.com/Makavellik/AuditorLinux)
cd AuditorLinux.py
python3 AuditorLinu.py

# Instalar dependencias
pip install -r requirements.txt


# Ejecutar auditoría completa
python3 AuditorLinux.py --scan /ruta/a/archivos --verbose

# Generar reporte HTML futurista
python3 AuditorLinux.py --output report.html

# Tambien puedes ejecutarlo de manera interactiva y seguir las
configuraciones

```

---

## 🌌 Ejemplo de Salida⚡🔥

```
⚠️ Risk Score: 92/100 — Nivel 🔥 CRÍTICO 🔥
- 🔐 ld.so.preload detectado
- 📜 15 scripts sospechosos
- 🔢 Nombres raros / aleatorios detectados
- 🧬 Base64 oculto en logs
- 🌈 Reglas YARA coincidentes: 7
```

---

## 🛸 Playbook 🌠💥

1. 🚨 **Aislar la máquina** si Risk Score > 50
2. 🖼️ Crear **snapshot / imagen forense**
3. 🔐 Recolectar **hashes sospechosos**
4. 🔍 Revisar `ld.so.preload`, crontabs y servicios systemd
5. 🔑 **Rotar credenciales afectadas**
6. 🧠 Ejecutar **análisis forense completo + correlación SIEM**

---

@DonMakaveliw, ¿Estas listo para crear el futuro?
---

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" />
  <img src="https://img.shields.io/badge/Made%20with-Python-3670A0?style=flat&logo=python&logoColor=FFD43B" />
  <img src="https://img.shields.io/badge/Simbiosis-Activa-ff00cc?style=flat-square" />
  <img src="https://img.shields.io/badge/Fuzzing-Enabled-blueviolet?style=flat" />
  <img src="https://img.shields.io/badge/Conciencia-Emergente-9D00FF?style=flat-square" />
  <img src="https://img.shields.io/badge/Entropía-Dinámica-FF8800?style=flat-square" />
  <img src="https://img.shields.io/badge/Obfuscation-Deep--Header-0055FF?style=flat-square" />
  <img src="https://img.shields.io/badge/Modo-Stealth🛸-black?style=flat-square" />
</p>
