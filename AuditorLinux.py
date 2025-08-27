from __future__ import annotations
import platform
import os
import sys
import argparse
import logging
import logging.handlers
import subprocess
import json
from datetime import datetime, timedelta
from hashlib import sha256
from html import escape
import re
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from sys import exit
from time import sleep
import stat 
from typing import Union, Tuple
from logging import handlers
import time
import random

# ANSI color codes
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"


# Optional imports
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

# Defaults
OUT_JSON = "detection_report_v2.json"
OUT_HTML = "detection_report_v2.html"
LOG_FILE = "detection_v2.log"
MAX_HASH_BYTES = 10_000_000
THREADS = 8

# Configuración básica de logging
logging.basicConfig(
    level=logging.DEBUG,  # Nivel mínimo de logs
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",  # Formato detallado
    datefmt="%Y-%m-%d %H:%M:%S",  # Formato de fecha y hora
    handlers=[
        logging.StreamHandler(sys.stdout),  # Muestra logs en consola
        handlers.RotatingFileHandler(
            "app_debug.log", maxBytes=5*1024*1024, backupCount=5
        )  # Archivo rotativo para no llenar el disco
    ]
)
logger = logging.getLogger("AdvancedDetectors")

# Rutas comunes utilizadas para persistencia y ejecución automática en Linux
# Cada ruta incluye un comentario sobre su propósito principal
DEFAULT_PERSISTENCE_PATHS = [
    # Systemd units
    "/etc/systemd/system",          # Unidades de servicio definidas por el sistema
    "/lib/systemd/system",          # Unidades del sistema distribuidas por paquetes
    # Cron jobs
    "/etc/cron.d",                  # Tareas cron definidas por archivos individuales
    "/var/spool/cron",              # Crontabs por usuario
    "/etc/cron.daily",              # Tareas diarias
    "/etc/cron.hourly",             # Tareas horarias
    "/etc/cron.weekly",             # Tareas semanales
    "/etc/cron.monthly",            # Tareas mensuales
    # Legacy init scripts
    "/etc/rc.local",                # Script de arranque local
    "/etc/init.d",                  # Scripts init clásicos
    # Biblioteca preload
    "/etc/ld.so.preload",           # Bibliotecas pre-cargadas (persistence stealth)
    # Binarios locales
    "/usr/local/bin",               # Ejecutables personalizados
    "/usr/local/sbin",              # Ejecutables de sistema personalizados
    # Autostart para entornos gráficos
    "/etc/xdg/autostart",           # Archivos .desktop para autoinicio de usuarios
    "~/.config/autostart",          # Autostart del usuario actual
    "~/.bashrc",                    # Inicialización de shell del usuario
    "~/.bash_profile",              # Inicialización de login shell
    "~/.profile",                   # Inicialización de login shell
    "~/.zshrc",                     # Configuración de Zsh si se usa
    # Scripts adicionales
    "/etc/profile.d",               # Scripts de inicialización del sistema
    "/etc/environment",             # Variables de entorno globales
]


SUSPICIOUS_SHEBANGS = [
    r"/bin/bash",
    r"/usr/bin/bash",
    r"/usr/bin/sh",
    r"/bin/sh",
    r"/usr/bin/python",
    r"/usr/bin/python3",
    r"/usr/bin/perl",
    r"/usr/bin/ruby",
    r"/usr/bin/env python",
    r"/usr/bin/env python3",
    r"/usr/bin/env perl",
    r"/usr/bin/env bash",
    r"/usr/bin/env sh",
    r"/usr/bin/env ruby",
    r"/bin/ksh",
    r"/usr/bin/ksh",
    r"/bin/zsh",
    r"/usr/bin/zsh",
]


# ------------------- Utilities -------------------

def setup_logging(level: str = "INFO", logfile: str = LOG_FILE, enable_syslog: bool = False):

    # ✨ Soporte opcional de color si colorlog está instalado
    try:
        from colorlog import ColoredFormatter
        use_colors = True
    except ImportError:
        use_colors = False

    # 🎯 Validación segura del nivel
    level = level.upper()
    lvl = getattr(logging, level, logging.INFO)

    logger = logging.getLogger()

    # Evita handlers duplicados si se llama múltiples veces
    if logger.handlers:
        logger.handlers.clear()

    logger.setLevel(lvl)

    # 🖨️ Formato base
    plain_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    
    # 🎨 Formato colorido para consola
    if use_colors:
        color_fmt = ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            }
        )
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(color_fmt)
    else:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(plain_fmt)

    logger.addHandler(sh)

    # 📁 Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(plain_fmt)
    logger.addHandler(fh)

    # 🧠 Opcional: soporte para syslog (ideal para sistemas Linux/Unix)
    if enable_syslog:
        try:
            syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
            syslog_handler.setFormatter(plain_fmt)
            logger.addHandler(syslog_handler)
        except Exception as e:
            logger.warning("No se pudo configurar syslog: %s", str(e))

    logger.debug("Logging configurado correctamente. Nivel: %s", level)



def run(cmd: str, timeout: int = 15, capture_stderr: bool = False) -> str:
    """
    Ejecuta un comando en shell y devuelve su salida como string.
    
    Args:
        cmd (str): Comando a ejecutar.
        timeout (int): Segundos máximos para la ejecución.
        capture_stderr (bool): Si True, captura stderr junto con stdout.
        
    Returns:
        str: Salida del comando. Devuelve cadena vacía si falla o excede el timeout.
    """
    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT if capture_stderr else subprocess.DEVNULL,
            text=True,
            timeout=timeout
        ).strip()
        logger.debug("run('%s') -> output length: %d", cmd, len(output))
        return output
    except subprocess.TimeoutExpired:
        logger.warning("run('%s') -> timeout after %d seconds", cmd, timeout)
        return ""
    except subprocess.CalledProcessError as e:
        logger.warning(
            "run('%s') -> command failed with code %d, output length: %d",
            cmd, e.returncode, len(e.output.strip()) if e.output else 0
        )
        return e.output.strip() if e.output and capture_stderr else ""
    except FileNotFoundError:
        logger.error("run('%s') -> command not found", cmd)
        return ""
    except Exception as e:
        logger.error("run('%s') -> unexpected error: %s", cmd, e, exc_info=True)
        return ""



def sha256_of_file(path: str, max_bytes: int = MAX_HASH_BYTES) -> Optional[str]:
    """
    Calcula el hash SHA256 de un archivo, hasta un límite de bytes.
    
    Parámetros:
        path (str): Ruta del archivo a hashear.
        max_bytes (int): Máximo número de bytes a leer (por defecto MAX_HASH_BYTES).
    
    Retorna:
        str | None: Hex digest del SHA256, o None si ocurre un error.
    
    Mejoras incluidas:
        - Manejo de excepciones más específico
        - Logging detallado de errores
        - Lectura en chunks para archivos grandes
        - Soporte de interrupción de lectura si se supera max_bytes
    """
    try:
        h = sha256()
        total_read = 0
        chunk_size = 8192  # Tamaño de chunk en bytes

        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break  # Fin de archivo
                h.update(chunk)
                total_read += len(chunk)

                if total_read > max_bytes:
                    logging.debug(
                        "sha256_of_file: límite de %d bytes alcanzado en %s",
                        max_bytes, path
                    )
                    break

        digest = h.hexdigest()
        logging.debug("sha256_of_file: hash calculado correctamente para %s", path)
        return digest

    except FileNotFoundError:
        logging.warning("sha256_of_file: archivo no encontrado: %s", path)
    except PermissionError:
        logging.warning("sha256_of_file: permiso denegado al acceder a: %s", path)
    except Exception as e:
        logging.error("sha256_of_file: error inesperado para %s: %s", path, e, exc_info=True)

    return None

# Detecta si estamos en Windows
IS_WINDOWS = platform.system() == "Windows"

# Solo importar pwd/grp si no estamos en Windows
if not IS_WINDOWS:
    import pwd
    import grp

def file_metadata(path: str, verbose: bool = False) -> dict:
    """
    Obtiene metadatos detallados de un archivo, compatible con Linux y Windows.
    """
    try:
        st = os.stat(path)

        file_type = (
            "directory" if os.path.isdir(path) else
            "symlink" if os.path.islink(path) else
            "regular" if os.path.isfile(path) else
            "socket" if hasattr(stat, "S_ISSOCK") and stat.S_ISSOCK(st.st_mode) else
            "fifo" if hasattr(stat, "S_ISFIFO") and stat.S_ISFIFO(st.st_mode) else
            "block" if hasattr(stat, "S_ISBLK") and stat.S_ISBLK(st.st_mode) else
            "character" if hasattr(stat, "S_ISCHR") and stat.S_ISCHR(st.st_mode) else
            "unknown"
        )

        # Usuario y grupo solo en Linux
        if not IS_WINDOWS:
            try:
                uid_name = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                uid_name = st.st_uid
            try:
                gid_name = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                gid_name = st.st_gid
            uid = st.st_uid
            gid = st.st_gid
        else:
            uid_name = gid_name = uid = gid = "N/A"

        return {
            "size": st.st_size,
            "uid": uid,
            "user": uid_name,
            "gid": gid,
            "group": gid_name,
            "mode": oct(st.st_mode & 0o7777),
            "type": file_type,
            "atime": datetime.fromtimestamp(st.st_atime).isoformat(),
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
            "is_readable": os.access(path, os.R_OK),
            "is_writable": os.access(path, os.W_OK),
            "is_executable": os.access(path, os.X_OK),
        }

    except Exception as e:
        if verbose:
            logging.warning("file_metadata failed for %s: %s", path, e, exc_info=True)
        return {}


# ------------------- Heuristic detectors -------------------


def detect_long_random_name(
    name: str,
    length_threshold: int = 18,
    verbose: bool = False,
    include_special_chars: bool = False
) -> Union[bool, Tuple[bool, int, List[str]]]:
    """
    Detecta si un nombre contiene una secuencia larga alfanumérica, lo que
    indica que probablemente fue generado automáticamente.

    Args:
        name (str): Nombre a analizar.
        length_threshold (int): Longitud mínima de la secuencia alfanumérica para considerarla "larga".
        verbose (bool): Si True, registra información detallada en logs.
        include_special_chars (bool): Si True, permite detectar secuencias que incluyan caracteres especiales como '.', '@', etc.

    Returns:
        bool o (bool, int, List[str]): Retorna True si se detecta un nombre generado automáticamente,
        junto con la longitud máxima de la secuencia alfanumérica y la lista de coincidencias si verbose=True.
    """
    try:
        # Regex flexible según si se permiten caracteres especiales
        pattern = r"[A-Za-z0-9_.@-]{%d,}" % length_threshold if include_special_chars else r"[A-Za-z0-9_-]{%d,}" % length_threshold
        regex = re.compile(pattern)
        matches = regex.findall(name)
        max_length = max((len(m) for m in matches), default=0)
        detected = bool(matches)

        if verbose:
            logger.debug(
                "detect_long_random_name('%s') -> detected: %s, max_sequence_length: %d, matches: %s",
                name, detected, max_length, matches
            )
            return detected, max_length, matches

        return detected

    except Exception as e:
        logger.error("Error en detect_long_random_name('%s'): %s", name, e, exc_info=True)
        return (False, 0, []) if verbose else False




def detect_base64_blobs_in_text(text: str, min_len: int = 200) -> dict:
    """
    Detecta posibles blobs base64 en el texto basándose en secuencias largas 
    de caracteres típicos de base64.

    Args:
        text (str): Texto a analizar.
        min_len (int): Longitud mínima de la secuencia para considerarla blob.

    Returns:
        dict: {
            "found": bool,         # True si se detecta al menos un blob
            "count": int,          # Número de blobs detectados
            "blobs": List[dict]    # Lista de blobs encontrados con info extendida
                                    # {"truncated": str, "length": int, "full": str}
        }
    """
    try:
        # Limpieza completa de caracteres invisibles y espacios
        clean_text = re.sub(r"\s+", "", text)

        # Expresión regular para detectar secuencias Base64 largas
        regex = re.compile(r"[A-Za-z0-9+/=]{%d,}" % min_len)
        matches = regex.findall(clean_text)

        # Preparar salida con truncamiento y longitud
        blobs_info = [
            {
                "truncated": m[:100] + "..." if len(m) > 100 else m,
                "length": len(m),
                "full": m
            }
            for m in matches
        ]

        found = len(matches) > 0
        logger.debug(
            "detect_base64_blobs_in_text -> found=%s, count=%d, first_blob=%s",
            found,
            len(matches),
            blobs_info[0]["truncated"] if found else None
        )

        return {
            "found": found,
            "count": len(matches),
            "blobs": blobs_info
        }

    except Exception as e:
        logger.error("Error en detect_base64_blobs_in_text: %s", e, exc_info=True)
        return {"found": False, "count": 0, "blobs": []}

def detect_exec_patterns(text: str) -> Dict[str, Any]:
    """
    Detecta patrones de ejecución de código como eval(), exec(), 
    decodificaciones base64, o comandos en línea de Python/Perl/Sh.

    Args:
        text (str): Texto a analizar.

    Returns:
        dict: {
            "found": bool,         # True si se detecta al menos un patrón
            "count": int,          # Número total de coincidencias detectadas
            "patterns": Dict[str,int] # Diccionario con patrón: cantidad de veces detectado
        }
    """
    try:
        # Limpieza básica del texto para evitar falsos negativos
        clean_text = re.sub(r"\s+", "", text)

        # Patrones sospechosos extendidos
        patterns = [
            r"eval\(",
            r"exec\(",
            r"base64_decode",
            r"b64decode",
            r"python\s*-c",
            r"perl\s*-e",
            r"sh\s*-c",
            r"system\(",
            r"os\.popen",
            r"subprocess\.",
            r"execfile\(",
            r"input\(",
            r"pickle\.loads",
            r"marshal\.loads"
        ]

        regex = re.compile("|".join(patterns), re.IGNORECASE)
        matches = regex.findall(clean_text)

        # Contar ocurrencias por patrón
        pattern_counts = {}
        for match in matches:
            pattern_counts[match.lower()] = pattern_counts.get(match.lower(), 0) + 1

        found = len(matches) > 0

        logger.debug(
            "detect_exec_patterns -> found=%s, total_matches=%d, pattern_counts=%s",
            found, len(matches), pattern_counts
        )

        return {
            "found": found,
            "count": len(matches),
            "patterns": pattern_counts
        }

    except Exception as e:
        logger.error("Error en detect_exec_patterns: %s", e, exc_info=True)
        return {"found": False, "count": 0, "patterns": {}}

# ------------------- Core scanning functions -------------------

def list_files_in_paths(paths: List[str], max_items: int = 2000, excludes: Set[str] = set()) -> List[str]:
    found: List[str] = []
    for p in paths:
        if p in excludes:
            continue
        try:
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    # filter excluded directories quickly
                    if any(ex in root for ex in excludes):
                        continue
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp in excludes:
                            continue
                        found.append(fp)
                        if len(found) >= max_items:
                            break
                    if len(found) >= max_items:
                        break
            elif os.path.isfile(p):
                found.append(p)
        except Exception:
            logging.debug("list_files_in_paths error on %s", p, exc_info=True)
            continue
    return found[:max_items]

def scan_file_for_obfuscation(path: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analiza un archivo para detectar posibles indicios de obfuscación o patrones sospechosos.

    Args:
        path (str): Ruta del archivo a analizar.
        verbose (bool): Si True, registra información detallada en logs.

    Returns:
        Dict[str, Any]: Diccionario con información del análisis:
            {
                "path": ruta del archivo,
                "suspect": bool,
                "reasons": lista de razones sospechosas,
                "meta": metadatos del archivo,
                "snippet_sample": muestra del contenido si es sospechoso
            }
    """
    result = {"path": path, "suspect": False, "reasons": [], "meta": file_metadata(path)}

    try:
        size = os.path.getsize(path)
        # Ignorar archivos vacíos o muy grandes
        if size == 0 or size > 8_000_000:
            if verbose:
                logger.debug("scan_file_for_obfuscation: ignorado por tamaño %d bytes -> %s", size, path)
            return result

        with open(path, "r", errors="ignore") as f:
            content = f.read()
            head = content[:512]

            # Detectar shebangs sospechosos
            if head.startswith("#!"):
                for s in SUSPICIOUS_SHEBANGS:
                    if s in head:
                        result["suspect"] = True
                        result["reasons"].append("shebang:" + head.splitlines()[0])
                        if verbose:
                            logger.debug("Shebang sospechoso detectado: %s -> %s", s, path)
                        break

            # Detectar blobs base64 grandes
            if detect_base64_blobs_in_text(content, min_len=200):
                result["suspect"] = True
                result["reasons"].append("base64_blob")
                if verbose:
                    logger.debug("Blob base64 detectado en %s", path)

            # Detectar patrones de ejecución
            if detect_exec_patterns(content):
                result["suspect"] = True
                result["reasons"].append("exec_pattern")
                if verbose:
                    logger.debug("Patrón de ejecución detectado en %s", path)

            # Agregar snippet para triage
            if result["suspect"]:
                result["snippet_sample"] = content[:1000]

    except Exception as e:
        if verbose:
            logger.warning("scan_file_for_obfuscation falló para %s: %s", path, e, exc_info=True)

    return result


def compute_hashes_concurrent(
    paths: List[str],
    threads: int = THREADS,
    verbose: bool = False,
    max_hash_bytes: int = MAX_HASH_BYTES
) -> List[Dict[str, Any]]:
    """
    Calcula hashes SHA256 de múltiples archivos de manera concurrente,
    incluyendo metadatos detallados de cada archivo.

    Args:
        paths (List[str]): Lista de rutas de archivos a procesar.
        threads (int): Número de hilos para procesamiento concurrente.
        verbose (bool): Si True, registra información detallada sobre cada archivo procesado.
        max_hash_bytes (int): Número máximo de bytes a leer por archivo para el hash.

    Returns:
        List[Dict[str, Any]]: Lista de diccionarios con información de cada archivo:
            {
                "path": ruta del archivo,
                "sha256": hash SHA256 (str o None si falla),
                "meta": metadatos del archivo (dict)
            }
    """
    results: List[Dict[str, Any]] = []

    if not paths:
        if verbose:
            logger.warning("compute_hashes_concurrent: no hay archivos para procesar")
        return results

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(sha256_of_file, path, max_bytes=max_hash_bytes): path for path in paths}

        for future in as_completed(futures):
            path = futures[future]
            try:
                hash_value = future.result()
                meta = file_metadata(path, verbose=verbose)
                results.append({"path": path, "sha256": hash_value, "meta": meta})
                if verbose:
                    logger.debug(
                        "compute_hashes_concurrent: procesado %s -> sha256: %s, size: %s",
                        path,
                        hash_value,
                        meta.get("size", "unknown")
                    )
            except Exception as e:
                logger.warning("compute_hashes_concurrent: fallo al procesar %s: %s", path, e, exc_info=True)
                results.append({"path": path, "sha256": None, "meta": {}})

    if verbose:
        logger.info("compute_hashes_concurrent: hashes calculados para %d archivos", len(results))

    return results


def scan_files_concurrent(
    paths: List[str],
    threads: int = THREADS,
    verbose: bool = False
) -> List[Dict[str, Any]]:
    """
    Escanea múltiples archivos concurrentemente para detectar obfuscación o patrones sospechosos.

    Args:
        paths (List[str]): Lista de rutas de archivos a analizar.
        threads (int): Número de hilos para ejecución concurrente.
        verbose (bool): Si True, registra información detallada sobre cada archivo procesado.

    Returns:
        List[Dict[str, Any]]: Lista de hallazgos con información de cada archivo sospechoso.
            Cada elemento incluye al menos:
            {
                "path": ruta del archivo,
                "suspect": bool,
                "details": información adicional según scan_file_for_obfuscation
            }
    """
    findings: List[Dict[str, Any]] = []

    if not paths:
        if verbose:
            logger.warning("scan_files_concurrent: no hay archivos para escanear")
        return findings

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_file_for_obfuscation, path): path for path in paths}

        for future in as_completed(futures):
            path = futures[future]
            try:
                result = future.result()
                if result.get("suspect"):
                    findings.append(result)
                if verbose:
                    logger.debug(
                        "scan_files_concurrent: %s -> suspect: %s, details: %s",
                        path,
                        result.get("suspect", False),
                        result.get("details", {})
                    )
            except Exception as e:
                logger.warning("scan_files_concurrent: fallo al escanear %s: %s", path, e, exc_info=True)

    if verbose:
        logger.info("scan_files_concurrent: archivos sospechosos detectados: %d", len(findings))

    return findings


# ------------------- YARA helpers (optional) -------------------
def load_yara_rules(rules_path: str, verbose: bool = False) -> Optional[yara.Rules]:
    """
    Carga reglas YARA desde un archivo o directorio de reglas. Devuelve None si yara-python 
    no está disponible o si falla la carga.

    Args:
        rules_path (str): Ruta al archivo o directorio de reglas YARA.
        verbose (bool): Si True, registra información detallada sobre el proceso.

    Returns:
        Optional[yara.Rules]: Objeto yara.Rules compilado o None si falla.
    """
    if not YARA_AVAILABLE:
        if verbose:
            logger.info("yara-python no disponible; se omite escaneo YARA")
        return None

    if not os.path.exists(rules_path):
        logger.warning("Archivo o directorio de reglas YARA no existe: %s", rules_path)
        return None

    try:
        # Compila reglas YARA desde archivo o directorio
        rules = yara.compile(filepath=rules_path) if os.path.isfile(rules_path) else yara.compile(filepaths={f: os.path.join(rules_path, f) for f in os.listdir(rules_path)})
        if verbose:
            logger.info("Reglas YARA cargadas correctamente desde %s", rules_path)
        return rules

    except yara.SyntaxError as e:
        logger.error("Error de sintaxis en archivo YARA %s: %s", rules_path, e)
    except Exception as e:
        logger.exception("Fallo al cargar reglas YARA desde %s: %s", rules_path, e)

    return None


def yara_scan_file(rules: Any, path: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Escanea un archivo con reglas YARA y devuelve coincidencias encontradas.

    Args:
        rules (Any): Objeto de reglas YARA compiladas.
        path (str): Ruta del archivo a escanear.
        verbose (bool): Si True, registra información adicional sobre cada coincidencia.

    Returns:
        List[Dict[str, Any]]: Lista de diccionarios con información de cada coincidencia:
            {
                "rule": nombre de la regla YARA,
                "namespace": namespace de la regla,
                "matches": lista de strings con los strings detectados
            }
    """
    matches: List[Dict[str, Any]] = []

    if not rules:
        if verbose:
            logger.warning("yara_scan_file: No se proporcionaron reglas para %s", path)
        return matches

    if not os.path.isfile(path):
        if verbose:
            logger.warning("yara_scan_file: Archivo no existe o no es regular: %s", path)
        return matches

    try:
        # Escaneo YARA seguro
        yara_matches = rules.match(path)
        for m in yara_matches:
            match_info = {
                "rule": getattr(m, "rule", "unknown"),
                "namespace": getattr(m, "namespace", "default"),
                "matches": []
            }
            # Extrae los strings detectados
            try:
                for s in getattr(m, "strings", []):
                    offset, identifier, data = s
                    match_info["matches"].append(f"{identifier}@{offset}: {data[:50]}{'...' if len(data) > 50 else ''}")
            except Exception as e:
                if verbose:
                    logger.debug("yara_scan_file: fallo procesando strings para %s: %s", path, e)
            matches.append(match_info)

        if verbose:
            logger.info("yara_scan_file: %d coincidencias encontradas en %s", len(matches), path)

    except Exception as e:
        logger.debug("yara_scan_file: Fallo escaneo YARA para %s: %s", path, e, exc_info=True)

    return matches


# ------------------- Higher-level checks -------------------

def check_ld_preload(verify_paths: bool = True) -> List[Dict[str, str]]:
    """
    Revisa el archivo /etc/ld.so.preload para detectar bibliotecas pre-cargadas.

    Args:
        verify_paths (bool): Si True, verifica si las rutas listadas realmente existen.

    Returns:
        List[Dict[str, str]]: Lista de diccionarios con información de cada entrada:
            {
                "path": ruta del archivo,
                "status": "exists" | "missing" | "listed" | "error_reading",
                "size": tamaño en bytes si existe,
                "permissions": permisos en octal si existe
            }
    """
    ld_path = "/etc/ld.so.preload"
    results: List[Dict[str, str]] = []

    if not os.path.exists(ld_path):
        logger.warning("check_ld_preload: %s no existe", ld_path)
        return results

    try:
        with open(ld_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        for line in lines:
            entry: Dict[str, str] = {"path": line, "status": "unknown", "size": "-", "permissions": "-"}
            if verify_paths:
                if os.path.exists(line):
                    entry["status"] = "exists"
                    try:
                        st = os.stat(line)
                        entry["size"] = str(st.st_size)
                        entry["permissions"] = oct(st.st_mode & 0o7777)
                    except Exception as e:
                        logger.warning("check_ld_preload: no se pudo obtener metadatos de %s: %s", line, e)
                else:
                    entry["status"] = "missing"
                    logger.warning("check_ld_preload: %s listado pero no existe", line)
            else:
                entry["status"] = "listed"

            results.append(entry)

        logger.info("check_ld_preload: procesadas %d entradas", len(results))

    except Exception as e:
        logger.error("check_ld_preload: error leyendo %s: %s", ld_path, e, exc_info=True)
        results.append({"path": ld_path, "status": "error_reading", "size": "-", "permissions": "-"})

    return results



def list_systemd_unit_files(limit: int = 1000, filter_status: str = None) -> List[Dict[str, str]]:
    """
    Lista los archivos de unidad systemd de tipo 'service'.
    
    Args:
        limit (int): Número máximo de unidades a retornar.
        filter_status (str, optional): Filtrar por estado ('enabled', 'disabled', 'static', 'masked').
    
    Returns:
        List[Dict[str, str]]: Lista de diccionarios con la información de cada unidad:
            {
                "unit": nombre de la unidad,
                "state": estado de la unidad
            }
    """
    units: List[Dict[str, str]] = []
    try:
        out = run("systemctl list-unit-files --type=service --no-pager --no-legend || true")
        if not out:
            logger.warning("list_systemd_unit_files: no se obtuvo salida de systemctl")
            return units

        for ln in out.splitlines():
            if not ln.strip():
                continue
            parts = ln.split()
            if len(parts) < 2:
                logger.debug("list_systemd_unit_files: línea ignorada '%s'", ln)
                continue
            unit_name, unit_state = parts[0], parts[1]
            if filter_status and unit_state.lower() != filter_status.lower():
                continue
            units.append({"unit": unit_name, "state": unit_state})
            if len(units) >= limit:
                break
        logger.info("list_systemd_unit_files: retornadas %d unidades", len(units))
    except Exception as e:
        logger.error("list_systemd_unit_files: error ejecutando systemctl: %s", e, exc_info=True)

    return units




def analyze_auth_logs_sample(limit_lines: int = 2000, search_patterns: List[str] = None) -> Dict[str, Any]:
    """
    Analiza logs de autenticación del sistema y extrae información relevante.

    Parámetros:
        limit_lines (int): Número máximo de líneas a leer de los logs.
        search_patterns (List[str]): Patrones adicionales para buscar en los logs.

    Retorna:
        Dict[str, Any]: Diccionario con:
            - log_path: ruta del log encontrado
            - sample_lines: primeras 500 líneas analizadas
            - base64_like_count: cantidad de líneas que parecen base64
            - tmp_exec_count: cantidad de referencias a /tmp o /var/tmp
            - top_ips: top 10 IPs detectadas
            - failed_login_count: cantidad de intentos fallidos de login
            - sudo_usage_count: cantidad de usos del comando sudo
            - notes: notas sobre errores o estado
    """

    if search_patterns is None:
        search_patterns = ["failed", "invalid", "error", "sudo", "authentication", "pam"]

    log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog"]
    found_log = next((p for p in log_paths if os.path.exists(p)), None)

    if not found_log:
        logging.warning("No se encontró un log de autenticación accesible.")
        return {"log_path": None, "notes": "No se encontró ningún archivo de log accesible."}

    try:
        pattern_regex = "|".join(re.escape(p) for p in search_patterns)
        command = f"tail -n {limit_lines} {found_log} | egrep -i '{pattern_regex}' || true"
        output = run(command)
        lines = output.splitlines()

        # Detectar líneas similares a base64
        base64_like = [l for l in lines if re.search(r"[A-Za-z0-9+/=]{150,}", l)]

        # Referencias a /tmp o /var/tmp
        tmp_execs = [l for l in lines if re.search(r"(/tmp/|/var/tmp/)", l)]

        # Cuentas de IPs
        ip_counter = {}
        for line in lines:
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                ip_counter[ip] = ip_counter.get(ip, 0) + 1
        top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]

        # Heurísticas adicionales
        failed_login_count = sum(1 for l in lines if "failed password" in l.lower())
        sudo_usage_count = sum(1 for l in lines if "sudo" in l.lower())

        logging.info(
            f"✅ Log analizado correctamente: {found_log} "
            f"({len(lines)} líneas, {len(base64_like)} base64, {len(tmp_execs)} tmp_exec, "
            f"{failed_login_count} login fallidos, {sudo_usage_count} usos de sudo)"
        )

        return {
            "log_path": found_log,
            "sample_lines": lines[:500],
            "base64_like_count": len(base64_like),
            "tmp_exec_count": len(tmp_execs),
            "top_ips": top_ips,
            "failed_login_count": failed_login_count,
            "sudo_usage_count": sudo_usage_count,
            "notes": "Análisis del log completado correctamente"
        }

    except Exception as e:
        logging.error("❌ Error al analizar el log %s: %s", found_log, e, exc_info=True)
        return {"log_path": found_log, "notes": f"Error al analizar el log: {e}"}


# ------------------- Risk scoring -------------------

def compute_risk_v2(report: Dict[str, Any], visualizar: bool = True) -> Dict[str, Any]:

    score = 0
    issues: List[str] = []

    # 🛠️ Heurísticas de riesgo
    if report.get("ld_preload"):
        score += 40
        issues.append("🔐 Presencia de 'ld.so.preload'")

    suspicious_scripts = report.get("suspicious_scripts", [])
    if suspicious_scripts:
        cnt = len(suspicious_scripts)
        score += min(40, cnt * 4)
        issues.append(f"📜 {cnt} scripts sospechosos detectados")

    if report.get("long_random_names"):
        score += 15
        issues.append("🔢 Nombres largos o aleatorios detectados")

    if report.get("world_writable_recent"):
        score += 10
        issues.append("🌍 Archivos world-writable o modificados recientemente")

    if report.get("auth_analysis", {}).get("base64_like_count", 0) > 3:
        score += 10
        issues.append("🧬 Blobs tipo base64 detectados en logs de autenticación")

    units = report.get("systemd_units", [])
    if any("enabled" in u.lower() for u in units):
        score += 5
        issues.append("⚙️ Unidades systemd habilitadas detectadas")

    if report.get("yara_matches_count", 0) > 0:
        yara_count = report["yara_matches_count"]
        score += min(25, yara_count * 5)
        issues.append(f"🧿 YARA coincidió con {yara_count} reglas")

    # 🧮 Normalizar puntuación
    if score > 100:
        score = 100

    risk_data = {
        "risk_score": score,
        "risk_issues": issues
    }

    # 📊 Salida visual opcional
    if visualizar:
        print(f"\n{BOLD}{CYAN}==== Evaluación de Riesgo: EXTREME v2 ===={RESET}")
        print(f"{BOLD}🎯 Riesgo Total:{RESET} ", end="")
        if score >= 80:
            print(f"{RED}{BOLD}{score}/100 🔥 Nivel CRÍTICO{RESET}")
        elif score >= 50:
            print(f"{YELLOW}{score}/100 ⚠️ Nivel ALTO{RESET}")
        elif score >= 20:
            print(f"{CYAN}{score}/100 🟡 Nivel MODERADO{RESET}")
        else:
            print(f"{GREEN}{score}/100 ✅ Nivel BAJO{RESET}")

        print(f"\n{BOLD}📌 Indicadores detectados:{RESET}")
        for issue in issues:
            print(f"  - {issue}")
        print()

    return risk_data


# ------------------- Report generation -------------------

def generate_html(report: Dict[str, Any], out_html: str = OUT_HTML) -> None:
    """
    Genera un reporte HTML visual a partir del diccionario de auditoría.

    Args:
        report (Dict[str, Any]): Reporte de auditoría con todos los datos.
        out_html (str): Ruta de salida del archivo HTML.
    """
    try:
        h = []

        # Header y estilos
        h.append(
            "<!doctype html><html><head><meta charset='utf-8'><title>EXTREME Detection v2</title>"
            "<style>"
            "body{font-family:Inter,Arial,sans-serif;background:#050812;color:#e6f3ff;padding:20px}"
            ".card{background:linear-gradient(135deg,#071226,#0b1420);padding:14px;"
            "border-radius:10px;margin-bottom:12px;box-shadow:0 10px 30px rgba(0,0,0,.6)}"
            "pre{background:#021022;padding:10px;border-radius:6px;overflow:auto;max-height:260px;}"
            "h1,h3{margin-top:0;}"
            "footer{opacity:.7;margin-top:18px;font-size:0.85em;}"
            "</style></head><body>"
        )

        # Título
        hostname = escape(report.get("basic", {}).get("hostname", "Desconocido"))
        h.append(f"<h1> Detection Auditor — {hostname}</h1>")

        # Risk score
        risk = report.get("risk", {})
        risk_score = risk.get("risk_score", "?")
        risk_issues = ", ".join(risk.get("risk_issues", []))[:1000]
        h.append(f"<div class='card'><strong>Risk score:</strong> {risk_score}/100<br>"
                 f"<em>Top issues:</em> {escape(risk_issues)}</div>")

        # Summary
        summary = {
            "hostname": report.get("basic", {}).get("hostname"),
            "os": report.get("basic", {}).get("os"),
            "uptime": report.get("basic", {}).get("uptime"),
            "suspicious_script_count": len(report.get("suspicious_scripts", [])),
            "yara_matches": report.get("yara_matches_count", 0)
        }
        h.append("<div class='card'><h3>Resumen</h3><pre>" + escape(json.dumps(summary, indent=2)) + "</pre></div>")

        # Bloques de datos extensibles
        data_blocks = [
            ("Scripts sospechosos (muestra)", "suspicious_scripts"),
            ("ld.so.preload", "ld_preload"),
            ("Nombres largos/aleatorios (muestra)", "long_random_names"),
            ("World-writable / recientes (muestra)", "world_writable_recent"),
            ("Auth logs - top IPs", ("auth_analysis", "top_ips")),
            ("YARA matches (muestra)", "yara_matches"),
            ("Hashes sospechosos (muestra)", "suspect_hashes")
        ]

        for title, key in data_blocks:
            content = []
            if isinstance(key, tuple):
                content = report.get(key[0], {}).get(key[1], [])
            else:
                content = report.get(key, [])
            if content:
                sample = json.dumps(content[:200], indent=2)
                h.append(f"<div class='card'><h3>{title}</h3><pre>{escape(sample)}</pre></div>")

        # Playbook sugerido
        playbook = [
            "1) Aislar la máquina si score > 50.",
            "2) Crear snapshot / imagen forense antes de tocar archivos.",
            "3) Recolectar hashes de 'suspect_hashes' y enviarlos a un repositorio seguro.",
            "4) Revisar ld.so.preload, crontabs y unidades systemd; documentar diferencias con imágenes limpias.",
            "5) Rotar credenciales afectadas, forzar cambio de claves si hay evidencia de exfiltración.",
            "6) Ejecutar análisis con herramientas forenses y correlacionar con SIEM.",
        ]
        h.append("<div class='card'><h3>Playbook sugerido</h3><pre>" + escape("\n".join(playbook)) + "</pre></div>")

        # Footer
        h.append("<footer>Generated: " + escape(report.get("generated_at", "Desconocido")) + "</footer>")
        h.append("</body></html>")

        # Escritura del archivo
        with open(out_html, "w", encoding="utf-8") as f:
            f.write("\n".join(h))

        logging.info("HTML report saved to %s", out_html)

    except Exception as e:
        logging.exception("Error generando HTML report: %s", e)


# ------------------- Main flow -------------------

def assemble_report(cfg: Dict[str, Any]) -> Dict[str, Any]:

    print(f"\n{BOLD}{CYAN}📊 Iniciando recolección de información extrema...{RESET}")

    report: Dict[str, Any] = {}
    report["generated_at"] = datetime.utcnow().isoformat() + "Z"

    print(f"{CYAN}🔎 Recopilando información básica del sistema...{RESET}")
    report["basic"] = {
        "hostname": run("hostname"),
        "user": run("whoami"),
        "os": run("cat /etc/os-release 2>/dev/null | sed -n 's/PRETTY_NAME=//p' | tr -d '\"'") or run("uname -a"),
        "uptime": run("uptime -p"),
    }

    print(f"{CYAN}📁 Escaneando rutas de persistencia...{RESET}")
    persistence_paths = cfg.get("persistence_paths", DEFAULT_PERSISTENCE_PATHS)
    excludes = set(cfg.get("excludes", []))
    report["persistence_files"] = list_files_in_paths(persistence_paths, max_items=cfg.get("max_paths", 2000), excludes=excludes)

    print(f"{CYAN}🧊 Recolectando archivos temporales...{RESET}")
    paths_to_check: List[str] = []
    for base in ["/tmp", "/var/tmp", "/home"]:
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                if any(ex in root for ex in excludes): continue
                for f in files:
                    fp = os.path.join(root, f)
                    if fp in excludes: continue
                    paths_to_check.append(fp)
                    if len(paths_to_check) >= cfg.get("max_tmp_paths", 2000):
                        break
                if len(paths_to_check) >= cfg.get("max_tmp_paths", 2000):
                    break

    print(f"{CYAN}🧬 Detectando nombres aleatorios/largos...{RESET}")
    report["long_random_names"] = []
    for p in paths_to_check:
        if detect_long_random_name(os.path.basename(p), length_threshold=cfg.get("random_name_len", 18)):
            report["long_random_names"].append({"path": p, "name": os.path.basename(p), "meta": file_metadata(p)})
            if len(report["long_random_names"]) >= cfg.get("max_long_names", 500):
                break

    candidate_scan_paths = (report["persistence_files"] + paths_to_check)[:cfg.get("scan_limit", 3000)]
    logging.info("Se escanearán %d archivos en búsqueda de ofuscación", len(candidate_scan_paths))

    print(f"{CYAN}🔍 Escaneando archivos en paralelo (ofuscación)...{RESET}")
    suspicious = scan_files_concurrent(candidate_scan_paths, threads=cfg.get("threads", THREADS))
    report["suspicious_scripts"] = suspicious

    print(f"{CYAN}🌐 Buscando archivos world-writable o recientes...{RESET}")
    report["world_writable_recent"] = []
    cutoff = datetime.now() - timedelta(days=cfg.get("recent_days", 14))
    for p in (report["persistence_files"] + paths_to_check):
        try:
            st = os.stat(p)
            mtime = datetime.fromtimestamp(st.st_mtime)
            if (st.st_mode & 0o002) or (mtime > cutoff):
                report["world_writable_recent"].append({"path": p, "meta": file_metadata(p)})
                if len(report["world_writable_recent"]) >= cfg.get("max_world_writable", 500):
                    break
        except Exception:
            continue

    print(f"{CYAN}⚙️  Analizando unidades systemd...{RESET}")
    report["systemd_units"] = list_systemd_unit_files(limit=cfg.get("systemd_limit", 1000))

    print(f"{CYAN}🛡️ Verificando ld.so.preload...{RESET}")
    report["ld_preload"] = check_ld_preload()

    print(f"{CYAN}📚 Analizando logs de autenticación...{RESET}")
    report["auth_analysis"] = analyze_auth_logs_sample(limit_lines=cfg.get("auth_lines", 2000))

    print(f"{CYAN}🔐 Calculando hashes de archivos sospechosos...{RESET}")
    suspect_paths = set(
        [s["path"] for s in report["suspicious_scripts"] if s.get("path")] +
        report["persistence_files"][:cfg.get("persistence_hash_limit", 500)] +
        [ln["path"] for ln in report["long_random_names"][:cfg.get("longname_hash_limit", 500)]]
    )
    logging.info("Calculando hashes para %d archivos sospechosos", len(suspect_paths))
    report["suspect_hashes"] = compute_hashes_concurrent(list(suspect_paths), threads=cfg.get("threads", THREADS))

    print(f"{CYAN}🧿 Escaneando con reglas YARA...{RESET}")
    yara_rules_path = cfg.get("yara_rules")
    yara_matches = []
    if yara_rules_path and YARA_AVAILABLE:
        rules = load_yara_rules(yara_rules_path)
        if rules:
            for p in list(suspect_paths)[:cfg.get("yara_scan_limit", 500)]:
                if os.path.isfile(p):
                    matches = yara_scan_file(rules, p)
                    if matches:
                        yara_matches.append({"path": p, "matches": matches})
    report["yara_matches"] = yara_matches
    report["yara_matches_count"] = len(yara_matches)

    print(f"{CYAN}🔩 Recolectando módulos y contenedores...{RESET}")
    report["lsmod"] = run("lsmod || true")[:20000]
    report["docker"] = run("docker ps -a --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}}' 2>/dev/null || true")[:10000]

    print(f"{CYAN}🔓 Recolectando muestra de archivos SUID/SGID...{RESET}")
    report["suid_sample"] = run("find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -printf '%M %u %g %p\\n' 2>/dev/null | head -n 200")

    print(f"{CYAN}📈 Calculando nivel de riesgo...{RESET}")
    risk = compute_risk_v2(report)
    report["risk"] = risk
    report["generated_at"] = datetime.utcnow().isoformat() + "Z"

    print(f"\n{GREEN}✅ Recolección finalizada. Reporte ensamblado exitosamente.{RESET}")
    return report


# ------------------- CLI & config -------------------

def load_config_file(path: Optional[str]) -> Dict[str, Any]:
    """
    Carga un archivo de configuración YAML de manera segura.

    Args:
        path (Optional[str]): Ruta al archivo YAML de configuración.

    Returns:
        Dict[str, Any]: Diccionario con la configuración cargada.
    """
    cfg: Dict[str, Any] = {}

    if not path:
        logging.debug("No se proporcionó ruta de configuración; retornando diccionario vacío.")
        return cfg

    if not yaml:
        logging.warning("PyYAML no disponible; se ignorará el archivo de configuración: %s", path)
        return cfg

    if not os.path.isfile(path):
        logging.warning("El archivo de configuración no existe o no es un archivo regular: %s", path)
        return cfg

    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            logging.info("Configuración cargada correctamente desde %s", path)
    except yaml.YAMLError as ye:
        logging.error("Error de parsing YAML en %s: %s", path, ye, exc_info=True)
    except Exception as e:
        logging.exception("Error leyendo el archivo de configuración %s: %s", path, e)

    return cfg

def parse_args() -> argparse.Namespace:
    """
    Parsea los argumentos de línea de comando para EXTREME Detection Auditor 
    y provee interacción opcional para confirmar configuración.
    """
    p = argparse.ArgumentParser(
        description="EXTREME Detection Auditor (defensivo). Ejecutar SOLO en sistemas que poseas."
    )
    p.add_argument("--config", "-c", help="Archivo YAML de configuración (opcional).")
    p.add_argument("--out-json", default=OUT_JSON, help="Archivo JSON de salida.")
    p.add_argument("--out-html", default=OUT_HTML, help="Archivo HTML de salida.")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING"], help="Nivel de log.")
    p.add_argument("--threads", type=int, default=THREADS, help="Número de hilos para hashing/scan.")
    p.add_argument("--i-own-this-machine", action="store_true", help="Confirma que eres propietario/admin.")
    p.add_argument("--yara-rules", help="Ruta a archivo de reglas YARA (opcional).")
    p.add_argument("--no-html", action="store_true", help="No generar HTML (solo JSON).")
    p.add_argument("--skip-confirm", action="store_true", help="Omitir confirmación de propiedad (útil para scripts).")
    p.add_argument("--verbose", action="store_true", help="Modo detallado de logging.")

    args = p.parse_args()

    # 🎛️ INTERACTIVO
    print(f"{BOLD}{CYAN}=== ⚙️  EXTREME Detection Auditor Linux ==={RESET}\n")

    if not args.i_own_this_machine and not args.skip_confirm:
        confirm = input(f"{RED}⚠️  Confirmación requerida:{RESET} ¿Eres el propietario/admin de esta máquina? ({GREEN}s{RESET}/{RED}n{RESET}): ").strip().lower()
        if confirm == "s":
            args.i_own_this_machine = True
        else:
            print(f"\n{RED}⛔ Abortando:{RESET} Debes confirmar propiedad/admin para continuar.\n")
            exit(2)

    # Config YAML
    if not args.config:
        cfg_input = input(f"{CYAN}🔧 Archivo YAML de configuración (opcional) [Enter para omitir]: {RESET}").strip()
        if cfg_input:
            args.config = cfg_input
            if not os.path.isfile(cfg_input):
                logger.warning("Archivo YAML proporcionado no existe: %s", cfg_input)

    # JSON Output
    if args.out_json == OUT_JSON:
        json_out = input(f"{CYAN}💾 Archivo JSON de salida [{OUT_JSON}]: {RESET}").strip()
        if json_out:
            args.out_json = json_out

    # HTML Output
    if args.out_html == OUT_HTML:
        html_out = input(f"{CYAN}🖼️  Archivo HTML de salida [{OUT_HTML}]: {RESET}").strip()
        if html_out:
            args.out_html = html_out

    # Log level
    log_level = input(f"{CYAN}📋 Nivel de log (DEBUG/INFO/WARNING) [{args.log_level}]: {RESET}").strip().upper()
    if log_level in ("DEBUG", "INFO", "WARNING"):
        args.log_level = log_level

    # Threads
    threads_input = input(f"{CYAN}⚙️  Número de hilos para análisis [{args.threads}]: {RESET}").strip()
    if threads_input.isdigit():
        args.threads = max(1, int(threads_input))  # al menos 1 hilo

    # YARA rules
    yara_input = input(f"{CYAN}🧬 Ruta a reglas YARA (opcional) [Enter para omitir]: {RESET}").strip()
    if yara_input:
        args.yara_rules = yara_input
        if not os.path.isfile(yara_input):
            logger.warning("Archivo YARA no encontrado: %s", yara_input)

    # No HTML
    no_html_input = input(f"{CYAN}🛑 ¿Omitir generación de HTML? (s/n) [n]: {RESET}").strip().lower()
    if no_html_input == "s":
        args.no_html = True

    print(f"\n{GREEN}✅ Configuración completada. Iniciando escaneo...{RESET}")
    sleep(0.5)
    return args

def main():
    """
    Función principal de EXTREME Detection Auditor.
    Realiza escaneo de sistema, genera reportes JSON y HTML, y maneja logs y errores.
    """
    try:
        args = parse_args()

        # Confirmación de propiedad/admin
        if not args.i_own_this_machine:
            print(f"{RED}{BOLD}⛔ ERROR:{RESET} Debes pasar {BOLD}--i-own-this-machine{RESET} para confirmar que posees/admins la máquina. Abortando.\n")
            sys.exit(2)

        # Configuración de logging
        setup_logging(level=args.log_level)
        logging.info("🚀Detection Auditor v2 iniciado")

        # Cargar configuración YAML si existe
        print(f"\n{CYAN}🧠 Cargando configuración...{RESET}")
        cfg = load_config_file(args.config)

        # 🔁 Aplicar overrides desde CLI
        cfg["threads"] = args.threads
        if args.yara_rules:
            cfg["yara_rules"] = args.yara_rules

        # 📌 Parámetros por defecto si no existen
        cfg.setdefault("persistence_paths", DEFAULT_PERSISTENCE_PATHS)
        cfg.setdefault("excludes", [])
        cfg.setdefault("scan_limit", 3000)
        cfg.setdefault("recent_days", 14)
        cfg.setdefault("max_paths", 2000)
        cfg.setdefault("threads", args.threads)

        # 🧪 Iniciar escaneo
        print(f"{YELLOW}🔍 Iniciando escaneo del sistema...{RESET}")
        try:
            report = assemble_report(cfg)
            logging.info("🧪 Escaneo completado exitosamente")
        except Exception:
            logging.exception("❌ Fallo al generar el reporte.")
            print(f"\n{RED}‼️  Error crítico durante la generación del reporte. Revisa los logs para más detalles.{RESET}")
            sys.exit(1)

        # 💾 Guardar JSON
        out_json = args.out_json
        try:
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logging.info(f"📁 Reporte JSON guardado en {out_json}")
            print(f"\n{GREEN}✅ Reporte JSON guardado correctamente: {BOLD}{out_json}{RESET}")
        except Exception as e:
            logging.exception("Error al guardar el archivo JSON")
            print(f"{RED}❌ No se pudo guardar el archivo JSON:{RESET} {e}")

        # 🌐 Generar HTML si corresponde
        if not args.no_html:
            try:
                generate_html(report, out_html=args.out_html)
                logging.info(f"🖼️  Reporte HTML guardado en {args.out_html}")
                print(f"{GREEN}✅ HTML generado exitosamente: {BOLD}{args.out_html}{RESET}")
            except Exception:
                logging.exception("❌ Fallo al generar HTML")
                print(f"{RED}⚠️  Error al generar el archivo HTML.{RESET}")
        else:
            print(f"{YELLOW}⚠️  HTML omitido por configuración.{RESET}")

        # 🔹 Resumen final
        print(f"\n{CYAN}📊 EXTREME Detection Audit v2 finalizado.{RESET}")
        print(f"{BOLD}📂 Resultados:{RESET} JSON → {args.out_json} {'| HTML → ' + args.out_html if not args.no_html else ''}")
        print(f"{GREEN}✨ Gracias por usar esta herramienta extrema. Mantente seguro.{RESET}\n")

    except KeyboardInterrupt:
        logging.warning("⛔ Escaneo interrumpido por usuario")
        print(f"\n{RED}❌ Escaneo interrumpido por el usuario.{RESET}")
        sys.exit(130)
    except Exception as e:
        logging.exception("Error inesperado en main: %s", e)
        print(f"\n{RED}❌ Error crítico inesperado: {e}{RESET}")
        sys.exit(1)


try:
    from colorama import Fore, init
except ImportError:
    print("Colorama no está instalado. Ejecuta: pip install colorama")
    sys.exit(1)

# Inicializamos colorama
init(autoreset=True)

def banner_neon():
    """
    Banner interdimensional con efecto neón y colores vibrantes.
    Texto visible: ByMakaveli, El futuro es hoy, etc.
    """
    neon_colors = [
        Fore.LIGHTRED_EX, 
        Fore.LIGHTGREEN_EX, 
        Fore.LIGHTYELLOW_EX, 
        Fore.LIGHTBLUE_EX, 
        Fore.LIGHTMAGENTA_EX, 
        Fore.LIGHTCYAN_EX, 
        Fore.WHITE
    ]

    title_lines = [
        "BYMAKAVELI",
        "EL FUTURO ES HOY",
        "🛸🌌✨⚡💫",
        "DETECCIÓN INTERDIMENSIONAL"
    ]

    print("\n" + "🌠 " * 15 + "\n")

    for line in title_lines:
        colored_line = ""
        for char in line:
            if char != " ":
                # Cada carácter recibe un color neón aleatorio
                colored_line += random.choice(neon_colors) + char
            else:
                colored_line += " "
        print(colored_line)
        time.sleep(0.5)

    print("\n" + "✨" * 50 + "\n")

if __name__ == "__main__":
    banner_neon()
    main()
