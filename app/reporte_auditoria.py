"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Versión corregida en el PR de auditoría (Parte M). Cada cambio va marcado
con [FIX] y su CWE, que es lo que pide la plantilla del PR.
"""

import hashlib
import os
import secrets
import sqlite3
import subprocess

import yaml

# [FIX] Secreto expuesto (CWE-798).
# Antes estaban aquí escritas tal cual, así que se dan por comprometidas:
# hay que ROTARLAS en el proveedor real, borrar la línea no basta porque
# siguen en el historial de Git. Ahora se leen del entorno y el .env no se sube.
NOTIFICATION_API_KEY = os.getenv("REPORTAUDIT_API_KEY")
SMTP_PASSWORD = os.getenv("REPORTAUDIT_SMTP_PASSWORD")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # [FIX] YAML inseguro (CWE-20). safe_load solo hace tipos básicos,
        # ya no construye objetos arbitrarios de Python desde el fichero.
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    cursor = conexion.cursor()
    # [FIX] Inyección SQL (CWE-89). El dato ya no se pega en el texto,
    # viaja como parámetro (?), separado de la orden. El apóstrofo de
    # o'brien_ltd pasa a ser un dato más, no parte de la SQL.
    query = "SELECT * FROM reportes WHERE cliente = ?"
    cursor.execute(query, (nombre_cliente,))
    resultados = cursor.fetchall()
    conexion.close()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    # [FIX] Inyección de comandos (CWE-78) + path traversal (CWE-22).
    # Fuera os.system: uso lista de args con shell=False, así ; & | etc
    # dejan de interpretarse. Me quedo con el basename y solo acepto .html
    # de la carpeta de reportes, nada de rutas raras.
    base = os.path.basename(nombre_archivo)
    if not base.endswith(".html"):
        raise ValueError("Nombre de archivo no válido")
    if ".." in base or "/" in base or "\\" in base:
        raise ValueError("Nombre de archivo no válido")
    for c in [";", "&", "|", "$", "`", "\n"]:
        if c in base:
            raise ValueError("Nombre de archivo no válido")
    salida = base + ".pdf"
    subprocess.run(
        ["wkhtmltopdf", base, salida],
        shell=False,
        check=False,
    )
    return salida


def hash_password_legacy(password, salt=None):
    """Genera el hash de una contraseña para el sistema legado de clientes."""
    # [FIX] Hash débil (CWE-327). Fuera MD5 sin salt: PBKDF2-HMAC-SHA256
    # con salt aleatorio y 200k vueltas. Devuelvo salt$hash para verificar.
    if salt is None:
        salt = secrets.token_bytes(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}${derivado.hex()}"


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # Uso la clave del entorno, ya no la del código
    clave = NOTIFICATION_API_KEY or ""
    prefijo = (clave[:6] + "...") if clave else "(sin clave)"
    print(f"[NotifyAPI key={prefijo}] -> {email}: {mensaje}")
    return True
