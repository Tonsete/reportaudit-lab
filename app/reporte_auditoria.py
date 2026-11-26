"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Versión corregida en el PR de auditoría (Parte M). Cada cambio va marcado
con [FIX] y su CWE, que es lo que pide la plantilla del PR.
"""

import hashlib
import os
import re
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

# Lista blanca de nombres de reporte: letras, números, _ . - y extensión .html.
# No puede empezar por "-" (wkhtmltopdf lo leería como una opción) ni contener
# "/" ni espacios: solo nombres de archivo de la carpeta de reportes.
NOMBRE_HTML_VALIDO = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.html")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # [FIX] YAML inseguro (CWE-502). safe_load solo hace tipos básicos,
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
    # Fuera os.system: lista de argumentos con shell=False, así ; & | etc.
    # nunca los interpreta una shell. Y en vez de una lista negra de
    # caracteres (siempre se escapa alguno), una lista blanca: el nombre
    # entero tiene que cumplir NOMBRE_HTML_VALIDO o se rechaza.
    if not NOMBRE_HTML_VALIDO.fullmatch(nombre_archivo):
        raise ValueError("Nombre de archivo no válido")
    salida = nombre_archivo + ".pdf"
    try:
        subprocess.run(["wkhtmltopdf", nombre_archivo, salida], shell=False, check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return salida


def hash_password_legacy(password, salt=None):
    """Genera el hash de una contraseña para el sistema legado de clientes."""
    # [FIX] Hash débil (CWE-327 / CWE-916). Fuera MD5 sin salt: PBKDF2-HMAC-SHA256
    # con salt aleatorio y 600k vueltas (recomendación de OWASP).
    # Devuelvo salt$hash para poder verificar.
    if salt is None:
        salt = secrets.token_bytes(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"{salt.hex()}${derivado.hex()}"


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # [FIX] Credencial en el log (CWE-532). Ni entera ni a trozos: los logs
    # se copian y se guardan años. Solo digo si la clave está configurada.
    estado = "configurada" if NOTIFICATION_API_KEY else "NO configurada"
    print(f"[NotifyAPI clave {estado}] -> {email}: {mensaje}")
    return True
