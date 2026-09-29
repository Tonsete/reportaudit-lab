# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Antonio García Gallego
- **Repositorio:** https://github.com/Tonsete/reportaudit-lab
- **Sistema operativo y versión de Python usados:** macOS 26.6.2 ARM, Python 3.14.7, venv del proyecto. No uso WSL porque estoy en Mac, lo hago todo en mi terminal que para este lab es lo mismo.

> La voy completando cuando la guía lo pide, no al final, que si no luego no me acuerdo de qué detectó cada herramienta.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

Leí primero `app/servicio.py` para ver por dónde entra el dato y luego seguí cada dato en `app/reporte_auditoria.py` hasta dónde acaba. Lo pienso como source -> sink, como si fuera agua sin filtrar hasta la tubería.

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41-42 | Inyección SQL, pega el nombre con `+` dentro de la SQL | `request.args.get("cliente")` en `servicio.py:41` | `cursor.execute(query)` en `reporte_auditoria.py:42` |
| 2 | `convertir_a_pdf` | 50-51 | Inyección de comandos, monta `wkhtmltopdf + nombre` y lo tira a `os.system` | `request.args.get("archivo")` en `servicio.py:53` | `os.system(comando)` en `reporte_auditoria.py:51` |
| 3 | `cargar_configuracion` | 33 | YAML inseguro, usa `yaml.load` con `Loader` completo | fichero `app/config.yaml` / parámetro `ruta_config` | `yaml.load(f, Loader=yaml.Loader)` |
| 4 | `hash_password_legacy` | 57 | Hash débil, MD5 de una vuelta sin salt | `password` que le pasan | `hashlib.md5(...).hexdigest()` |
| 5 | `NOTIFICATION_API_KEY` | 21 | Clave de API en código, está en Git para siempre | - | constante en código |
| 6 | `SMTP_PASSWORD` | 22 | Contraseña SMTP en código, igual que la anterior | - | constante en código |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

- H1: con un apóstrofo tipo `o'brien_ltd` ya peta con `OperationalError near "brien_ltd"`, y con algo malicioso podrían leer o borrar la tabla de reportes de todos los clientes.
- H2: con un `;` o `&` en el nombre del archivo la shell ejecuta lo que quiera en el servidor, o sea, se hacen con la máquina.
- H3: con el Loader completo el YAML puede construir objetos de Python, así que una config tocada podría ejecutar código al arrancar.
- H4: el MD5 sin salt se revienta con rainbow tables en nada, las contraseñas legacy quedarían al aire.
- H5: la API key está en el repo, cualquiera que clone el proyecto puede mandar notificaciones como si fuéramos nosotros. Hay que rotarla.
- H6: lo mismo con el SMTP, pueden leer o mandar correo como ReportAudit. También hay que rotarla y sacarla a `.env`.

Síntoma que lo confirma: pedí `http://127.0.0.1:8087/reportes?cliente=o'brien_ltd` y me devolvió 500 con `sqlite3.OperationalError: near "brien_ltd": syntax error`. O sea, dato y orden van mezclados.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ yo lo vi por el apóstrofo | pendiente (lo miro en VS Code) | pendiente | pendiente | pendiente | ✗ con p/python no la ve porque la query va en variable antes del execute (3 hallazgos en total) | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ por el `os.system` con `+` | pendiente | pendiente | pendiente | pendiente | ✗ no la marca con p/python+p/secrets | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ `yaml.load` con `Loader` | pendiente | pendiente | pendiente | pendiente | ✓ `python.lang.security.deserialization.avoid-pyyaml-load` (línea 33) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ `hashlib.md5` pelado | pendiente | pendiente | pendiente | pendiente | ✓ `insecure-hash-algorithm-md5` + `md5-used-as-password` (línea 57, cuenta como 2 reglas pero es 1 fallo) | n/a |
| H5 Clave de API escrita en el código | ✓ línea 21 | pendiente | pendiente | pendiente | pendiente | ✗ p/secrets no la canta (es genérica, no parece AWS) | ✗ Trivy secret no la ve, solo mira dependencias aquí |
| H6 Contraseña SMTP escrita en el código | ✓ línea 22 | pendiente | pendiente | pendiente | pendiente | ✗ igual que H5 | ✗ igual |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

De momento, con lo que llevo, ninguna lo pilla todo sola. Yo a mano pillé los 6 porque seguí el dato, pero no sé de CVEs. Las de SCA no miran mi código y las SAST no miran dependencias. Por eso hay que combinarlas.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2 (flask==3.0.0, pyyaml==6.0.3) |
| Componentes Python en el SBOM | 8 en `requirements.txt` (flask, werkzeug, jinja2, itsdangerous, click, markupsafe, blinker, pyyaml) + colorama de Windows. Lo generé con `syft scan requirements.txt` en `docs/evidencias/sbom.spdx.json` |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | Si escaneo `dir:.` salen 1000+ porque pilla el venv y tools, por eso lo hago sobre `requirements.txt` que es lo que va a prod |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | SPDX 2.3 (`sbom.spdx.json`) y CycloneDX 1.7 (`sbom.cyclonedx.json`) |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | transitiva (`# via flask`) | GHSA-2g68-c3qc-8985 y otras 5 | High (1) + Medium (5) | 3.1.x | Sí, Flask la usa para todo el HTTP, así que el parser multipart y el debugger nos afectan | actualizar con Dependabot |
| jinja2 | 3.1.2 | transitiva (`# via flask`) | GHSA-h75v-3vvj-5mfj y otras 4 | Medium (5) | 3.1.6 | Sí, Flask renderiza con Jinja, los escapes del sandbox son explotables | actualizar |
| flask | 3.0.0 | directa | GHSA-68rp-wp8r-4726 | Low | 3.1.x | Poco, es lo del `Vary: Cookie`, pero igual se actualiza | actualizar |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

Pendiente, pero ya sé que Dependabot solo me va a abrir PRs de seguridad (tengo `open-pull-requests-limit: 0` en la plantilla) mientras que Grype me lista todo lo del SBOM.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

Hecho: `docs/evidencias/reportaudit.openvex.json` con 2 statements en `fixed` (Werkzeug y Jinja2), porque sí nos afectaban y los actualicé, no los escondo.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (yaml + 2 de md5) en `docs/evidencias/semgrep.json` del PR anterior | 0, lo acabo de correr y sale limpio. El pre-commit antes bloqueaba y ahora da Passed |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 en main (SQLi, command injection, MD5 y log de secretos) | Los jobs SAST-CodeQL del pipeline pasan. Queda 1 aviso nuevo de la decoración que es conservador (marca el subprocess aunque ya valido con basename), lo dejo documentado |
| Vulnerabilidades en SonarQube Cloud (rama main) | varias en el primer análisis | Los jobs SAST-Sonar pasan. El Quality Gate de la decoración pide 80% coverage, que sin tests en Lab 1 no hay (eso viene en Tema 3) |
| Security Hotspots por revisar en SonarQube Cloud | pendientes de revisar | revisados en el PR fix |
| Vulnerabilidades de Grype sobre el SBOM | 12 (6 Werkzeug + 5 Jinja2 + 1 Flask) | 0 con Flask 3.1.3 + Werkzeug 3.1.9 + Jinja2 3.1.6 + click 8.2.1 |
| Alertas abiertas de Dependabot | 0 de pip (ya voy al día), 2 de actions que ya fusioné (checkout 6->7, sonar 7->8) | 0 abiertas ahora mismo |

Protección de main: exige PR + los 2 checks `SAST - SonarQube Cloud` y `SAST - CodeQL`. La puse con API y ya no deja pushear directo. Me falta añadir al compi como reviewer cuando me pase su usuario.

---

## Preguntas de comprobación (Sección 7 de la guía)

1. pendiente
2. pendiente
3. pendiente
4. pendiente
5. pendiente
6. pendiente
7. pendiente
8. pendiente
9. pendiente
10. pendiente
11. pendiente
12. pendiente
