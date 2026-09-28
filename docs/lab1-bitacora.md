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
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ yo lo vi por el apóstrofo | pendiente | pendiente | pendiente | pendiente | pendiente (con p/python a veces lo pasa por alto si la query va en variable) | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ por el `os.system` con `+` | pendiente | pendiente | pendiente | pendiente | pendiente | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ `yaml.load` con `Loader` | pendiente | pendiente | pendiente | pendiente | ✓ `python.lang.security.deserialization.avoid-pyyaml-load` | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ `hashlib.md5` pelado | pendiente | pendiente | pendiente | pendiente | ✓ `insecure-hash-algorithm-md5` + `md5-used-as-password` | n/a |
| H5 Clave de API escrita en el código | ✓ línea 21 | pendiente | pendiente | pendiente | pendiente | ✓ `p/secrets` | ✓ Trivy secret |
| H6 Contraseña SMTP escrita en el código | ✓ línea 22 | pendiente | pendiente | pendiente | pendiente | ✓ `p/secrets` | ✓ Trivy secret |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

De momento, con lo que llevo, ninguna lo pilla todo sola. Yo a mano pillé los 6 porque seguí el dato, pero no sé de CVEs. Las de SCA no miran mi código y las SAST no miran dependencias. Por eso hay que combinarlas.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2 (flask==3.0.0, pyyaml==6.0.3) |
| Componentes Python en el SBOM | pendiente (lo saco con Syft en `docs/evidencias/sbom.spdx.json`) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | pendiente |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | CycloneDX o SPDX según lo que me pida Syft, lo anoto cuando lo genere |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| pendiente (lo relleno cuando corra Grype + Trivy) |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

Pendiente, pero ya sé que Dependabot solo me va a abrir PRs de seguridad (tengo `open-pull-requests-limit: 0` en la plantilla) mientras que Grype me lista todo lo del SBOM.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

Pendiente: `docs/evidencias/reportaudit.openvex.json`.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | pendiente (unos 3 bloqueantes con p/python) | pendiente, objetivo 0 |
| Alertas abiertas de CodeQL (Security → Code scanning) | pendiente | pendiente, objetivo 0 |
| Vulnerabilidades en SonarQube Cloud (rama main) | pendiente | pendiente, objetivo 0 |
| Security Hotspots por revisar en SonarQube Cloud | pendiente | pendiente, objetivo 0 |
| Vulnerabilidades de Grype sobre el SBOM | pendiente | pendiente |
| Alertas abiertas de Dependabot | pendiente | pendiente, objetivo 0 |

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
