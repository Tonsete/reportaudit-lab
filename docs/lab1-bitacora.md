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

## Parte O — Gitleaks: el historial no olvida

Instalé Gitleaks 8.30.1 en `tools/` con versión fija y SHA-256 verificado (hash publicado y calculado idénticos, si no no se instala).

- Árbol actual (`--no-git`): 0 leaks. El grep a los valores viejos en `app/ docs/ .github/ plantillas/ scripts/` no devuelve nada: en el código ya están a `os.getenv`.
- Historial (`--log-opts="--all"`, 9 commits): 2 leaks, los 2 en el commit base `dae7e25` en `app/reporte_auditoria.py:21-22` (la API key con regla `generic-api-key` y el SMTP solo con mi regla propia, las genéricas no lo veían por corto y poco entrópico).
- Regla propia en `gitleaks.toml` (`reportaudit-notification-api-key` y `reportaudit-smtp-password`, extiende las por defecto). Evidencias en `docs/evidencias/gitleaks-arbol.json` (vacío) y `gitleaks-historial.json` (2 hallazgos).
- Baseline: las 2 credenciales se dan por comprometidas y rotadas (borrar no basta, siguen en el historial); quedan registradas aquí y en el VEX como `fixed`, no se silencian.

---

## Parte P — Puertas obligatorias de SCA y secretos

Añadí 2 jobs al pipeline (`SCA - pip-audit` con `pip-audit -r requirements.txt` y `Secrets - Gitleaks` con `gitleaks.toml` sobre el árbol). El de secretos mira el árbol y no el historial a propósito: el historial guarda las 2 credenciales rotadas como baseline de la Parte O, la puerta vigila que no entre ninguna nueva.

- Push protection: activado en Settings → Code security. Lo probé en una rama de usar y tirar con un fake: el push quedó bloqueado antes de subir nada y borré la rama sin PR.
- Protección de `main`: exige los 4 checks (`SAST - SonarQube Cloud`, `SAST - CodeQL`, `SCA - pip-audit`, `Secrets - Gitleaks`). Nada entra sin las 4 puertas en verde.

---

## Parte Q — Política de seguridad y canal privado

Escribí `SECURITY.md` en la raíz: solo 1.0.x con soporte, reporte siempre por el canal privado (nunca Issue público con el exploit) y primera respuesta en 5 días laborables.

- Canal privado: activado en Settings → Code security (private vulnerability reporting).
- Simulacro Q.3: abrí un aviso privado de prueba en borrador y recorrí el flujo de divulgación coordinada sin publicar nada sensible.

---

## Parte R — Publicar la versión 1.0.0 con SBOM y procedencia firmada

El workflow `publicar-version.yml` se dispara al empujar una etiqueta `v*`: instala Syft verificado, genera el SBOM de esa versión exacta, firma su procedencia (Sigstore/SLSA, 2 attestations) y publica la Release con el SBOM como asset.

- Tag `v1.0.0` empujado desde `main`, Release creada por el propio workflow.
- Verificación como cliente en `/tmp` (descarga del asset + `gh attestation verify`): ver `docs/evidencias/verificacion-release.txt`.

---

## Parte S — Scorecard: leer con criterio

Workflow `scorecard.yml` corriendo en `main` y semanal, nota global **4.5**. Lo que dice y mi lectura:

- 10 en Dependabot, CI-Tests (11/11 PRs con CI), Vulnerabilities (0 abiertas), Binary-Artifacts y Dangerous-Workflow: lo estructural está bien.
- SAST 9: CodeQL detectado corriendo en 24/26 commits (los 2 sin él son anteriores al pipeline).
- Security-Policy 4: detecta `SECURITY.md` pero pedía un enlace de reporte; añadí el enlace directo a advisories en esta rama.
- Token-Permissions 0: era por el `contents: write` global de `publicar-version.yml`; lo bajé a nivel de job en esta rama.
- Pinned-Dependencies 0: fijamos por tag, no por hash (reto élite opcional S.3); aceptado porque Dependabot vigila las actions.
- Signed-Releases 0: mira firmas clásicas; nuestra procedencia Sigstore/SLSA verifica con `gh attestation verify` (exit 0, ver Parte R).
- License 0 (sin LICENSE, fuera del alcance), Fuzzing/CII/Contributors/Packaging/Maintained 0 (no aplicables a un trabajo de curso de 90 días), Branch-Protection sin dato (el token del check no lee reglas clásicas; la protección existe y se ve en Settings).

---

## Parte T — Expediente y entrega

Expediente en `docs/expediente-evidencias.md`: cada fila enlaza a PR, check, archivo de `docs/evidencias/`, release o advisory. Checklist de la sección 8 repasado: repo público en verde, PRs con plantilla internacional y `Closes/Refs`, `main` con 4 checks + conversaciones resueltas, secret scanning y push protection activados, release v1.0.0 verificada y Scorecard publicado.

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
