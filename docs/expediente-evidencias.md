# Expediente de evidencias de ReportAudit (Parte T)

Índice CRA: cada fila enlaza a una evidencia verificable del repositorio.
Autor: Antonio García Gallego · Repo: https://github.com/Tonsete/reportaudit-lab

| Requisito | Evidencia verificable | Estado |
|---|---|---|
| SAST en cada PR (SonarQube Cloud) | Workflow `.github/workflows/cadena-suministro.yml` + checks `SAST - SonarQube Cloud` en verde en PRs #1, #4, #20–#24 | ✔ |
| SAST en cada PR (CodeQL `security-extended`) | Mismo workflow, checks `SAST - CodeQL` en verde + `Security → Code scanning` sin alertas abiertas en `main` | ✔ |
| Guardián local pre-commit (Semgrep) | `.pre-commit-config.yaml` + `docs/evidencias/semgrep.json` (3 → 0) | ✔ |
| Dependabot + updates agrupados | `.github/dependabot.yml` + PRs #2 y #3 fusionados | ✔ |
| SBOM de cada versión | `docs/evidencias/sbom.spdx.json` (SPDX 2.3) y `sbom.cyclonedx.json` (CycloneDX 1.7): 2 directas, 6 transitivas | ✔ |
| Triage SCA + VEX | `docs/evidencias/grype.json` (12 → 0), `trivy.json`, `reportaudit.openvex.json` (`fixed`) | ✔ |
| Secretos fuera del código e historial auditado | `gitleaks.toml` + `docs/evidencias/gitleaks-arbol.json` (0) y `gitleaks-historial.json` (2 en `dae7e25`, rotadas) + push protection activado | ✔ |
| Puertas obligatorias en `main` | Regla de protección: `SAST - SonarQube Cloud`, `SAST - CodeQL`, `SCA - pip-audit`, `Secrets - Gitleaks` | ✔ |
| Política + canal privado + simulacro | `SECURITY.md` + private reporting activado + borrador `GHSA-8ph9-cm9f-fcw8` (draft, sin publicar) | ✔ |
| Versión firmada y verificable | Tag `v1.0.0`, Release con 2 SBOM + 2 attestations Sigstore/SLSA, `docs/evidencias/verificacion-release.txt` (exit 0) | ✔ |
| Madurez medida (Scorecard 4.5) | `.github/workflows/scorecard.yml` + lectura en bitácora (Parte S): 10 en Dependabot/CI-Tests/Vulnerabilities/Binarios, resto justificado | ✔ |
| Trazabilidad Issue → PR | Milestone `Lab 1 - Secure supply chain`, Issues #6–#18 cerrados con su PR o comentario | ✔ |
| Plantilla PR internacional | `.github/PULL_REQUEST_TEMPLATE.md` (PR #19) | ✔ |

Riesgos aceptados y documentados (no silenciados): Quality Gate de decoración pide cobertura sin tests (Tema 3), pinning por hash de actions (opcional S.3, vigilado por Dependabot), sin LICENSE (fuera del alcance del lab), Fuzzing/CII/empacado no aplicables a un trabajo de curso.
