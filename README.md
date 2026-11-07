# Retail Shared Actions

Acciones compuestas consumidas por devsecops-templates. No contienen jobs ni orquestan pipelines.

- `analysis-validator`: valida tecnologia, lenguaje y contexto; emite `blocking`, `sonar`, `dependency_review`, `codeql_language` y `codeql_build_mode`. La obligatoriedad deriva de la rama base real del PR, no de un parametro manipulable.
- `deployment-validator`: exige main, valida la casilla rollback y el tag, consulta la membresia activa en el equipo `retail-operator` de actor y triggering_actor para todos los despliegues y comprueba que el tag corresponde a un run productivo exitoso. Emite el SHA autorizado. `execute.cjs` escribe el resumen de autorizacion o denegacion incluso si falla. Ante errores, deniega. No usa environments.
- `security-report`: evalua SARIF de CodeQL, consulta el Quality Gate del analysisId exacto de SonarQube y consolida summary/comentario actualizable en PR. No ejecuta codigo del PR para reportar; usa GITHUB_TOKEN para el comentario y no GH_TOKEN_G4.
- `tests/security-report.test.cjs`: pruebas de severidades, politica obligatoria/informativa, API Sonar, timeout, comentarios nuevos/actualizados, forks y runs desactualizados.
- `tests/policy.test.cjs`: pruebas con API simulada, sin credenciales ni despliegues. Ejecutar con `node --test tests/*.test.cjs`.
- `.github/workflows/validate-actions.yml`: ejecuta las pruebas en push/PR.

La configuracion de secretos, ramas, SonarQube y operacion se documenta en el README de devsecops-templates. Las acciones se deben consumir por SHA real despues de publicarse.
