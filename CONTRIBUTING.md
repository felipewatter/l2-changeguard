# Contribuindo

Contribuições são bem-vindas via issue e pull request; use apenas snapshots sintéticos. Antes de enviar:

1. Mantenha o motor offline, não introduza coleta remota silenciosa, execução de comandos ou segredos em fixtures.
2. Adicione caso de teste positivo **e** negativo para alterações de regra, preserve determinismo e compatibilidade de schema.
3. Execute `python -m unittest discover -s tests -v` e `python -m compileall -q src tests`.
4. Explique falsos positivos/falsos negativos, escopo de vendor/LAG/STP e impactos de performance.
5. Inclua atualização de `README`, `docs/SCHEMA.md`, `CHANGELOG.md` ou ameaça quando necessário.
6. Não modifique a versão sem actualizar `src/l2_changeguard/__init__.py`, `pyproject.toml` e release notes em conjunto.

A análise de alterações é uma **ferramenta auxiliar**, jamais autorização automática para executar mudança em infraestrutura.
