# Relatório de validação local — v0.1.0 (09/11/2026)

## Execução disponível

- Ambiente local: **Python 3.13.5** (Linux).
- **87 testes `unittest` aprovados** (validação, motor, CLI, mutações adversariais e distribuição).
- **96% de cobertura combinada de linhas/ramificações** do pacote Python, medidos com `coverage 7.13.3` e `coverage run --branch --source=src/l2_changeguard -m unittest discover -s tests -q`.
- `python -m compileall -q src tests scripts`: aprovado.
- CLI `audit` com baseline seguro: `exit 0`.
- CLI `compare` com mudança sintética insegura: `exit 2`, quatro ocorrências introduzidas (L2C002, L2C003, L2C004, L2C005).
- Instalação editável e empacotamento Wheel local (`pip wheel --no-build-isolation --no-deps`): aprovados.
- Release ZIP: integridade do manifesto SHA-256 por arquivo, ausência de caminhos inseguros e artefatos internos, determinismo entre duas execuções — automatizados em `tests/test_release.py`.

## Limites do relatório

Não foram executados nesta etapa os nove jobs GitHub Actions (Ubuntu/Windows/macOS × Python 3.11/3.12/3.13), nem foi criado release remoto. Eles dependem da publicação no GitHub após autorização. A cobertura de código não implica correção semântica de todas as variantes STP, LAG, MLAG e configuração específica de fabricante.

## Comandos de reprodução

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/build_release.py dist
```
