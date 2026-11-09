# L2 ChangeGuard

**Auditoria offline de mudanças de rede Layer 2 com evidências verificáveis — VLAN, LLDP, STP e MAC.**

[![CI](https://github.com/felipewatter/l2-changeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/l2-changeguard/actions/workflows/ci.yml) [![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)

**English documentation:** [README.en.md](README.en.md) · **Autor:** [Felipe Silva](https://github.com/felipewatter) · **Versão:** `0.1.0`

> **Escopo:** ferramenta local, somente leitura, orientada a snapshots estruturados. **Não acessa switches**, não faz descoberta de rede nem aplica comandos de configuração. Detecta sinais de risco, não comprova que determinado incidente ocorre na rede real.

## O problema operacional

Mudanças aparentemente simples em portas de switches podem produzir incompatibilidade de VLANs, perda de conectividade, loops de encaminhamento e enfraquecimento de políticas de acesso. Inspecionar manualmente todas as conexões, comparar a configuração anterior e documentar evidências consome tempo e é propenso a falhas. O L2 ChangeGuard fornece **um gate reproduzível antes da mudança**, trabalhando em dados locais e sanitizados.

## Funcionalidades reais (v0.1.0)

| Regra | Risco analisado | Nível |
|---|---|---|
| **L2C001** | LLDP ausente, desatualizado ou sem reciprocidade no inventário | Médio |
| **L2C002** | Divergências de tipo de porta, VLAN de acesso, VLAN nativa ou allowlist de trunk | Alto |
| **L2C003** | Ciclo **potencial** no grafo de links trunk com LLDP recíproco e STP explicitamente `forwarding` nos dois extremos de uma VLAN | Crítico |
| **L2C004** | Mesmo MAC/VLAN observado em mais de uma porta **do mesmo switch** | Alto |
| **L2C005** | Proteções de borda ausentes: BPDU Guard e Port Security (política configurável) | Médio |
| **L2C006** | VLAN nativa fora da lista de VLANs aprovadas | Médio |
| **L2C007** | Dispositivo crítico com menos de dois vizinhos distintos no grafo LLDP recíproco | Médio |
| **L2C008** | STP explicitamente desativado em VLAN marcada como protegida | Alto |

**Além das regras:** comparação entre baseline/candidato (`introduced`, `resolved`, `persisting`), severidades, identificadores de ocorrência estáveis, bloqueio por limiar configurável, saída JSON e SARIF 2.1.0, limites de entrada e release com ZIP/manifesto SHA-256.

## Início rápido

**Pré-requisito:** Python 3.11 ou superior. **Dependências em runtime:** nenhuma.

```bash
git clone https://github.com/felipewatter/l2-changeguard.git
cd l2-changeguard
python -m pip install -e .

# Audita o estado atual (baseline sintético sem riscos novos severos)
l2changeguard audit --candidate examples/baseline.json --policy examples/policy.json --fail-on high

# Simula uma mudança com riscos; por padrão retorna código 2 (bloqueado)
l2changeguard compare --baseline examples/baseline.json \
  --candidate examples/candidate-risky.json \
  --policy examples/policy.json --fail-on high \
  --output change-report.json --sarif change-report.sarif
```

No Windows PowerShell, utilize os mesmos comandos em **uma linha** ou use o continuador de linha do PowerShell (acento grave `` ` ``). Sem instalar, executar a partir da raiz com `PYTHONPATH=src` (Linux/macOS) ou `$env:PYTHONPATH='src'` (PowerShell) e `python -m l2_changeguard`.

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Análise concluída sem violações no limiar selecionado |
| `2` | Gate bloqueado por ao menos um finding com severidade >= `--fail-on` |
| `3` | Erro de leitura, parse, validação ou gravação de relatório |

`--fail-on` aceita `critical`, `high` (padrão), `medium`, `low` e `none`. Em `audit`, todas as ocorrências entram no gate. Em `compare`, apenas **ocorrências introduzidas** entram no gate; riscos persistentes aparecem no relatório, mas não bloqueiam por padrão. A equipe deve avaliar todos os riscos, inclusive os persistentes.

## Exemplo de evidência e comparação

No cenário sintético disponibilizado em `examples/` há três switches: um core e duas distribuições. O baseline possui bloqueio STP observado em um dos links da topologia triangular. O candidato transforma esse estado em forwarding e inclui uma divergência de VLAN permitida, observações MAC conflitantes e ausência de BPDU Guard.

```bash
python -m l2_changeguard compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --policy examples/policy.json --fail-on high
```

A saída inclui `verdict: "blocked"`, `introduced` com as novas ocorrências e a descrição da evidência associada. **Não é uma confirmação de loop real:** inconsistência de observações, LAGs e nuances de STP dependem de validação por um engenheiro.

## Modelo de dados

A entrada é **JSON explícito** — não aceita dumps de comandos de fabricantes nem configurações executáveis. Cada dispositivo contém `id` e `ports`; cada porta declara `mode` (`access`/`trunk`), VLAN de acesso ou VLAN nativa e allowlist, estados STP **observados por VLAN**, LLDP do par (quando conhecido), flags de hardening e observações MAC.

Campos opcionais: `admin_up` (padrão `true`), `bpdu_guard`/`port_security` (padrão `false`), `stp` (padrão vazio), `lldp` (padrão nulo), `macs` (padrão vazio). Um STP desconhecido **não** é equiparado a `forwarding`.

[Especificação completa do schema, exemplos e limites](docs/SCHEMA.md) · [Arquitetura e algoritmos](docs/ARCHITECTURE.md).

## Integração de segurança em CI/CD

O repositório inclui `.github/workflows/ci.yml`, com **nove combinações** (Ubuntu, Windows e macOS × Python 3.11, 3.12 e 3.13). Ele compila fontes, executa testes e valida tanto um cenário permitido quanto um bloqueado. O token do CI tem permissão mínima (`contents: read`); checkout/setup-python estão fixados por commit SHA. Não são usados dispositivos reais ou segredos.

Quando a execução **push para `main`** termina com sucesso, `.github/workflows/release.yml` confere se o commit aprovado ainda corresponde ao head de `main`, gera um pacote ZIP determinístico e um manifesto SHA-256 por arquivo e tenta publicar o release correspondente à versão do `pyproject.toml`. Releases existentes não são sobrescritos. O workflow de publicação recebe `contents: write` apenas no job que efetivamente necessita dessa permissão. **A publicação remota depende das permissões e configurações do GitHub** e precisa ser confirmada na interface após a criação do repositório.

```bash
# Testes locais, sem dependências extras
python -m unittest discover -s tests -v

# Cria artefatos de release auditáveis
python scripts/build_release.py dist
```

## Segurança e limites

* Validação estrita de campos e tipos; rejeição de nomes de VLAN inválidos, duplicatas, peers autoapontados e MACs fora das VLANs declaradas.
* Limites de 2 MB por documento JSON, 256 dispositivos, 4.096 portas e 16.384 observações MAC; somente arquivo local.
* Não captura tráfego, não busca CVEs, não faz probe, não verifica autenticação de LLDP, não calcula roteamento L3, não implementa LACP/MLAG/EtherChannel, não infere mapeamento de tráfego de usuários e não aplica mudanças.
* O detector de ciclo usa **grafo observado**; enlaces paralelos entre dois dispositivos não são tratados como ciclo para reduzir falso positivo de LAG. Ciclos não observados podem passar despercebidos.
* Uma mesma entrada MAC aprendida em portas diferentes não comprova ataque; pode representar movimentação legítima ou amostras inconsistentes.
* Dados reais de topologia podem ser confidenciais. Os exemplos publicados são inteiramente fictícios.

[Threat model](docs/THREAT_MODEL.md) · [Relato responsável](SECURITY.md) · [Contribuição](CONTRIBUTING.md) · [Notas do release](docs/RELEASE_NOTES.md).

## Estrutura do projeto

```text
src/l2_changeguard/       Modelo validado, motor de auditoria, CLI e relatórios
examples/                 Topologia sintética segura, baseline e candidato
scripts/                  Empacotamento reproduzível e manifesto de checksums
tests/                    Testes de validação, detecção, CLI e regressão
.github/workflows/        CI multiplataforma e release condicionado a CI verde
docs/                     Arquitetura, schema, riscos, testes e notas de versão
```

## Licença

MIT © 2026 Felipe Silva. Uso sujeito à licença, sem garantias de conformidade, disponibilidade ou segurança de rede.
