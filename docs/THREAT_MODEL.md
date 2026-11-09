# Threat model — L2 ChangeGuard v0.1.0

## Objetivos

Ajudar operadores a detectar mudanças perigosas em snapshots JSON estruturados, mantendo operação local e somente leitura. Um evento de risco exige revisão humana antes do rollout.

## Ativos e fronteiras de confiança

- **Arquivos de entrada**: snapshots e políticas fornecidas pelo operador; são considerados não confiáveis e devem ser sanitizados.
- **Motor local**: processo Python sem privilégios que valida, analisa e grava apenas relatórios solicitados.
- **Saídas**: JSON, SARIF, ZIP e checksums; podem conter nomes, MACs e topologia empresarial se usados dados reais.
- **GitHub Actions**: ambiente efêmero; testes usam apenas fixtures sintéticas, sem tokens de infraestrutura. O release tem permissão de escrita limitada a `contents` e nunca roda em contexto `pull_request_target`.

## Ameaças e controles

| Ameaça | Mitigação | Residual |
|---|---|---|
| Snapshot malformado / excesso de memória | JSON 2 MB, limites de cardinalidade, rejeição estrita | Algoritmos podem ser pesados no limite máximo; verifique dados de origem |
| Inclusão acidental de segredos | Schema sem campos de credenciais, fixtures fictícias | IDs de dispositivos, MACs e políticas reais continuam sensíveis |
| Uso malicioso de portabilidade de relatórios | SARIF com nome-base do arquivo, output local explícito | Mensagens incluem evidência de topologia fornecida pelo usuário |
| Supply chain de actions | Pins de SHA, mínimo privilégio, CI matrix | Requer revisões de atualização e controles de branch |
| Falso negativo no ciclo de camada 2 | Requer reciprocidade LLDP e STP declarado forwarding | Sem LLDP/STP completo, LAG/MLAG ou bridge invisível não detecta certos ciclos |
| Falso positivo de MAC move | Escopo por mesmo switch e VLAN | Aprendizado atrasado / mobilidade legítima podem ser sinalizados |
| Uso de relatório antigo como atual | Release revalida SHA testado; fingerprints estáveis | Operador deve usar snapshots recentes, coletados no mesmo intervalo |

## Fora do escopo

Execução de comandos, credenciais, automação de remediação, testes ativos, SNMP/SSH, autorização de dispositivos, roteamento L3, autenticação de LLDP, parsing de configuração nativa de fornecedor, topologia física exata, mensuração de capacidade e garantias de conformidade. O projeto não é substituto para Batfish, monitoramento STP ou ferramentas especializadas de fabricantes.

## Orientações de resposta

Achados críticos/altos devem bloquear alterações até análise humana. Documentar janela de mudança, plano de rollback e confirmação no equipamento. Não submeter arquivos reais em PRs ou issues públicas.
