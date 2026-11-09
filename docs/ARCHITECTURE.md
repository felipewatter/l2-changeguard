# Arquitetura e decisões técnicas

```text
Snapshot JSON ─> parser estrito ─> dataclasses imutáveis (política/portas)
                                      │
                                      ▼
                   vínculos LLDP, VLANs, estado STP e observações MAC
                                      │
                                      ▼
                           8 regras de auditoria
                                      │
        ┌─────────────────────────────┴────────────────────────────┐
        ▼                                                          ▼
   audit (all findings)                                   compare (before/after)
                                                                   │
                                                   fingerprints de ocorrência
                                                                   │
                                      introduced / resolved / persisting
        └─────────────────────────────┬────────────────────────────┘
                                      ▼
                           gate por severidade
                                      │
                             JSON / SARIF 2.1.0
```

O núcleo é Python stdlib; não existe acesso a equipamento, rede, banco, chave de API ou serviço remoto em runtime.

## Estratégia de grafos

1. Ler cada declaração LLDP; somente considerar enlace confirmado quando `A/porta-x` declara `B/porta-y`, a contraparte existe, está `admin_up` e declara **exatamente** `A/porta-x`.
2. Normalizar cada aresta não direcionada a um único par; divergências de modo ou VLAN são findings independentes.
3. Para cada VLAN presente nas duas extremidades, considerar apenas *trunk-trunk* cuja VLAN esteja permitida e cujo STP esteja **explicitamente forwarding** nos dois lados.
4. Executar union-find por VLAN. Um enlace que une componentes já conectados fecha um ciclo observado; não gerar alerta para pares com apenas dois nós (pode ser link agregado/duplo). O resultado é *suspeita*, não prova de loop operacional.

O algoritmo deliberadamente evita declarar um loop quando STP está ausente, `blocking`, `disabled` ou quando LLDP não é recíproco. Isso reduz falsos positivos e pode produzir **falsos negativos** por observabilidade incompleta. Não interpreta BPDUs, timers STP, priority/root bridge, EtherChannel/LACP, EVPN, MLAG ou topologias virtuais.

## MAC e identidade

O detector de MAC indexa `(device, VLAN, MAC)` e procura observações simultâneas em mais de uma porta **desse mesmo switch**. Isso pode indicar flapping, mas dados atrasados e transição legítima também geram alerta. Presença do mesmo MAC em switches diferentes é **normal** e não produz finding. O projeto não faz spoofing detection real, captura de tráfego ou fingerprint de clientes.

## Segurança de CI

A CI exige sucesso do baseline e bloqueio intencional do candidato; o release só é elegível após workflow `CI` em push para `main` concluído com sucesso. Revalida SHA do HEAD da branch antes de publicar e não substitui um release existente. Dependabot monitora GitHub Actions.

### Considerações de determinismo

A ordenação de portas, achados e relatórios é estável independentemente da ordem dos dispositivos no arquivo. Reporta somente dados de entradas e nomes de arquivo, não caminhos locais absolutos em SARIF. O ZIP é gerado com ordem e timestamp fixos e acompanhado de manifesto por arquivo e checksums de artefatos. A garantia de builds idênticos exige **o mesmo conteúdo dos arquivos**, Python compatível e biblioteca de compressão equivalente; o manifesto por arquivo é a referência independente.
