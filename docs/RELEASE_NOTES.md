# L2 ChangeGuard v0.1.0 — Initial public release

Primeira versão pública: verificação de alterações de switches Layer 2, **somente offline**.

- Oito regras auditáveis de LLDP, VLAN, STP, observações MAC e hardening.
- Análise de baseline e candidato; classificação de novas ocorrências, resoluções e riscos persistentes.
- Saídas JSON/SARIF, fingerprints estáveis, limiar de bloqueio configurável.
- Validação estrita de entrada, exemplos fictícios, testes e CI multiplataforma.
- ZIP de fontes, manifesto SHA-256 por arquivo e SHA256SUMS; licença MIT.

**Limitações:** os alertas são indicativos; não há acesso a switches, implementação de SNMP/SSH, tradução de comandos de fabricantes, modelo completo de STP/LACP/MLAG ou prova de loops. Consulte `README.md`, `docs/THREAT_MODEL.md` e `docs/SCHEMA.md`.

Esta versão só deve ser publicada após conclusão verde do workflow CI para o commit exato de `main`.
