# Schema v1 / formato do snapshot

O schema é validado estritamente pelo módulo `model.py`. JSON deve ser UTF-8, sem propriedades duplicadas nem chaves desconhecidas.

## Snapshot

```json
{
  "schema_version": 1,
  "devices": [
    {
      "id": "sw-example",
      "ports": [
        {
          "id": "gi-1/1",
          "mode": "trunk",
          "native_vlan": 999,
          "allowed_vlans": [10, 20, 999],
          "admin_up": true,
          "bpdu_guard": false,
          "port_security": false,
          "stp": {"10": "forwarding", "20": "blocking"},
          "lldp": {"device": "sw-peer", "port": "gi-1/1"},
          "macs": [{"address": "02:00:00:00:00:01", "vlan": 10}]
        },
        {
          "id": "gi-1/2",
          "mode": "access",
          "access_vlan": 10,
          "bpdu_guard": true,
          "port_security": true
        }
      ]
    }
  ]
}
```

**Obrigatório**: `schema_version`, `devices` (1–256), `device.id` (não duplicado), `device.ports` (pode ser vazio), `port.id` (não duplicado por dispositivo), `port.mode` (`access` ou `trunk`) e campos de VLAN correspondentes ao modo. Em modo `access` requer `access_vlan` (inteiro 1–4094) e rejeita `allowed_vlans` e `native_vlan`. Em `trunk` requer `native_vlan` e `allowed_vlans` (array sem duplicatas); rejeita `access_vlan`. Uma porta trunk pode ter allowlist vazia. VLAN nativa não precisa constar na allowlist (algumas arquiteturas fazem pruning da VLAN nativa).

**Opcionais**: `admin_up` booleano (padrão `true`), `bpdu_guard` e `port_security` booleanos (padrão `false`), `stp` (mapa com chaves VLAN decimal canônica e valores `forwarding`, `blocking`, `disabled`), `lldp` (`device`/`port`, IDs não vazios) e `macs` (objetos `{address, vlan}`). O estado `stp` só pode mencionar VLANs transportadas na porta. Um estado ausente é **desconhecido**; não se transforma automaticamente em forwarding. LLDP exige reciprocidade para inferir enlace confiável entre dois pontos observados.

O modelo é uma abstração **fabricante-neutra**, não aceita texto de `show running-config`, `show lldp` ou `show mac address-table`. Converter outputs de fabricantes exige coletor separado, com documentação e validação; nada disso integra a v0.1.0.

## Política

```json
{
  "protected_vlans": [10, 20],
  "allowed_native_vlans": [999],
  "critical_devices": ["sw-core"],
  "require_access_bpdu_guard": true,
  "require_access_port_security": true
}
```

Todos os campos da política são opcionais. `protected_vlans`, `allowed_native_vlans` e `critical_devices` são listas únicas; flags obrigatoriamente booleanas se presentes. Uma allowlist vazia de native VLAN desabilita a verificação L2C006. Não interpreta ausência de evidência como aprovação de segurança.

## Limites e integridade

Arquivo individual: até 2.000.000 bytes; 256 dispositivos; 4.096 portas; 16.384 entradas MAC; até 4.094 VLANs por porta. IDs de switch/porta: texto imprimível de 1 a 80 caracteres; MAC `xx:xx:xx:xx:xx:xx`, normalizado em minúsculas. Entrada contraditória é rejeitada (código 3), não corrigida.

## Semântica de comparação

A ocorrência de finding é identificada por `sha256([rule_id, subject])` truncado a 20 caracteres hexadecimais; se **somente a mensagem** mudar, permanece como issue existente. Uma mudança no sujeito, VLAN, porta ou ID de regra pode gerar uma ocorrência nova. O projeto não oferece esquema de exceções nem assinatura criptográfica de políticas nesta versão.
