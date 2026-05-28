# 🛡️ Anti-DDoS nftables — OpenWrt 23.05 x86

Script de proteção contra DDoS e ataques de rede para **OpenWrt 23.05 x86**, escrito em **POSIX sh** puro (compatível com `busybox ash`) e utilizando **nftables** como backend de firewall.

Desenvolvido e otimizado para servidores de jogos, com proteção específica para **Ragnarok Online** (brAthena / eAthena), mas funcional para qualquer roteador OpenWrt com interface WAN dedicada.

---

## ✨ Funcionalidades

| Proteção | Descrição |
|---|---|
| **Bogon Filter** | Bloqueia IPs reservados/inválidos na entrada e saída da WAN |
| **SYN Flood** | Limita pacotes SYN por segundo com burst configurável |
| **ICMP Flood** | Limita requisições ICMP (ping) por segundo |
| **UDP Flood** | Limita tráfego UDP novo vindo da WAN |
| **Port Scan** | Detecta e bane IPs que fazem varredura de portas (XMAS, NULL scan, etc.) |
| **ARP Limit** | Limita requisições ARP por MAC para mitigar ARP flooding na LAN |
| **SSH Guard** | Protege o SSH contra brute-force com banimento automático por IP |
| **Ragnarok Online** | Rate limit por porta (6900/6121/5121), limite de conexões simultâneas por IP e proteção anti-brute-force no Login Server |
| **WAN/WireGuard Drop** | Opção para bloquear todo o input nas interfaces WAN ou WireGuard |

---

## ⚙️ Requisitos

- OpenWrt **23.05** ou superior (x86/x86_64)
- `nftables` (já incluído no OpenWrt 23.05)
- `busybox` com suporte a `ash`, `sed`, `grep`, `mktemp` (padrão no OpenWrt)
- `uci` (para detecção automática da interface WAN)

---

## 🚀 Instalação

**1. Copie o script para o roteador:**

```sh
scp ddos_protection.sh root@192.168.1.1:/etc/ddos_protection.sh
```

**2. Dê permissão de execução:**

```sh
chmod +x /etc/ddos_protection.sh
```

**3. Execute manualmente para testar:**

```sh
sh /etc/ddos_protection.sh
```

**4. (Opcional) Execute automaticamente no boot via `/etc/rc.local`:**

Edite `/etc/rc.local` e adicione antes do `exit 0`:

```sh
sh /etc/ddos_protection.sh
```

Ou crie um script em `/etc/init.d/` para controle via `service`.

---

## 🔧 Configuração

Toda a configuração fica na seção `CONFIG` e `PARAMETERS` no topo do script. Não é necessário modificar nada fora dessas seções.

### Seção CONFIG — ligar/desligar módulos

```sh
wan_device=""            # Vazio = detecção automática via UCI
                         # Manual: "eth0" ou múltiplas: "eth0,eth1"

bogon="1"                # Filtro de IPs bogon: 1=ativo, 0=desativo
forward_router=""        # IP/rede do roteador upstream (se houver)

syn_flood="1"            # Proteção SYN flood
icmp_flood="1"           # Proteção ICMP flood
udp_flood="1"            # Proteção UDP flood
port_scan_detection="1"  # Detecção de port scan
arp_limit_enable="1"     # Limite de ARP por MAC

wan_input_drop="0"       # Bloquear todo input na WAN (cuidado!)
wireguard_input_drop="0" # Bloquear todo input nas interfaces WireGuard
reject_with_icmp="0"     # Rejeitar com ICMP em vez de simplesmente dropar

ragnarok_protection="1"  # Proteção específica para Ragnarok Online
ssh_protection="1"       # Proteção contra brute-force SSH
```

### Seção PARAMETERS — ajustar limites

```sh
# SYN Flood
syn_flood_limit="300"    # Pacotes SYN aceitos por segundo (global)
syn_flood_burst="500"    # Rajada permitida acima do limite

# ICMP Flood
icmp_flood_limit="15"    # Pacotes ICMP aceitos por segundo
icmp_flood_burst="10"

# UDP Flood (Ragnarok é TCP puro; UDP externo é ruído)
udp_flood_limit="20"
udp_flood_burst="10"

# Port Scan
portscan_limit="15"      # Pacotes antes de banir o IP
portscan_drop_time="24h" # Tempo de banimento (s, m, h)
portscan_src_ports="22"  # Portas de origem isentas da detecção
portscan_dst_ports="{ 22, 6900, 6121, 5121 }" # Portas de destino isentas

# Ragnarok Online
ragnarok_login_rate="2"           # Novas conexões/s por IP no Login Server (6900)
ragnarok_login_burst="10"
ragnarok_char_rate="3"            # Novas conexões/s por IP no Char Server (6121)
ragnarok_char_burst="15"
ragnarok_map_rate="5"             # Novas conexões/s por IP no Map Server (5121)
ragnarok_map_burst="30"
ragnarok_conn_limit="10"          # Máximo de conexões simultâneas por IP nas 3 portas
ragnarok_login_bf_rate="1/minute" # Tentativas de login por minuto por IP (anti-brute-force)
ragnarok_login_bf_burst="5"

# SSH
ssh_port="22"            # Porta SSH (altere se usar porta não-padrão)
ssh_rate="3/minute"      # Novas conexões SSH por IP por minuto
ssh_burst="5"            # Burst antes do rate limit entrar
ssh_ban_time="1h"        # Tempo de banimento após exceder o limite
```

---

## 🏗️ Arquitetura das Regras

O script gera regras em duas tabelas nftables e as aplica atomicamente:

```
Prioridade -500  → tcp_portscan::portscan_drop    — drop imediato de IPs já banidos por scan
Prioridade -495  → DDOS::filter_ddos              — flags inválidas, bogon, fragmentos, MSS tiny, ICMP/SYN flood
Prioridade -160  → tcp_portscan::portscan_detection — detecção ativa de port scan
Prioridade -155  → DDOS::drop_ddos               — ct invalid, UDP flood, Ragnarok rate limit
Prioridade -154  → DDOS::ro_login_guard           — brute-force Login Server (6900)
Prioridade   -5  → DDOS::ssh_guard               — brute-force SSH (hook input)
Prioridade   -5  → DDOS::drop_forward            — bogon no forward
Prioridade   +5  → DDOS::drop_postrouting        — bogon no postrouting
ARP hook input 0 → ARP::arp_limit                — limite ARP por MAC
```

---

## 🔍 Diagnóstico e Monitoramento

**Ver regras ativas:**
```sh
nft list ruleset
```

**Ver IPs banidos por port scan:**
```sh
nft list set inet tcp_portscan enemies4
```

**Ver IPs banidos no SSH:**
```sh
nft list set inet DDOS ssh_banned
```

**Ver IPs banidos no Login Server:**
```sh
nft list set inet DDOS ro_login_banned
```

**Ver contadores em tempo real:**
```sh
nft list table inet DDOS
```

**Ver logs do kernel:**
```sh
logread | grep DDOS
```

**Desbanir um IP manualmente:**
```sh
# SSH
nft delete element inet DDOS ssh_banned { 1.2.3.4 }

# Port scan
nft delete element inet tcp_portscan enemies4 { 1.2.3.4 }

# Login Server
nft delete element inet DDOS ro_login_banned { 1.2.3.4 }
```

---

## ⚠️ Avisos Importantes

- **Teste sempre** antes de deixar rodar no boot. Um erro de configuração pode bloquear o acesso ao roteador.
- O script aplica as regras **atomicamente**: valida a sintaxe com `nft -c` antes de aplicar. Se a validação falhar, o firewall atual **não é alterado**.
- Se a validação falhar, o arquivo temporário de regras é **mantido em `/tmp/`** para inspeção manual.
- O script é **IPv4-only** — não adiciona regras para IPv6.
- `wan_input_drop="1"` bloqueia **todo** tráfego novo entrando na WAN, incluindo o seu acesso remoto. Use com cuidado.
- Ao alterar `ssh_port`, lembre de atualizar também `portscan_src_ports` e `portscan_dst_ports` se necessário.

---

## 📝 Licença

MIT — sinta-se livre para usar, modificar e distribuir.
