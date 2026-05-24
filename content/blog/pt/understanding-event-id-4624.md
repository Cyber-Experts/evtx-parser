---
title: "Event ID Windows 4624: decodificando cada logon bem-sucedido"
description: "O que um registro 4624 realmente contém, por que o campo LogonType importa mais que o próprio evento, e como lê-los em escala."
date: "2026-05-17"
---

O event ID 4624 — «Uma conta foi conectada com sucesso» — é registrado no canal `Security` toda vez que o Windows autentica uma identidade. É o registro mais volumoso na maioria das estações e a espinha dorsal de quase toda investigação de IR. Saber lê-lo não é negociável.

## O que tem dentro de um registro 4624

A parte interessante vive em `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Os campos `Subject*` são o contexto de segurança que *solicitou* o logon (frequentemente `S-1-5-18` para SYSTEM no início de um serviço). Os campos `Target*` são a identidade que acabou autenticada. Confundi-los custa horas a um analista.

## LogonType é o campo que importa

O Windows define dez tipos de logon; na prática só alguns guiam a triagem:

- **2 — Interactive**: logon físico ou de console.
- **3 — Network**: SMB, RPC, WinRM, qualquer coisa via rede. A grande maioria do tráfego normal.
- **4 — Batch**: tarefas agendadas executando sob uma conta de usuário.
- **5 — Service**: serviço iniciado sob uma conta específica.
- **7 — Unlock**: estação desbloqueada após screen lock.
- **8 — NetworkCleartext**: raro, suspeito — credenciais em texto puro (Basic auth no IIS, equipamentos antigos).
- **9 — NewCredentials**: `runas /netonly`, frequentemente usado por atacantes para carregar credenciais de domínio em uma máquina onde só têm direitos locais.
- **10 — RemoteInteractive**: RDP. Combina com `IpAddress` para atribuição da fonte.
- **11 — CachedInteractive**: conta de domínio autenticada com credenciais em cache (nenhum DC alcançável).

Um 4624 com LogonType **10** vindo de um IP externo às 03h de domingo conta outra história que 50 LogonType **3** vindos de um servidor de backup às 02h.

## Com o que encadear

Um 4624 bem-sucedido sozinho raramente é um achado. Torna-se um quando combinado com:

- **4625** precedendo a partir da mesma fonte — um sucesso após uma rajada de falhas é a assinatura clássica de brute-force-com-sucesso.
- **4672** (privilégios especiais atribuídos) — sinaliza logons que concederam privilégios como `SeDebugPrivilege`, útil para detectar uso de conta privilegiada.
- **4648** (logon com credenciais explícitas) — captura `runas` e outros padrões de passagem de credenciais.

## Lendo em escala

O parser desta página extrai esses campos diretamente do XML do registro e os exibe na tabela. Filtre por `LogonType` pelos buckets da timeline e pelo filtro de texto (`4624` na busca), exporte o conjunto filtrado como CSV e pivote em `SubjectUserSid` + `IpAddress` na ferramenta que preferir. O XML completo de cada registro está a um clique.
