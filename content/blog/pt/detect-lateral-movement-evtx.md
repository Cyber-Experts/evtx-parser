---
title: "Detetar movimento lateral no Security.evtx"
description: "Como as ferramentas adversárias reais se movem host-a-host em ambientes Windows, e as combinações precisas de event IDs no Security.evtx que apanham PsExec, Impacket e WMIExec."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

O movimento lateral é onde a maioria das intrusões passa de "têm um ponto de apoio" para "são donos do domínio". É também onde o logging do Windows é mais útil e mais enganador. Os eventos de que precisa estão todos em `Security.evtx` e `System.evtx`. Lê-los isoladamente não o leva a lado nenhum. Lê-los nos pares certos, com a correlação cross-host certa, é o que separa uma timeline útil de uma parede de `4624`s.

Esta é a parte da investigação em que paro de fazer scroll e começo a fazer grep por `LogonId`.

## O esqueleto: o que acontece quando um atacante se move

Não há um padrão universal de movimento lateral, mas há uma *forma* universal:

1. O atacante autentica-se do host A para o host B, ou com o token do utilizador atual (pass-the-hash, pass-the-ticket ou um Kerberos TGT/TGS roubado) ou com credenciais explícitas para uma conta diferente.
2. Algo no host B executa o payload do atacante: um serviço, uma tarefa agendada, uma criação de processo via WMI, uma sessão PowerShell remota ou uma invocação DCOM.
3. Voltam a sair para buscar ferramentas, segredos ou o próximo salto.

Cada passo deixa eventos. A pergunta é se está a olhar para os certos, e se a instrumentação existe sequer.

## 4624 LogonType 3 é a porta da frente

Um logon de rede bem-sucedido (`EventID=4624` com `LogonType=3`) é a primitiva de movimento lateral mais comum no log. Também é o evento mais ruidoso que o Windows gera. Um file server num escritório de 500 lugares produz dezenas de milhares destes por dia, todos legítimos. Filtrar só por `LogonType=3` não o leva a lado nenhum.

O que o leva:

- `IpAddress` e `WorkstationName` nos dados do evento. As anomalias agrupam-se aqui. Uma workstation a fazer logon num servidor a partir de uma sub-rede diferente às 02:14 UTC não é nada.
- `AuthenticationPackageName` e `LogonProcessName`. Logons NTLM (`NTLM` / `NtLmSsp`) entre hosts inscritos no domínio num ambiente Kerberos são suspeitos por defeito. Um ambiente Kerberos limpo deve usar Kerberos exclusivamente para auth intra-domínio, com NTLM como fallback apenas para acesso por nome não-DNS e legado.
- Padrões de `TargetUserName`. Contas de serviço a fazer logon interativo são bandeiras vermelhas. Contas de domain admin a fazer logon em workstations são bandeiras vermelhas.

O pivot que quer: emparelhar cada `4624 Type 3` interessante com o `4672` (privilégios especiais) correspondente no mesmo `TargetLogonId`. Se o logon ganhou privilégios admin, tem candidato a abuso de credenciais. Se não ganhou, o atacante está a operar com um token menos privilegiado e tem tempo.

## 4648 é o evento que mais defensores subutilizam

`4648` ("foi tentado um logon usando credenciais explícitas") é gerado sempre que um processo a correr como conta A invoca credenciais para a conta B para fazer alguma coisa. É o evento que quer para atribuição. Quando o `mimikatz` ou o `Rubeus` injetam um ticket e o operador corre `net use \\TARGET /user:CORP\admin <pass>`, obtém um `4648` no host de origem a mostrar ambas as contas e o alvo.

Os campos que importam:

- `SubjectUserName` / `SubjectLogonId` — quem iniciou.
- `TargetUserName` / `TargetServerName` — credenciais de quem, contra o quê.
- `ProcessName` — que binário fez a invocação. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (para execução baseada em WMI), e cada vez mais `pwsh.exe` são os suspeitos do costume.

O `4648` é a ligação entre um host comprometido e o próximo salto. Se tem um host suspeito, despeje `4648` do seu log de Security primeiro. Vai dizer-lhe que credenciais o atacante tem e onde tentou usá-las, por ordem temporal, num único sítio.

## 4672 e a história dos privilégios

O `4672` aparece imediatamente após o `4624` para qualquer logon que termine com pelo menos um privilégio sensível (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc). É gerado para cada logon de um membro de `Administrators`, `Domain Admins` ou qualquer conta com privilégios de elevação de token.

Trate-o como uma etiqueta, não como uma descoberta. A query útil é "mostra-me cada `4672` seguido em 60 segundos por um `4624 Type 3` de um IP de origem que não é DC", que evidencia uso de token admin a partir de workstations que não o deveriam emitir. A query não útil é "mostra-me cada `4672`", que devolve cada arranque de serviço em cada servidor.

## 4697 e 7045: serviços como execução remota

PsExec, `psexec.py` do Impacket e `smbexec.py` funcionam escrevendo um binário de serviço para o share `ADMIN$` do alvo, registando-o via Service Control Manager, iniciando-o e desmontando-o. Isto deixa:

- `5145` no alvo a mostrar acesso a `\\target\ADMIN$` com o nome do ficheiro escrito (se auditoria de acesso a objetos estiver ligada).
- `7045` em `System.evtx` a mostrar a instalação do serviço. O caminho do binário do serviço e o nome do serviço estão nos dados do evento. O PsExec usa por defeito `PSEXESVC` em `%SystemRoot%`; o Impacket aleatoriza ambos, com padrões que variam por versão e estão bem documentados.
- `4697` em `Security.evtx` para a mesma instalação de serviço se tiver a política de auditoria de sistema definida.
- `4624 Type 3` da workstation de origem do operador.

A assinatura é a *combinação*: `4624 Type 3` de uma origem invulgar, seguido imediatamente por `5145` para `ADMIN$`, seguido imediatamente por `7045` para um serviço cujo binário vive algures onde não devia. Cada evento isolado é plausível. A combinação, em segundos, com o mesmo `LogonId` a ligá-los, não é.

Nomes de serviço a vigiar no `7045`: strings aleatórias de 8 caracteres minúsculos (default do Impacket), `PSEXESVC` (default do PsExec), `WinExec` ou variantes, qualquer coisa com um caminho de binário sob `C:\Windows\` que não esteja assinado e não esteja no conjunto normal de serviços do sistema.

## 5140 e 5145: acesso a partilhas SMB em detalhe

O `5140` regista que uma share foi acedida; o `5145` regista o nome do ficheiro acedido dentro da share, *se* auditoria de acesso a objetos para a share estiver ativada. A maioria dos ambientes não ativa o `5145` por causa do ruído. A maioria também gostaria de o ter num incidente.

Para movimento lateral, os eventos `5145` que importam são acessos a `ADMIN$`, `C$`, `IPC$` e quaisquer caminhos `SYSVOL`/`NETLOGON` a partir de origens invulgares. O `psexec.py` escreve o seu binário de serviço escrevendo para `\\target\ADMIN$\<random>.exe`. O `secretsdump.py` lê `\\target\C$\Windows\System32\config\SAM` (e SYSTEM, e SECURITY). Cada um deles é um `5145` com um `RelativeTargetName` que deve saltar à vista.

Combine `5145` com o [USN journal](https://www.usnparser.com) no alvo. O journal terá um `FILE_CREATE` para o mesmo ficheiro com o mesmo timestamp, o que dá uma confirmação de segunda fonte de que o ficheiro realmente aterrou, e uma referência de registo [MFT](https://www.mftparser.com) para perseguir.

## WMI como vetor de movimento lateral

A execução remota baseada em WMI (`wmic /node:... process call create`, `wmiexec.py` do Impacket, PowerShell `Invoke-WmiMethod`) é mais difícil de detetar só no Security.evtx porque não instala um serviço. Obtém:

- `4624 Type 3` no alvo.
- Uma criação de processo no alvo com `WmiPrvSE.exe` como parent. Isto está no Sysmon `EventID=1` se o Sysmon estiver ligado. No `4688` é a mesma imagem se a auditoria de linha de comandos estiver ligada.
- Eventos WMI em `Microsoft-Windows-WMI-Activity%4Operational.evtx` a mostrar o consumer.

Se o Sysmon não estiver ligado, o movimento lateral via WMI é maioritariamente invisível nos logs de eventos com configuração predefinida. Esta é uma das razões pelas quais cada baseline de configuração empurra o Sysmon com força.

## Correlacionar entre hosts

O movimento lateral é um problema de grafos. Um `4648` no host A a nomear o host B e a conta `corp\admin` é uma aresta. O correspondente `4624 Type 3` no host B vindo do IP do host A, com `TargetUserName=admin`, é a outra ponta da mesma aresta. O `4769` (Kerberos service ticket) no DC a mostrar o pedido de ticket para `cifs/hostB` por `admin@CORP` é a terceira testemunha.

Na prática quer tudo:

- Eventos de logon do `Security.evtx` do host de origem.
- Eventos de logon do `Security.evtx` do host alvo.
- Eventos TGT (`4768`) e TGS (`4769`) do `Security.evtx` do domain controller.
- Eventos reencaminhados de qualquer coletor WEC, que por vezes têm a única cópia intacta se o log local de um host foi limpo.

Ligue-os por `LogonId` dentro de um host e por timestamp + conta + IP entre hosts. O paper clássico do JPCERT/CC apresenta isto em detalhe e é o melhor documento gratuito sobre o tópico.

Para os artefactos do lado do host que sobrevivem à limpeza do log, apoie-se em [Prefetch](https://www.prefetchparser.com) para evidência de execução de ferramentas do atacante, na chave `Services` do [registry](https://www.registryparser.com) para o rasto de um binário de serviço instalado-e-removido, e em [LNK files](https://www.lnkparser.com) e [jump lists](https://www.jumplistparser.com) para evidência de ficheiros que um operador abriu durante uma sessão hands-on.

## Leitura adicional

- ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) do JPCERT/CC. A referência. Leia duas vezes.
- A [matriz Lateral Movement do MITRE ATT&CK](https://attack.mitre.org/tactics/TA0008/) e os mapeamentos de fontes de dados por técnica.
- O [diretório examples do Impacket](https://github.com/fortra/impacket/tree/master/examples). Se não leu o que `psexec.py`, `wmiexec.py` e `smbexec.py` fazem mesmo na rede, as suas deteções são palpites.
