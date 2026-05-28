---
title: "Triagem EVTX: o que ler primeiro quando se tem uma hora e um host"
description: "Uma ordem de operações de praticante para triagem de Windows Event Logs durante resposta a incidentes — que canais importam, que event IDs lhe mentem e onde o Sysmon faz o trabalho pesado."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

Se alguém lhe entrega um bundle EVTX de um host que pensa estar comprometido e lhe dá uma hora, não tem tempo para elegância. Tem tempo para uma ordem de operações que funcionou vezes suficientes para confiar nela antes de ter lido um único registo.

Esta é a minha. Não é a referência completa e não é o correto para cada caso — investigações de insider de combustão lenta precisam de uma postura completamente diferente — mas para a pergunta padrão "isto está popped, e como", é o que corro.

## Que canais realmente devolvem o tempo

Uma instalação default de Windows traz para cima de trezentos canais EVTX. Vai olhar para uns sete deles. Os que importam consistentemente:

- `Security.evtx` — logons, uso de privilégios, alterações de contas. A primeira paragem para cada incidente interativo.
- `Microsoft-Windows-Sysmon%4Operational.evtx` — se o Sysmon estiver implantado (e devia implorar, pedir, ameaçar até que esteja), é aqui que vive o sinal real. Criações de processos com linhas de comando, criações de ficheiros, ligações de rede, DNS, image loads. Tudo o que o `Security.evtx` insinua sem dizer.
- `System.evtx` — instalações de serviços, drivers carregados, eventos de arranque, mudanças de hora. Muitas vezes o único sítio onde movimento lateral deixa uma instalação de serviço para trás.
- `Application.evtx` — geralmente ruído, mas erros de macros Office, exceções .NET e alguns side-channels de EDR aparecem aqui.
- `Microsoft-Windows-PowerShell%4Operational.evtx` — module logging e eventos de pipeline, se ativados. O log de script block `4104` é onde encontra cada linha de PowerShell malicioso, assumindo que o logging estava on. É o segundo canal mais importante a seguir ao Sysmon quando ambos estão ativos.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — criação, eliminação e execução de tarefas agendadas. Lê-se rápido, paga depressa.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` — subscrições WMI e registos de consumers. Barato de ler; apanha um padrão específico de persistência.

Se o host tem Defender, pegue também em `Microsoft-Windows-Windows Defender%4Operational.evtx`. A família `1116` / `1117` é por vezes a única menção contemporânea ao ficheiro que importou.

Tudo o resto pode deixar para a segunda passagem.

## A primeira coisa que abro não é o log de Security

O reflexo predefinido é fazer grep ao `Security.evtx` por `4624`. Deixei de fazer isso na primeira passagem e provavelmente você também devia. O log de Security num servidor movimentado regista milhares de logons legítimos por hora. Vai afogar-se em ruído antes de ter enquadrado a pergunta.

O que abro primeiro, quando existe, é o `Sysmon%4Operational.evtx` filtrado a `EventID=1` (criação de processo) na janela suspeita. O Sysmon dá-lhe o processo parent, a linha de comando tal como invocada, o utilizador, o integrity level, e os hashes do parent e do filho. Isso é suficiente para ler uma história a partir do ecrã.

Se o Sysmon não está presente (e num número deprimente de parques Windows corporativos ainda não está), o meu movimento seguinte é o `Security.evtx` filtrado a `4688` *com auditoria de linha de comandos ativada*. Se as linhas de comando não estão auditadas obtém o nome do programa nu, o que é mal útil — nesse ponto salto para AmCache, Prefetch e o [USN journal](https://www.usnparser.com) para reconstruir o que correu.

O corolário que vale a pena dizer alto: uma investigação EVTX sem Sysmon e sem linhas de comando `4688` é maioritariamente um jogo de adivinha. Se está a ler isto antes de um incidente, corrija isso primeiro.

## Os event IDs que deixa de ter de procurar

Acaba por aprendê-los de cor. A versão curta, com a forma como penso em cada um em IR:

- `4624` — logon bem-sucedido. Leia `LogonType` primeiro: `3` é rede (file share, ferramenta remota), `10` é RDP / Terminal Services, `2` é interativo, `9` é `runas` com credenciais explícitas. `5` é serviço. O `LogonType` carrega mais significado do que o próprio evento.
- `4625` — logon falhado. Surtos são ataques de spray; isolados em muitas contas são credential stuffing.
- `4634` / `4647` — logoff e logoff iniciado pelo utilizador. Útil para fechar o bracket numa sessão.
- `4648` — logon com credenciais explícitas. O que realmente quer para atribuição de movimento lateral: quando a conta A usa credenciais da conta B para iniciar um processo ou ligar-se a algures, este é o registo. A maioria dos defensores subutiliza-o.
- `4672` — privilégios especiais atribuídos no logon. A linha "esta conta acabou de se tornar admin". Combine com o `4624` que precede.
- `4688` — criação de processo. Útil apenas quando a auditoria de linha de comandos está ativada (Group Policy: *Audit Process Creation* e *Include command line in process creation events*). Sem isso, obtém nomes de programas.
- `4697` — serviço instalado. Movimento lateral via PsExec, Impacket-`smbexec` e ferramentas similares vive aqui.
- `4720` / `4732` / `4738` — conta criada, mudança de membership de grupo, conta alterada. Persistência adora estes.
- `1102` — log de Security foi limpo. Se vir isto, o resto do log de Security até esse ponto é suspeito ou está ausente. O facto de o evento existir é a arma fumegante.
- `5140` / `5145` — share de rede acedida. O último regista o nome do ficheiro; se está ligado, o movimento lateral via SMB é auditável em detalhe.
- `7045` — serviço instalado (log System). Espelha o `4697` mas a partir do canal System.
- `Sysmon 1` — criação de processo com contexto completo. O event ID mais útil em DFIR se o Sysmon estiver ligado.
- `Sysmon 3` — ligação de rede. Apanha C2 outbound mesmo quando o Defender não apanhou.
- `Sysmon 10` — acesso a processo. O que apanha dumping de credenciais do `lsass.exe`.
- `Sysmon 11` — criação de ficheiro. Apanha atividade de dropper que não chegou a executar.
- `PowerShell 4104` — script block logging. Regista o texto completo de cada comando PowerShell, incluindo ofuscados (deofuscados pós-descodificação em muitos casos).

Mantenho uma cheat sheet impressa ao lado da secretária e você também devia. Não é glamoroso e poupa minutos reais.

## Os eventos que lhe mentem, ou são fáceis de ler mal

`4624 Type 3` de `\\NT AUTHORITY\ANONYMOUS LOGON` não é "o atacante está dentro". Normalmente é uma enumeração de share mal configurada, um vulnerability scanner ou um de meia dúzia de mecanismos internos do Windows. Valide antes de escalar.

`4625` contra uma única conta de serviço à taxa de uma por minuto é quase sempre uma credencial cached velha algures. Olhe para o campo workstation de origem antes de lhe chamar brute force.

Os timestamps em Security.evtx são hora local no host que os gerou por defeito em algumas ferramentas, UTC noutras. Quando carrega um bundle numa nova ferramenta, faça sanity check encontrando um logon que consegue correlacionar com um evento externo conhecido (uma atualização de ticket, uma sessão VPN) e confirme offsets. Já vi relatórios inteiros enviesados em 4 horas porque alguém se esqueceu de verificar.

A limpeza de event log (`1102`) é geralmente barulhenta, mas o apagamento seletivo de registos é uma besta diferente. `wevtutil cl` limpa o canal inteiro, o que é detetável. Ferramentas como o `phant0m` e `Invoke-Phant0m` em vez disso suspendem as threads do serviço de eventos, o que não deixa evento de limpeza mas cria uma lacuna visível. Procure a lacuna, não só o `1102`.

Eventos reencaminhados (`Microsoft-Windows-EventLog%4ForwardedEvents`) preservam o RecordID do host de origem e os timestamps originais. Se tiver um subscriber WEC que sobreviveu ao incidente, essas cópias são por vezes o único registo intacto que resta.

Se o log de Security mostra `1100` (shutdown do serviço de eventos) seguido por uma lacuna inexplicada, está a olhar para uma das tentativas mais limpas de limpar evidência. Cross-valide contra [hives do registry](https://www.registryparser.com), a [Master File Table](https://www.mftparser.com) e Prefetch.

## Carving e recuperação, quando faltam registos

Os registos EVTX podem ser recuperados por carving de disco não alocado e de [pagefile.sys](https://www.pagefilesysparser.com) quando o ficheiro ativo foi limpo ou rodado. O cabeçalho do registo (magic `2a 2a 00 00`) é distintivo o suficiente para o carving por assinatura funcionar razoavelmente bem. O `hayabusa` da Yamato Security e o `evtx_dump` ambos lidam com ficheiros malformados com streams de registo remendados.

Se está a lidar com um host onde suspeita que o log foi adulterado, tente também recuperar registos EVTX a partir de um [RAM dump](https://www.ramparser.com). O serviço de event log faz cache em memória de registos recentes; um snapshot tirado perto do incidente por vezes contém registos que nunca chegaram a disco.

## Para onde ir a partir de um hit

Um único evento raramente fecha um caso. Os pontos de pivot a que recorro, por ordem:

- Um `4624` suspeito → procure o `4672` correspondente, as falhas `4625` precedentes, e que processo foi criado com esse token depois (Sysmon 1 com `LogonId` correspondente).
- Uma instalação de serviço `7045` ou `4697` → verifique `Microsoft-Windows-TaskScheduler%4Operational.evtx` para tarefas de seguimento, e o [registry](https://www.registryparser.com) em `HKLM\SYSTEM\CurrentControlSet\Services\` para o caminho do binário.
- Um Sysmon 10 contra `lsass.exe` → árvore de processos do processo requisitante, drops de ficheiros no diretório de trabalho, ligações de rede para destinos não corporativos.
- Um PowerShell 4104 com conteúdo ofuscado → descodifique numa sandbox, depois procure o mesmo payload a aterrar noutros hosts (a maioria dos atores enterprise reutiliza).

## Ler EVTX no browser

O [parser neste site](https://www.evtxparser.com) lê EVTX inteiramente client-side: largue um ficheiro e obtém uma tabela ordenável e filtrável com canal, RecordID, EventID, hora, computador e o XML renderizado. Sem upload, o que importa porque EVTX de ambientes regulados quase sempre contém PII que não quer atravessar uma fronteira de fornecedor.

## Leitura adicional

- ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) do JPCERT/CC — o documento único mais útil sobre correlação de eventos de movimento lateral. Vale a pena uma leitura devagar.
- O [EvtxECmd](https://github.com/EricZimmerman/evtx) de Eric Zimmerman — parser offline com as saídas canónicas de mapeamento de campos.
- A configuração Sysmon que a Microsoft Threat Intelligence (antiga SwiftOnSecurity) mantém como baseline: [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Comece daqui, não escreva o seu do zero.

A versão cínica de tudo o que foi dito: com Sysmon e auditoria de linha de comandos, o EVTX dá-lhe 80% do que precisa para reconstruir uma intrusão. Sem eles, está a fazer forense na silhueta do evento, em vez do evento em si.
