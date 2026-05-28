---
title: "Começa aqui: o guia do analista DFIR sobre .evtx"
description: "O que é o .evtx, que canais importam, os Event IDs a conhecer e onde encontrar cada um em disco. Um ponto de partida de navegação para tudo o resto neste blogue."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` é o formato binário do log de eventos do Windows que a Microsoft introduziu no Vista para substituir o antigo `.evt`. É a espinha dorsal de toda a resposta a incidentes em Windows: logons, instalações de serviço, tarefas agendadas, linhas de comando PowerShell, árvores de processos do Sysmon. Tudo isto é serializado neste formato. Este post é o índice. Uma orientação de um ecrã, seguida de ligações para os artigos mais profundos sobre os canais e Event IDs que realmente importam num caso.

Novo no `.evtx`? Comece por [o que é um ficheiro .evtx](/pt/blog/what-is-an-evtx-file) e [como abrir um](/pt/blog/how-to-open-an-evtx-file). O resto deste post pressupõe que já está à vontade com o formato e quer saber o que ler primeiro quando um host está a arder.

## Onde vivem os ficheiros

Os logs ativos ficam em `C:\Windows\System32\winevt\Logs\`. Um canal, um ficheiro `.evtx`. Os predefinidos que terá sempre:

- `Security.evtx`. Logons, uso de privilégios, alterações de política de auditoria. Maior valor forense na maioria dos casos.
- `System.evtx`. Drivers, serviços, erros ao nível do SO.
- `Application.evtx`. Erros ao nível da aplicação.
- `Setup.evtx` e `ForwardedEvents.evtx`. Registos de instalação e tráfego WEF reencaminhado.

Mais canais por aplicação em `Microsoft-Windows-*`. Os que justificam o seu lugar num caso:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Só existe se o Sysmon estiver instalado. Quando está, vale ouro.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Scriptblock e module logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Criação e execução de tarefas agendadas.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo de vida das sessões RDP.

Para detalhes profundos sobre como um ficheiro está organizado (os chunks de 64 KB, as tabelas de templates XML, BinXML), ver [a análise ao nível dos chunks](/pt/blog/evtx-file-format-chunks).

## Os Event IDs a conhecer

A lista curta que cobre a maior parte daquilo em que um analista se apoia:

- [**4624** logon bem-sucedido](/pt/blog/understanding-event-id-4624). Leia-o através de `LogonType`. O campo decide se está a olhar para uma sessão de consola (2), de rede (3), RDP (10) ou `runas /netonly` (9).
- [**4625** logon falhado](/pt/blog/detecting-4625-brute-force). Os surtos são reconhecimento, brute force ou password spray, consoante os campos que se agrupam.
- [**1102** log de Segurança limpo](/pt/blog/event-id-1102-cleared-log). Se o vir, o log que tem em mãos tem uma lacuna conhecida. Anote-o de forma bem visível.
- [**4104** PowerShell scriptblock](/pt/blog/powershell-4104-scriptblock). O corpo do script *depois* de descodificação e reflexão. O controlo defensivo gratuito mais útil da plataforma.
- [**7045** serviço instalado](/pt/blog/service-creation-event-id-7045). Uma das técnicas de persistência mais citadas no MITRE ATT&CK (T1543.003). Também é a assinatura do PsExec.
- [**Sysmon 1** criação de processo](/pt/blog/sysmon-event-id-1-process-create). O registo de criação de processo mais rico que o Windows consegue produzir quando o Sysmon está presente.

Para o fluxo de trabalho que liga tudo, leia [triagem EVTX quando se tem uma hora e um host](/pt/blog/evtx-triage-incident-response).

## Como este site se encaixa

O parser na página inicial é o crate Rust [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compilado para WebAssembly e executado dentro de um Web Worker. Larga-se um `.evtx`, o worker percorre os chunks e obtém-se uma linha temporal de eventos filtrável e o XML por registo. Tudo no browser, nada é enviado. Use-o para triagem ad-hoc quando não quer iniciar um EDR nem mover um ficheiro de um sistema que não é seu.

Se está a [recolher `.evtx` de um host ativo](/pt/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), esse post cobre os quatro métodos padrão com os compromissos de cadeia de custódia que cada um faz.

O EVTX raramente é o único artefacto de que precisa. Combine-o com parsers de [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [prefetch](https://www.prefetchparser.com) e [LNK](https://www.lnkparser.com). Quando precisa de cavar mais fundo, a análise de [pagefile](https://www.pagefilesysparser.com) e [RAM dump](https://www.ramparser.com) recupera o que os logs em disco perderam. Para linhas temporais de atividade do utilizador, [SRUM](https://www.srumparser.com), [jump lists](https://www.jumplistparser.com), [recycle bin](https://www.recyclebinparser.com), [recent file cache](https://www.recentfilecacheparser.com) e [browser history](https://www.browserforensics.app) preenchem as lacunas que o EVTX não consegue preencher.
