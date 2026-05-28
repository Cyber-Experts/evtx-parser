---
title: "Limpeza de event log e as lacunas que sobrevivem"
description: "Como os atacantes limpam logs de eventos do Windows, que evidência fica em disco e em canais reencaminhados, e a diferença entre wevtutil cl e ferramentas de suspensão de threads como o Invoke-Phant0m."
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

A limpeza de event logs é a técnica anti-forense que todo o operador aprende primeiro e a que deixa o rasto mais usável. Esta segunda parte é contra-intuitiva. O ponto todo de limpar logs é remover evidência, e um atacante que conseguiu limpar o `Security.evtx` removeu milhares de eventos que queria ler. Mas o ato de limpar é ele próprio barulhento, as técnicas que tentam ser mais silenciosas deixam uma assinatura diferente e igualmente diagnóstica, e os canais de que a maioria dos operadores se esquece preservam o suficiente para reconstruir o que foi limpo.

Saber o que sobrevive importa porque muda a pergunta que faz ao host. "O que está no log de Security" passa a "o que falta no log de Security, e para onde foram esses eventos".

## 1102, 104, 1100: a forma barulhenta

O reflexo predefinido de um operador que quer eliminar o log de Security é `wevtutil cl Security`. Isto produz:

- Um único `EventID=1102` em `Security.evtx`, gerado imediatamente depois da limpeza, a registar a conta que fez a limpeza e a hora. Este evento sobrevive no log limpo porque é o primeiro evento escrito no ficheiro recém-limpo. Trate-o como a arma fumegante. O nome da conta, a workstation de origem e a hora da limpeza estão todos nos dados do evento.
- Um `EventID=104` correspondente em `System.evtx` do provider `Microsoft-Windows-Eventlog`, com o nome do canal que foi limpo. Este é o espelho System do `1102`. Por vezes só um dos dois sobrevive porque o operador limpou múltiplos canais e a ordem importa.
- Um `1100` do serviço Event Log a indicar shutdown do serviço, se o operador parou o serviço antes de limpar. A combinação de `1100` seguido por uma lacuna inexplicada seguida por `1102` é o padrão clássico de "shutdown, adulterar, reiniciar".

Estes três eventos são a assinatura barulhenta. Um atacante que sabe o que faz não os vai gerar, ou vai gerá-los e depois limpar *de novo* para os remover, o que produz um segundo `1102` e um log sobrevivente ainda mais pequeno. Cada passagem de limpeza deixa um `1102`. O facto de um host ter múltiplos `1102`s no histórico é anómalo por si só.

Os eventos limpos não são as únicas vítimas. Limpar um canal reinicia o ficheiro EVTX subjacente, o que significa que o ficheiro em disco é reescrito. Os chunks do ficheiro antigo ficam não alocados. Recuperam-se do disco se imager o host dentro de uma janela razoável, que é o outro ramo desta história (coberto no post de carving).

## `wevtutil cl` vs suspensão de threads

Um operador mais sofisticado não limpa logs de todo. Suspende as threads do serviço Windows Event Log (`eventlog`), faz a coisa barulhenta que quer fazer e retoma as threads. Enquanto as threads estão suspensas, os eventos gerados pelo SO e pelas aplicações são enfileirados na infraestrutura ETW mas não escritos para o ficheiro EVTX. Quando as threads retomam, a fila é maioritariamente esvaziada, mas eventos que transbordaram o buffer durante a janela de suspensão perdem-se para sempre.

Isto é o que o `Invoke-Phant0m` faz (PowerShell, de Halil Dalabasmaz). O módulo Mimikatz `event::drop` faz algo semelhante mas opera ao hookar o callback ETW dentro do processo do serviço. Ambos deixam:

- Sem `1102`. Nada foi limpo.
- Sem `104`. Mesma razão.
- Uma lacuna. Eventos antes e depois da janela de suspensão estão presentes; eventos de dentro estão em falta. Esta é a deteção.

A lacuna é detetável de duas formas. A primeira é uma verificação de sanidade de RecordIDs contíguos: o cabeçalho de chunk EVTX regista `FirstEventRecordIdentifier` e `LastEventRecordIdentifier`, e pode verificar que os RecordIDs são monotónicos ao longo de chunks. A suspensão não quebra o contador de RecordID (o serviço está suspenso, não o provider ETW do kernel), mas os timestamps dentro do chunk vão mostrar uma janela sem eventos de providers ocupados, o que num domain controller é gritantemente óbvio.

A segunda é correlação contra canais que não consegue suspender sem voltar a elevar. O canal `Microsoft-Windows-EventLog%4Operational.evtx` regista o ciclo de vida do próprio serviço de event log. A suspensão de threads não gera eventos explícitos de "thread suspensa" aqui, mas o heartbeat interno do serviço (eventos `105`, `106` e eventos de debug específicos do provider quando o canal operacional está em verbosidade mais alta) por vezes regista a inconsistência.

A terceira, mais difícil, é o rasto do [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config). O Sysmon escreve para o seu próprio canal via o seu próprio driver e não é afetado por suspensão do serviço de event log. Um host com Sysmon vai ter um registo contínuo de criações de processos e image loads através da janela de suspensão. Cruze a hora da suposta lacuna em `Security.evtx` contra o canal `Operational` do Sysmon; se o Sysmon mostra um processo `powershell.exe` com conteúdo de linha de comandos a corresponder ao código fonte Phant0m (ou a qualquer uma das dezenas de variantes públicas) a correr no início da lacuna, tem a sua resposta.

## O canal de eventos reencaminhados

O Windows Event Collector (WEC) é o mecanismo padrão para reencaminhar eventos para um coletor central. Os eventos reencaminhados chegam ao coletor em `Microsoft-Windows-EventLog%4ForwardedEvents` (nos subscritores Windows Event Collector) e retêm o campo `Computer` do host de origem, o `RecordID` original e os timestamps originais.

Se o seu ambiente tem WEC e o próprio coletor não foi comprometido, o canal de eventos reencaminhados é por vezes o único registo intacto do que aconteceu num host cujo log local foi limpo. Os eventos são byte-iguais ao que foi gerado no host de origem (modulo metadados adicionados pelo coletor), e o `RecordID` do host de origem permite costurar a cópia reencaminhada de volta à timeline de RecordID do log local.

A pegadinha: as subscrições WEC são pull-based por defeito, com um heartbeat de 15 minutos. Um atacante rápido pode limpar o log local entre heartbeats de reencaminhamento e o coletor só terá os eventos antes do último pull bem-sucedido. Configure subscrições em modo `MinLatency` (push, com latência de batch de 30 segundos) nos canais que lhe importam. Custa rede e throughput do coletor; paga-se da primeira vez que precisa.

A outra pegadinha: o WEC não reencaminha por defeito. Se ninguém configurou a subscrição, o canal do coletor está vazio. Verifique o estado da subscrição em coletores candidatos antes de apostar uma investigação neste caminho de evidência.

## Apagamento seletivo e a questão ao nível EVTX

O apagamento seletivo de registos (remover eventos específicos de um ficheiro EVTX ativo mantendo o resto) é teoricamente possível editando o ficheiro com conhecimento do formato e recomputando os CRCs do chunk. Na prática ninguém faz isto em operações ao vivo porque o serviço de event log tem o ficheiro aberto e bloqueado; não consegue editá-lo a partir de userland sem derrubar o serviço, e derrubar o serviço gera eventos `1100`/`105`.

O que acontece no terreno é adulteração offline após o facto. Um operador que exfiltra o ficheiro EVTX, edita-o na sua própria máquina e o re-carrega para substituir o ficheiro ativo (depois de parar o serviço) vai deixar:

- CRCs inconsistentes em chunks que editaram, a menos que tenham recomputado corretamente tanto o CRC do cabeçalho do chunk como o CRC da região de registos.
- `LastEventRecordNumber` inconsistente em cabeçalhos de chunk se não os atualizaram também.
- Descontinuidades em RecordIDs ao longo de fronteiras de chunk.

Qualquer parser decente sinaliza estes. O `evtx_dump` avisa em mismatch de CRC por defeito. O `EvtxECmd` regista a discrepância na sua saída. Trate qualquer aviso de CRC durante parsing de um ficheiro EVTX de um host suspeito de comprometimento como um indicador potencial de adulteração e faça imagem ao disco subjacente antes de fazer mais nada.

## O que aparece apenas em `Microsoft-Windows-EventLog%4Operational.evtx`

Este canal é separado do `Security.evtx` e a maioria dos atacantes ignora-o. Regista:

- Início e paragem do serviço de event log (`105`, `106`).
- Mudanças de estado de canal (subscrição iniciada, canal ativado/desativado).
- Eventos de registo de manifesto.

Quando o serviço Event Log é reiniciado (porque o operador usou `Stop-Service eventlog`, ou porque corrigiu algo e reiniciou), obtém eventos aqui que emparelham com a família `1100`/`105`/`106`. Se o `Security.evtx` mostra `1100` no tempo T e o `EventLog%4Operational.evtx` mostra uma mudança de estado de serviço correspondente no mesmo T, o shutdown foi ordenado. Se o `Security.evtx` mostra uma lacuna sem `1100` mas o `EventLog%4Operational.evtx` mostra que o serviço foi reiniciado, o serviço crashou ou foi morto sem um shutdown ordenado, o que é suspeito por si só.

Este canal é pequeno e lê-se depressa. Adicione-o à sua checklist de triagem por defeito.

## Cross-validar contra artefactos do host

Quando o log de Security desapareceu ou foi adulterado, os artefactos que sobrevivem são os suspeitos do costume:

- A [Master File Table](https://www.mftparser.com) para o próprio ficheiro EVTX. Os timestamps `$STANDARD_INFORMATION` e `$FILE_NAME` vão mostrar quando o ficheiro foi reescrito por limpeza.
- O [USN journal](https://www.usnparser.com) para eventos `DATA_OVERWRITE` e `DATA_TRUNCATION` em `Security.evtx`. Estes mostram a limpeza em termos de journal com timestamps de alta resolução.
- [Prefetch](https://www.prefetchparser.com) para execução de `wevtutil.exe`, ou para runs de `powershell.exe` que alinharam com a suposta limpeza.
- [Shimcache](https://www.shimcacheparser.com) e [AmCache](https://www.amcacheparser.com) para ferramentas que o operador trouxe para fazer a limpeza, particularmente se usaram um binário não-padrão.
- Artefactos de [RAM dump](https://www.ramparser.com) se capturou um. A cache em memória do serviço de event log vai ter registos que nunca foram flushed para disco.

O log de Security é uma fonte. Trate-o como uma fonte. A investigação que depende só dele está a um ficheiro adulterado de ser inútil. O [parser neste site](https://www.evtxparser.com) sinaliza mismatches de CRC de chunk e lacunas de RecordID na sua saída, que é a verificação barata de primeira passagem para saber se está a olhar para um log adulterado antes de investir uma hora a lê-lo.

## Leitura adicional

- A [fonte Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) de Halil Dalabasmaz. Leia o que faz. A deteção segue-se diretamente.
- A [entrada do ThreatHunter-Playbook sobre 1102](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html) de Roberto Rodriguez e o material em redor sobre deteção de limpeza.
- A documentação Microsoft sobre [subscrições Windows Event Collector](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) para a configuração WEC que lhe dá a rede de segurança de eventos reencaminhados.
