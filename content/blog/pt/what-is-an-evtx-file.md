---
title: "O que é um ficheiro .evtx? O formato do log de eventos do Windows explicado"
description: "Um ficheiro .evtx é um log binário de eventos do Windows. Onde vivem, o que está lá dentro, como diferem dos .evt e como abri-los. Sem instalação."
date: "2026-05-24"
faq:
  - question: "O que é um ficheiro .evtx?"
    answer: "Um ficheiro .evtx é o formato binário do log de eventos do Windows introduzido com o Windows Vista. Armazena eventos de sistema, segurança e aplicação escritos pelo serviço EventLog. Cada máquina Windows tem dezenas de ficheiros .evtx em C:\\Windows\\System32\\winevt\\Logs\\, um por canal."
  - question: "Onde são guardados os ficheiros .evtx no Windows?"
    answer: "A localização predefinida é C:\\Windows\\System32\\winevt\\Logs\\. Os três ficheiros com mais tráfego são Security.evtx, System.evtx e Application.evtx. Os canais por aplicação vivem na mesma pasta com nomes como Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Qual é a diferença entre .evtx e .evt?"
    answer: ".evt é o formato binário legado que o Windows usou até ao XP e Server 2003. O .evtx substituiu-o no Windows Vista (2007) com um esquema baseado em chunks e BinXML que suporta metadados de evento mais ricos, logs maiores e consultas estruturadas via wevtutil e Get-WinEvent. Os dois formatos não são intercambiáveis."
  - question: "Como abro um ficheiro .evtx?"
    answer: "Ferramentas integradas do Windows: Event Viewer (eventvwr.msc), wevtutil na linha de comandos ou Get-WinEvent no PowerShell. Multiplataforma: o parser baseado no browser deste site (sem instalação, sem upload) ou evtxecmd na linha de comandos. Veja o nosso post how-to-open-an-evtx-file para todas as opções."
  - question: "Posso abrir um ficheiro .evtx em macOS ou Linux?"
    answer: "Sim. As ferramentas nativas do Windows não funcionam, mas vários parsers multiplataforma funcionam: o parser no browser deste site (qualquer SO com um browser moderno), python-evtx, o crate Rust evtx e evtxecmd via .NET. Nenhum exige um host Windows."
---

Um ficheiro `.evtx` é o formato binário do log de eventos do Windows que a Microsoft lançou com o Vista em 2007 para substituir o antigo `.evt`. Cada evento que o sistema operativo, um driver, um serviço ou uma aplicação escreve para o log de eventos do Windows acaba num ficheiro `.evtx` em disco. São a espinha dorsal de toda a investigação Windows. Se faz DFIR em Windows, passará mais tempo dentro destes ficheiros do que em qualquer outra classe de artefactos.

## Resposta rápida

Os ficheiros `.evtx` são escritos pelo serviço EventLog do Windows em `C:\Windows\System32\winevt\Logs\`. Um ficheiro por **canal** (`Security.evtx`, `System.evtx`, `Application.evtx`, mais canais por aplicação). Internamente, cada ficheiro é um contentor binário em chunks de registos codificados em `BinXML`. Não é texto simples. Lêem-se com o Event Viewer, `wevtutil`, `Get-WinEvent` ou um parser de terceiros.

## Onde vivem os ficheiros .evtx

Localização padrão em todas as versões suportadas do Windows (Vista até Windows 11 e Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Cada ficheiro `.evtx` mapeia para um canal de eventos. Os predefinidos:

- `Security.evtx`. Logons, uso de privilégios, alterações de política de auditoria. Maior valor forense na maioria dos casos.
- `System.evtx`. Drivers, serviços, erros ao nível do kernel.
- `Application.evtx`. Erros de aplicação e eventos informativos.
- `Setup.evtx`. Registos de instalação.
- `ForwardedEvents.evtx`. Eventos recolhidos de outros hosts via Windows Event Forwarding (WEF).

Os canais por aplicação são guardados na mesma pasta com `%4` a substituir o separador de caminho:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Eventos de processo, rede e ficheiro do Sysmon (quando instalado).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Scriptblock e module logging do PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Criação e execução de tarefas agendadas.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo de vida das sessões RDP.

Os canais que rodam produzem ficheiros de arquivo com timestamp na mesma pasta (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). O ficheiro ativo é mantido aberto pelo serviço EventLog enquanto o Windows estiver em execução, o que é a razão pela qual existe [um post de recolha sobre como obter estes ficheiros de um host ativo](/pt/blog/collecting-evtx-from-live-system).

## O que está dentro de um ficheiro .evtx

O ficheiro é um contentor binário, não texto simples. Um cabeçalho de 4 KB (assinatura `ElfFile\0`) é seguido por uma sequência de **chunks** de 64 KB. Cada chunk tem o seu próprio cabeçalho (`ElfChnk`), uma tabela dos **templates** XML que nele aparecem e um fluxo de registos que referenciam esses templates por ID. Um parser reconstrói cada evento substituindo os valores ao nível do registo nos placeholders do template. É por isto que o `.evtx` é mais compacto em disco do que XML literal.

Uma vez descodificado, cada registo é um documento XML com duas metades:

- `<System>`. Nome do fornecedor, canal, Event ID, nível (1 Crítico a 5 Detalhado), nome do computador, contexto de segurança e timestamp UTC de escrita.
- `<EventData>`. Parâmetros específicos do fornecedor: a conta-alvo num logon, o caminho da imagem numa criação de processo, a chave de registo numa escrita auditada, e assim por diante.

O Event ID por si só raramente chega para triagem. O sinal forense vive em `<EventData>`. Para as mecânicas profundas do formato (chunks, BinXML, templates, recuperação de chunks "dirty") veja [a análise ao nível dos chunks](/pt/blog/evtx-file-format-chunks).

## .evtx vs .evt: porque o formato mudou

O formato `.evt` legado que o Windows usou até ao XP e Server 2003 tinha três limites duros que o novo formato foi desenhado para resolver:

- **Strings de tamanho fixo.** Os registos `.evt` transportavam referências a tabelas de mensagens em vez da mensagem completa. As junções em tempo de render quebravam quando os DLLs de origem estavam em falta ou tinham sido atualizados.
- **Sem consulta estruturada.** A filtragem exigia ler e analisar todos os registos linearmente.
- **Um canal por ficheiro.** Logs de aplicações personalizadas precisavam dos seus próprios formatos não padronizados.

O `.evtx` (Vista, 2007) introduziu registos BinXML, ficheiros por canal com aninhamento arbitrário, filtragem ao estilo XPath via `wevtutil qe` e `Get-WinEvent -FilterHashtable`, e um layout em chunks que sobrevive a escritas parciais. O compromisso foi uma quebra total de compatibilidade. `.evt` e `.evtx` não são intercambiáveis e a única ferramenta integrada que lê `.evt` num Windows moderno é o `wevtutil` com a flag legada (e apenas para exportar para `.evtx`).

## Como abrir um ficheiro .evtx

Cinco caminhos comuns, aproximadamente por ordem de fricção:

1. **No browser, sem instalação.** Larga o ficheiro no parser da página inicial deste site. Corre o crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilado para WebAssembly dentro de um Web Worker. Nada sai da sua máquina. Ideal para triagem ad-hoc quando não quer ligar uma VM forense.
2. **Event Viewer (`eventvwr.msc`).** GUI integrada do Windows. Ação / Abrir Log Guardado / selecionar o `.evtx`. Bom para navegar, fraco para filtrar em escala.
3. **`wevtutil` / `Get-WinEvent`.** Linha de comandos e PowerShell, ambos vêm com o Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` despeja todos os registos. `Get-WinEvent -Path` devolve objetos que podem ir para `Where-Object`.
4. **EvtxECmd.** O parser de Eric Zimmerman. Multiplataforma via .NET, rápido, produz CSV com uma linha por registo e `<EventData>` achatado.
5. **`python-evtx`.** Python puro, fácil de incluir em scripts. Mais lento do que o crate Rust, mas útil quando já tem uma cadeia de ferramentas Python.

Para um passo-a-passo completo de cada um com os comandos que iria mesmo correr, veja [Como abrir um ficheiro .evtx](/pt/blog/how-to-open-an-evtx-file).

## Quando se encontra `.evtx` no terreno

- **Resposta a incidentes.** Retirado de um host comprometido como parte da triagem. Os canais de interesse dependem da pista: `Security` para logons e abuso de privilégios, `Sysmon` para árvores de processos, `PowerShell` para conteúdo de scriptblock. Combine com [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com) e [prefetch](https://www.prefetchparser.com) para corroborar execução.
- **Auditorias de conformidade.** Os auditores pedem `Security.evtx` sobre uma janela definida para verificar logon e histórico de alterações de política.
- **Depuração de aplicações.** `Application.evtx` mais canais por fornecedor frequentemente contêm contexto de crash e erro que os logs da própria aplicação não têm.
- **Threat hunting.** Regras de cauda longa contra `.evtx` arquivados (ou um SIEM que reencaminha o canal ativo) apanham padrões de combustão lenta como RDP fora de horas ou drift de `LogonType` em contas de serviço.

O pivô mais útil é o Event ID. Para a lista curta que dá frutos num SOC real ([4624](/pt/blog/understanding-event-id-4624), [4625](/pt/blog/detecting-4625-brute-force), [1102](/pt/blog/event-id-1102-cleared-log), [4104](/pt/blog/powershell-4104-scriptblock), [7045](/pt/blog/service-creation-event-id-7045), [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create)) veja [a orientação inicial](/pt/blog/welcome).

## Leitura adicional

- [Documentação Microsoft: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Especificação do formato EVTX libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (parser Rust)](https://github.com/omerbenamram/evtx)
