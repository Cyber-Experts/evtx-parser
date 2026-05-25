---
title: "O que é um arquivo .evtx? O formato Windows Event Log explicado"
description: "Um arquivo .evtx é um Windows Event Log binário. Onde ficam, o que tem dentro, em que diferem dos .evt e como abri-los — sem instalar nada."
date: "2026-05-24"
faq:
  - question: "O que é um arquivo .evtx?"
    answer: "Um arquivo .evtx é o formato binário do Windows Event Log introduzido com o Windows Vista. Ele armazena eventos de sistema, segurança e aplicações gravados pelo serviço EventLog. Cada máquina Windows tem dezenas de arquivos .evtx em C:\\Windows\\System32\\winevt\\Logs\\, um por canal."
  - question: "Onde os arquivos .evtx ficam armazenados no Windows?"
    answer: "O local padrão é C:\\Windows\\System32\\winevt\\Logs\\. Os três arquivos de maior tráfego são Security.evtx, System.evtx e Application.evtx. Canais por aplicação ficam na mesma pasta com nomes como Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Qual a diferença entre .evtx e .evt?"
    answer: ".evt é o formato binário legado que o Windows usou até o XP e o Server 2003. O .evtx o substituiu no Windows Vista (2007) com um layout baseado em chunks e em BinXML que suporta metadados de evento mais ricos, logs maiores e consultas estruturadas via wevtutil e Get-WinEvent. Os dois formatos não são intercambiáveis."
  - question: "Como abrir um arquivo .evtx?"
    answer: "Ferramentas nativas do Windows: Event Viewer (eventvwr.msc), wevtutil pela linha de comando ou Get-WinEvent pelo PowerShell. Multiplataforma: abra no parser via navegador deste site (sem instalação, sem upload) ou use o evtxecmd pela linha de comando. Veja nosso post sobre como abrir um arquivo .evtx para todas as opções."
  - question: "Posso abrir um arquivo .evtx no macOS ou Linux?"
    answer: "Sim. As ferramentas nativas do Windows não funcionam, mas vários parsers multiplataforma funcionam: o parser via navegador deste site (qualquer sistema operacional com um navegador moderno), python-evtx, a crate Rust evtx e o evtxecmd via mono. Nenhum deles exige um host Windows."
---

Um arquivo `.evtx` é o formato binário do Windows Event Log que a Microsoft lançou com o Windows Vista em 2007 para substituir o antigo formato `.evt`. Cada evento que o sistema operacional, um driver, um serviço ou uma aplicação grava no Windows Event Log vai parar em um arquivo `.evtx` em disco. Eles são a espinha dorsal de toda investigação em Windows.

## Resposta rápida

Os arquivos `.evtx` são gravados pelo serviço Windows EventLog em `C:\Windows\System32\winevt\Logs\`. Há um arquivo por **canal** (`Security.evtx`, `System.evtx`, `Application.evtx`, além de canais por aplicação). Internamente, cada arquivo é um contêiner binário em chunks com registros codificados em `BinXML` — não é texto puro. Você os lê com Event Viewer, `wevtutil`, `Get-WinEvent` ou um parser de terceiros.

## Onde os arquivos .evtx ficam

O local padrão em todas as versões do Windows suportadas (do Vista ao Windows 11 / Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Cada arquivo `.evtx` corresponde a um canal de eventos. Os padrões que você sempre encontra:

- `Security.evtx` — logons, uso de privilégios, mudanças de política de auditoria. O de maior valor forense na maioria dos casos.
- `System.evtx` — drivers, serviços, erros em nível de kernel.
- `Application.evtx` — erros e eventos informativos de aplicações.
- `Setup.evtx` — registros de instalação.
- `ForwardedEvents.evtx` — eventos coletados de outros hosts via Windows Event Forwarding (WEF).

Canais por aplicação ficam na mesma pasta, com `%4` representando o separador de caminho:

- `Microsoft-Windows-Sysmon%4Operational.evtx` — eventos de processo, rede e arquivo do Sysmon (quando instalado).
- `Microsoft-Windows-PowerShell%4Operational.evtx` — logging de scriptblock e módulos do PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — criação e execução de tarefas agendadas.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` — ciclo de vida de sessão RDP.

Canais que sofrem rotação produzem arquivos de arquivo morto com timestamp na mesma pasta (`Security.evtx`, `Archive-Security-2026-05-23-…evtx`). O arquivo ativo fica aberto pelo serviço EventLog enquanto o Windows está em execução.

## O que há dentro de um arquivo .evtx

O arquivo é um contêiner binário, não texto puro. Um cabeçalho de 4 KB (magic `ElfFile\0`) é seguido por uma sequência de **chunks** de 64 KB. Cada chunk tem seu próprio cabeçalho (`ElfChnk`), uma tabela dos **templates** XML que aparecem dentro dele e um fluxo de registros que referenciam esses templates por ID. Um parser reconstrói cada evento substituindo valores do registro nos placeholders do template — é isso que torna o `.evtx` mais compacto em disco do que XML literal.

Uma vez decodificado, cada registro é um documento XML com duas metades:

- `<System>` — nome do provider, canal, Event ID, nível (1 Critical → 5 Verbose), nome do computador, contexto de segurança e timestamp de gravação em UTC.
- `<EventData>` — parâmetros específicos do provider: a conta de destino em um logon, o caminho da imagem em um process create, a chave de registro em uma escrita auditada e assim por diante.

O Event ID sozinho raramente é suficiente para triagem. O sinal forense vive em `<EventData>`. Para a mecânica profunda do formato — chunks, BinXML, templates, recuperação de chunks sujos — veja [Por dentro do formato de arquivo EVTX](/pt/blog/evtx-file-format-chunks).

## .evtx vs .evt: por que o formato mudou

O formato legado `.evt` que o Windows usou até o XP e o Server 2003 tinha três limites duros que o novo formato foi desenhado para resolver:

- **Strings de tamanho fixo.** Os registros `.evt` carregavam referências a uma message-table em vez da mensagem completa; os joins em tempo de render quebravam quando as DLLs de origem estavam ausentes ou tinham sido atualizadas.
- **Sem consulta estruturada.** Filtrar exigia ler e fazer parse de cada registro linearmente.
- **Um único canal por arquivo.** Logs personalizados de aplicação precisavam de seus próprios formatos não padronizados.

O `.evtx` (Vista, 2007) introduziu registros BinXML, arquivos por canal com aninhamento arbitrário, filtragem em estilo XPath via `wevtutil qe` e `Get-WinEvent -FilterHashtable`, e um layout em chunks que sobrevive a gravações parciais. O custo foi uma quebra total de compatibilidade — `.evt` e `.evtx` não são intercambiáveis, e a única ferramenta nativa que lê `.evt` em um Windows moderno é o `wevtutil` com a flag legada (e apenas para exportar para `.evtx`).

## Como abrir um arquivo .evtx

Cinco caminhos comuns, em ordem aproximada de fricção:

1. **No seu navegador, sem instalação** — solte o arquivo no parser na página inicial deste site. Ele roda a crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilada para WebAssembly dentro de um Web Worker. Nada sai da sua máquina. Bom para triagem ad-hoc quando você não quer subir uma VM forense.
2. **Event Viewer (`eventvwr.msc`)** — a GUI nativa do Windows. Abra o Event Viewer → Action → Open Saved Log… → selecione o `.evtx`. Bom para navegar, fraco para filtrar em escala.
3. **`wevtutil` / `Get-WinEvent`** — linha de comando e PowerShell, ambos acompanham o Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` despeja todos os registros; `Get-WinEvent -Path` retorna objetos que você pode encadear no `Where-Object`.
4. **EvtxECmd** — o parser do Eric Zimmerman. Multiplataforma via .NET, rápido, produz CSV com uma linha por registro e o `<EventData>` completo achatado.
5. **`python-evtx`** — Python puro, fácil de scriptar. Mais lento que a crate Rust mas útil quando você já tem uma stack de tooling em Python.

Para um passo a passo completo de cada método com os comandos que você realmente executaria, veja [Como abrir um arquivo .evtx](/pt/blog/how-to-open-an-evtx-file).

## Quando você encontra .evtx no mundo real

- **Resposta a incidentes.** Extraído de um host comprometido como parte da triagem. Os canais de interesse dependem da pista — `Security` para logons e abuso de privilégio, `Sysmon` para árvores de processo, `PowerShell` para o conteúdo dos scriptblocks.
- **Auditorias de compliance.** Auditores pedem `Security.evtx` em uma janela definida para verificar o histórico de logons e de mudanças de política.
- **Debugging de aplicação.** O `Application.evtx` mais canais por fornecedor frequentemente trazem o contexto de crash e erro que os próprios logs da aplicação não trazem.
- **Threat hunting.** Regras de cauda longa contra `.evtx` arquivados (ou um SIEM encaminhando o canal ao vivo) capturam padrões de queima lenta como RDP fora do horário ou drift de `LogonType` de conta de serviço.

O pivô individual mais útil é o Event ID. Para a lista curta que se paga em um SOC real — [4624 logon bem-sucedido](/pt/blog/understanding-event-id-4624), [4625 logon falhado](/pt/blog/detecting-4625-brute-force), [1102 log apagado](/pt/blog/event-id-1102-cleared-log), [4104 scriptblock do PowerShell](/pt/blog/powershell-4104-scriptblock), [7045 serviço instalado](/pt/blog/service-creation-event-id-7045), [Sysmon 1 process create](/pt/blog/sysmon-event-id-1-process-create) — veja [a orientação inicial](/pt/blog/welcome).
