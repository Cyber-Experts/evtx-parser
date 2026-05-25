---
title: "Como coletar logs .evtx de um sistema Windows ativo (4 métodos)"
description: "Quatro formas de extrair .evtx de um host Windows ativo — wevtutil, FTK Imager, KAPE, leitura NTFS bruta — com os trade-offs de cadeia de custódia de cada uma e os comandos que você de fato vai rodar."
date: "2026-05-17"
howto:
  name: "Como coletar logs .evtx de um sistema Windows ativo"
  steps:
    - name: "Exportar com wevtutil"
      text: "Execute wevtutil epl Security C:\\triage\\Security.evtx como administrador para selar uma cópia portátil do canal Security ativo sem tocar no arquivo em uso."
    - name: "Adquirir com FTK Imager"
      text: "Abra o FTK Imager, Add Evidence Item → Physical or Logical Drive, navegue até \\Windows\\System32\\winevt\\Logs\\, selecione os arquivos de canal (incluindo *.evtx arquivados) e Export Files. O FTK lê NTFS diretamente, contornando os locks de arquivo do serviço EventLog."
    - name: "Coleta em massa com KAPE"
      text: "Execute kape.exe --tsource C: --target EventLogs --tdest C:\\triage para puxar em uma só passada todos os .evtx sob winevt\\Logs\\ com metadados de cadeia de custódia. Combine com o módulo WindowsEventLogs para parsear já na coleta."
    - name: "Leitura NTFS bruta"
      text: "Quando houver suspeita de adulteração, use RawCopy ou tsk_recover para abrir o volume abaixo da camada do sistema de arquivos (\\\\.\\PhysicalDriveN ou \\\\.\\C:) e ler cada .evtx byte a byte a partir da MFT. O serviço EventLog não consegue bloquear esse caminho."
---

O primeiro problema difícil em uma investigação de event log não é o parsing, é *pegar os arquivos*. Em um host Windows em execução, o serviço EventLog mantém handles abertos para os [arquivos `.evtx`](/pt/blog/what-is-an-evtx-file) ativos em `C:\Windows\System32\winevt\Logs\`, o que significa que um `copy` ingênuo falha. Quatro abordagens cobrem praticamente todos os casos.

## Nativo: wevtutil / Get-WinEvent

O método mais simples exporta registros (não o arquivo) via a API documentada:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Isso produz um `.evtx` selado contendo todos os registros atualmente no log. Rápido, não exige ferramentas de terceiros e roda como administrador. A desvantagem: não captura os arquivos `.evtx` arquivados (rotacionados), apenas o ativo.

Equivalente em PowerShell:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` retorna registros parseados, não o arquivo. Útil para um CSV rápido de triagem, mas perde a fidelidade binária necessária para análise forense mais profunda — [recuperação em nível de chunk, inspeção de dirty chunks, carving](/pt/blog/evtx-file-format-chunks).

## FTK Imager

Para aquisição em nível de disco ou sistema de arquivos, o FTK Imager é o padrão. Adicione o drive ativo como evidência (Physical Drive ou Logical Drive), navegue até `\Windows\System32\winevt\Logs\`, clique com o botão direito nos arquivos de canal e Export Files. O FTK lê as estruturas NTFS subjacentes diretamente, contornando o lock do sistema de arquivos que o serviço EventLog mantém. Ele também exporta arquivos `*.evtx` arquivados (aqueles com timestamps no nome) que o `wevtutil` não toca.

O trade-off é que o FTK lê arquivos que podem estar em escrita — o `.evtx` resultante pode ter um chunk final dirty. A maioria dos parsers ([incluindo este](/pt/blog/how-to-open-an-evtx-file)) lida com isso de forma elegante, mas vale verificar.

## KAPE

Para resposta a incidente em escala, o Kroll Artifact Parser and Extractor (KAPE) automatiza a coleta de todo arquivo forensicamente relevante em uma única passagem:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

O target `EventLogs` extrai todo `.evtx` sob `winevt\Logs\` mais os arquivos de event tracing relacionados. Combine com o módulo `WindowsEventLogs` para também executar um parse imediato e produzir um CSV junto aos arquivos brutos. Recomendado para qualquer engajamento de IR que toque mais de um host.

## Leitura NTFS bruta

Para máxima fidelidade — útil quando você suspeita que as APIs do sistema de arquivos ativo estão sendo interceptadas ou quer aquisição bit a bit — leia o volume abaixo da camada do sistema de arquivos. Ferramentas como [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) ou o `RawCopy.exe` de Eric Zimmerman abrem o volume via `\\.\PhysicalDriveN` ou `\\.\C:`, percorrem a MFT e emitem o conteúdo do arquivo byte a byte. O serviço EventLog não consegue bloquear isso porque a leitura contorna inteiramente a camada do sistema de arquivos.

## Quando usar qual

- **Triagem rápida em um host, você tem admin**: `wevtutil`.
- **Aquisição forense completa, você já tem uma imagem de disco**: FTK Imager ou `tsk_recover` contra a imagem.
- **Engajamento de IR, múltiplos hosts**: KAPE.
- **Suspeita de rootkit ou tampering ativo**: NTFS bruto via RawCopy ou TSK no volume ativo, com o host isolado da rede.

Qualquer que seja sua escolha, documente. A cadeia de proveniência importa em relatórios de incidente — um CSV parseado não diz nada sobre se veio de um host ativo com o serviço EventLog rodando ou de uma imagem selada.
