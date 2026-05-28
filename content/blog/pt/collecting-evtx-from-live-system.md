---
title: "Como recolher logs .evtx de um sistema Windows ativo (4 métodos)"
description: "Quatro formas de extrair .evtx de um host Windows ativo: wevtutil, FTK Imager, KAPE, NTFS em bruto. Com os compromissos de cadeia de custódia de cada um e os comandos que vai mesmo executar."
date: "2026-05-17"
howto:
  name: "Como recolher logs .evtx de um sistema Windows ativo"
  steps:
    - name: "Exportar com wevtutil"
      text: "Executar wevtutil epl Security C:\\triage\\Security.evtx como administrador para selar uma cópia portátil do canal Security ativo sem tocar no ficheiro ao vivo."
    - name: "Adquirir com FTK Imager"
      text: "Abrir o FTK Imager, Add Evidence Item, navegar para \\Windows\\System32\\winevt\\Logs\\, selecionar os ficheiros de canal (incluindo *.evtx arquivados) e Export Files. O FTK lê NTFS diretamente, contornando os locks do serviço EventLog."
    - name: "Recolha em massa com KAPE"
      text: "Executar kape.exe --tsource C: --target EventLogs --tdest C:\\triage para extrair todos os .evtx sob winevt\\Logs\\ numa só passagem, com metadados de cadeia de custódia. Combine com o módulo WindowsEventLogs para fazer parsing no momento da recolha."
    - name: "Leitura NTFS em bruto"
      text: "Quando se suspeita de adulteração, use RawCopy ou tsk_recover para abrir o volume abaixo da camada do filesystem (\\\\.\\PhysicalDriveN ou \\\\.\\C:) e ler cada .evtx byte a byte a partir do MFT. O serviço EventLog não consegue bloquear este caminho."
---

O primeiro problema sério num trabalho com logs de eventos não é o parsing. É tirar os ficheiros do host sem o serviço EventLog a dar-lhe na mão. Num Windows em execução, o serviço mantém handles abertos para os [ficheiros `.evtx`](/pt/blog/what-is-an-evtx-file) ativos em `C:\Windows\System32\winevt\Logs\`, por isso um `copy` ingénuo devolve erros de sharing violation. Quatro métodos cobrem quase todos os casos com que me cruzei.

## wevtutil e Get-WinEvent: integrados, mais rápidos

O caminho mais barato usa a API documentada pela Microsoft:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Isto produz um `.evtx` selado contendo cada registo atualmente no canal. Sem ferramentas de terceiros, precisa de shell de administrador. O senão que vale dizer alto: `epl` só captura o log ativo. Os ficheiros `Archive-Security-*.evtx` rotacionados no mesmo diretório ficam para trás. Se a rotação aconteceu há pouco e os registos que quer estão num arquivo, este método não os apanha.

O PowerShell devolve registos já em parsed:

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

Isto dá-lhe um CSV, não um `.evtx`. Conveniente para triagem ad-hoc na máquina. Inútil para [recuperação ao nível dos chunks, inspeção de chunks "dirty" ou carving a partir de espaço não alocado](/pt/blog/evtx-file-format-chunks), porque deitou fora a fidelidade binária.

## FTK Imager: aquisição ao nível NTFS

Quando quer o ficheiro, não os registos, o FTK Imager é o cavalo de batalha. Adicione a drive ativa como evidência (Physical Drive ou Logical Drive), navegue para `\Windows\System32\winevt\Logs\`, clique com o botão direito nos ficheiros de canal e Export Files. O FTK lê as estruturas NTFS subjacentes diretamente, contornando o lock do sistema de ficheiros que o serviço EventLog mantém. Também captura os ficheiros `Archive-*.evtx` que `wevtutil epl` salta.

Compromisso: o FTK lê ficheiros que podem estar a meio de uma escrita. O chunk final no canal ativo pode estar dirty. A maioria dos parsers lida com isto graciosamente (incluindo o [parser no browser deste site](/pt/blog/how-to-open-an-evtx-file)), mas verifique na bancada antes de o escrever num relatório. As entradas correspondentes no [USN journal](https://www.usnparser.com) são uma corroboração útil quando se suspeita que o serviço EventLog fez algo fora do padrão durante a aquisição.

## KAPE: recolha em massa à velocidade do IR

Quando a missão envolve mais do que um host, o Kroll Artifact Parser and Extractor paga-se a si próprio numa hora.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

O target `EventLogs` apanha todos os `.evtx` sob `winevt\Logs\` mais os ficheiros ETW relacionados. Combine com o módulo `!EZParser` ou `WindowsEventLogs` e o KAPE também corre o EvtxECmd sobre a recolha à saída, dando-lhe CSVs já parsed lado a lado com a evidência em bruto. Já que está, os targets `RegistryHives` e `FileSystem` apanham os dados do [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com) e [prefetch](https://www.prefetchparser.com) que vai querer de qualquer maneira.

A saída do KAPE vem com metadados de copy log. Isso conta para a cadeia de custódia mais do que se reconhece.

## Leitura NTFS em bruto: quando suspeita de adulteração

Para máxima fidelidade, desça abaixo da camada do filesystem. O `tsk_recover` e `icat` do Sleuth Kit, ou o `RawCopy.exe` de Eric Zimmerman, abrem o volume via `\\.\PhysicalDriveN` ou `\\.\C:`, percorrem o MFT e emitem o conteúdo do ficheiro byte a byte. O serviço EventLog não consegue bloquear isto porque a leitura não passa pela API de ficheiros Win32.

Use isto quando há um rootkit no horizonte, quando tem razão para pensar que um filter driver de kernel está a intercetar as leituras de `\winevt\Logs\`, ou quando simplesmente não confia no SO em execução. Combine o resultado com um [RAM dump](https://www.ramparser.com) tirado no mesmo momento. O serviço de log de eventos faz cache em memória dos registos recentes, e um snapshot tirado minutos antes da adulteração contém por vezes registos que nunca chegaram a disco.

## Qual usar quando

- Um host, tem admin, tem uma hora: `wevtutil epl` para cada canal que importa, zip do diretório, feito.
- Imagem de disco já em mãos: FTK Imager ou `tsk_recover` contra a imagem. Mais rápido do que o host ativo, e não precisa de coordenar com o SOC.
- Vários hosts, missão de IR real: KAPE. Nada se aproxima no throughput.
- Suspeita de adulteração ao vivo ou rootkit: RawCopy ou TSK contra o volume, com a rede do host isolada.

Seja qual for o que escolher, documente. CSVs parsed nada dizem sobre proveniência. Uma linha nas notas do caso a dizer `KAPE 1.3.0.2 EventLogs target, hash file attached` é a diferença entre um anexo de prova e uma opinião.

## Leitura adicional

- [Documentação KAPE](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)
