---
title: "Carving de registos EVTX apagados e recuperação de logs rotacionados"
description: "Carving por assinatura de registos EVTX em espaço não alocado, pagefile e memória, e as ferramentas que lidam graciosamente com chunks malformados quando o log ativo já não tem o que precisa."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

O log de Security de um controlador de domínio movimentado roda em horas, não em dias. O tamanho de canal predefinido é 20 MB, o que dá uns milhares de registos num host ruidoso. Quando faz a imagem do disco em resposta a um incidente que começou há três semanas, os eventos que realmente queria já saíram do ficheiro ativo e estão em espaço não alocado, no pagefile e possivelmente em hibernação. Recuperá-los por carving é parte rotineira de qualquer investigação assente em EVTX, e a maioria dos defensores salta-o porque trata o ficheiro ativo como fonte da verdade.

Não é. O ficheiro ativo são os últimos 20 MB. O disco tem o resto.

## A assinatura: `2a 2a 00 00`

Todo o registo EVTX começa com a sequência mágica de quatro bytes `2a 2a 00 00`. Isto é `**` seguido de dois bytes nulos. A assinatura é distintiva o suficiente para que varrer uma imagem de disco em bruto com `bulk_extractor`, `scalpel` ou até um grep de quatro bytes devolva um conjunto útil de candidatos. A densidade da assinatura num volume Windows é baixa; a maioria dos hits são registos reais.

A estrutura que se segue à magic está bem definida o suficiente para validar candidatos de forma barata:

- Bytes 4-7: `Size` (uint32). Deve ser plausível (mínimo 32 bytes, tipicamente abaixo de 4 KB).
- Bytes 8-15: `EventRecordIdentifier` (uint64). Deve ser um RecordID razoável para a janela temporal.
- Bytes 16-23: `WriteTime` como FILETIME. Deve cair entre o Vista (a primeira versão com EVTX) e hoje.
- Bytes `Size-4` a `Size`: o mesmo valor `Size`, repetido como marcador final.

Um candidato em que o `Size` da cabeça coincide com o da cauda, o FILETIME se descodifica para uma data plausível e o RecordID está dentro do intervalo, é com altíssima probabilidade um registo real. Os falsos positivos caem praticamente a zero com estas quatro verificações.

O desafio é o que fazer com os bytes entre a cabeça e a cauda.

## O problema do chunk

Os registos EVTX referenciam templates e strings armazenados uma única vez por chunk. Um registo recuperado isoladamente tem arrays de substituição sem template ao qual aplicar. Pode ler os valores tipados do array de substituição diretamente, o que basta para recuperar dados ao nível dos campos ("utilizador X fez logon no instante T a partir do IP Y"), mas o XML renderizado que um parser em produção daria não é reconstruível sem o chunk.

Esta é a diferença entre dois resultados de carving:

- **Carving só de registos**: recupera RecordID, timestamp, EventID e os valores de substituição. Pode construir uma vista campo a campo do evento, mas não o XML legível por humanos.
- **Carving de chunks**: encontra um chunk (magic `ElfChnk\0`, alinhado a 64 KB) e recupera a sua tabela de templates junto com os registos. Agora tem tudo.

`ElfChnk\0` também é carvable por assinatura. O alinhamento de 64 KB ajuda porque os chunks ficam em fronteiras de setor no disco; uma varredura de assinatura alinhada a offset é rápida. A maioria das ferramentas de carving suporta ambos os modos e deve correr os dois. Os chunks dão-lhe eventos legíveis; os registos órfãos preenchem o resto quando nenhum chunk envolvente sobreviveu.

## Onde vivem os bytes

Os sítios que vale a pena varrer, por ordem de rendimento:

- **Clusters não alocados no volume que aloja `%SystemRoot%\System32\winevt\Logs\`**. Quando um ficheiro EVTX roda ou é limpo, o conteúdo antigo fica não alocado. O NTFS não zera clusters não alocados, por isso os bytes são recuperáveis até serem reutilizados. Num servidor com pouca rotatividade de escrita, podem ser semanas.
- **Espaço slack no ficheiro EVTX ativo**. Os ficheiros EVTX são escritos em chunks de 64 KB. O último chunk fica frequentemente preenchido só parcialmente, com a slack a conter a geração anterior de dados escritos nesses bytes antes do chunk atual ter sido reduzido. Vale uma varredura.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. O serviço de log de eventos faz cache em memória dos registos e templates recentes. As páginas que suportam essas estruturas são paginadas sob pressão de memória. O pagefile é uma mina de ouro para registos que nunca foram escritos para disco porque o host crashou ou foi morto antes que chegassem lá.
- **`hiberfil.sys`**. Snapshot comprimido da memória física no momento da hibernação. Descomprima com `Volatility 3` ou Hibr2Bin e procure as assinaturas de registo na memória bruta resultante.
- **[RAM dump](https://www.ramparser.com)** capturado durante resposta ao vivo. O working set do serviço de log de eventos vai conter registos recentes e os templates necessários para os renderizar.
- **Shadow copies (VSS)**. Snapshots antigos do volume contêm versões antigas dos ficheiros EVTX ativos. `vshadow` ou `vssadmin list shadows` seguidos de `mklink /d` para montar a shadow dão-lhe uma cópia de geração anterior do ficheiro, com os registos que estavam ativos no momento da shadow.

VSS é a fonte de maior alavancagem em hosts que o têm ativado e que não foram adulterados na camada VSS. Um servidor Windows moderno tem tipicamente 7-30 dias de shadow copies. Se o incidente foi há três semanas, a shadow do momento do incidente pode ter o log ativo tal como existia então, sem adulteração.

## Ferramentas que lidam com input malformado

Um ficheiro EVTX limpo é raro em cenários de carving. Vai ter chunks parciais, registos sem cauda, templates a referenciar offsets fora do chunk e falhas de CRC por todo o lado. Os parsers que lidam com isto não são os mesmos que lidam com ficheiros limpos.

- **`EvtxECmd`** (Eric Zimmerman). O melhor da classe para trabalho de IR em campo. Passe `--inc` para incluir registos que falharam o parsing normal e ele emite o que conseguiu ler de registos parciais. A saída CSV é o que quer para trabalho de timeline.
- **`hayabusa`** (Yamato Security). Construído para hunting em grandes corpora EVTX, com regras estilo Sigma. Lida razoavelmente com chunks parciais e é rápido. O filtro `--exclude-status` permite reduzir o ruído de registos corrompidos.
- **`evtx_dump`** (crate Rust do Omer Ben-Amram). Robusto contra estruturas malformadas, saída JSONL. Bom para pipelines para `jq` ou um SIEM.
- **`evtxtools`** (Joachim Metz, parte do libevtx). A implementação canónica do formato. Mais lento que os outros, mas diz-lhe exatamente que campo falhou em que validação quando um registo é parcialmente recuperado, o que é o que se quer ao depurar saída de carving.
- **`bulk_extractor`** com o scanner EVTX. O próprio passo de carving. Produz registos candidatos com os seus offsets na imagem fonte para posterior validação.

Um pipeline prático:

1. `bulk_extractor -E evtx -o out/ image.dd` para carving de registos e chunks candidatos a partir da imagem do disco.
2. Reagrupar os chunks em ficheiros EVTX sintéticos concatenando os chunks carved com um cabeçalho de ficheiro forjado. Os exemplos do `libevtx` incluem um reagrupador de chunks compatível com `evtxexport`.
3. Correr `EvtxECmd` sobre o ficheiro reagrupado com `--inc` para despejar tudo o que for legível para CSV.
4. Cruzar os RecordIDs carved com os RecordIDs do ficheiro ativo para encontrar os registos que não estavam no log ativo.

A saída do passo 4 é o que o carving lhe dá: os eventos que o atacante ou o tempo removeram do ficheiro ativo.

## Quando o log ativo não mostra nada porque rolou

O caso comum para carving não é a limpeza anti-forense; é a rotação. Um incidente há 30 dias num host com um log de Security de 20 MB e 50 eventos por segundo já fez rolar o ficheiro inteiro dezenas de vezes. O log ativo mostra as últimas horas. Tudo o que está no meio está em não alocado.

O carving aqui é simples porque não houve adulteração. Varre o não alocado, encontra chunks, reagrupa. O rendimento depende de quanta rotatividade de escrita o volume teve desde a rotação. Um volume de servidor com ficheiros de sistema maioritariamente estáticos e o diretório EVTX como fonte dominante de escrita vai manter chunks antigos intactos por muito tempo. Um volume com escrita aplicacional pesada vai sobrescrever as regiões não alocadas mais depressa.

Um truque que ajuda: o diretório EVTX está em `%SystemRoot%\System32\winevt\Logs\`, que é um dos pontos mais frios do volume em termos de escritas concorrentes. Cluster runs que foram libertados quando o ficheiro EVTX rolou ficam frequentemente não alocados durante semanas. O mesmo não é verdade para volumes que alojam dados aplicacionais.

## O que fazer com o que recuperou

Os registos carved entram na mesma timeline dos registos ativos. O RecordID e o WriteTime sobrevivem ao carving e são as chaves de junção. Um `4624 Type 3` carved na altura do suposto acesso inicial é tão útil quanto um ativo, com a ressalva de que pode não conseguir renderizar o seu XML completo.

Cruzar com:

- As entradas da [Master File Table](https://www.mftparser.com) para `Security.evtx` para ver quando o ficheiro foi reescrito por limpeza ou rotação.
- O [USN journal](https://www.usnparser.com) para eventos `DATA_OVERWRITE` no ficheiro EVTX, que dá timestamps de alta resolução para cada rotação.
- [Prefetch](https://www.prefetchparser.com) para os binários que correram durante a lacuna, já que o `Prefetch` é independente de `Security.evtx` e sobrevive à limpeza do log.
- [AmCache](https://www.amcacheparser.com) e [Shimcache](https://www.shimcacheparser.com) para evidência de primeira execução.
- As hives do [registry](https://www.registryparser.com) em shadow copies para o estado no momento do incidente.

Um registo carved que alinha com uma entrada de Prefetch e um timestamp MFT num binário suspeito é uma descoberta. Um registo carved isolado é uma pista que vale a pena seguir.

## Leitura adicional

- O trabalho original de carving de Andreas Schuster no [paper DFRWS 2007](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). As heurísticas de carving em qualquer ferramenta moderna remontam aqui.
- A documentação do [EvtxECmd](https://github.com/EricZimmerman/evtx) de Eric Zimmerman e a flag `--inc` para tratamento de registos parciais.
- O [hayabusa](https://github.com/Yamato-Security/hayabusa) da Yamato Security e o seu corpus de amostras agrupado, útil para testar pipelines de carving.
- O [bulk_extractor](https://github.com/simsong/bulk_extractor) de Simson Garfinkel e o seu módulo de scanner EVTX.
