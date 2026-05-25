---
title: "Lendo o formato binário do log de eventos do Windows"
description: "Uma introdução curta sobre como arquivos .evtx são organizados, o que cada evento contém e por que esse formato binário importa em forense."
date: "2026-05-16"
---

O log de eventos do Windows — `.evtx` — é o formato binário que a Microsoft introduziu no Windows Vista para substituir o antigo `.evt`. Ele é a espinha dorsal de quase toda resposta a incidentes em Windows: logons, inicializações de serviço, linhas de comando PowerShell, criações de processo do Sysmon e uma longa lista de canais específicos de provedores são serializados nele.

Novo em `.evtx`? Comece por [o que é um arquivo .evtx](/pt/blog/what-is-an-evtx-file) e [como abrir um](/pt/blog/how-to-open-an-evtx-file). O resto deste post é a orientação por canal e Event ID para analistas já familiarizados com o formato.

## Como um arquivo é organizado

Todo `.evtx` começa com um cabeçalho de 4 KB (assinatura `ElfFile\0`, checksum e contagem de chunks), seguido por uma sequência de blocos de 64 KB. Cada bloco tem seu próprio cabeçalho (`ElfChnk`), uma tabela de templates XML usados no bloco e um fluxo de registros binários que referenciam esses templates por ID. O parser reconstrói cada evento ligando os marcadores do template aos valores presentes no registro.

## Como é um registro

Decodificado, cada registro é um documento XML com duas partes principais:

- `<System>` — nome do provedor, canal, Event ID, nível (1 Crítico → 5 Detalhado), nome do computador, contexto de segurança e timestamp UTC de gravação.
- `<EventData>` — parâmetros específicos do provedor: conta alvo num logon, caminho da imagem numa criação de processo, etc.

O Event ID isolado raramente basta para triagem; o sinal forense vive no payload `<EventData>`.

## Como esta ferramenta lê

O parser é o crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx), compilado para WebAssembly e carregado num Web Worker. Ao soltar um arquivo, o worker o lê em memória, percorre cada bloco e reconstrói o XML de cada registro. Nada trafega pela rede — desligue o wifi para verificar.
