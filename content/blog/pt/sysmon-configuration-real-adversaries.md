---
title: "Configuração do Sysmon que apanha adversários reais"
description: "Uma visão opinativa do Sysmon: que IDs de evento realmente importam em IR, porque olafhartong/sysmon-modular é a baseline certa, e os erros de configuração que vos cegam para ataques reais."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

O Sysmon é a única coisa de maior alavancagem que se pode implementar num endpoint Windows. É grátis, é assinado pela Microsoft, e um Sysmon bem configurado transforma o Windows de uma caixa preta em algo que de facto se pode investigar. Um Sysmon mal configurado, por outro lado, é o mesmo custo de espaço em disco com a maior parte da visibilidade excluída por filtros demasiado agressivos. Entrei em mais ambientes com o segundo do que com o primeiro.

Esta é a postura de configuração que defendo em todos os trabalhos que tocam visibilidade de endpoint.

## Os EIDs que valem o espaço em disco

O Sysmon define 29 IDs de evento na versão 15. Não são todos necessários. Os que retribuem o armazenamento que custam, por ordem de retorno por byte:

- **EID 1 Process create**. O evento mais útil em DFIR. Processo pai, processo filho, command line, integrity level, utilizador, ambos os hashes de processo, e o process GUID. Se não registarem mais nada do Sysmon, registem isto.
- **EID 3 Network connection**. Todas as ligações TCP/UDP de saída com processo origem, IP destino, porta, e a imagem do processo. O evento de detecção de C2. O filtro é essencial aqui (uma instalação por defeito regista cada pedido do browser e a vossa retenção arde numa semana), mas o valor por evento é extremo. Apanhem saídas para destinos invulgares de processos invulgares (`rundll32.exe` para um IP residencial, `mshta.exe` para qualquer coisa).
- **EID 7 Image loaded**. Carregamentos de DLL e driver com o hash da imagem carregada e o estado de assinatura. É assim que se apanha DLL search-order hijacking, sideloading e drivers sem assinatura. Caro registar tudo; barato e alto rendimento registar módulos sem assinatura e módulos carregados de localizações não-standard.
- **EID 10 Process accessed**. Eventos de acesso a memória cross-process com o processo origem, processo alvo, máscara de acesso concedida, e o call trace. Este é o evento de credential dumping. O `mimikatz` abre `lsass.exe` com `PROCESS_VM_READ` (`0x10`) e `PROCESS_QUERY_INFORMATION` (`0x400`). Todos os dumpers modernos o fazem. A detecção escreve-se sozinha.
- **EID 11 File created**. Criações de novo ficheiro com o processo que escreve. Apanha actividade de dropper que não conseguiu executar, staging de ransomware, e a maioria das escritas de payload mediadas por LOLBin.

Estes cinco são a fundação. Se só tiverem esses, bem configurados, apanharam a maior parte do que chamariam uma intrusão real antes de se tornar uma.

O nível seguinte que vale a pena ligar:

- **EID 8 CreateRemoteThread**. Injecção de thread através de fronteiras de processo. O evento clássico de process injection.
- **EID 13 Registry value set**. Persistência via registo. Afinar para as chaves run, serviços, image file execution options, e os caminhos de COM hijack.
- **EID 17/18 Named pipe created/connected**. Beacons do Cobalt Strike e muitos frameworks de pós-exploração usam named pipes para SMB e comunicações entre processos. Os nomes dos pipes são frequentemente defaults que sobrevivem de trabalho para trabalho.
- **EID 22 DNS query**. DNS de saída com o processo requisitante. Apanha C2 baseado em DNS (DGA, DNS tunnel) quando o EID 3 falhou a ligação porque nunca abriu um socket TCP/UDP.
- **EID 25 Process tampering**. Eventos de manipulação de imagem (process hollowing, doppelganging). Sysmon 13+.

EID 12 (registry key/value create), 14 (registry key/value renamed), 15 (file stream created com FileCreateStreamHash) e 23 (file delete com archive) são úteis em investigações específicas mas produzem demasiado volume para registar em todo o lado por defeito. Liguem-nos para um host que estejam a observar de perto ou para caminhos específicos.

EID 2 (process changed file creation time) é um evento anti-timestomp de nicho. Vale a pena em file servers. Opcional noutro lado.

EID 4, 5, 6 (eventos de estado do Sysmon) são operacionais, não de detecção. Registem-nos para poderem saber quando o Sysmon foi adulterado.

## Porque `olafhartong/sysmon-modular` é o ponto de partida certo

Há meia dúzia de configs Sysmon públicos de qualidade variável. Os dois mais citados são o `sysmon-config` do SwiftOnSecurity e o `sysmon-modular` do Olaf Hartong. Ambos são bons. O `sysmon-modular` é aquele para o qual empurro pela sua estrutura.

O layout modular divide os filtros por EID e por técnica em ficheiros XML individuais que são concatenados na implementação. Os benefícios que isto vos dá:

- **Diffabilidade**. Mudanças ao filtro de uma única técnica aparecem como um diff de ficheiro único em git. Comparem com um XML monolítico de 4000 linhas onde uma pequena mudança desaparece no ruído.
- **Overlays por ambiente**. Vocês commitam a árvore upstream e fazem layer com as vossas exclusões específicas do ambiente por cima nos vossos próprios ficheiros. Quando o upstream actualiza um filtro, fazem `git merge` e os vossos overlays sobrevivem.
- **Autoria orientada por cobertura**. Os filtros estão organizados por técnica MITRE ATT&CK. Conseguem ver de relance que técnicas têm cobertura e quais não têm. A análise de lacunas é a árvore de ficheiros.
- **Manutenção activa**. O Hartong actualiza o repositório contra novas técnicas e novas versões do Sysmon. A config SwiftOnSecurity tem longas fases de estagnação entre actualizações.

Comecem do `sysmon-modular`. Commitam na vossa árvore de gestão de config. Fazem layer com as vossas exclusões. Não escrevam o vosso próprio do zero; vão falhar coisas.

## Os erros de configuração que vos cegam

Os padrões que vejo em trabalhos reais que custam mais visibilidade:

**Excluir demasiado agressivamente no EID 1**. O instinto é excluir cada processo legítimo tagarela para manter o volume gerível. O erro é excluir por caminho ou imagem do pai sem pensar no que um atacante pode fazer spawn a partir desse pai. Se excluírem cada filho de `services.exe`, excluíram o lugar exacto onde correm os binários de serviço instalados pelo PsExec. Excluam por `User` (contas de sistema a correr binários conhecidos como bons), por `IntegrityLevel`, e por correspondência precisa de `CommandLine`, não só pelo pai.

**Excluir EID 3 por nome de imagem**. "Excluir todas as ligações de rede do `chrome.exe`" é a regra má canónica. A primeira coisa que um atacante faz quando precisa de evadir o logging do EID 3 é fazer hijack de um processo de browser. Excluam por gama de IP destino (RFC1918 para RFC1918, a vossa própria infra), por porta (o conjunto de portas IPC que validaram), ou por tuplo processo+destino. Nunca só por imagem.

**Não registar EID 7 de todo**. O logging de Image load é o EID mais pesado do Sysmon por volume. A tentação de o desactivar é forte. O custo de o desactivar é que o DLL sideloading, a técnica mais comum nas intrusões modernas, fica invisível para vós. O caminho do meio: filtrar `Image load` para módulos sem assinatura, módulos carregados de `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%`, e `%PROGRAMDATA%`, e módulos com nomes que correspondem a listas conhecidas de abuso. Isto reduz o volume numa ordem de magnitude e mantém o sinal.

**Falhar EID 11 por completo em caminhos escrevíveis pelo utilizador**. EID 11 registado para `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%`, e `%PUBLIC%` apanha quase todos os droppers. Algumas configs excluem estes por causa do volume. O volume é o ponto: é onde acontecem as escritas que importam.

**Não incluir o algoritmo de hash que querem**. O elemento `<HashAlgorithms>` controla que hashes o Sysmon calcula. O default é só SHA1. `IMPHASH` é o import-hash, muito usado em rastreamento de malware; `SHA256` é o que a maioria das plataformas de threat intel usa como chave. Definam `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` para os eventos se alinharem com o que os vossos dados de intel usam.

**Não registar command lines no pai**. O Sysmon EID 1 regista tanto `CommandLine` (filho) como `ParentCommandLine` (pai). Algumas configs desactivam `ParentCommandLine`. Isto mata o pivô mais útil na investigação de árvore de processos; sem isso têm um nome de imagem do pai mas nenhuma ideia de que argumentos iniciaram esse pai.

**Não activar EID 22 (DNS) de todo**. O logging de DNS é recente (Sysmon 10+) e muitas configs são anteriores. Liguem-no. Filtrem hosts tagarelas (`*.windowsupdate.com`, o vosso AD interno), registem tudo o resto.

## A troca de espaço em disco

Um Sysmon bem configurado numa workstation típica produz 100-500 MB de EVTX por dia. Num servidor ocupado, 1-5 GB. O tamanho de canal por defeito é 64 MB, o que significa que o ficheiro `Microsoft-Windows-Sysmon%4Operational.evtx` roda em horas e a vossa retenção utilizável é curta.

A correcção é em duas etapas. Primeiro, aumentem o tamanho do canal. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` define-o para 4 GB, o que vos dá dias a semanas na maioria dos hosts. Segundo, encaminhem para um collector central com retenção mais longa. O WEC funciona; agentes SIEM funcionam; o repositório [Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) tem o XML para a subscrição de canal.

A retenção centralizada importa mais que a retenção local porque o ficheiro local é o que o atacante pode limpar. Uma cópia encaminhada num collector que eles não podem alcançar é o registo durável. Configurem ambos.

## Como é um bom Sysmon numa investigação

Um host com `sysmon-modular` implementado, todos os cinco EIDs core a registar, EID 7 filtrado para módulos interessantes, e encaminhamento para um collector, dá-vos:

- Uma árvore de processos para cada execução no host, com command lines, hashes, e o contexto de utilizador.
- Cada ligação de rede de saída com o processo originador.
- Cada carregamento de DLL de um directório escrevível pelo utilizador.
- Cada acesso a memória contra `lsass.exe`.
- Cada criação de ficheiro em `%TEMP%` e `%APPDATA%`.
- Cada query DNS com o processo requisitante.

A história da intrusão lê-se sozinha desta data. Não precisam de adivinhar. Não precisam de fazer carving. Lêem-na, de cima a baixo, e as lacunas na história são as perguntas a perseguir. Cruzem com [AmCache](https://www.amcacheparser.com) e [Prefetch](https://www.prefetchparser.com) para evidência de execução binária, o [registo](https://www.registryparser.com) para persistência, e o [USN journal](https://www.usnparser.com) para as mutações de sistema de ficheiros que o EID 11 do Sysmon pode ter falhado se o seu filtro estivesse desligado. O parser neste site lê canais Sysmon com a mesma fidelidade que Security.evtx.

Sem Sysmon, têm `Security.evtx` e uma wishlist.

## Leitura adicional

- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) do Olaf Hartong. O repositório. Leiam o README, depois leiam três ou quatro dos ficheiros XML específicos de técnica para apanhar o feel do estilo de filtro.
- [Documentação do Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) da Microsoft. A referência oficial; magra mas precisa.
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) de Roberto Rodriguez. Caçadas orientadas a Sysmon com as queries escritas.
- O [sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide) da TrustedSec. O doc de referência para a semântica de filtros.
