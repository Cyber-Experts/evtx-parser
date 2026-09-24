---
title: "Descrição do Event ID não encontrada: como resolver"
description: "Por que o Visualizador de Eventos não encontra a descrição de um Event ID, o que significam códigos como %%1833 e como ler o evento mesmo assim, offline."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "O que significa «The description for Event ID X from source Y cannot be found»?"
    answer: "O registro em si está íntegro. Um registro .evtx armazena apenas o Event ID, o nome do provider e as strings de inserção (EventData / UserData). A frase que você normalmente lê no Visualizador de Eventos é um modelo guardado na DLL de mensagens do provider, na máquina que exibe o log. Se esse provider não estiver registrado na sua máquina, o Visualizador não consegue montar a frase e mostra este erro seguido das strings de inserção brutas."
  - question: "Os dados do evento foram perdidos ou corrompidos?"
    answer: "Não. Todos os campos continuam no registro. Abra a aba Detalhes (Modo de Exibição XML) do Visualizador de Eventos, ou leia os campos de EventData com Get-WinEvent, wevtutil ou um parser. Só falta o texto legível que os envolve."
  - question: "O que significa %%1833 em um evento?"
    answer: "%%1833 é uma referência a uma mensagem de parâmetro resolvida a partir de msobjs.dll, o arquivo de mensagens de parâmetro do provider de auditoria de segurança. %%1833 significa Impersonation (campo ImpersonationLevel do 4624). Outros comuns: %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 tipo de elevação do token 1/2/3."
  - question: "Como exportar um .evtx para que abra com as descrições em outro computador?"
    answer: "Na máquina de origem, no Visualizador de Eventos, use Salvar Todos os Eventos Como, escolha .evtx e selecione a opção de exibir informações para os idiomas desejados. O Visualizador grava uma pasta LocaleMetaData com arquivos .MTA ao lado do .evtx. Copie os dois juntos. wevtutil archive-log (wevtutil al) faz o mesmo pela linha de comando."
  - question: "Posso ler o evento sem instalar o provider?"
    answer: "Sim. Em DFIR você raramente precisa da mensagem renderizada: os campos de EventData contêm todos os valores que a mensagem mostraria. O parser no navegador do evtxparser.com também mostra uma descrição de uma linha para os eventos DFIR mais comuns e decodifica offline os códigos %%, os códigos NTSTATUS e os tipos de criptografia Kerberos, sem enviar o arquivo."
---

Você copia um `Security.evtx` de um host suspeito, abre na sua estação de análise e todo registro mostra:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

Em seguida vem um bloco de valores brutos: `%%2313`, `0xC000006A`, `0x17`. Nada está quebrado e nada foi perdido. É uma falha de *renderização*, não de dados. Este artigo explica onde o texto da descrição realmente vive, por que ele some, como corrigir quando você precisa dele e por que, na triagem, normalmente você não precisa. (Se você só quer os eventos legíveis agora: [o parser no navegador](/pt) renderiza descrições e decodifica esses códigos offline.)

## O que o erro realmente significa

Um registro `.evtx` não armazena a frase que você lê no Visualizador de Eventos. Ele armazena o bloco `<System>` (provider, Event ID, horário, computador) e as **strings de inserção** em `<EventData>` ou `<UserData>` ([o que há dentro de um registro](/pt/blog/what-is-an-evtx-file)). A frase («An account failed to log on. Subject: … Failure Reason: …» em um Windows em inglês) é um modelo com marcadores `%1`, `%2` guardado em um **recurso de tabela de mensagens** dentro de uma DLL ou EXE pertencente ao provider do evento.

Onde o Windows procura esse arquivo depende do tipo de provider:

- **Fontes de eventos clássicas (legacy)** são registradas em `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, com o caminho no valor `EventMessageFile` (e, opcionalmente, `ParameterMessageFile` e `CategoryMessageFile`).
- **Providers baseados em manifesto** (do Vista em diante, a família `Microsoft-Windows-*`) são registrados em `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. Os valores `MessageFileName`, `ResourceFileName` e `ParameterFileName` apontam para os binários que carregam o manifesto compilado (recurso `WEVT_TEMPLATE`) e a tabela de mensagens.

O ponto-chave: **o Visualizador de Eventos renderiza a mensagem na máquina onde você visualiza o log**, usando o registro e as DLLs dessa máquina. A máquina que gravou o evento não importa na hora da exibição. Se o provider não estiver registrado localmente, não há modelo, e você recebe o erro seguido das strings de inserção brutas.

## Causas comuns

- **O log veio de outro host.** O caso DFIR clássico. Um agente de terceiros, um EDR, uma instância de SQL Server ou uma aplicação de negócio do host de origem não têm provider na sua estação de análise. Abrir o arquivo no macOS, no Linux ou em uma VM limpa tem o mesmo efeito: nenhum provider do Windows.
- **O software foi desinstalado.** O desinstalador removeu a DLL, mas os eventos antigos ainda referenciam a fonte.
- **DLL ausente, corrompida ou movida.** O registro aponta para um caminho que não existe mais, ou `EventMessageFile` está gravado como `REG_SZ` em vez de `REG_EXPAND_SZ`, então `%SystemRoot%` nunca é expandido.
- **Incompatibilidade 32/64 bits.** Um instalador de 32 bits gravou sua DLL no que achava ser `System32` (na verdade `SysWOW64`, pelo redirecionamento do sistema de arquivos), enquanto a pilha do Event Log de 64 bits lê o caminho registrado como o `System32` real.
- **Idioma.** A tabela de mensagens do provider existe, mas não no idioma de exibição, ou você abriu uma exportação salva «com informações de exibição» para um idioma diferente do seu visualizador.

## Os códigos %%: mensagens de parâmetro

Mesmo quando a descrição principal é renderizada, alguns campos mostram `%%1833` ou `%%2313` em vez de palavras. São referências a **mensagens de parâmetro**: o valor é um ID em uma segunda tabela de mensagens, o `ParameterMessageFile` / `ParameterFileName` do provider. Para o provider de auditoria de segurança, esse arquivo é `msobjs.dll`. Offline, essas referências ficam sem resolução. As que vale a pena saber de cor (rótulos como aparecem em um Windows em inglês):

| Código | Significado | Onde aparece |
|--------|-------------|--------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Tipo 1, token completo (UAC desativado ou admin interno) | 4688 `TokenElevationType` |
| `%%1937` | Tipo 2, token elevado | 4688 `TokenElevationType` |
| `%%1938` | Tipo 3, token limitado | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (conta bloqueada) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (conta desabilitada) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

O trio `%%2080 %%2082 %%2084` é a assinatura normal de uma conta recém-criada em um [4720](/pt/blog/event-id-4720-account-created). Um `%%1937` em um [4688](/pt/blog/event-id-4688-process-creation) é um processo iniciado com token de administrador completo após um prompt do UAC.

Valores hexadecimais não são códigos `%%`. Os campos `Status` / `SubStatus` do [4625](/pt/blog/detecting-4625-brute-force) são códigos NTSTATUS: `0xC000006A` é senha errada para uma conta válida, `0xC0000064` um nome de usuário que não existe, `0xC0000234` uma conta bloqueada. `TicketEncryptionType` no [4769](/pt/blog/event-id-4769-kerberoasting) é um etype Kerberos: `0x17` é RC4-HMAC, `0x12` AES256. Ambos aparecem como hexadecimal bruto mesmo quando o provider está presente.

## Correção 1: exportar com informações de exibição

Se você ainda tem acesso ao host de origem, exporte o log para que ele viaje com suas mensagens. No Visualizador de Eventos: clique com o botão direito no log, **Salvar Todos os Eventos Como…**, escolha `.evtx` e, na caixa de diálogo seguinte, selecione a exibição de informações para os idiomas desejados (**Display information for these languages** em um Windows em inglês). O Visualizador grava uma pasta `LocaleMetaData` ao lado do arquivo, com um `.MTA` por idioma. Mantenha a pasta ao lado do `.evtx` ao copiá-lo; o Visualizador da máquina de análise a utiliza.

Pela linha de comando:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) adiciona os metadados de idioma a um arquivo exportado. Para coleta em escala, veja [coletar EVTX de um sistema em execução](/pt/blog/collecting-evtx-from-live-system).

## Correção 2: instalar ou reparar o provider

Em uma máquina que você administra, quando os eventos do seu próprio software não são renderizados:

- Reinstale ou repare a aplicação dona da fonte.
- Verifique `EventMessageFile` em `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`: o caminho precisa existir, e o tipo do valor deve ser `REG_EXPAND_SZ` se contiver `%SystemRoot%`.
- Para providers com manifesto, confira `Get-WinEvent -ListProvider <Name>`; se falhar ou não listar mensagens, o registro do manifesto está quebrado (`wevtutil im <manifest>.man` registra de novo, com os binários no lugar).

## Correção 3: renderizar no host de origem

`Get-WinEvent` só preenche a propriedade `Message` quando o provider está presente localmente. No host de origem (ou em uma máquina com o mesmo software instalado), isto funciona:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Na sua estação, o mesmo comando retorna um `Message` vazio, mas `.Properties` e `.ToXml()` continuam expondo todos os valores. Mais receitas de filtragem em [consultar EVTX com Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent) (em inglês).

## Correção 4: normalmente você não precisa da mensagem

Em DFIR, a frase renderizada é uma conveniência. Todo valor que ela mostraria está em `<EventData>`: `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. A aba **Detalhes** (Modo de Exibição XML) do Visualizador os mostra mesmo quando a aba Geral exibe o erro. Quem analisa em escala lê os campos diretamente de qualquer forma, e é assim que você deve abordar o [4624](/pt/blog/understanding-event-id-4624) e o resto da [família de eventos de logon](/en/blog/windows-logon-events-explained): os nomes de campo são estáveis entre versões e idiomas do Windows; o texto renderizado não.

## Ler eventos offline no navegador

O [parser EVTX](/pt) agora mostra uma descrição legível de uma linha para cerca de 60 eventos DFIR comuns: logons e falhas 4625, alterações de contas e grupos, Kerberos 4768/4769/4771, NTLM 4776, serviços 7045/4697, tarefas agendadas, Sysmon, PowerShell 4104 e RDP. Ele também decodifica em linha os códigos `%%`, os códigos NTSTATUS (`0xC000006A` senha errada, `0xC0000064` usuário desconhecido) e os tipos de criptografia de tickets Kerberos (`0x17` RC4). Não precisa de DLLs de provider nem de Windows; o arquivo é analisado no seu navegador e nunca é enviado. Para outras formas de abrir o arquivo, veja [como abrir um arquivo EVTX](/pt/blog/how-to-open-an-evtx-file).

## Checklist

- O erro significa que **a máquina que exibe** não tem o provider, não que o registro esteja danificado.
- Leia `<EventData>` na aba Detalhes, via `.Properties` do `Get-WinEvent` ou com um parser.
- Decodifique as referências `%%` com a tabela acima; decodifique `Status` / `SubStatus` como NTSTATUS.
- Precisa do texto renderizado para um relatório? Reexporte no host de origem com informações de exibição (`LocaleMetaData`) ou `wevtutil al`.
- Para o seu próprio software, corrija `EventMessageFile` ou registre o manifesto novamente.
