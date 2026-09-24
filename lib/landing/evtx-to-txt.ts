import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";

export const EVTX_TO_TXT: LocaleContent<LandingContent> = {
  en: {
    metaTitle: "EVTX to TXT — convert .evtx to readable text online",
    metaDescription:
      "Convert a Windows .evtx event log to a plain text file in your browser. Free EVTX to TXT converter — no upload, no install. One readable block per event, easy to grep or paste.",
    h1: "Convert EVTX to TXT (plain text)",
    intro:
      "An .evtx file is binary, so Notepad shows garbage. This converter turns it into a readable .txt file — one block per event with its time, Event ID, provider and every EventData field — right in your browser. Nothing is uploaded and nothing needs to be installed.",
    ctaLabel: "Open the EVTX to TXT converter",
    formatsHeading: "What the text file looks like",
    formats: [
      {
        name: "One block per event",
        body: "Each event starts with a header line — record number, timestamp, level and Event ID — followed by provider, channel and computer, then one indented line per EventData field. Events are separated by a blank line.",
        code: "Record #48213 | 2026-09-12T08:14:03.512Z | Information | Event ID 4624\nProvider: Microsoft-Windows-Security-Auditing\nChannel: Security\nComputer: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Made for grep and reports",
        body: "Plain text works with grep, findstr, diff and any editor, and pastes cleanly into a ticket or an incident report. Filter first so the file only contains the events that matter.",
      },
      {
        name: "Raw XML when you need it",
        body: "Tick “Raw XML column” before exporting and each block also includes the event's full <Event> XML.",
      },
    ],
    stepsHeading: "How to convert EVTX to TXT",
    steps: [
      {
        title: "Open the converter",
        body: "Open the EVTX parser homepage. Parsing runs in your browser tab through WebAssembly.",
      },
      {
        title: "Drop your .evtx file",
        body: "Drag one or more .evtx files onto the drop zone, or click to choose them.",
      },
      {
        title: "Filter, then Export TXT",
        body: "Use the filter bar, Event ID chips or timeline to keep only relevant events, then click Export TXT. The .txt file downloads locally.",
      },
    ],
    faqHeading: "EVTX to TXT FAQ",
    faq: [
      {
        q: "How do I convert EVTX to TXT with wevtutil?",
        a: "On Windows: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. The /lf:true switch tells wevtutil the argument is a log file rather than a live channel. It needs a Windows host with the matching provider manifests to render message text.",
      },
      {
        q: "Can Event Viewer export an EVTX file to text?",
        a: "Yes: open the saved log, choose Save All Events As… and pick Text (Tab delimited). You get summary columns plus the rendered message, without the individual EventData fields.",
      },
      {
        q: "Why can't I just open an EVTX file in Notepad?",
        a: "EVTX is a binary format: 64 KB chunks of BinXML records that reference shared templates. The text only exists after a parser rebuilds each record, which is what this converter does.",
      },
      {
        q: "Does the TXT export include the event message?",
        a: "It includes every structured field of the event. The friendly Message sentence Event Viewer shows is built from provider DLLs installed on Windows, so it is not stored in the .evtx and no offline parser can reproduce it exactly.",
      },
    ],
  },
  fr: {
    metaTitle: "EVTX en TXT — convertir un .evtx en texte lisible",
    metaDescription:
      "Convertissez un journal d'événements Windows .evtx en fichier texte dans votre navigateur. Convertisseur EVTX vers TXT gratuit — sans envoi, sans installation. Un bloc lisible par événement, facile à grep ou coller.",
    h1: "Convertir EVTX en TXT (texte brut)",
    intro:
      "Un fichier .evtx est binaire, donc le Bloc-notes n'affiche que du charabia. Ce convertisseur le transforme en fichier .txt lisible — un bloc par événement avec son heure, son Event ID, son fournisseur et tous les champs EventData — directement dans votre navigateur. Rien n'est envoyé et rien n'a besoin d'être installé.",
    ctaLabel: "Ouvrir le convertisseur EVTX vers TXT",
    formatsHeading: "À quoi ressemble le fichier texte",
    formats: [
      {
        name: "Un bloc par événement",
        body: "Chaque événement commence par une ligne d'en-tête — numéro d'enregistrement, horodatage, niveau et Event ID — suivie du fournisseur, du canal et de l'ordinateur, puis d'une ligne indentée par champ EventData. Les événements sont séparés par une ligne vide.",
        code: "Enr. #48213 | 2026-09-12T08:14:03.512Z | Information | ID d'événement 4624\nFournisseur: Microsoft-Windows-Security-Auditing\nCanal: Security\nOrdinateur: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Pensé pour grep et les rapports",
        body: "Le texte brut fonctionne avec grep, findstr, diff et n'importe quel éditeur, et se colle proprement dans un ticket ou un rapport d'incident. Filtrez d'abord pour que le fichier ne contienne que les événements pertinents.",
      },
      {
        name: "Le XML brut si besoin",
        body: "Cochez « Colonne XML brut » avant l'export et chaque bloc inclura aussi le XML <Event> complet de l'événement.",
      },
    ],
    stepsHeading: "Comment convertir un fichier EVTX en TXT",
    steps: [
      {
        title: "Ouvrir le convertisseur",
        body: "Ouvrez la page d'accueil d'EVTX parser. L'analyse s'exécute dans l'onglet de votre navigateur via WebAssembly.",
      },
      {
        title: "Déposez votre fichier .evtx",
        body: "Glissez un ou plusieurs fichiers .evtx dans la zone de dépôt, ou cliquez pour les choisir.",
      },
      {
        title: "Filtrez, puis Exporter TXT",
        body: "Utilisez la barre de filtres, les puces d'Event ID ou la chronologie pour ne garder que les événements pertinents, puis cliquez sur Exporter TXT. Le fichier .txt est téléchargé localement.",
      },
    ],
    faqHeading: "FAQ sur la conversion EVTX vers TXT",
    faq: [
      {
        q: "Comment convertir EVTX en TXT avec wevtutil ?",
        a: "Sous Windows : wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. Le commutateur /lf:true indique à wevtutil que l'argument est un fichier journal et non un canal actif. Il faut une machine Windows disposant des manifestes de fournisseur correspondants pour afficher le texte des messages.",
      },
      {
        q: "Event Viewer peut-il exporter un fichier EVTX en texte ?",
        a: "Oui : ouvrez le journal enregistré, choisissez « Save All Events As… » et sélectionnez « Text (Tab delimited) ». Vous obtenez des colonnes de résumé plus le message rendu, sans les champs EventData individuels.",
      },
      {
        q: "Pourquoi ne puis-je pas simplement ouvrir un fichier EVTX dans le Bloc-notes ?",
        a: "EVTX est un format binaire : des blocs de 64 Ko d'enregistrements BinXML qui référencent des modèles partagés. Le texte n'existe qu'une fois qu'un analyseur a reconstruit chaque enregistrement — c'est ce que fait ce convertisseur.",
      },
      {
        q: "L'export TXT inclut-il le message de l'événement ?",
        a: "Il inclut tous les champs structurés de l'événement. La phrase Message conviviale affichée par Event Viewer est construite à partir des DLL de fournisseur installées sur Windows ; elle n'est donc pas stockée dans le .evtx et aucun analyseur hors ligne ne peut la reproduire exactement.",
      },
    ],
  },
  de: {
    metaTitle: "EVTX in TXT — .evtx online in lesbaren Text umwandeln",
    metaDescription:
      "Wandeln Sie ein Windows-.evtx-Ereignisprotokoll im Browser in eine Textdatei um. Kostenloser EVTX-zu-TXT-Konverter — ohne Upload, ohne Installation. Ein lesbarer Block pro Ereignis, einfach zu grep(en) oder einzufügen.",
    h1: "EVTX in TXT (Klartext) umwandeln",
    intro:
      "Eine .evtx-Datei ist binär, daher zeigt der Editor nur Zeichensalat. Dieser Konverter macht daraus eine lesbare .txt-Datei — ein Block pro Ereignis mit Zeit, Event ID, Anbieter und allen EventData-Feldern — direkt in Ihrem Browser. Es wird nichts hochgeladen und nichts muss installiert werden.",
    ctaLabel: "EVTX-zu-TXT-Konverter öffnen",
    formatsHeading: "So sieht die Textdatei aus",
    formats: [
      {
        name: "Ein Block pro Ereignis",
        body: "Jedes Ereignis beginnt mit einer Kopfzeile — Datensatznummer, Zeitstempel, Stufe und Event ID — gefolgt von Anbieter, Kanal und Computer, dann einer eingerückten Zeile pro EventData-Feld. Ereignisse sind durch eine Leerzeile getrennt.",
        code: "Eintrag #48213 | 2026-09-12T08:14:03.512Z | Information | Event ID 4624\nAnbieter: Microsoft-Windows-Security-Auditing\nKanal: Security\nComputer: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Gemacht für grep und Berichte",
        body: "Klartext funktioniert mit grep, findstr, diff und jedem Editor und lässt sich sauber in ein Ticket oder einen Vorfallbericht einfügen. Filtern Sie zuerst, damit die Datei nur die relevanten Ereignisse enthält.",
      },
      {
        name: "Rohes XML, wenn Sie es brauchen",
        body: "Aktivieren Sie vor dem Export „Rohe-XML-Spalte“, und jeder Block enthält zusätzlich das vollständige <Event>-XML des Ereignisses.",
      },
    ],
    stepsHeading: "So konvertieren Sie EVTX in TXT",
    steps: [
      {
        title: "Konverter öffnen",
        body: "Öffnen Sie die Startseite von EVTX parser. Das Parsen läuft über WebAssembly in Ihrem Browser-Tab.",
      },
      {
        title: "Legen Sie Ihre .evtx-Datei ab",
        body: "Ziehen Sie eine oder mehrere .evtx-Dateien in die Ablagezone oder klicken Sie, um sie auszuwählen.",
      },
      {
        title: "Filtern, dann TXT exportieren",
        body: "Nutzen Sie die Filterleiste, Event-ID-Chips oder die Zeitleiste, um nur relevante Ereignisse zu behalten, und klicken Sie dann auf TXT exportieren. Die .txt-Datei wird lokal heruntergeladen.",
      },
    ],
    faqHeading: "FAQ zu EVTX in TXT",
    faq: [
      {
        q: "Wie konvertiere ich EVTX mit wevtutil in TXT?",
        a: "Unter Windows: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. Der Schalter /lf:true teilt wevtutil mit, dass das Argument eine Protokolldatei und kein Live-Kanal ist. Es braucht einen Windows-Host mit den passenden Anbieter-Manifesten, um den Nachrichtentext darzustellen.",
      },
      {
        q: "Kann Event Viewer eine EVTX-Datei in Text exportieren?",
        a: "Ja: Öffnen Sie das gespeicherte Protokoll, wählen Sie „Save All Events As…“ und dann „Text (Tab delimited)“. Sie erhalten zusammenfassende Spalten plus die gerenderte Nachricht, ohne die einzelnen EventData-Felder.",
      },
      {
        q: "Warum kann ich eine EVTX-Datei nicht einfach im Editor öffnen?",
        a: "EVTX ist ein binäres Format: 64-KB-Blöcke aus BinXML-Datensätzen, die auf gemeinsame Vorlagen verweisen. Der Text entsteht erst, nachdem ein Parser jeden Datensatz rekonstruiert hat — genau das macht dieser Konverter.",
      },
      {
        q: "Enthält der TXT-Export die Ereignisnachricht?",
        a: "Er enthält jedes strukturierte Feld des Ereignisses. Der freundliche Message-Satz, den Event Viewer anzeigt, wird aus auf Windows installierten Anbieter-DLLs erzeugt, ist also nicht in der .evtx gespeichert, und kein Offline-Parser kann ihn exakt reproduzieren.",
      },
    ],
  },
  es: {
    metaTitle: "EVTX a TXT — convierte .evtx en texto legible online",
    metaDescription:
      "Convierte un registro de eventos de Windows .evtx a un archivo de texto en tu navegador. Conversor de EVTX a TXT gratuito — sin subir nada, sin instalar. Un bloque legible por evento, fácil de usar con grep o pegar.",
    h1: "Convertir EVTX a TXT (texto sin formato)",
    intro:
      "Un archivo .evtx es binario, así que el Bloc de notas muestra caracteres ilegibles. Este conversor lo convierte en un archivo .txt legible — un bloque por evento con su hora, Event ID, proveedor y todos los campos EventData — directamente en tu navegador. No se sube nada y no hace falta instalar nada.",
    ctaLabel: "Abrir el conversor de EVTX a TXT",
    formatsHeading: "Cómo es el archivo de texto",
    formats: [
      {
        name: "Un bloque por evento",
        body: "Cada evento comienza con una línea de encabezado — número de registro, marca de tiempo, nivel y Event ID — seguida del proveedor, el canal y el equipo, y luego una línea con sangría por cada campo EventData. Los eventos se separan con una línea en blanco.",
        code: "Reg. #48213 | 2026-09-12T08:14:03.512Z | Información | ID de evento 4624\nProveedor: Microsoft-Windows-Security-Auditing\nCanal: Security\nEquipo: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Pensado para grep e informes",
        body: "El texto sin formato funciona con grep, findstr, diff y cualquier editor, y se pega limpiamente en un ticket o un informe de incidente. Filtra primero para que el archivo solo contenga los eventos relevantes.",
      },
      {
        name: "XML sin procesar cuando lo necesites",
        body: "Marca «Columna XML sin procesar» antes de exportar y cada bloque incluirá también el XML <Event> completo del evento.",
      },
    ],
    stepsHeading: "Cómo convertir EVTX a TXT",
    steps: [
      {
        title: "Abre el conversor",
        body: "Abre la página de inicio de EVTX parser. El análisis se ejecuta en la pestaña de tu navegador mediante WebAssembly.",
      },
      {
        title: "Suelta tu archivo .evtx",
        body: "Arrastra uno o varios archivos .evtx a la zona de soltar, o haz clic para elegirlos.",
      },
      {
        title: "Filtra y luego Exportar TXT",
        body: "Usa la barra de filtros, los chips de Event ID o la línea de tiempo para conservar solo los eventos relevantes, y luego haz clic en Exportar TXT. El archivo .txt se descarga localmente.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre EVTX a TXT",
    faq: [
      {
        q: "¿Cómo convierto EVTX a TXT con wevtutil?",
        a: "En Windows: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. El modificador /lf:true le indica a wevtutil que el argumento es un archivo de registro y no un canal en vivo. Necesita un equipo Windows con los manifiestos de proveedor correspondientes para renderizar el texto del mensaje.",
      },
      {
        q: "¿Puede Event Viewer exportar un archivo EVTX a texto?",
        a: "Sí: abre el registro guardado, elige «Save All Events As…» y selecciona «Text (Tab delimited)». Obtienes columnas de resumen más el mensaje renderizado, sin los campos EventData individuales.",
      },
      {
        q: "¿Por qué no puedo simplemente abrir un archivo EVTX en el Bloc de notas?",
        a: "EVTX es un formato binario: bloques de 64 KB de registros BinXML que referencian plantillas compartidas. El texto solo existe después de que un analizador reconstruye cada registro, que es justo lo que hace este conversor.",
      },
      {
        q: "¿La exportación a TXT incluye el mensaje del evento?",
        a: "Incluye todos los campos estructurados del evento. La frase Message amigable que muestra Event Viewer se genera a partir de las DLL de proveedor instaladas en Windows, por lo que no se almacena en el .evtx y ningún analizador sin conexión puede reproducirla con exactitud.",
      },
    ],
  },
  it: {
    metaTitle: "EVTX in TXT — converti .evtx in testo leggibile online",
    metaDescription:
      "Converti un registro eventi di Windows .evtx in un file di testo nel tuo browser. Convertitore EVTX in TXT gratuito — senza upload, senza installazione. Un blocco leggibile per ogni evento, facile da usare con grep o incollare.",
    h1: "Convertire EVTX in TXT (testo semplice)",
    intro:
      "Un file .evtx è binario, quindi Blocco note mostra caratteri illeggibili. Questo convertitore lo trasforma in un file .txt leggibile — un blocco per evento con orario, Event ID, provider e ogni campo EventData — direttamente nel tuo browser. Non viene caricato nulla e non serve installare nulla.",
    ctaLabel: "Apri il convertitore EVTX in TXT",
    formatsHeading: "Come appare il file di testo",
    formats: [
      {
        name: "Un blocco per evento",
        body: "Ogni evento inizia con una riga di intestazione — numero di record, timestamp, livello e Event ID — seguita da provider, canale e computer, poi una riga rientrata per ogni campo EventData. Gli eventi sono separati da una riga vuota.",
        code: "Rec. #48213 | 2026-09-12T08:14:03.512Z | Informazione | Event ID 4624\nProvider: Microsoft-Windows-Security-Auditing\nCanale: Security\nComputer: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Pensato per grep e i report",
        body: "Il testo semplice funziona con grep, findstr, diff e qualsiasi editor, e si incolla in modo pulito in un ticket o in un report di incidente. Filtra prima così il file contiene solo gli eventi che contano.",
      },
      {
        name: "XML grezzo quando serve",
        body: "Seleziona «Colonna XML grezzo» prima di esportare e ogni blocco includerà anche l'XML <Event> completo dell'evento.",
      },
    ],
    stepsHeading: "Come convertire EVTX in TXT",
    steps: [
      {
        title: "Apri il convertitore",
        body: "Apri la homepage di EVTX parser. Il parsing viene eseguito nella scheda del tuo browser tramite WebAssembly.",
      },
      {
        title: "Rilascia il tuo file .evtx",
        body: "Trascina uno o più file .evtx nell'area di rilascio, oppure fai clic per sceglierli.",
      },
      {
        title: "Filtra, poi Esporta TXT",
        body: "Usa la barra dei filtri, i chip Event ID o la timeline per mantenere solo gli eventi rilevanti, poi fai clic su Esporta TXT. Il file .txt viene scaricato localmente.",
      },
    ],
    faqHeading: "FAQ su EVTX in TXT",
    faq: [
      {
        q: "Come converto EVTX in TXT con wevtutil?",
        a: "Su Windows: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. L'opzione /lf:true indica a wevtutil che l'argomento è un file di log e non un canale live. Serve un host Windows con i manifest del provider corrispondenti per rendere il testo del messaggio.",
      },
      {
        q: "Event Viewer può esportare un file EVTX in testo?",
        a: "Sì: apri il log salvato, scegli «Save All Events As…» e seleziona «Text (Tab delimited)». Ottieni colonne di riepilogo più il messaggio renderizzato, senza i singoli campi EventData.",
      },
      {
        q: "Perché non posso aprire un file EVTX direttamente nel Blocco note?",
        a: "EVTX è un formato binario: blocchi da 64 KB di record BinXML che fanno riferimento a modelli condivisi. Il testo esiste solo dopo che un parser ricostruisce ogni record, ed è esattamente ciò che fa questo convertitore.",
      },
      {
        q: "L'esportazione TXT include il messaggio dell'evento?",
        a: "Include ogni campo strutturato dell'evento. La frase Message facile da leggere mostrata da Event Viewer viene costruita dalle DLL del provider installate su Windows, quindi non è memorizzata nel .evtx e nessun parser offline può riprodurla esattamente.",
      },
    ],
  },
  pt: {
    metaTitle: "EVTX para TXT — converta .evtx em texto legível online",
    metaDescription:
      "Converta um log de eventos do Windows .evtx em um arquivo de texto no seu navegador. Conversor de EVTX para TXT gratuito — sem upload, sem instalação. Um bloco legível por evento, fácil de usar com grep ou colar.",
    h1: "Converter EVTX para TXT (texto simples)",
    intro:
      "Um arquivo .evtx é binário, então o Bloco de Notas mostra apenas caracteres ilegíveis. Este conversor o transforma em um arquivo .txt legível — um bloco por evento com hora, Event ID, provedor e todos os campos EventData — diretamente no seu navegador. Nada é enviado e nada precisa ser instalado.",
    ctaLabel: "Abrir o conversor de EVTX para TXT",
    formatsHeading: "Como é o arquivo de texto",
    formats: [
      {
        name: "Um bloco por evento",
        body: "Cada evento começa com uma linha de cabeçalho — número do registro, timestamp, nível e Event ID — seguida do provedor, canal e computador, depois uma linha recuada por campo EventData. Os eventos são separados por uma linha em branco.",
        code: "Reg. #48213 | 2026-09-12T08:14:03.512Z | Informação | Event ID 4624\nProvedor: Microsoft-Windows-Security-Auditing\nCanal: Security\nComputador: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "Feito para grep e relatórios",
        body: "O texto simples funciona com grep, findstr, diff e qualquer editor, e cola de forma limpa em um chamado ou relatório de incidente. Filtre antes para que o arquivo contenha apenas os eventos relevantes.",
      },
      {
        name: "XML bruto quando você precisar",
        body: "Marque «Coluna XML bruto» antes de exportar e cada bloco também incluirá o XML <Event> completo do evento.",
      },
    ],
    stepsHeading: "Como converter EVTX para TXT",
    steps: [
      {
        title: "Abra o conversor",
        body: "Abra a página inicial do EVTX parser. A análise é executada na aba do seu navegador via WebAssembly.",
      },
      {
        title: "Solte seu arquivo .evtx",
        body: "Arraste um ou mais arquivos .evtx para a área de soltar, ou clique para escolhê-los.",
      },
      {
        title: "Filtre e depois Exportar TXT",
        body: "Use a barra de filtros, os chips de Event ID ou a linha do tempo para manter apenas os eventos relevantes, depois clique em Exportar TXT. O arquivo .txt é baixado localmente.",
      },
    ],
    faqHeading: "Perguntas frequentes sobre EVTX para TXT",
    faq: [
      {
        q: "Como converto EVTX para TXT com wevtutil?",
        a: "No Windows: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt. O parâmetro /lf:true informa ao wevtutil que o argumento é um arquivo de log, não um canal ativo. É necessário um host Windows com os manifestos de provedor correspondentes para renderizar o texto da mensagem.",
      },
      {
        q: "O Event Viewer pode exportar um arquivo EVTX para texto?",
        a: "Sim: abra o log salvo, escolha «Save All Events As…» e selecione «Text (Tab delimited)». Você obtém colunas de resumo além da mensagem renderizada, sem os campos EventData individuais.",
      },
      {
        q: "Por que não posso simplesmente abrir um arquivo EVTX no Bloco de Notas?",
        a: "EVTX é um formato binário: blocos de 64 KB de registros BinXML que referenciam modelos compartilhados. O texto só existe depois que um parser reconstrói cada registro, que é exatamente o que este conversor faz.",
      },
      {
        q: "A exportação TXT inclui a mensagem do evento?",
        a: "Ela inclui todos os campos estruturados do evento. A frase amigável de Message exibida pelo Event Viewer é construída a partir das DLLs de provedor instaladas no Windows, portanto não é armazenada no .evtx e nenhum parser offline pode reproduzi-la com exatidão.",
      },
    ],
  },
  ja: {
    metaTitle: "EVTX を TXT に変換 — オンラインで読めるテキストへ",
    metaDescription:
      "Windows の .evtx イベントログをブラウザでプレーンテキストファイルに変換。無料の EVTX から TXT への変換ツール — アップロード不要、インストール不要。イベントごとに読みやすい1ブロック、grep や貼り付けも簡単です。",
    h1: "EVTX を TXT（プレーンテキスト）に変換",
    intro:
      ".evtx ファイルはバイナリ形式のため、メモ帳で開くと文字化けします。このコンバーターは、時刻・Event ID・プロバイダ・すべての EventData フィールドを含む、イベントごとに1ブロックの読みやすい .txt ファイルに、ブラウザ上で直接変換します。何もアップロードされず、インストールも不要です。",
    ctaLabel: "EVTX から TXT への変換ツールを開く",
    formatsHeading: "テキストファイルの見え方",
    formats: [
      {
        name: "イベントごとに1ブロック",
        body: "各イベントは、レコード番号・タイムスタンプ・レベル・Event ID を含むヘッダー行で始まり、続いてプロバイダ、チャネル、コンピュータが記載され、その後 EventData フィールドごとにインデントされた行が続きます。イベントは空行で区切られます。",
        code: "レコード #48213 | 2026-09-12T08:14:03.512Z | 情報 | Event ID 4624\nプロバイダ: Microsoft-Windows-Security-Auditing\nチャネル: Security\nコンピュータ: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "grep やレポートに最適",
        body: "プレーンテキストは grep、findstr、diff、どのエディタでも扱え、チケットやインシデントレポートにそのまま貼り付けられます。まずフィルタリングして、必要なイベントだけがファイルに含まれるようにしましょう。",
      },
      {
        name: "必要なら生 XML も",
        body: "エクスポート前に「生 XML 列」にチェックを入れると、各ブロックにイベントの完全な <Event> XML も含まれます。",
      },
    ],
    stepsHeading: "EVTX を TXT に変換する方法",
    steps: [
      {
        title: "コンバーターを開く",
        body: "EVTX parser のホームページを開きます。解析は WebAssembly によってブラウザのタブ内で実行されます。",
      },
      {
        title: ".evtx ファイルをドロップする",
        body: "1つまたは複数の .evtx ファイルをドロップゾーンにドラッグするか、クリックして選択します。",
      },
      {
        title: "フィルタしてから TXT をエクスポート",
        body: "フィルターバー、Event ID チップ、またはタイムラインを使って関連するイベントだけを残し、TXT をエクスポートをクリックします。.txt ファイルがローカルにダウンロードされます。",
      },
    ],
    faqHeading: "EVTX から TXT への変換に関する FAQ",
    faq: [
      {
        q: "wevtutil で EVTX を TXT に変換するには？",
        a: "Windows では: wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt。/lf:true スイッチは、引数がライブチャネルではなくログファイルであることを wevtutil に伝えます。メッセージテキストをレンダリングするには、対応するプロバイダーマニフェストを持つ Windows ホストが必要です。",
      },
      {
        q: "Event Viewer で EVTX ファイルをテキストにエクスポートできますか？",
        a: "はい。保存されたログを開き、「Save All Events As…」を選択して「Text (Tab delimited)」を選びます。個々の EventData フィールドは含まれませんが、要約列とレンダリングされたメッセージが得られます。",
      },
      {
        q: "なぜ EVTX ファイルをメモ帳で直接開けないのですか？",
        a: "EVTX はバイナリ形式です。共有テンプレートを参照する BinXML レコードの 64 KB チャンクで構成されています。テキストはパーサーが各レコードを再構築して初めて存在します。これがこのコンバーターの処理内容です。",
      },
      {
        q: "TXT エクスポートにはイベントメッセージが含まれますか？",
        a: "イベントの構造化されたすべてのフィールドが含まれます。Event Viewer が表示するわかりやすい Message の文章は、Windows にインストールされたプロバイダーの DLL から生成されるため、.evtx には保存されておらず、オフラインのパーサーで正確に再現することはできません。",
      },
    ],
  },
  zh: {
    metaTitle: "EVTX 转 TXT——在线转换为可读文本",
    metaDescription:
      "在浏览器中将 Windows .evtx 事件日志转换为纯文本文件。免费的 EVTX 转 TXT 工具——无需上传，无需安装。每个事件一个易读的文本块，便于 grep 或粘贴。",
    h1: "将 EVTX 转换为 TXT（纯文本）",
    intro:
      ".evtx 文件是二进制格式，因此记事本打开后只会显示乱码。此转换器可将其转换为易读的 .txt 文件——每个事件一个文本块，包含时间、Event ID、提供程序以及所有 EventData 字段——直接在您的浏览器中完成。不会上传任何内容，也无需安装任何软件。",
    ctaLabel: "打开 EVTX 转 TXT 转换器",
    formatsHeading: "文本文件是什么样子",
    formats: [
      {
        name: "每个事件一个文本块",
        body: "每个事件以一行标题开始——记录编号、时间戳、级别和 Event ID——随后是提供程序、通道和计算机，再接着是每个 EventData 字段的一行缩进内容。事件之间以空行分隔。",
        code: "记录 #48213 | 2026-09-12T08:14:03.512Z | 信息 | Event ID 4624\n提供程序: Microsoft-Windows-Security-Auditing\n通道: Security\n计算机: WS-042.corp.local\n  LogonType: 10\n  TargetUserName: j.doe\n  IpAddress: 203.0.113.17",
      },
      {
        name: "专为 grep 和报告设计",
        body: "纯文本可配合 grep、findstr、diff 和任意编辑器使用，也能干净地粘贴到工单或事件报告中。建议先筛选，让文件只包含相关的事件。",
      },
      {
        name: "需要时提供原始 XML",
        body: "导出前勾选“原始 XML 列”，每个文本块还将包含该事件完整的 <Event> XML。",
      },
    ],
    stepsHeading: "如何将 EVTX 转换为 TXT",
    steps: [
      {
        title: "打开转换器",
        body: "打开 EVTX parser 主页。解析通过 WebAssembly 在您的浏览器标签页中运行。",
      },
      {
        title: "拖入您的 .evtx 文件",
        body: "将一个或多个 .evtx 文件拖到拖放区，或单击选择它们。",
      },
      {
        title: "筛选后导出 TXT",
        body: "使用筛选栏、Event ID 标签或时间线只保留相关事件，然后单击导出 TXT。.txt 文件将下载到本地。",
      },
    ],
    faqHeading: "关于 EVTX 转 TXT 的常见问题",
    faq: [
      {
        q: "如何使用 wevtutil 将 EVTX 转换为 TXT？",
        a: "在 Windows 上：wevtutil qe C:\\path\\Security.evtx /lf:true /f:text > events.txt。/lf:true 开关告诉 wevtutil 该参数是日志文件而非实时通道。它需要一台拥有匹配的提供程序清单的 Windows 主机才能渲染消息文本。",
      },
      {
        q: "Event Viewer 能否将 EVTX 文件导出为文本？",
        a: "可以：打开已保存的日志，选择“Save All Events As…”，再选择“Text (Tab delimited)”。您会得到摘要列以及渲染后的消息，但不包含各个 EventData 字段。",
      },
      {
        q: "为什么我不能直接在记事本中打开 EVTX 文件？",
        a: "EVTX 是一种二进制格式：由引用共享模板的 BinXML 记录组成的 64 KB 分块。只有在解析器重建每条记录之后，文本才会存在——这正是此转换器所做的工作。",
      },
      {
        q: "TXT 导出是否包含事件消息？",
        a: "它包含事件的每个结构化字段。Event Viewer 显示的友好 Message 语句是由安装在 Windows 上的提供程序 DLL 生成的，因此并未存储在 .evtx 中，任何离线解析器都无法精确重现它。",
      },
    ],
  },
};
