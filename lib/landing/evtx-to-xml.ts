import type { LocaleContent } from "./locale-content";

export type EvtxToXml = {
  metaTitle: string;
  metaDescription: string;
  h1: string;
  intro: string;
  ctaLabel: string;
  formatsHeading: string;
  formats: { name: string; body: string }[];
  stepsHeading: string;
  steps: { title: string; body: string }[];
  faqHeading: string;
  faq: { q: string; a: string }[];
};

export const EVTX_TO_XML: LocaleContent<EvtxToXml> = {
  en: {
    metaTitle: "Convert EVTX to XML, JSON or CSV — free online, no upload",
    metaDescription:
      "Convert a Windows .evtx event log to XML, JSON or CSV in your browser. Free online EVTX converter — no upload, no install. Each record's raw XML is rebuilt locally.",
    h1: "Convert EVTX to XML, JSON or CSV",
    intro:
      "Turn a Windows .evtx event log into clean XML, JSON or CSV directly in your browser. Parsing and conversion run client-side via a Rust parser compiled to WebAssembly, so the file never leaves your device — no upload, no install, no Windows host required.",
    ctaLabel: "Open the EVTX converter",
    formatsHeading: "Which format do you need?",
    formats: [
      {
        name: "EVTX to XML",
        body: "Each event in a .evtx file is stored as BinXML against a template table. The converter rebuilds the exact <Event> XML for every record — the same structure wevtutil or Get-WinEvent would emit — so you can grep, diff or feed it into an XML-aware pipeline.",
      },
      {
        name: "EVTX to JSON",
        body: "JSON export flattens each record's System block and EventData fields into one object per event, ready for jq, a SIEM ingest path or a notebook. The raw event XML is included alongside the parsed fields when you need both.",
      },
      {
        name: "EVTX to CSV",
        body: "CSV export gives you one row per event with the common columns (record, time, level, Event ID, provider, channel, computer). Filter to a single Event ID first and the EventData keys become real columns — open the result straight in Excel.",
      },
    ],
    stepsHeading: "How to convert an EVTX file",
    steps: [
      {
        title: "Open the converter",
        body: "Open the EVTX parser homepage. Nothing is uploaded — the page loads a WebAssembly parser that runs entirely in your browser tab.",
      },
      {
        title: "Drop your .evtx file",
        body: "Drag a .evtx file (Security.evtx, System.evtx, Sysmon, PowerShell…) onto the drop zone, or click to choose one. You can drop several files at once to convert them together.",
      },
      {
        title: "Export to XML, JSON or CSV",
        body: "Filter or sort if you like, then click Export. Choose JSON or CSV, or enable the raw-XML column to capture each event's full XML. The file downloads locally.",
      },
    ],
    faqHeading: "EVTX conversion FAQ",
    faq: [
      {
        q: "Is the EVTX converter free and does it upload my file?",
        a: "It is free and nothing is uploaded. The .evtx is read into your browser's memory and parsed locally with a Rust/WebAssembly parser; you can disconnect from the network and it still works.",
      },
      {
        q: "How do I convert EVTX to XML without Windows?",
        a: "Use this in-browser converter on Linux or macOS, or the evtx_dump CLI. Both rebuild the event XML offline — no Event Viewer, wevtutil or Windows runtime needed.",
      },
      {
        q: "Can I convert a large or multiple EVTX files?",
        a: "Yes. A few hundred MB is comfortable in a modern browser, and you can load multiple .evtx files and export them as one combined CSV or JSON.",
      },
    ],
  },
  fr: {
    metaTitle: "Convertir EVTX en XML, JSON ou CSV — en ligne, sans envoi",
    metaDescription:
      "Convertissez un journal d'événements Windows .evtx en XML, JSON ou CSV dans votre navigateur. Convertisseur EVTX gratuit en ligne — sans envoi, sans installation. Le XML brut de chaque enregistrement est reconstruit localement.",
    h1: "Convertir EVTX en XML, JSON ou CSV",
    intro:
      "Transformez un journal d'événements Windows .evtx en XML, JSON ou CSV propre directement dans votre navigateur. L'analyse et la conversion s'exécutent côté client via un analyseur Rust compilé en WebAssembly : le fichier ne quitte jamais votre appareil — sans envoi, sans installation, sans machine Windows.",
    ctaLabel: "Ouvrir le convertisseur EVTX",
    formatsHeading: "De quel format avez-vous besoin ?",
    formats: [
      {
        name: "EVTX vers XML",
        body: "Chaque événement d'un fichier .evtx est stocké en BinXML par rapport à une table de modèles. Le convertisseur reconstruit le XML <Event> exact de chaque enregistrement — la même structure que produiraient wevtutil ou Get-WinEvent — afin que vous puissiez le grep, le diff ou l'injecter dans un pipeline orienté XML.",
      },
      {
        name: "EVTX vers JSON",
        body: "L'export JSON aplatit le bloc System et les champs EventData de chaque enregistrement en un objet par événement, prêt pour jq, un pipeline d'ingestion SIEM ou un notebook. Le XML brut de l'événement est inclus aux côtés des champs analysés lorsque vous avez besoin des deux.",
      },
      {
        name: "EVTX vers CSV",
        body: "L'export CSV vous donne une ligne par événement avec les colonnes courantes (enregistrement, heure, niveau, Event ID, fournisseur, canal, ordinateur). Filtrez d'abord sur un seul Event ID et les clés EventData deviennent de vraies colonnes — ouvrez le résultat directement dans Excel.",
      },
    ],
    stepsHeading: "Comment convertir un fichier EVTX",
    steps: [
      {
        title: "Ouvrir le convertisseur",
        body: "Ouvrez la page d'accueil d'EVTX parser. Rien n'est envoyé — la page charge un analyseur WebAssembly qui s'exécute entièrement dans l'onglet de votre navigateur.",
      },
      {
        title: "Déposez votre fichier .evtx",
        body: "Glissez un fichier .evtx (Security.evtx, System.evtx, Sysmon, PowerShell…) dans la zone de dépôt, ou cliquez pour en choisir un. Vous pouvez déposer plusieurs fichiers à la fois pour les convertir ensemble.",
      },
      {
        title: "Exporter en XML, JSON ou CSV",
        body: "Filtrez ou triez si vous le souhaitez, puis cliquez sur Exporter. Choisissez JSON ou CSV, ou activez la colonne XML brut pour capturer le XML complet de chaque événement. Le fichier est téléchargé localement.",
      },
    ],
    faqHeading: "FAQ sur la conversion EVTX",
    faq: [
      {
        q: "Le convertisseur EVTX est-il gratuit et envoie-t-il mon fichier ?",
        a: "Il est gratuit et rien n'est envoyé. Le .evtx est lu dans la mémoire de votre navigateur et analysé localement avec un analyseur Rust/WebAssembly ; vous pouvez vous déconnecter du réseau, cela fonctionne toujours.",
      },
      {
        q: "Comment convertir EVTX en XML sans Windows ?",
        a: "Utilisez ce convertisseur dans le navigateur sous Linux ou macOS, ou l'utilitaire evtx_dump en ligne de commande. Les deux reconstruisent le XML des événements hors ligne — pas besoin d'Event Viewer, de wevtutil ni d'un runtime Windows.",
      },
      {
        q: "Puis-je convertir un fichier EVTX volumineux ou plusieurs fichiers ?",
        a: "Oui. Quelques centaines de Mo passent sans problème dans un navigateur moderne, et vous pouvez charger plusieurs fichiers .evtx et les exporter en un seul CSV ou JSON combiné.",
      },
    ],
  },
  de: {
    metaTitle: "EVTX in XML, JSON oder CSV umwandeln — online, ohne Upload",
    metaDescription:
      "Wandeln Sie ein Windows-.evtx-Ereignisprotokoll im Browser in XML, JSON oder CSV um. Kostenloser Online-EVTX-Konverter — ohne Upload, ohne Installation. Das rohe XML jedes Datensatzes wird lokal rekonstruiert.",
    h1: "EVTX in XML, JSON oder CSV umwandeln",
    intro:
      "Verwandeln Sie ein Windows-.evtx-Ereignisprotokoll direkt im Browser in sauberes XML, JSON oder CSV. Parsen und Konvertierung laufen clientseitig über einen in WebAssembly kompilierten Rust-Parser, sodass die Datei Ihr Gerät nie verlässt — ohne Upload, ohne Installation, ohne Windows-Host.",
    ctaLabel: "EVTX-Konverter öffnen",
    formatsHeading: "Welches Format benötigen Sie?",
    formats: [
      {
        name: "EVTX zu XML",
        body: "Jedes Ereignis in einer .evtx-Datei wird als BinXML gegen eine Vorlagentabelle gespeichert. Der Konverter rekonstruiert das exakte <Event>-XML für jeden Datensatz — dieselbe Struktur, die wevtutil oder Get-WinEvent ausgeben würden — sodass Sie es grep, diff oder in eine XML-fähige Pipeline einspeisen können.",
      },
      {
        name: "EVTX zu JSON",
        body: "Der JSON-Export flacht den System-Block und die EventData-Felder jedes Datensatzes zu einem Objekt pro Ereignis ab, bereit für jq, einen SIEM-Ingest-Pfad oder ein Notebook. Das rohe Ereignis-XML wird neben den geparsten Feldern mitgeliefert, wenn Sie beides benötigen.",
      },
      {
        name: "EVTX zu CSV",
        body: "Der CSV-Export liefert Ihnen eine Zeile pro Ereignis mit den gängigen Spalten (Datensatz, Zeit, Stufe, Event ID, Anbieter, Kanal, Computer). Filtern Sie zuerst auf eine einzelne Event ID, und die EventData-Schlüssel werden zu echten Spalten — öffnen Sie das Ergebnis direkt in Excel.",
      },
    ],
    stepsHeading: "So konvertieren Sie eine EVTX-Datei",
    steps: [
      {
        title: "Konverter öffnen",
        body: "Öffnen Sie die Startseite von EVTX parser. Es wird nichts hochgeladen — die Seite lädt einen WebAssembly-Parser, der vollständig in Ihrem Browser-Tab läuft.",
      },
      {
        title: "Legen Sie Ihre .evtx-Datei ab",
        body: "Ziehen Sie eine .evtx-Datei (Security.evtx, System.evtx, Sysmon, PowerShell…) in die Ablagezone oder klicken Sie, um eine auszuwählen. Sie können mehrere Dateien gleichzeitig ablegen, um sie zusammen zu konvertieren.",
      },
      {
        title: "Nach XML, JSON oder CSV exportieren",
        body: "Filtern oder sortieren Sie bei Bedarf und klicken Sie dann auf Exportieren. Wählen Sie JSON oder CSV, oder aktivieren Sie die Roh-XML-Spalte, um das vollständige XML jedes Ereignisses zu erfassen. Die Datei wird lokal heruntergeladen.",
      },
    ],
    faqHeading: "FAQ zur EVTX-Konvertierung",
    faq: [
      {
        q: "Ist der EVTX-Konverter kostenlos und lädt er meine Datei hoch?",
        a: "Er ist kostenlos und es wird nichts hochgeladen. Die .evtx wird in den Speicher Ihres Browsers eingelesen und lokal mit einem Rust/WebAssembly-Parser verarbeitet; Sie können die Netzwerkverbindung trennen, und es funktioniert weiterhin.",
      },
      {
        q: "Wie konvertiere ich EVTX ohne Windows in XML?",
        a: "Nutzen Sie diesen Browser-Konverter unter Linux oder macOS oder das CLI-Tool evtx_dump. Beide rekonstruieren das Ereignis-XML offline — kein Event Viewer, kein wevtutil und keine Windows-Laufzeit nötig.",
      },
      {
        q: "Kann ich eine große oder mehrere EVTX-Dateien konvertieren?",
        a: "Ja. Ein paar hundert MB sind in einem modernen Browser problemlos möglich, und Sie können mehrere .evtx-Dateien laden und sie als eine kombinierte CSV oder JSON exportieren.",
      },
    ],
  },
  es: {
    metaTitle: "Convertir EVTX a XML, JSON o CSV — en línea, sin subir",
    metaDescription:
      "Convierte un registro de eventos de Windows .evtx a XML, JSON o CSV en tu navegador. Conversor de EVTX gratuito en línea — sin subir nada, sin instalar. El XML sin procesar de cada registro se reconstruye localmente.",
    h1: "Convertir EVTX a XML, JSON o CSV",
    intro:
      "Convierte un registro de eventos de Windows .evtx en XML, JSON o CSV limpio directamente en tu navegador. El análisis y la conversión se ejecutan en el lado del cliente mediante un analizador Rust compilado a WebAssembly, por lo que el archivo nunca sale de tu dispositivo — sin subir nada, sin instalar, sin un host Windows.",
    ctaLabel: "Abrir el conversor de EVTX",
    formatsHeading: "¿Qué formato necesitas?",
    formats: [
      {
        name: "EVTX a XML",
        body: "Cada evento de un archivo .evtx se almacena como BinXML frente a una tabla de plantillas. El conversor reconstruye el XML <Event> exacto de cada registro — la misma estructura que emitirían wevtutil o Get-WinEvent — para que puedas hacer grep, diff o introducirlo en una canalización que entienda XML.",
      },
      {
        name: "EVTX a JSON",
        body: "La exportación a JSON aplana el bloque System y los campos EventData de cada registro en un objeto por evento, listo para jq, una ruta de ingesta de SIEM o un notebook. El XML sin procesar del evento se incluye junto a los campos analizados cuando necesitas ambos.",
      },
      {
        name: "EVTX a CSV",
        body: "La exportación a CSV te da una fila por evento con las columnas habituales (registro, hora, nivel, Event ID, proveedor, canal, equipo). Filtra primero por un único Event ID y las claves de EventData se convierten en columnas reales — abre el resultado directamente en Excel.",
      },
    ],
    stepsHeading: "Cómo convertir un archivo EVTX",
    steps: [
      {
        title: "Abre el conversor",
        body: "Abre la página de inicio de EVTX parser. No se sube nada — la página carga un analizador WebAssembly que se ejecuta por completo en la pestaña de tu navegador.",
      },
      {
        title: "Suelta tu archivo .evtx",
        body: "Arrastra un archivo .evtx (Security.evtx, System.evtx, Sysmon, PowerShell…) a la zona de soltar, o haz clic para elegir uno. Puedes soltar varios archivos a la vez para convertirlos juntos.",
      },
      {
        title: "Exporta a XML, JSON o CSV",
        body: "Filtra u ordena si quieres y luego haz clic en Exportar. Elige JSON o CSV, o activa la columna de XML sin procesar para capturar el XML completo de cada evento. El archivo se descarga localmente.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre la conversión de EVTX",
    faq: [
      {
        q: "¿El conversor de EVTX es gratuito y sube mi archivo?",
        a: "Es gratuito y no se sube nada. El .evtx se lee en la memoria de tu navegador y se analiza localmente con un analizador Rust/WebAssembly; puedes desconectarte de la red y sigue funcionando.",
      },
      {
        q: "¿Cómo convierto EVTX a XML sin Windows?",
        a: "Usa este conversor en el navegador en Linux o macOS, o la herramienta de línea de comandos evtx_dump. Ambos reconstruyen el XML de los eventos sin conexión — sin Event Viewer, sin wevtutil ni un entorno de ejecución de Windows.",
      },
      {
        q: "¿Puedo convertir un archivo EVTX grande o varios archivos?",
        a: "Sí. Unos cientos de MB se manejan con comodidad en un navegador moderno, y puedes cargar varios archivos .evtx y exportarlos como un único CSV o JSON combinado.",
      },
    ],
  },
  it: {
    metaTitle: "Convertire EVTX in XML, JSON o CSV — online, senza upload",
    metaDescription:
      "Converti un registro eventi di Windows .evtx in XML, JSON o CSV nel tuo browser. Convertitore EVTX gratuito online — senza upload, senza installazione. L'XML grezzo di ogni record viene ricostruito localmente.",
    h1: "Convertire EVTX in XML, JSON o CSV",
    intro:
      "Trasforma un registro eventi di Windows .evtx in XML, JSON o CSV puliti direttamente nel tuo browser. Parsing e conversione vengono eseguiti lato client tramite un parser Rust compilato in WebAssembly, quindi il file non lascia mai il tuo dispositivo — senza upload, senza installazione, senza un host Windows.",
    ctaLabel: "Apri il convertitore EVTX",
    formatsHeading: "Di quale formato hai bisogno?",
    formats: [
      {
        name: "EVTX in XML",
        body: "Ogni evento in un file .evtx è memorizzato come BinXML rispetto a una tabella di modelli. Il convertitore ricostruisce l'esatto XML <Event> per ogni record — la stessa struttura che emetterebbero wevtutil o Get-WinEvent — così puoi farne grep, diff o inserirlo in una pipeline che gestisce l'XML.",
      },
      {
        name: "EVTX in JSON",
        body: "L'esportazione JSON appiattisce il blocco System e i campi EventData di ogni record in un oggetto per evento, pronto per jq, un percorso di ingestione SIEM o un notebook. L'XML grezzo dell'evento è incluso accanto ai campi analizzati quando ti servono entrambi.",
      },
      {
        name: "EVTX in CSV",
        body: "L'esportazione CSV ti dà una riga per evento con le colonne comuni (record, ora, livello, Event ID, provider, canale, computer). Filtra prima su un singolo Event ID e le chiavi EventData diventano colonne reali — apri il risultato direttamente in Excel.",
      },
    ],
    stepsHeading: "Come convertire un file EVTX",
    steps: [
      {
        title: "Apri il convertitore",
        body: "Apri la homepage di EVTX parser. Non viene caricato nulla — la pagina carica un parser WebAssembly che gira interamente nella scheda del tuo browser.",
      },
      {
        title: "Rilascia il tuo file .evtx",
        body: "Trascina un file .evtx (Security.evtx, System.evtx, Sysmon, PowerShell…) nell'area di rilascio, oppure fai clic per sceglierne uno. Puoi rilasciare più file contemporaneamente per convertirli insieme.",
      },
      {
        title: "Esporta in XML, JSON o CSV",
        body: "Filtra o ordina se vuoi, poi fai clic su Esporta. Scegli JSON o CSV, oppure abilita la colonna XML grezzo per catturare l'XML completo di ogni evento. Il file viene scaricato localmente.",
      },
    ],
    faqHeading: "FAQ sulla conversione EVTX",
    faq: [
      {
        q: "Il convertitore EVTX è gratuito e carica il mio file?",
        a: "È gratuito e non viene caricato nulla. Il .evtx viene letto nella memoria del tuo browser e analizzato localmente con un parser Rust/WebAssembly; puoi disconnetterti dalla rete e continua a funzionare.",
      },
      {
        q: "Come converto EVTX in XML senza Windows?",
        a: "Usa questo convertitore nel browser su Linux o macOS, oppure lo strumento da riga di comando evtx_dump. Entrambi ricostruiscono l'XML degli eventi offline — senza Event Viewer, wevtutil o un runtime Windows.",
      },
      {
        q: "Posso convertire un file EVTX grande o più file?",
        a: "Sì. Qualche centinaio di MB si gestisce comodamente in un browser moderno, e puoi caricare più file .evtx ed esportarli come un unico CSV o JSON combinato.",
      },
    ],
  },
  pt: {
    metaTitle: "Converter EVTX para XML, JSON ou CSV — online, sem upload",
    metaDescription:
      "Converta um log de eventos do Windows .evtx para XML, JSON ou CSV no seu navegador. Conversor de EVTX gratuito online — sem upload, sem instalação. O XML bruto de cada registro é reconstruído localmente.",
    h1: "Converter EVTX para XML, JSON ou CSV",
    intro:
      "Transforme um log de eventos do Windows .evtx em XML, JSON ou CSV limpos diretamente no seu navegador. A análise e a conversão são executadas no lado do cliente por meio de um parser Rust compilado para WebAssembly, de modo que o arquivo nunca sai do seu dispositivo — sem upload, sem instalação, sem um host Windows.",
    ctaLabel: "Abrir o conversor de EVTX",
    formatsHeading: "De qual formato você precisa?",
    formats: [
      {
        name: "EVTX para XML",
        body: "Cada evento em um arquivo .evtx é armazenado como BinXML em relação a uma tabela de modelos. O conversor reconstrói o XML <Event> exato de cada registro — a mesma estrutura que o wevtutil ou o Get-WinEvent emitiriam — para que você possa fazer grep, diff ou inseri-lo em um pipeline que entende XML.",
      },
      {
        name: "EVTX para JSON",
        body: "A exportação para JSON achata o bloco System e os campos EventData de cada registro em um objeto por evento, pronto para o jq, um caminho de ingestão de SIEM ou um notebook. O XML bruto do evento é incluído ao lado dos campos analisados quando você precisa de ambos.",
      },
      {
        name: "EVTX para CSV",
        body: "A exportação para CSV fornece uma linha por evento com as colunas comuns (registro, hora, nível, Event ID, provedor, canal, computador). Filtre primeiro por um único Event ID e as chaves de EventData tornam-se colunas reais — abra o resultado diretamente no Excel.",
      },
    ],
    stepsHeading: "Como converter um arquivo EVTX",
    steps: [
      {
        title: "Abra o conversor",
        body: "Abra a página inicial do EVTX parser. Nada é enviado — a página carrega um parser WebAssembly que roda inteiramente na aba do seu navegador.",
      },
      {
        title: "Solte seu arquivo .evtx",
        body: "Arraste um arquivo .evtx (Security.evtx, System.evtx, Sysmon, PowerShell…) para a área de soltar, ou clique para escolher um. Você pode soltar vários arquivos ao mesmo tempo para convertê-los juntos.",
      },
      {
        title: "Exporte para XML, JSON ou CSV",
        body: "Filtre ou ordene se quiser, depois clique em Exportar. Escolha JSON ou CSV, ou ative a coluna de XML bruto para capturar o XML completo de cada evento. O arquivo é baixado localmente.",
      },
    ],
    faqHeading: "Perguntas frequentes sobre a conversão de EVTX",
    faq: [
      {
        q: "O conversor de EVTX é gratuito e ele envia meu arquivo?",
        a: "É gratuito e nada é enviado. O .evtx é lido na memória do seu navegador e analisado localmente com um parser Rust/WebAssembly; você pode se desconectar da rede e ele continua funcionando.",
      },
      {
        q: "Como converto EVTX para XML sem o Windows?",
        a: "Use este conversor no navegador no Linux ou macOS, ou a ferramenta de linha de comando evtx_dump. Ambos reconstroem o XML dos eventos offline — sem Event Viewer, wevtutil ou um runtime do Windows.",
      },
      {
        q: "Posso converter um arquivo EVTX grande ou vários arquivos?",
        a: "Sim. Algumas centenas de MB são tranquilas em um navegador moderno, e você pode carregar vários arquivos .evtx e exportá-los como um único CSV ou JSON combinado.",
      },
    ],
  },
  ja: {
    metaTitle: "EVTX を XML・JSON・CSV に変換 — 無料・アップロード不要",
    metaDescription:
      "Windows の .evtx イベントログをブラウザで XML、JSON、CSV に変換。無料のオンライン EVTX コンバーター — アップロード不要、インストール不要。各レコードの生 XML はローカルで再構築されます。",
    h1: "EVTX を XML、JSON、CSV に変換",
    intro:
      "Windows の .evtx イベントログを、ブラウザ上で直接きれいな XML、JSON、CSV に変換します。解析と変換は WebAssembly にコンパイルされた Rust パーサーによってクライアント側で実行されるため、ファイルがデバイスから出ることはありません — アップロード不要、インストール不要、Windows ホストも不要です。",
    ctaLabel: "EVTX コンバーターを開く",
    formatsHeading: "どの形式が必要ですか？",
    formats: [
      {
        name: "EVTX から XML へ",
        body: ".evtx ファイル内の各イベントは、テンプレートテーブルに対して BinXML として格納されています。コンバーターは各レコードについて正確な <Event> XML を再構築します — wevtutil や Get-WinEvent が出力するのと同じ構造です — ので、grep や diff を行ったり、XML に対応したパイプラインに渡したりできます。",
      },
      {
        name: "EVTX から JSON へ",
        body: "JSON エクスポートは、各レコードの System ブロックと EventData フィールドをイベントごとに 1 つのオブジェクトへ平坦化し、jq、SIEM の取り込み経路、ノートブックですぐに使えるようにします。両方が必要な場合は、解析済みフィールドと並んでイベントの生 XML も含まれます。",
      },
      {
        name: "EVTX から CSV へ",
        body: "CSV エクスポートでは、共通の列（レコード、時刻、レベル、Event ID、プロバイダー、チャネル、コンピューター）を持つイベントごとに 1 行が得られます。まず単一の Event ID で絞り込むと EventData のキーが実際の列になり、結果をそのまま Excel で開けます。",
      },
    ],
    stepsHeading: "EVTX ファイルの変換方法",
    steps: [
      {
        title: "コンバーターを開く",
        body: "EVTX parser のホームページを開きます。何もアップロードされません — ページはブラウザのタブ内で完全に動作する WebAssembly パーサーを読み込みます。",
      },
      {
        title: ".evtx ファイルをドロップする",
        body: ".evtx ファイル（Security.evtx、System.evtx、Sysmon、PowerShell…）をドロップゾーンにドラッグするか、クリックして選択します。複数のファイルを一度にドロップして、まとめて変換することもできます。",
      },
      {
        title: "XML、JSON、CSV にエクスポートする",
        body: "必要に応じてフィルタリングや並べ替えを行い、エクスポートをクリックします。JSON か CSV を選ぶか、生 XML 列を有効にして各イベントの完全な XML を取り込みます。ファイルはローカルにダウンロードされます。",
      },
    ],
    faqHeading: "EVTX 変換に関する FAQ",
    faq: [
      {
        q: "EVTX コンバーターは無料ですか？ファイルはアップロードされますか？",
        a: "無料で、何もアップロードされません。.evtx はブラウザのメモリに読み込まれ、Rust/WebAssembly パーサーでローカルに解析されます。ネットワークを切断しても動作します。",
      },
      {
        q: "Windows を使わずに EVTX を XML に変換するには？",
        a: "Linux や macOS でこのブラウザ内コンバーターを使うか、evtx_dump CLI を使います。どちらもイベントの XML をオフラインで再構築します — Event Viewer、wevtutil、Windows ランタイムは不要です。",
      },
      {
        q: "大きな EVTX ファイルや複数の EVTX ファイルを変換できますか？",
        a: "はい。最新のブラウザなら数百 MB は快適に扱え、複数の .evtx ファイルを読み込んで、1 つの結合された CSV または JSON としてエクスポートできます。",
      },
    ],
  },
  zh: {
    metaTitle: "将 EVTX 转换为 XML、JSON 或 CSV——免费在线，无需上传",
    metaDescription:
      "在浏览器中将 Windows .evtx 事件日志转换为 XML、JSON 或 CSV。免费的在线 EVTX 转换器——无需上传，无需安装。每条记录的原始 XML 均在本地重建。",
    h1: "将 EVTX 转换为 XML、JSON 或 CSV",
    intro:
      "直接在浏览器中将 Windows .evtx 事件日志转换为干净的 XML、JSON 或 CSV。解析和转换通过编译为 WebAssembly 的 Rust 解析器在客户端运行，因此文件绝不会离开您的设备——无需上传，无需安装，也无需 Windows 主机。",
    ctaLabel: "打开 EVTX 转换器",
    formatsHeading: "您需要哪种格式？",
    formats: [
      {
        name: "EVTX 转 XML",
        body: ".evtx 文件中的每个事件都以 BinXML 形式相对于模板表存储。转换器为每条记录重建准确的 <Event> XML——与 wevtutil 或 Get-WinEvent 输出的结构相同——因此您可以对其执行 grep、diff，或将其输入支持 XML 的流水线。",
      },
      {
        name: "EVTX 转 JSON",
        body: "JSON 导出将每条记录的 System 块和 EventData 字段扁平化为每个事件一个对象，可直接用于 jq、SIEM 摄取路径或 notebook。当您同时需要两者时，事件的原始 XML 会与解析后的字段一并包含在内。",
      },
      {
        name: "EVTX 转 CSV",
        body: "CSV 导出为每个事件提供一行，包含常用列（记录、时间、级别、Event ID、提供程序、通道、计算机）。先筛选到单个 Event ID，EventData 的键就会变成真正的列——直接在 Excel 中打开结果即可。",
      },
    ],
    stepsHeading: "如何转换 EVTX 文件",
    steps: [
      {
        title: "打开转换器",
        body: "打开 EVTX parser 主页。不会上传任何内容——页面会加载一个完全在您浏览器标签页中运行的 WebAssembly 解析器。",
      },
      {
        title: "拖入您的 .evtx 文件",
        body: "将 .evtx 文件（Security.evtx、System.evtx、Sysmon、PowerShell…）拖到拖放区，或单击选择一个。您可以一次拖入多个文件，将它们一起转换。",
      },
      {
        title: "导出为 XML、JSON 或 CSV",
        body: "如有需要可先筛选或排序，然后单击导出。选择 JSON 或 CSV，或启用原始 XML 列以捕获每个事件的完整 XML。文件将下载到本地。",
      },
    ],
    faqHeading: "EVTX 转换常见问题",
    faq: [
      {
        q: "EVTX 转换器是免费的吗？它会上传我的文件吗？",
        a: "它是免费的，并且不会上传任何内容。.evtx 会被读入您浏览器的内存，并使用 Rust/WebAssembly 解析器在本地解析；即使断开网络连接它仍可正常工作。",
      },
      {
        q: "如何在没有 Windows 的情况下将 EVTX 转换为 XML？",
        a: "在 Linux 或 macOS 上使用这个浏览器内转换器，或使用 evtx_dump 命令行工具。两者都能离线重建事件 XML——无需 Event Viewer、wevtutil 或 Windows 运行时。",
      },
      {
        q: "我可以转换大型 EVTX 文件或多个文件吗？",
        a: "可以。在现代浏览器中处理几百 MB 毫无压力，您还可以加载多个 .evtx 文件，并将它们导出为一个合并的 CSV 或 JSON。",
      },
    ],
  },
};
