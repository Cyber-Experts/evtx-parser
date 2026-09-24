import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";

export const EVTX_VIEWER_MAC_LINUX: LocaleContent<LandingContent> = {
  en: {
    metaTitle: "EVTX Viewer for Mac & Linux — open .evtx files without Windows",
    metaDescription:
      "How to open an .evtx file on macOS or Linux. Free browser-based EVTX viewer — no upload, no install — plus the command-line options: evtx_dump, python-evtx, Chainsaw.",
    h1: "Open EVTX files on Mac and Linux",
    intro:
      "Event Viewer only exists on Windows, but .evtx files often end up on a Mac or a Linux analysis box. The quickest option is this browser-based EVTX viewer: it runs in Safari, Chrome or Firefox on any OS, parses the file locally with WebAssembly and never uploads it.",
    ctaLabel: "Open the EVTX viewer",
    formatsHeading: "Your options on macOS and Linux",
    formats: [
      {
        name: "In the browser (no install)",
        body: "Drop the .evtx on the EVTX parser homepage. You get a searchable table, an Event ID breakdown, a timeline, built-in detections and CSV, TXT, JSON or XML export. It works the same on macOS, Linux and ChromeOS.",
      },
      {
        name: "evtx_dump (Rust CLI)",
        body: "The fastest command-line parser, with prebuilt macOS and Linux binaries. Outputs XML, JSON or JSON Lines.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "A pure-Python library and script, handy inside notebooks and existing Python tooling. Slower than the Rust parser on large logs.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw or Hayabusa",
        body: "Cross-platform hunting tools that run Sigma rules over a folder of .evtx files. Use them when you want detections across many logs rather than to browse one.",
      },
    ],
    stepsHeading: "How to open an EVTX file on a Mac",
    steps: [
      {
        title: "Copy the .evtx off the Windows host",
        body: "Logs live in C:\\Windows\\System32\\winevt\\Logs. Copy the files you need (Security.evtx, System.evtx…) or export them from Event Viewer with Save All Events As.",
      },
      {
        title: "Open EVTX parser in your browser",
        body: "Safari, Chrome and Firefox all work. The parser loads once and then runs offline.",
      },
      {
        title: "Drop the file and explore",
        body: "Drag the .evtx onto the page. Filter by Event ID, user or time, open any event's raw XML, and export what you need.",
      },
    ],
    faqHeading: "EVTX on Mac and Linux FAQ",
    faq: [
      {
        q: "Can I open an EVTX file on a Mac?",
        a: "Yes. macOS has no built-in viewer for Windows event logs, but a browser-based viewer like this one or a command-line parser such as evtx_dump reads the file directly. No Windows virtual machine is required.",
      },
      {
        q: "How do I open an EVTX file on Linux?",
        a: "Open it in this browser-based viewer, or use evtx_dump or python-evtx from a terminal. All three parse the binary format natively on Linux.",
      },
      {
        q: "Will I see the same message text as Event Viewer?",
        a: "You see every structured field of each event. The friendly message sentence is rendered on Windows from provider DLLs that are not part of the .evtx, so no macOS or Linux tool can reproduce it exactly.",
      },
      {
        q: "Is it safe to open sensitive logs in a browser?",
        a: "With this viewer, yes: the file is parsed inside your browser tab and never sent anywhere. You can disconnect from the network after the page loads to confirm it.",
      },
    ],
  },
  fr: {
    metaTitle: "Ouvrir un fichier EVTX sur Mac et Linux — sans Windows",
    metaDescription:
      "Comment ouvrir un fichier .evtx sous macOS ou Linux. Lecteur EVTX gratuit en ligne — sans envoi, sans installation — plus les options en ligne de commande : evtx_dump, python-evtx, Chainsaw.",
    h1: "Ouvrir des fichiers EVTX sur Mac et Linux",
    intro:
      "L'Observateur d'événements n'existe que sous Windows, mais les fichiers .evtx se retrouvent souvent sur un Mac ou une machine d'analyse Linux. L'option la plus rapide est ce lecteur EVTX dans le navigateur : il fonctionne dans Safari, Chrome ou Firefox sur n'importe quel OS, analyse le fichier localement avec WebAssembly et ne l'envoie jamais.",
    ctaLabel: "Ouvrir le lecteur EVTX",
    formatsHeading: "Vos options sur macOS et Linux",
    formats: [
      {
        name: "Dans le navigateur (sans installation)",
        body: "Déposez le .evtx sur la page d'accueil d'EVTX parser. Vous obtenez un tableau consultable, une répartition par Event ID, une chronologie, des détections intégrées et un export CSV, TXT, JSON ou XML. Cela fonctionne de la même façon sur macOS, Linux et ChromeOS.",
      },
      {
        name: "evtx_dump (CLI Rust)",
        body: "L'analyseur en ligne de commande le plus rapide, avec des binaires précompilés pour macOS et Linux. Produit du XML, du JSON ou du JSON Lines.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "Une bibliothèque et un script purement Python, pratiques dans des notebooks et avec l'outillage Python existant. Plus lent que l'analyseur Rust sur de gros journaux.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw ou Hayabusa",
        body: "Des outils de chasse multiplateformes qui exécutent des règles Sigma sur un dossier de fichiers .evtx. Utilisez-les pour obtenir des détections sur de nombreux journaux plutôt que pour parcourir un seul fichier.",
      },
    ],
    stepsHeading: "Comment ouvrir un fichier EVTX sur un Mac",
    steps: [
      {
        title: "Copiez le .evtx depuis l'hôte Windows",
        body: "Les journaux se trouvent dans C:\\Windows\\System32\\winevt\\Logs. Copiez les fichiers dont vous avez besoin (Security.evtx, System.evtx…) ou exportez-les depuis l'Observateur d'événements avec « Enregistrer tous les événements sous ».",
      },
      {
        title: "Ouvrez EVTX parser dans votre navigateur",
        body: "Safari, Chrome et Firefox fonctionnent tous. L'analyseur se charge une fois puis s'exécute hors ligne.",
      },
      {
        title: "Déposez le fichier et explorez",
        body: "Glissez le .evtx sur la page. Filtrez par Event ID, utilisateur ou heure, ouvrez le XML brut de n'importe quel événement, et exportez ce dont vous avez besoin.",
      },
    ],
    faqHeading: "FAQ EVTX sur Mac et Linux",
    faq: [
      {
        q: "Puis-je ouvrir un fichier EVTX sur un Mac ?",
        a: "Oui. macOS n'a pas de lecteur intégré pour les journaux d'événements Windows, mais un lecteur dans le navigateur comme celui-ci ou un analyseur en ligne de commande comme evtx_dump lit le fichier directement. Aucune machine virtuelle Windows n'est nécessaire.",
      },
      {
        q: "Comment ouvrir un fichier EVTX sous Linux ?",
        a: "Ouvrez-le dans ce lecteur dans le navigateur, ou utilisez evtx_dump ou python-evtx depuis un terminal. Les trois analysent le format binaire nativement sous Linux.",
      },
      {
        q: "Verrai-je le même texte de message que dans l'Observateur d'événements ?",
        a: "Vous voyez chaque champ structuré de chaque événement. La phrase de message conviviale est générée sous Windows à partir de DLL de fournisseur qui ne font pas partie du .evtx, donc aucun outil macOS ou Linux ne peut la reproduire exactement.",
      },
      {
        q: "Est-il sûr d'ouvrir des journaux sensibles dans un navigateur ?",
        a: "Avec ce lecteur, oui : le fichier est analysé dans l'onglet de votre navigateur et n'est jamais envoyé nulle part. Vous pouvez vous déconnecter du réseau après le chargement de la page pour le vérifier.",
      },
    ],
  },
  de: {
    metaTitle: "EVTX-Datei auf Mac & Linux öffnen — ohne Windows",
    metaDescription:
      "So öffnen Sie eine .evtx-Datei unter macOS oder Linux. Kostenloser browserbasierter EVTX-Viewer — ohne Upload, ohne Installation — plus die Kommandozeilen-Optionen: evtx_dump, python-evtx, Chainsaw.",
    h1: "EVTX-Dateien unter Mac und Linux öffnen",
    intro:
      "Die Ereignisanzeige gibt es nur unter Windows, aber .evtx-Dateien landen oft auf einem Mac oder einer Linux-Analysestation. Die schnellste Option ist dieser browserbasierte EVTX-Viewer: Er läuft in Safari, Chrome oder Firefox auf jedem Betriebssystem, parst die Datei lokal mit WebAssembly und lädt sie nie hoch.",
    ctaLabel: "EVTX-Viewer öffnen",
    formatsHeading: "Ihre Optionen unter macOS und Linux",
    formats: [
      {
        name: "Im Browser (keine Installation)",
        body: "Legen Sie die .evtx auf der Startseite von EVTX parser ab. Sie erhalten eine durchsuchbare Tabelle, eine Event-ID-Aufschlüsselung, eine Zeitleiste, integrierte Erkennungen sowie CSV-, TXT-, JSON- oder XML-Export. Das funktioniert auf macOS, Linux und ChromeOS gleichermaßen.",
      },
      {
        name: "evtx_dump (Rust-CLI)",
        body: "Der schnellste Kommandozeilen-Parser, mit vorgefertigten macOS- und Linux-Binaries. Gibt XML, JSON oder JSON Lines aus.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "Eine reine Python-Bibliothek samt Skript, praktisch in Notebooks und bestehendem Python-Tooling. Bei großen Protokollen langsamer als der Rust-Parser.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw oder Hayabusa",
        body: "Plattformübergreifende Hunting-Tools, die Sigma-Regeln über einen Ordner voller .evtx-Dateien laufen lassen. Nutzen Sie sie, wenn Sie Erkennungen über viele Protokolle hinweg statt nur ein einzelnes zu durchsuchen wünschen.",
      },
    ],
    stepsHeading: "So öffnen Sie eine EVTX-Datei auf einem Mac",
    steps: [
      {
        title: "Kopieren Sie die .evtx vom Windows-Host",
        body: "Protokolle liegen unter C:\\Windows\\System32\\winevt\\Logs. Kopieren Sie die benötigten Dateien (Security.evtx, System.evtx…) oder exportieren Sie sie aus der Ereignisanzeige mit „Alle Ereignisse speichern unter“.",
      },
      {
        title: "Öffnen Sie EVTX parser in Ihrem Browser",
        body: "Safari, Chrome und Firefox funktionieren alle. Der Parser wird einmal geladen und läuft danach offline.",
      },
      {
        title: "Datei ablegen und erkunden",
        body: "Ziehen Sie die .evtx auf die Seite. Filtern Sie nach Event ID, Benutzer oder Zeit, öffnen Sie das rohe XML jedes Ereignisses und exportieren Sie, was Sie brauchen.",
      },
    ],
    faqHeading: "FAQ zu EVTX unter Mac und Linux",
    faq: [
      {
        q: "Kann ich eine EVTX-Datei auf einem Mac öffnen?",
        a: "Ja. macOS hat keinen integrierten Viewer für Windows-Ereignisprotokolle, aber ein browserbasierter Viewer wie dieser oder ein Kommandozeilen-Parser wie evtx_dump liest die Datei direkt. Es ist keine Windows-VM erforderlich.",
      },
      {
        q: "Wie öffne ich eine EVTX-Datei unter Linux?",
        a: "Öffnen Sie sie in diesem browserbasierten Viewer, oder verwenden Sie evtx_dump oder python-evtx aus einem Terminal. Alle drei parsen das Binärformat nativ unter Linux.",
      },
      {
        q: "Sehe ich denselben Meldungstext wie in der Ereignisanzeige?",
        a: "Sie sehen jedes strukturierte Feld jedes Ereignisses. Der freundliche Meldungssatz wird unter Windows aus Anbieter-DLLs gerendert, die nicht Teil der .evtx sind, sodass kein macOS- oder Linux-Tool ihn exakt reproduzieren kann.",
      },
      {
        q: "Ist es sicher, sensible Protokolle in einem Browser zu öffnen?",
        a: "Mit diesem Viewer ja: Die Datei wird innerhalb Ihres Browser-Tabs geparst und niemals irgendwohin gesendet. Sie können nach dem Laden der Seite die Netzwerkverbindung trennen, um das zu bestätigen.",
      },
    ],
  },
  es: {
    metaTitle: "Visor de EVTX para Mac y Linux — abrir .evtx sin Windows",
    metaDescription:
      "Cómo abrir un archivo .evtx en macOS o Linux. Visor de EVTX gratuito en el navegador — sin subir nada, sin instalar — además de las opciones de línea de comandos: evtx_dump, python-evtx, Chainsaw.",
    h1: "Abrir archivos EVTX en Mac y Linux",
    intro:
      "El Visor de eventos solo existe en Windows, pero los archivos .evtx a menudo acaban en un Mac o en una máquina de análisis Linux. La opción más rápida es este visor de EVTX en el navegador: funciona en Safari, Chrome o Firefox en cualquier sistema operativo, analiza el archivo localmente con WebAssembly y nunca lo sube.",
    ctaLabel: "Abrir el visor de EVTX",
    formatsHeading: "Tus opciones en macOS y Linux",
    formats: [
      {
        name: "En el navegador (sin instalar)",
        body: "Suelta el .evtx en la página de inicio de EVTX parser. Obtienes una tabla con búsqueda, un desglose por Event ID, una línea de tiempo, detecciones integradas y exportación a CSV, TXT, JSON o XML. Funciona igual en macOS, Linux y ChromeOS.",
      },
      {
        name: "evtx_dump (CLI en Rust)",
        body: "El analizador de línea de comandos más rápido, con binarios precompilados para macOS y Linux. Genera XML, JSON o JSON Lines.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "Una biblioteca y un script en Python puro, útiles en notebooks y en herramientas Python ya existentes. Más lento que el analizador en Rust con registros grandes.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw o Hayabusa",
        body: "Herramientas de caza multiplataforma que ejecutan reglas Sigma sobre una carpeta de archivos .evtx. Úsalas cuando quieras detecciones en muchos registros en lugar de explorar uno solo.",
      },
    ],
    stepsHeading: "Cómo abrir un archivo EVTX en un Mac",
    steps: [
      {
        title: "Copia el .evtx desde el host Windows",
        body: "Los registros están en C:\\Windows\\System32\\winevt\\Logs. Copia los archivos que necesites (Security.evtx, System.evtx…) o expórtalos desde el Visor de eventos con «Guardar todos los eventos como».",
      },
      {
        title: "Abre EVTX parser en tu navegador",
        body: "Safari, Chrome y Firefox funcionan todos. El analizador se carga una vez y luego funciona sin conexión.",
      },
      {
        title: "Suelta el archivo y explora",
        body: "Arrastra el .evtx a la página. Filtra por Event ID, usuario o momento, abre el XML sin procesar de cualquier evento y exporta lo que necesites.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre EVTX en Mac y Linux",
    faq: [
      {
        q: "¿Puedo abrir un archivo EVTX en un Mac?",
        a: "Sí. macOS no tiene un visor integrado para los registros de eventos de Windows, pero un visor en el navegador como este o un analizador de línea de comandos como evtx_dump lee el archivo directamente. No se necesita ninguna máquina virtual Windows.",
      },
      {
        q: "¿Cómo abro un archivo EVTX en Linux?",
        a: "Ábrelo en este visor en el navegador, o usa evtx_dump o python-evtx desde una terminal. Los tres analizan el formato binario de forma nativa en Linux.",
      },
      {
        q: "¿Veré el mismo texto de mensaje que en el Visor de eventos?",
        a: "Verás todos los campos estructurados de cada evento. La frase del mensaje amigable se genera en Windows a partir de DLL de proveedor que no forman parte del .evtx, así que ninguna herramienta de macOS o Linux puede reproducirla exactamente.",
      },
      {
        q: "¿Es seguro abrir registros sensibles en un navegador?",
        a: "Con este visor, sí: el archivo se analiza dentro de la pestaña de tu navegador y nunca se envía a ningún sitio. Puedes desconectarte de la red después de cargar la página para confirmarlo.",
      },
    ],
  },
  it: {
    metaTitle: "Visualizzatore EVTX per Mac e Linux — aprire .evtx senza Windows",
    metaDescription:
      "Come aprire un file .evtx su macOS o Linux. Visualizzatore EVTX gratuito nel browser — senza upload, senza installazione — più le opzioni da riga di comando: evtx_dump, python-evtx, Chainsaw.",
    h1: "Aprire file EVTX su Mac e Linux",
    intro:
      "Il Visualizzatore eventi esiste solo su Windows, ma i file .evtx finiscono spesso su un Mac o su una macchina di analisi Linux. L'opzione più rapida è questo visualizzatore EVTX nel browser: funziona in Safari, Chrome o Firefox su qualsiasi sistema operativo, analizza il file localmente con WebAssembly e non lo carica mai.",
    ctaLabel: "Apri il visualizzatore EVTX",
    formatsHeading: "Le tue opzioni su macOS e Linux",
    formats: [
      {
        name: "Nel browser (senza installazione)",
        body: "Rilascia il .evtx sulla homepage di EVTX parser. Ottieni una tabella ricercabile, una ripartizione per Event ID, una timeline, rilevamenti integrati ed esportazione in CSV, TXT, JSON o XML. Funziona allo stesso modo su macOS, Linux e ChromeOS.",
      },
      {
        name: "evtx_dump (CLI Rust)",
        body: "Il parser da riga di comando più veloce, con binari precompilati per macOS e Linux. Produce XML, JSON o JSON Lines.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "Una libreria e uno script in puro Python, comodi nei notebook e con gli strumenti Python già esistenti. Più lento del parser Rust sui log di grandi dimensioni.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw o Hayabusa",
        body: "Strumenti di hunting multipiattaforma che eseguono regole Sigma su una cartella di file .evtx. Usali quando vuoi rilevamenti su molti log invece di sfogliarne uno solo.",
      },
    ],
    stepsHeading: "Come aprire un file EVTX su un Mac",
    steps: [
      {
        title: "Copia il .evtx dall'host Windows",
        body: "I log si trovano in C:\\Windows\\System32\\winevt\\Logs. Copia i file che ti servono (Security.evtx, System.evtx…) oppure esportali dal Visualizzatore eventi con «Salva tutti gli eventi con nome».",
      },
      {
        title: "Apri EVTX parser nel tuo browser",
        body: "Safari, Chrome e Firefox funzionano tutti. Il parser si carica una volta e poi funziona offline.",
      },
      {
        title: "Rilascia il file ed esplora",
        body: "Trascina il .evtx sulla pagina. Filtra per Event ID, utente o ora, apri l'XML grezzo di qualsiasi evento ed esporta ciò che ti serve.",
      },
    ],
    faqHeading: "FAQ su EVTX su Mac e Linux",
    faq: [
      {
        q: "Posso aprire un file EVTX su un Mac?",
        a: "Sì. macOS non ha un visualizzatore integrato per i log eventi di Windows, ma un visualizzatore nel browser come questo o un parser da riga di comando come evtx_dump legge il file direttamente. Non serve alcuna macchina virtuale Windows.",
      },
      {
        q: "Come apro un file EVTX su Linux?",
        a: "Aprilo in questo visualizzatore nel browser, oppure usa evtx_dump o python-evtx da un terminale. Tutti e tre analizzano il formato binario nativamente su Linux.",
      },
      {
        q: "Vedrò lo stesso testo del messaggio del Visualizzatore eventi?",
        a: "Vedrai ogni campo strutturato di ciascun evento. La frase del messaggio descrittivo viene generata su Windows a partire da DLL del provider che non fanno parte del .evtx, quindi nessuno strumento macOS o Linux può riprodurla esattamente.",
      },
      {
        q: "È sicuro aprire log sensibili in un browser?",
        a: "Con questo visualizzatore sì: il file viene analizzato all'interno della scheda del browser e non viene mai inviato da nessuna parte. Puoi disconnetterti dalla rete dopo il caricamento della pagina per verificarlo.",
      },
    ],
  },
  pt: {
    metaTitle: "Visualizador de EVTX para Mac e Linux — abrir .evtx sem Windows",
    metaDescription:
      "Como abrir um arquivo .evtx no macOS ou Linux. Visualizador de EVTX gratuito no navegador — sem upload, sem instalação — além das opções de linha de comando: evtx_dump, python-evtx, Chainsaw.",
    h1: "Abrir arquivos EVTX no Mac e no Linux",
    intro:
      "O Visualizador de Eventos só existe no Windows, mas os arquivos .evtx frequentemente acabam em um Mac ou em uma máquina de análise Linux. A opção mais rápida é este visualizador de EVTX no navegador: ele roda no Safari, Chrome ou Firefox em qualquer sistema operacional, analisa o arquivo localmente com WebAssembly e nunca o envia.",
    ctaLabel: "Abrir o visualizador de EVTX",
    formatsHeading: "Suas opções no macOS e no Linux",
    formats: [
      {
        name: "No navegador (sem instalação)",
        body: "Solte o .evtx na página inicial do EVTX parser. Você obtém uma tabela pesquisável, uma repartição por Event ID, uma linha do tempo, detecções integradas e exportação para CSV, TXT, JSON ou XML. Funciona da mesma forma no macOS, Linux e ChromeOS.",
      },
      {
        name: "evtx_dump (CLI em Rust)",
        body: "O analisador de linha de comando mais rápido, com binários pré-compilados para macOS e Linux. Gera XML, JSON ou JSON Lines.",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "Uma biblioteca e um script em Python puro, úteis em notebooks e em ferramentas Python já existentes. Mais lento que o analisador em Rust em logs grandes.",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw ou Hayabusa",
        body: "Ferramentas de hunting multiplataforma que executam regras Sigma sobre uma pasta de arquivos .evtx. Use-as quando quiser detecções em muitos logs em vez de navegar por apenas um.",
      },
    ],
    stepsHeading: "Como abrir um arquivo EVTX em um Mac",
    steps: [
      {
        title: "Copie o .evtx do host Windows",
        body: "Os logs ficam em C:\\Windows\\System32\\winevt\\Logs. Copie os arquivos de que precisa (Security.evtx, System.evtx…) ou exporte-os do Visualizador de Eventos com «Salvar Todos os Eventos Como».",
      },
      {
        title: "Abra o EVTX parser no seu navegador",
        body: "Safari, Chrome e Firefox funcionam todos. O analisador é carregado uma vez e depois roda offline.",
      },
      {
        title: "Solte o arquivo e explore",
        body: "Arraste o .evtx para a página. Filtre por Event ID, usuário ou horário, abra o XML bruto de qualquer evento e exporte o que precisar.",
      },
    ],
    faqHeading: "Perguntas frequentes sobre EVTX no Mac e no Linux",
    faq: [
      {
        q: "Posso abrir um arquivo EVTX em um Mac?",
        a: "Sim. O macOS não tem um visualizador integrado para logs de eventos do Windows, mas um visualizador no navegador como este ou um analisador de linha de comando como o evtx_dump lê o arquivo diretamente. Nenhuma máquina virtual Windows é necessária.",
      },
      {
        q: "Como abro um arquivo EVTX no Linux?",
        a: "Abra-o neste visualizador no navegador, ou use evtx_dump ou python-evtx a partir de um terminal. Os três analisam o formato binário nativamente no Linux.",
      },
      {
        q: "Verei o mesmo texto de mensagem que o Visualizador de Eventos?",
        a: "Você vê todos os campos estruturados de cada evento. A frase de mensagem amigável é renderizada no Windows a partir de DLLs de provedor que não fazem parte do .evtx, então nenhuma ferramenta macOS ou Linux pode reproduzi-la exatamente.",
      },
      {
        q: "É seguro abrir logs sensíveis em um navegador?",
        a: "Com este visualizador, sim: o arquivo é analisado dentro da aba do seu navegador e nunca é enviado a lugar nenhum. Você pode se desconectar da rede depois que a página carregar para confirmar isso.",
      },
    ],
  },
  ja: {
    metaTitle: "Mac・Linux 用 EVTX ビューアー — Windows 不要で .evtx を開く",
    metaDescription:
      "macOS や Linux で .evtx ファイルを開く方法。無料のブラウザベース EVTX ビューアー — アップロード不要、インストール不要 — に加え、evtx_dump、python-evtx、Chainsaw などのコマンドラインの選択肢。",
    h1: "Mac と Linux で EVTX ファイルを開く",
    intro:
      "イベント ビューアーは Windows にしか存在しませんが、.evtx ファイルは Mac や Linux の解析マシンに渡ることがよくあります。最も手早い方法はこのブラウザベースの EVTX ビューアーです。Safari、Chrome、Firefox のどの OS でも動作し、WebAssembly でファイルをローカルに解析し、アップロードは一切行いません。",
    ctaLabel: "EVTX ビューアーを開く",
    formatsHeading: "macOS と Linux での選択肢",
    formats: [
      {
        name: "ブラウザ内（インストール不要）",
        body: "EVTX parser のホームページに .evtx をドロップします。検索可能なテーブル、Event ID の内訳、タイムライン、組み込みの検知、そして CSV、TXT、JSON、XML へのエクスポートが得られます。macOS、Linux、ChromeOS で同じように動作します。",
      },
      {
        name: "evtx_dump（Rust 製 CLI）",
        body: "最速のコマンドラインパーサーで、macOS・Linux 向けのビルド済みバイナリがあります。XML、JSON、JSON Lines を出力します。",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "純粋な Python 製のライブラリとスクリプトで、ノートブックや既存の Python ツールの中で便利に使えます。大きなログでは Rust パーサーより低速です。",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw または Hayabusa",
        body: ".evtx ファイルのフォルダーに対して Sigma ルールを実行するクロスプラットフォームのハンティングツールです。1 つのログを閲覧するのではなく、多数のログにわたる検知が欲しいときに使います。",
      },
    ],
    stepsHeading: "Mac で EVTX ファイルを開く方法",
    steps: [
      {
        title: ".evtx を Windows ホストからコピーする",
        body: "ログは C:\\Windows\\System32\\winevt\\Logs にあります。必要なファイル（Security.evtx、System.evtx…）をコピーするか、イベント ビューアーの「すべてのイベントを名前を付けて保存」からエクスポートします。",
      },
      {
        title: "ブラウザで EVTX parser を開く",
        body: "Safari、Chrome、Firefox のいずれでも動作します。パーサーは一度読み込まれた後、オフラインで動作します。",
      },
      {
        title: "ファイルをドロップして調べる",
        body: ".evtx をページにドラッグします。Event ID、ユーザー、時刻でフィルタリングし、任意のイベントの生 XML を開き、必要なものをエクスポートします。",
      },
    ],
    faqHeading: "Mac と Linux での EVTX に関する FAQ",
    faq: [
      {
        q: "Mac で EVTX ファイルを開けますか？",
        a: "はい。macOS には Windows のイベントログ用の標準ビューアーはありませんが、このようなブラウザベースのビューアーや evtx_dump のようなコマンドラインパーサーがファイルを直接読み取ります。Windows の仮想マシンは不要です。",
      },
      {
        q: "Linux で EVTX ファイルを開くにはどうすればよいですか？",
        a: "このブラウザベースのビューアーで開くか、ターミナルから evtx_dump や python-evtx を使用します。3 つとも Linux 上でバイナリ形式をネイティブに解析します。",
      },
      {
        q: "イベント ビューアーと同じメッセージ文が表示されますか？",
        a: "各イベントのすべての構造化フィールドが表示されます。わかりやすいメッセージ文は、.evtx には含まれないプロバイダー DLL から Windows 上でレンダリングされるため、macOS や Linux のツールで正確に再現することはできません。",
      },
      {
        q: "機密性の高いログをブラウザで開いても安全ですか？",
        a: "このビューアーであれば安全です。ファイルはブラウザのタブ内で解析され、どこにも送信されません。ページの読み込み後にネットワークを切断して確認することもできます。",
      },
    ],
  },
  zh: {
    metaTitle: "Mac 和 Linux 版 EVTX 查看器——无需 Windows 打开 .evtx",
    metaDescription:
      "如何在 macOS 或 Linux 上打开 .evtx 文件。免费的浏览器端 EVTX 查看器——无需上传，无需安装——以及命令行选项：evtx_dump、python-evtx、Chainsaw。",
    h1: "在 Mac 和 Linux 上打开 EVTX 文件",
    intro:
      "事件查看器只存在于 Windows 上，但 .evtx 文件经常最终出现在 Mac 或 Linux 分析主机上。最快的方法是这个基于浏览器的 EVTX 查看器：它可在任何操作系统的 Safari、Chrome 或 Firefox 中运行，使用 WebAssembly 在本地解析文件，绝不上传。",
    ctaLabel: "打开 EVTX 查看器",
    formatsHeading: "您在 macOS 和 Linux 上的选择",
    formats: [
      {
        name: "在浏览器中（无需安装）",
        body: "将 .evtx 拖放到 EVTX parser 主页上。您将获得可搜索的表格、按 Event ID 的分类统计、时间线、内置检测，以及 CSV、TXT、JSON 或 XML 导出。在 macOS、Linux 和 ChromeOS 上的表现完全相同。",
      },
      {
        name: "evtx_dump（Rust 命令行工具）",
        body: "最快的命令行解析器，提供预编译的 macOS 和 Linux 二进制文件。可输出 XML、JSON 或 JSON Lines。",
        code: "evtx_dump -o jsonl Security.evtx | jq 'select(.Event.System.EventID == 4624)'",
      },
      {
        name: "python-evtx",
        body: "纯 Python 库及脚本，在 notebook 和现有 Python 工具链中都很方便。处理大型日志时比 Rust 解析器慢。",
        code: "pip install python-evtx\nevtx_dump.py Security.evtx > security.xml",
      },
      {
        name: "Chainsaw 或 Hayabusa",
        body: "跨平台的威胁狩猎工具，可对一个文件夹中的 .evtx 文件批量运行 Sigma 规则。当您需要在大量日志中进行检测，而不是浏览单个文件时使用。",
      },
    ],
    stepsHeading: "如何在 Mac 上打开 EVTX 文件",
    steps: [
      {
        title: "从 Windows 主机复制 .evtx",
        body: "日志位于 C:\\Windows\\System32\\winevt\\Logs。复制您需要的文件（Security.evtx、System.evtx…），或从事件查看器中使用「将所有事件另存为」导出。",
      },
      {
        title: "在浏览器中打开 EVTX parser",
        body: "Safari、Chrome 和 Firefox 均可使用。解析器只需加载一次，之后即可离线运行。",
      },
      {
        title: "拖入文件并浏览",
        body: "将 .evtx 拖到页面上。按 Event ID、用户或时间筛选，打开任意事件的原始 XML，并导出您需要的内容。",
      },
    ],
    faqHeading: "关于 Mac 和 Linux 上 EVTX 的常见问题",
    faq: [
      {
        q: "我可以在 Mac 上打开 EVTX 文件吗？",
        a: "可以。macOS 没有内置的 Windows 事件日志查看器，但像这样的浏览器端查看器或 evtx_dump 这样的命令行解析器可以直接读取该文件。不需要任何 Windows 虚拟机。",
      },
      {
        q: "如何在 Linux 上打开 EVTX 文件？",
        a: "在这个浏览器端查看器中打开它，或者从终端使用 evtx_dump 或 python-evtx。这三者都能在 Linux 上原生解析该二进制格式。",
      },
      {
        q: "我看到的消息文本会和事件查看器中的一样吗？",
        a: "您会看到每个事件的所有结构化字段。友好的消息句子是 Windows 根据不属于 .evtx 的提供程序 DLL 渲染出来的，因此任何 macOS 或 Linux 工具都无法精确还原它。",
      },
      {
        q: "在浏览器中打开敏感日志安全吗？",
        a: "使用这个查看器是安全的：文件在您浏览器标签页内解析，绝不会发送到任何地方。您可以在页面加载后断开网络连接来验证这一点。",
      },
    ],
  },
};
