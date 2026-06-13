import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";
import { SITE_URL, canonicalFor, localeAlternates, OG_LOCALE } from "@/app/_lib/site";
import { pickLocale, type LocaleContent } from "./locale-content";

export type ChannelKey = "security" | "system";

export type ChannelContent = {
  metaTitle: string;
  metaDescription: string;
  h1: string;
  intro: string;
  ctaLabel: string;
  whatHeading: string;
  whatBody: string[];
  eventsHeading: string;
  events: { id: number; name: string }[];
  openHeading: string;
  openBody: string;
};

export const CHANNEL_PATH: Record<ChannelKey, string> = {
  security: "/security-evtx",
  system: "/system-evtx",
};

const SECURITY: LocaleContent<ChannelContent> = {
  en: {
    metaTitle: "Security.evtx explained — open & parse the Windows Security log",
    metaDescription:
      "What Security.evtx is, the Event IDs that matter for DFIR (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102), and how to open it in your browser — no upload, no install.",
    h1: "Security.evtx — the Windows Security event log",
    intro:
      "Security.evtx is the channel that records authentication, privilege use and account management on a Windows host. It is the single most important log in almost every incident response investigation, and you can open it here in your browser without Event Viewer or a Windows machine.",
    ctaLabel: "Open Security.evtx in your browser",
    whatHeading: "What is Security.evtx?",
    whatBody: [
      "Security.evtx lives in C:\\Windows\\System32\\winevt\\Logs alongside System.evtx and Application.evtx. It holds the Security channel: logon and logoff events, privilege assignments, process creation (with command-line auditing enabled), account and group changes, and Kerberos ticket activity emitted by the local Security Reference Monitor.",
      "Because it captures who authenticated, from where, and what they did, Security.evtx is where lateral movement, privilege escalation and persistence usually leave their first trace. It is also a prime anti-forensics target — event 1102 records that the log itself was cleared.",
    ],
    eventsHeading: "Key Security.evtx Event IDs",
    events: [
      { id: 4624, name: "Successful logon" },
      { id: 4625, name: "Failed logon" },
      { id: 4672, name: "Special privileges assigned" },
      { id: 4688, name: "Process creation" },
      { id: 4720, name: "User account created" },
      { id: 4768, name: "Kerberos TGT requested" },
      { id: 4769, name: "Kerberos service ticket requested" },
      { id: 1102, name: "Audit log cleared" },
    ],
    openHeading: "How to open a Security.evtx file",
    openBody:
      "Drop Security.evtx onto the parser above (or load it together with System.evtx and the Sysmon channel for cross-log triage). Parsing runs locally via a Rust/WebAssembly parser — the log never leaves your browser. Filter by Event ID, inspect each record's raw XML, and export to CSV, JSON or XML.",
  },
  fr: {
    metaTitle: "Security.evtx expliqué — ouvrir et analyser le journal Security",
    metaDescription:
      "Ce qu'est Security.evtx, les Event ID qui comptent pour le DFIR (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102) et comment l'ouvrir dans votre navigateur — sans envoi, sans installation.",
    h1: "Security.evtx — le journal d'événements de sécurité Windows",
    intro:
      "Security.evtx est le canal qui enregistre l'authentification, l'utilisation des privilèges et la gestion des comptes sur un hôte Windows. C'est le journal le plus important dans presque toutes les investigations de réponse à incident, et vous pouvez l'ouvrir ici dans votre navigateur sans Event Viewer ni machine Windows.",
    ctaLabel: "Ouvrir Security.evtx dans votre navigateur",
    whatHeading: "Qu'est-ce que Security.evtx ?",
    whatBody: [
      "Security.evtx se trouve dans C:\\Windows\\System32\\winevt\\Logs, aux côtés de System.evtx et Application.evtx. Il contient le canal Security : les événements de connexion et de déconnexion, les attributions de privilèges, la création de processus (avec l'audit de ligne de commande activé), les modifications de comptes et de groupes, et l'activité des tickets Kerberos émise par le Security Reference Monitor local.",
      "Parce qu'il capture qui s'est authentifié, depuis où et ce qu'il a fait, Security.evtx est l'endroit où le déplacement latéral, l'élévation de privilèges et la persistance laissent généralement leur première trace. C'est aussi une cible anti-forensique de premier plan — l'événement 1102 indique que le journal lui-même a été effacé.",
    ],
    eventsHeading: "Event ID clés de Security.evtx",
    events: [
      { id: 4624, name: "Connexion réussie" },
      { id: 4625, name: "Échec de connexion" },
      { id: 4672, name: "Privilèges spéciaux attribués" },
      { id: 4688, name: "Création de processus" },
      { id: 4720, name: "Compte utilisateur créé" },
      { id: 4768, name: "Demande de TGT Kerberos" },
      { id: 4769, name: "Demande de ticket de service Kerberos" },
      { id: 1102, name: "Journal d'audit effacé" },
    ],
    openHeading: "Comment ouvrir un fichier Security.evtx",
    openBody:
      "Déposez Security.evtx sur l'analyseur ci-dessus (ou chargez-le avec System.evtx et le canal Sysmon pour un tri inter-journaux). L'analyse s'exécute localement via un analyseur Rust/WebAssembly — le journal ne quitte jamais votre navigateur. Filtrez par Event ID, inspectez le XML brut de chaque enregistrement et exportez en CSV, JSON ou XML.",
  },
  de: {
    metaTitle: "Security.evtx erklärt — Windows-Sicherheitsprotokoll öffnen",
    metaDescription:
      "Was Security.evtx ist, die für DFIR relevanten Event IDs (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102) und wie Sie es im Browser öffnen — ohne Upload, ohne Installation.",
    h1: "Security.evtx — das Windows-Sicherheitsereignisprotokoll",
    intro:
      "Security.evtx ist der Kanal, der Authentifizierung, Rechtenutzung und Kontoverwaltung auf einem Windows-Host aufzeichnet. Es ist in fast jeder Incident-Response-Untersuchung das wichtigste Protokoll, und Sie können es hier im Browser öffnen — ohne Event Viewer oder einen Windows-Rechner.",
    ctaLabel: "Security.evtx im Browser öffnen",
    whatHeading: "Was ist Security.evtx?",
    whatBody: [
      "Security.evtx liegt in C:\\Windows\\System32\\winevt\\Logs neben System.evtx und Application.evtx. Es enthält den Security-Kanal: An- und Abmeldeereignisse, Rechtezuweisungen, Prozesserstellung (bei aktivierter Befehlszeilenüberwachung), Konto- und Gruppenänderungen sowie die Kerberos-Ticket-Aktivität, die der lokale Security Reference Monitor ausgibt.",
      "Weil es erfasst, wer sich von wo authentifiziert und was er getan hat, ist Security.evtx der Ort, an dem laterale Bewegung, Rechteausweitung und Persistenz meist ihre erste Spur hinterlassen. Es ist außerdem ein bevorzugtes Anti-Forensik-Ziel — Ereignis 1102 zeigt an, dass das Protokoll selbst gelöscht wurde.",
    ],
    eventsHeading: "Wichtige Event IDs von Security.evtx",
    events: [
      { id: 4624, name: "Erfolgreiche Anmeldung" },
      { id: 4625, name: "Fehlgeschlagene Anmeldung" },
      { id: 4672, name: "Besondere Rechte zugewiesen" },
      { id: 4688, name: "Prozesserstellung" },
      { id: 4720, name: "Benutzerkonto erstellt" },
      { id: 4768, name: "Kerberos-TGT angefordert" },
      { id: 4769, name: "Kerberos-Dienstticket angefordert" },
      { id: 1102, name: "Überwachungsprotokoll gelöscht" },
    ],
    openHeading: "So öffnen Sie eine Security.evtx-Datei",
    openBody:
      "Legen Sie Security.evtx auf den Parser oben ab (oder laden Sie es zusammen mit System.evtx und dem Sysmon-Kanal für eine protokollübergreifende Triage). Das Parsen läuft lokal über einen Rust/WebAssembly-Parser — das Protokoll verlässt nie Ihren Browser. Filtern Sie nach Event ID, untersuchen Sie das rohe XML jedes Datensatzes und exportieren Sie nach CSV, JSON oder XML.",
  },
  es: {
    metaTitle: "Security.evtx explicado — abrir y analizar el log de seguridad",
    metaDescription:
      "Qué es Security.evtx, los Event ID que importan para el DFIR (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102) y cómo abrirlo en tu navegador — sin subir nada, sin instalar.",
    h1: "Security.evtx — el registro de eventos de seguridad de Windows",
    intro:
      "Security.evtx es el canal que registra la autenticación, el uso de privilegios y la gestión de cuentas en un host Windows. Es el log más importante en casi toda investigación de respuesta a incidentes, y puedes abrirlo aquí en tu navegador sin Event Viewer ni una máquina Windows.",
    ctaLabel: "Abrir Security.evtx en tu navegador",
    whatHeading: "¿Qué es Security.evtx?",
    whatBody: [
      "Security.evtx reside en C:\\Windows\\System32\\winevt\\Logs junto a System.evtx y Application.evtx. Contiene el canal Security: eventos de inicio y cierre de sesión, asignaciones de privilegios, creación de procesos (con la auditoría de línea de comandos habilitada), cambios de cuentas y grupos, y la actividad de tickets Kerberos emitida por el Security Reference Monitor local.",
      "Como captura quién se autenticó, desde dónde y qué hizo, Security.evtx es donde el movimiento lateral, la escalada de privilegios y la persistencia suelen dejar su primer rastro. También es un objetivo antiforense de primer orden — el evento 1102 registra que el propio log fue borrado.",
    ],
    eventsHeading: "Event ID clave de Security.evtx",
    events: [
      { id: 4624, name: "Inicio de sesión correcto" },
      { id: 4625, name: "Inicio de sesión fallido" },
      { id: 4672, name: "Privilegios especiales asignados" },
      { id: 4688, name: "Creación de proceso" },
      { id: 4720, name: "Cuenta de usuario creada" },
      { id: 4768, name: "TGT de Kerberos solicitado" },
      { id: 4769, name: "Ticket de servicio Kerberos solicitado" },
      { id: 1102, name: "Registro de auditoría borrado" },
    ],
    openHeading: "Cómo abrir un archivo Security.evtx",
    openBody:
      "Suelta Security.evtx en el analizador de arriba (o cárgalo junto con System.evtx y el canal Sysmon para un triaje entre logs). El análisis se ejecuta localmente mediante un analizador Rust/WebAssembly — el log nunca sale de tu navegador. Filtra por Event ID, inspecciona el XML sin procesar de cada registro y exporta a CSV, JSON o XML.",
  },
  it: {
    metaTitle: "Security.evtx spiegato — aprire e analizzare il log di sicurezza",
    metaDescription:
      "Cos'è Security.evtx, gli Event ID che contano per il DFIR (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102) e come aprirlo nel browser — senza upload, senza installazione.",
    h1: "Security.evtx — il registro eventi di sicurezza di Windows",
    intro:
      "Security.evtx è il canale che registra l'autenticazione, l'uso dei privilegi e la gestione degli account su un host Windows. È il log più importante in quasi ogni indagine di risposta agli incidenti, e puoi aprirlo qui nel browser senza Event Viewer né una macchina Windows.",
    ctaLabel: "Apri Security.evtx nel browser",
    whatHeading: "Cos'è Security.evtx?",
    whatBody: [
      "Security.evtx risiede in C:\\Windows\\System32\\winevt\\Logs accanto a System.evtx e Application.evtx. Contiene il canale Security: eventi di accesso e disconnessione, assegnazioni di privilegi, creazione di processi (con l'auditing della riga di comando abilitato), modifiche di account e gruppi e l'attività dei ticket Kerberos emessa dal Security Reference Monitor locale.",
      "Poiché registra chi si è autenticato, da dove e cosa ha fatto, Security.evtx è il punto in cui movimento laterale, escalation dei privilegi e persistenza lasciano di solito la loro prima traccia. È anche un bersaglio anti-forense privilegiato — l'evento 1102 indica che il log stesso è stato cancellato.",
    ],
    eventsHeading: "Event ID chiave di Security.evtx",
    events: [
      { id: 4624, name: "Accesso riuscito" },
      { id: 4625, name: "Accesso non riuscito" },
      { id: 4672, name: "Privilegi speciali assegnati" },
      { id: 4688, name: "Creazione di processo" },
      { id: 4720, name: "Account utente creato" },
      { id: 4768, name: "TGT Kerberos richiesto" },
      { id: 4769, name: "Ticket di servizio Kerberos richiesto" },
      { id: 1102, name: "Registro di controllo cancellato" },
    ],
    openHeading: "Come aprire un file Security.evtx",
    openBody:
      "Rilascia Security.evtx sul parser qui sopra (oppure caricalo insieme a System.evtx e al canale Sysmon per un triage tra log). Il parsing viene eseguito localmente tramite un parser Rust/WebAssembly — il log non lascia mai il browser. Filtra per Event ID, ispeziona l'XML grezzo di ogni record ed esporta in CSV, JSON o XML.",
  },
  pt: {
    metaTitle: "Security.evtx explicado — abrir e analisar o log de segurança",
    metaDescription:
      "O que é o Security.evtx, os Event ID que importam para o DFIR (4624, 4625, 4672, 4688, 4720, 4768/4769, 1102) e como abri-lo no navegador — sem upload, sem instalação.",
    h1: "Security.evtx — o log de eventos de segurança do Windows",
    intro:
      "O Security.evtx é o canal que registra a autenticação, o uso de privilégios e o gerenciamento de contas em um host Windows. É o log mais importante em quase toda investigação de resposta a incidentes, e você pode abri-lo aqui no navegador sem o Event Viewer ou uma máquina Windows.",
    ctaLabel: "Abrir Security.evtx no navegador",
    whatHeading: "O que é o Security.evtx?",
    whatBody: [
      "O Security.evtx fica em C:\\Windows\\System32\\winevt\\Logs ao lado de System.evtx e Application.evtx. Ele contém o canal Security: eventos de logon e logoff, atribuições de privilégios, criação de processos (com a auditoria de linha de comando habilitada), alterações de contas e grupos e a atividade de tickets Kerberos emitida pelo Security Reference Monitor local.",
      "Como captura quem se autenticou, de onde e o que fez, o Security.evtx é onde o movimento lateral, a elevação de privilégios e a persistência normalmente deixam seu primeiro rastro. É também um alvo antiforense de primeira linha — o evento 1102 registra que o próprio log foi limpo.",
    ],
    eventsHeading: "Event ID principais do Security.evtx",
    events: [
      { id: 4624, name: "Logon bem-sucedido" },
      { id: 4625, name: "Falha de logon" },
      { id: 4672, name: "Privilégios especiais atribuídos" },
      { id: 4688, name: "Criação de processo" },
      { id: 4720, name: "Conta de usuário criada" },
      { id: 4768, name: "TGT Kerberos solicitado" },
      { id: 4769, name: "Ticket de serviço Kerberos solicitado" },
      { id: 1102, name: "Log de auditoria limpo" },
    ],
    openHeading: "Como abrir um arquivo Security.evtx",
    openBody:
      "Solte o Security.evtx no parser acima (ou carregue-o junto com o System.evtx e o canal do Sysmon para uma triagem entre logs). A análise é executada localmente por meio de um parser Rust/WebAssembly — o log nunca sai do seu navegador. Filtre por Event ID, inspecione o XML bruto de cada registro e exporte para CSV, JSON ou XML.",
  },
  ja: {
    metaTitle: "Security.evtx を解説 — Windows セキュリティログを開く",
    metaDescription:
      "Security.evtx とは何か、DFIR で重要な Event ID（4624、4625、4672、4688、4720、4768/4769、1102）、そしてブラウザで開く方法 — アップロード不要、インストール不要。",
    h1: "Security.evtx — Windows のセキュリティイベントログ",
    intro:
      "Security.evtx は、Windows ホスト上の認証、特権の使用、アカウント管理を記録するチャネルです。ほぼすべてのインシデント対応調査で最も重要なログであり、Event Viewer も Windows マシンも使わずに、ここブラウザで開けます。",
    ctaLabel: "ブラウザで Security.evtx を開く",
    whatHeading: "Security.evtx とは？",
    whatBody: [
      "Security.evtx は C:\\Windows\\System32\\winevt\\Logs に、System.evtx や Application.evtx と並んで存在します。Security チャネルを保持し、ログオンとログオフのイベント、特権の割り当て、プロセス作成（コマンドライン監査が有効な場合）、アカウントとグループの変更、ローカルの Security Reference Monitor が発行する Kerberos チケットのアクティビティが含まれます。",
      "誰がどこから認証し、何をしたかを捉えるため、Security.evtx は横方向の移動、特権昇格、永続化が最初の痕跡を残す場所です。また、アンチフォレンジックの主要なターゲットでもあります — イベント 1102 は、ログ自体が消去されたことを記録します。",
    ],
    eventsHeading: "Security.evtx の主要な Event ID",
    events: [
      { id: 4624, name: "ログオン成功" },
      { id: 4625, name: "ログオン失敗" },
      { id: 4672, name: "特殊な特権の割り当て" },
      { id: 4688, name: "プロセス作成" },
      { id: 4720, name: "ユーザーアカウント作成" },
      { id: 4768, name: "Kerberos TGT 要求" },
      { id: 4769, name: "Kerberos サービスチケット要求" },
      { id: 1102, name: "監査ログの消去" },
    ],
    openHeading: "Security.evtx ファイルを開く方法",
    openBody:
      "上のパーサーに Security.evtx をドロップします（または System.evtx や Sysmon チャネルと一緒に読み込んで、ログ横断のトリアージを行います）。解析は Rust/WebAssembly パーサーによってローカルで実行され — ログがブラウザの外に出ることはありません。Event ID でフィルタリングし、各レコードの生 XML を確認して、CSV、JSON、XML にエクスポートできます。",
  },
  zh: {
    metaTitle: "Security.evtx 详解 — 打开并解析 Windows 安全日志",
    metaDescription:
      "Security.evtx 是什么、对 DFIR 重要的 Event ID（4624、4625、4672、4688、4720、4768/4769、1102），以及如何在浏览器中打开它——无需上传，无需安装。",
    h1: "Security.evtx — Windows 安全事件日志",
    intro:
      "Security.evtx 是记录 Windows 主机上身份验证、权限使用和账户管理的通道。在几乎所有事件响应调查中，它都是最重要的日志，您可以在此处的浏览器中打开它，无需 Event Viewer 或 Windows 机器。",
    ctaLabel: "在浏览器中打开 Security.evtx",
    whatHeading: "什么是 Security.evtx？",
    whatBody: [
      "Security.evtx 位于 C:\\Windows\\System32\\winevt\\Logs，与 System.evtx 和 Application.evtx 并列。它保存 Security 通道：登录和注销事件、权限分配、进程创建（启用命令行审核时）、账户和组的更改，以及由本地 Security Reference Monitor 发出的 Kerberos 票据活动。",
      "由于它记录了谁进行了身份验证、从何处以及做了什么，Security.evtx 通常是横向移动、权限提升和持久化留下第一道痕迹的地方。它也是反取证的首要目标——事件 1102 记录了日志本身被清除。",
    ],
    eventsHeading: "Security.evtx 关键 Event ID",
    events: [
      { id: 4624, name: "登录成功" },
      { id: 4625, name: "登录失败" },
      { id: 4672, name: "已分配特殊权限" },
      { id: 4688, name: "进程创建" },
      { id: 4720, name: "已创建用户账户" },
      { id: 4768, name: "已请求 Kerberos TGT" },
      { id: 4769, name: "已请求 Kerberos 服务票据" },
      { id: 1102, name: "审核日志已清除" },
    ],
    openHeading: "如何打开 Security.evtx 文件",
    openBody:
      "将 Security.evtx 拖到上方的解析器中（或与 System.evtx 和 Sysmon 通道一起加载，以进行跨日志分流）。解析通过 Rust/WebAssembly 解析器在本地运行——日志绝不会离开您的浏览器。按 Event ID 筛选，查看每条记录的原始 XML，并导出为 CSV、JSON 或 XML。",
  },
};

const SYSTEM: LocaleContent<ChannelContent> = {
  en: {
    metaTitle: "System.evtx explained — open & parse the Windows System log",
    metaDescription:
      "What System.evtx is, the Event IDs that matter for DFIR (7045, 7036, 7034, 6005, 6006, 104), and how to open it in your browser — no upload, no install.",
    h1: "System.evtx — the Windows System event log",
    intro:
      "System.evtx records what the operating system, drivers and services do on a Windows host. It is where service-based persistence, driver loads and unexpected reboots show up, and you can open it here in your browser without Event Viewer or a Windows machine.",
    ctaLabel: "Open System.evtx in your browser",
    whatHeading: "What is System.evtx?",
    whatBody: [
      "System.evtx lives in C:\\Windows\\System32\\winevt\\Logs next to Security.evtx and Application.evtx. It holds the System channel: service installation and state changes (from the Service Control Manager), driver events, Event Log service start/stop, and time or power transitions.",
      "For DFIR it is the companion to Security.evtx: a malicious service installed for persistence (7045) and started (7036) is recorded here, and the Event Log start/stop pair (6005/6006) plus 104 help you spot gaps where logging was off or cleared.",
    ],
    eventsHeading: "Key System.evtx Event IDs",
    events: [
      { id: 7045, name: "Service installed" },
      { id: 7036, name: "Service state changed" },
      { id: 6005, name: "Event Log service started" },
      { id: 6006, name: "Event Log service stopped" },
      { id: 104, name: "Log cleared" },
    ],
    openHeading: "How to open a System.evtx file",
    openBody:
      "Drop System.evtx onto the parser above (or load it together with Security.evtx for a combined timeline). Parsing runs locally via a Rust/WebAssembly parser — the log never leaves your browser. Filter by Event ID, inspect each record's raw XML, and export to CSV, JSON or XML.",
  },
  fr: {
    metaTitle: "System.evtx expliqué — ouvrir et analyser le journal System",
    metaDescription:
      "Ce qu'est System.evtx, les Event ID qui comptent pour le DFIR (7045, 7036, 7034, 6005, 6006, 104) et comment l'ouvrir dans votre navigateur — sans envoi, sans installation.",
    h1: "System.evtx — le journal d'événements système Windows",
    intro:
      "System.evtx enregistre ce que font le système d'exploitation, les pilotes et les services sur un hôte Windows. C'est là qu'apparaissent la persistance par services, les chargements de pilotes et les redémarrages inattendus, et vous pouvez l'ouvrir ici dans votre navigateur sans Event Viewer ni machine Windows.",
    ctaLabel: "Ouvrir System.evtx dans votre navigateur",
    whatHeading: "Qu'est-ce que System.evtx ?",
    whatBody: [
      "System.evtx se trouve dans C:\\Windows\\System32\\winevt\\Logs à côté de Security.evtx et Application.evtx. Il contient le canal System : l'installation et les changements d'état des services (par le Service Control Manager), les événements de pilotes, le démarrage/arrêt du service Event Log, ainsi que les transitions d'heure ou d'alimentation.",
      "Pour le DFIR, c'est le compagnon de Security.evtx : un service malveillant installé pour la persistance (7045) puis démarré (7036) y est enregistré, et la paire de démarrage/arrêt du service Event Log (6005/6006) ainsi que l'événement 104 vous aident à repérer les périodes où la journalisation était désactivée ou effacée.",
    ],
    eventsHeading: "Event ID clés de System.evtx",
    events: [
      { id: 7045, name: "Service installé" },
      { id: 7036, name: "État de service modifié" },
      { id: 6005, name: "Service Event Log démarré" },
      { id: 6006, name: "Service Event Log arrêté" },
      { id: 104, name: "Journal effacé" },
    ],
    openHeading: "Comment ouvrir un fichier System.evtx",
    openBody:
      "Déposez System.evtx sur l'analyseur ci-dessus (ou chargez-le avec Security.evtx pour une chronologie combinée). L'analyse s'exécute localement via un analyseur Rust/WebAssembly — le journal ne quitte jamais votre navigateur. Filtrez par Event ID, inspectez le XML brut de chaque enregistrement et exportez en CSV, JSON ou XML.",
  },
  de: {
    metaTitle: "System.evtx erklärt — Windows-Systemprotokoll öffnen",
    metaDescription:
      "Was System.evtx ist, die für DFIR relevanten Event IDs (7045, 7036, 7034, 6005, 6006, 104) und wie Sie es im Browser öffnen — ohne Upload, ohne Installation.",
    h1: "System.evtx — das Windows-Systemereignisprotokoll",
    intro:
      "System.evtx zeichnet auf, was Betriebssystem, Treiber und Dienste auf einem Windows-Host tun. Hier zeigen sich dienstbasierte Persistenz, Treiberladevorgänge und unerwartete Neustarts, und Sie können es hier im Browser öffnen — ohne Event Viewer oder einen Windows-Rechner.",
    ctaLabel: "System.evtx im Browser öffnen",
    whatHeading: "Was ist System.evtx?",
    whatBody: [
      "System.evtx liegt in C:\\Windows\\System32\\winevt\\Logs neben Security.evtx und Application.evtx. Es enthält den System-Kanal: Dienstinstallationen und Zustandsänderungen (vom Service Control Manager), Treiberereignisse, Start/Stopp des Event-Log-Dienstes sowie Zeit- oder Stromübergänge.",
      "Für DFIR ist es der Begleiter von Security.evtx: Ein zur Persistenz installierter (7045) und gestarteter (7036) Schaddienst wird hier aufgezeichnet, und das Start/Stopp-Paar des Event-Log-Dienstes (6005/6006) plus 104 helfen Ihnen, Lücken zu erkennen, in denen die Protokollierung aus oder gelöscht war.",
    ],
    eventsHeading: "Wichtige Event IDs von System.evtx",
    events: [
      { id: 7045, name: "Dienst installiert" },
      { id: 7036, name: "Dienstzustand geändert" },
      { id: 6005, name: "Event-Log-Dienst gestartet" },
      { id: 6006, name: "Event-Log-Dienst gestoppt" },
      { id: 104, name: "Protokoll gelöscht" },
    ],
    openHeading: "So öffnen Sie eine System.evtx-Datei",
    openBody:
      "Legen Sie System.evtx auf den Parser oben ab (oder laden Sie es zusammen mit Security.evtx für eine kombinierte Zeitleiste). Das Parsen läuft lokal über einen Rust/WebAssembly-Parser — das Protokoll verlässt nie Ihren Browser. Filtern Sie nach Event ID, untersuchen Sie das rohe XML jedes Datensatzes und exportieren Sie nach CSV, JSON oder XML.",
  },
  es: {
    metaTitle: "System.evtx explicado — abrir y analizar el log del sistema",
    metaDescription:
      "Qué es System.evtx, los Event ID que importan para el DFIR (7045, 7036, 7034, 6005, 6006, 104) y cómo abrirlo en tu navegador — sin subir nada, sin instalar.",
    h1: "System.evtx — el registro de eventos del sistema de Windows",
    intro:
      "System.evtx registra lo que hacen el sistema operativo, los controladores y los servicios en un host Windows. Es donde aparecen la persistencia basada en servicios, las cargas de controladores y los reinicios inesperados, y puedes abrirlo aquí en tu navegador sin Event Viewer ni una máquina Windows.",
    ctaLabel: "Abrir System.evtx en tu navegador",
    whatHeading: "¿Qué es System.evtx?",
    whatBody: [
      "System.evtx reside en C:\\Windows\\System32\\winevt\\Logs junto a Security.evtx y Application.evtx. Contiene el canal System: instalación de servicios y cambios de estado (del Service Control Manager), eventos de controladores, inicio/parada del servicio Event Log, y transiciones de hora o energía.",
      "Para el DFIR es el complemento de Security.evtx: un servicio malicioso instalado para persistencia (7045) y arrancado (7036) queda registrado aquí, y el par de inicio/parada del servicio Event Log (6005/6006) más el 104 te ayudan a detectar huecos donde el registro estaba desactivado o se borró.",
    ],
    eventsHeading: "Event ID clave de System.evtx",
    events: [
      { id: 7045, name: "Servicio instalado" },
      { id: 7036, name: "Estado de servicio cambiado" },
      { id: 6005, name: "Servicio Event Log iniciado" },
      { id: 6006, name: "Servicio Event Log detenido" },
      { id: 104, name: "Registro borrado" },
    ],
    openHeading: "Cómo abrir un archivo System.evtx",
    openBody:
      "Suelta System.evtx en el analizador de arriba (o cárgalo junto con Security.evtx para una línea de tiempo combinada). El análisis se ejecuta localmente mediante un analizador Rust/WebAssembly — el log nunca sale de tu navegador. Filtra por Event ID, inspecciona el XML sin procesar de cada registro y exporta a CSV, JSON o XML.",
  },
  it: {
    metaTitle: "System.evtx spiegato — aprire e analizzare il log di sistema",
    metaDescription:
      "Cos'è System.evtx, gli Event ID che contano per il DFIR (7045, 7036, 7034, 6005, 6006, 104) e come aprirlo nel browser — senza upload, senza installazione.",
    h1: "System.evtx — il registro eventi di sistema di Windows",
    intro:
      "System.evtx registra ciò che fanno il sistema operativo, i driver e i servizi su un host Windows. È dove emergono la persistenza basata sui servizi, i caricamenti di driver e i riavvii imprevisti, e puoi aprirlo qui nel browser senza Event Viewer né una macchina Windows.",
    ctaLabel: "Apri System.evtx nel browser",
    whatHeading: "Cos'è System.evtx?",
    whatBody: [
      "System.evtx risiede in C:\\Windows\\System32\\winevt\\Logs accanto a Security.evtx e Application.evtx. Contiene il canale System: installazione dei servizi e cambi di stato (dal Service Control Manager), eventi dei driver, avvio/arresto del servizio Event Log e transizioni di orario o alimentazione.",
      "Per il DFIR è il complemento di Security.evtx: un servizio malevolo installato per la persistenza (7045) e avviato (7036) viene registrato qui, e la coppia di avvio/arresto del servizio Event Log (6005/6006) più il 104 ti aiutano a individuare le lacune in cui il logging era disattivato o cancellato.",
    ],
    eventsHeading: "Event ID chiave di System.evtx",
    events: [
      { id: 7045, name: "Servizio installato" },
      { id: 7036, name: "Stato del servizio modificato" },
      { id: 6005, name: "Servizio Event Log avviato" },
      { id: 6006, name: "Servizio Event Log arrestato" },
      { id: 104, name: "Registro cancellato" },
    ],
    openHeading: "Come aprire un file System.evtx",
    openBody:
      "Rilascia System.evtx sul parser qui sopra (oppure caricalo insieme a Security.evtx per una timeline combinata). Il parsing viene eseguito localmente tramite un parser Rust/WebAssembly — il log non lascia mai il browser. Filtra per Event ID, ispeziona l'XML grezzo di ogni record ed esporta in CSV, JSON o XML.",
  },
  pt: {
    metaTitle: "System.evtx explicado — abrir e analisar o log do sistema",
    metaDescription:
      "O que é o System.evtx, os Event ID que importam para o DFIR (7045, 7036, 7034, 6005, 6006, 104) e como abri-lo no navegador — sem upload, sem instalação.",
    h1: "System.evtx — o log de eventos do sistema do Windows",
    intro:
      "O System.evtx registra o que o sistema operacional, os drivers e os serviços fazem em um host Windows. É onde a persistência baseada em serviços, os carregamentos de drivers e as reinicializações inesperadas aparecem, e você pode abri-lo aqui no navegador sem o Event Viewer ou uma máquina Windows.",
    ctaLabel: "Abrir System.evtx no navegador",
    whatHeading: "O que é o System.evtx?",
    whatBody: [
      "O System.evtx fica em C:\\Windows\\System32\\winevt\\Logs ao lado de Security.evtx e Application.evtx. Ele contém o canal System: instalação de serviços e mudanças de estado (pelo Service Control Manager), eventos de drivers, início/parada do serviço Event Log e transições de hora ou energia.",
      "Para o DFIR, é o companheiro do Security.evtx: um serviço malicioso instalado para persistência (7045) e iniciado (7036) é registrado aqui, e o par de início/parada do serviço Event Log (6005/6006) mais o 104 ajudam você a identificar lacunas em que o registro estava desativado ou foi limpo.",
    ],
    eventsHeading: "Event ID principais do System.evtx",
    events: [
      { id: 7045, name: "Serviço instalado" },
      { id: 7036, name: "Estado do serviço alterado" },
      { id: 6005, name: "Serviço Event Log iniciado" },
      { id: 6006, name: "Serviço Event Log interrompido" },
      { id: 104, name: "Log limpo" },
    ],
    openHeading: "Como abrir um arquivo System.evtx",
    openBody:
      "Solte o System.evtx no parser acima (ou carregue-o junto com o Security.evtx para uma linha do tempo combinada). A análise é executada localmente por meio de um parser Rust/WebAssembly — o log nunca sai do seu navegador. Filtre por Event ID, inspecione o XML bruto de cada registro e exporte para CSV, JSON ou XML.",
  },
  ja: {
    metaTitle: "System.evtx を解説 — Windows システムログを開く",
    metaDescription:
      "System.evtx とは何か、DFIR で重要な Event ID（7045、7036、7034、6005、6006、104）、そしてブラウザで開く方法 — アップロード不要、インストール不要。",
    h1: "System.evtx — Windows のシステムイベントログ",
    intro:
      "System.evtx は、Windows ホスト上でオペレーティングシステム、ドライバー、サービスが何を行うかを記録します。サービスによる永続化、ドライバーの読み込み、予期しない再起動が現れる場所であり、Event Viewer も Windows マシンも使わずに、ここブラウザで開けます。",
    ctaLabel: "ブラウザで System.evtx を開く",
    whatHeading: "System.evtx とは？",
    whatBody: [
      "System.evtx は C:\\Windows\\System32\\winevt\\Logs に、Security.evtx や Application.evtx と並んで存在します。System チャネルを保持し、サービスのインストールと状態変更（Service Control Manager による）、ドライバーイベント、Event Log サービスの開始/停止、時刻や電源の遷移が含まれます。",
      "DFIR にとっては Security.evtx の相棒です。永続化のためにインストール（7045）されて開始（7036）された悪意あるサービスはここに記録され、Event Log サービスの開始/停止のペア（6005/6006）と 104 は、ログが無効化または消去されていた空白期間を見つける手がかりになります。",
    ],
    eventsHeading: "System.evtx の主要な Event ID",
    events: [
      { id: 7045, name: "サービスのインストール" },
      { id: 7036, name: "サービス状態の変更" },
      { id: 6005, name: "Event Log サービス開始" },
      { id: 6006, name: "Event Log サービス停止" },
      { id: 104, name: "ログの消去" },
    ],
    openHeading: "System.evtx ファイルを開く方法",
    openBody:
      "上のパーサーに System.evtx をドロップします（または Security.evtx と一緒に読み込んで、統合タイムラインを作成します）。解析は Rust/WebAssembly パーサーによってローカルで実行され — ログがブラウザの外に出ることはありません。Event ID でフィルタリングし、各レコードの生 XML を確認して、CSV、JSON、XML にエクスポートできます。",
  },
  zh: {
    metaTitle: "System.evtx 详解 — 打开并解析 Windows 系统日志",
    metaDescription:
      "System.evtx 是什么、对 DFIR 重要的 Event ID（7045、7036、7034、6005、6006、104），以及如何在浏览器中打开它——无需上传，无需安装。",
    h1: "System.evtx — Windows 系统事件日志",
    intro:
      "System.evtx 记录操作系统、驱动程序和服务在 Windows 主机上的行为。它是基于服务的持久化、驱动程序加载和意外重启出现的地方，您可以在此处的浏览器中打开它，无需 Event Viewer 或 Windows 机器。",
    ctaLabel: "在浏览器中打开 System.evtx",
    whatHeading: "什么是 System.evtx？",
    whatBody: [
      "System.evtx 位于 C:\\Windows\\System32\\winevt\\Logs，与 Security.evtx 和 Application.evtx 并列。它保存 System 通道：服务安装和状态更改（来自 Service Control Manager）、驱动程序事件、Event Log 服务的启动/停止，以及时间或电源转换。",
      "对于 DFIR，它是 Security.evtx 的搭档：为持久化而安装（7045）并启动（7036）的恶意服务会记录在此，而 Event Log 服务的启动/停止对（6005/6006）加上 104 可帮助您发现日志被关闭或清除的空白时段。",
    ],
    eventsHeading: "System.evtx 关键 Event ID",
    events: [
      { id: 7045, name: "已安装服务" },
      { id: 7036, name: "服务状态已更改" },
      { id: 6005, name: "Event Log 服务已启动" },
      { id: 6006, name: "Event Log 服务已停止" },
      { id: 104, name: "日志已清除" },
    ],
    openHeading: "如何打开 System.evtx 文件",
    openBody:
      "将 System.evtx 拖到上方的解析器中（或与 Security.evtx 一起加载，以获得合并的时间线）。解析通过 Rust/WebAssembly 解析器在本地运行——日志绝不会离开您的浏览器。按 Event ID 筛选，查看每条记录的原始 XML，并导出为 CSV、JSON 或 XML。",
  },
};

export const CHANNELS: Record<ChannelKey, LocaleContent<ChannelContent>> = {
  security: SECURITY,
  system: SYSTEM,
};

export function channelContent(key: ChannelKey, locale: Locale): ChannelContent {
  return pickLocale(CHANNELS[key], locale);
}

export function channelMetadata(key: ChannelKey, locale: Locale): Metadata {
  const c = channelContent(key, locale);
  const path = CHANNEL_PATH[key];
  const url = canonicalFor(locale, path);
  return {
    metadataBase: new URL(SITE_URL),
    title: c.metaTitle,
    description: c.metaDescription,
    alternates: { canonical: url, languages: localeAlternates(path) },
    openGraph: {
      type: "website",
      siteName: getDict(locale).meta.siteName,
      title: c.metaTitle,
      description: c.metaDescription,
      url,
      locale: OG_LOCALE[locale],
      images: [
        {
          url: `${canonicalFor(locale)}/opengraph-image`,
          width: 1200,
          height: 630,
          alt: c.metaTitle,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: c.metaTitle,
      description: c.metaDescription,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

export function channelGraph(key: ChannelKey, locale: Locale) {
  const c = channelContent(key, locale);
  const url = canonicalFor(locale, CHANNEL_PATH[key]);
  const siteName = getDict(locale).meta.siteName;
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: c.metaTitle,
        description: c.metaDescription,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
      },
      {
        "@type": "ItemList",
        "@id": `${url}#events`,
        name: c.eventsHeading,
        numberOfItems: c.events.length,
        itemListElement: c.events.map((e, i) => ({
          "@type": "ListItem",
          position: i + 1,
          name: `${e.id} — ${e.name}`,
          url: `${SITE_URL}/${locale}/event-id/${e.id}`,
        })),
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: siteName,
            item: `${SITE_URL}/${locale}`,
          },
          { "@type": "ListItem", position: 2, name: c.h1, item: url },
        ],
      },
    ],
  };
}
