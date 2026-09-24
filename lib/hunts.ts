// Ready-made hunts: one-click searches for common attacker activity, written
// in the search-box query language (lib/search-query.ts) so the analyst can
// read, tweak and extend them. OR binds loosest: each OR-branch is an AND
// group, so provider constraints are repeated per branch.

import type { LocaleContent } from "@/lib/landing/locale-content";

export type HuntCategory =
  | "credential"
  | "lateral"
  | "persistence"
  | "execution"
  | "evasion";

export type Hunt = {
  id: string;
  category: HuntCategory;
  /** MITRE ATT&CK technique, for the tooltip. */
  mitre?: string;
  query: string;
  name: LocaleContent<string>;
};

export const HUNTS: Hunt[] = [
  {
    id: "rdp-logons",
    category: "lateral",
    mitre: "T1021.001",
    query:
      "EventID:4624 LogonType:10 OR Provider:*RemoteConnectionManager* EventID:1149 OR Provider:*LocalSessionManager* EventID:21 OR Provider:*LocalSessionManager* EventID:25",
    name: { en: "RDP logons and reconnects", fr: "Connexions et reconnexions RDP", de: "RDP-Anmeldungen und Wiederverbindungen", es: "Inicios de sesión y reconexiones RDP", it: "Accessi e riconnessioni RDP", pt: "Logons e reconexões RDP", ja: "RDPログオンと再接続", zh: "RDP登录与重新连接" },
  },
  {
    id: "failed-logons",
    category: "credential",
    mitre: "T1110",
    query:
      "EventID:4625 OR EventID:4771 OR EventID:4776 -Status:0x0",
    name: { en: "Failed logons (brute force, spraying)", fr: "Échecs de connexion (force brute, spraying)", de: "Fehlgeschlagene Anmeldungen (Brute-Force, Spraying)", es: "Inicios de sesión fallidos (fuerza bruta, spraying)", it: "Accessi falliti (forza bruta, spraying)", pt: "Logons falhos (força bruta, spraying)", ja: "ログオン失敗(ブルートフォース、パスワードスプレー)", zh: "登录失败(暴力破解、密码喷洒)" },
  },
  {
    id: "lockouts",
    category: "credential",
    mitre: "T1110",
    query: "EventID:4740",
    name: { en: "Account lockouts", fr: "Verrouillages de compte", de: "Kontosperrungen", es: "Bloqueos de cuenta", it: "Blocchi account", pt: "Bloqueios de conta", ja: "アカウントロックアウト", zh: "账户锁定" },
  },
  {
    id: "explicit-creds",
    category: "lateral",
    mitre: "T1078",
    query: "EventID:4648",
    name: { en: "Logons with explicit credentials (runas, lateral movement)", fr: "Connexions avec identifiants explicites (runas, mouvement latéral)", de: "Anmeldungen mit expliziten Anmeldeinformationen (runas, Lateral Movement)", es: "Inicios de sesión con credenciales explícitas (runas, movimiento lateral)", it: "Accessi con credenziali esplicite (runas, movimento laterale)", pt: "Logons com credenciais explícitas (runas, movimento lateral)", ja: "明示的な資格情報によるログオン(runas、ラテラルムーブメント)", zh: "使用显式凭据登录(runas、横向移动)" },
  },
  {
    id: "ntlm-network",
    category: "lateral",
    mitre: "T1550.002",
    query: "EventID:4624 LogonType:3 AuthenticationPackageName:NTLM -TargetUserName:ANONYMOUS*",
    name: { en: "NTLM network logons (pass-the-hash candidates)", fr: "Connexions réseau NTLM (candidats pass-the-hash)", de: "NTLM-Netzwerkanmeldungen (Pass-the-Hash-Kandidaten)", es: "Inicios de sesión de red NTLM (candidatos pass-the-hash)", it: "Accessi di rete NTLM (candidati pass-the-hash)", pt: "Logons de rede NTLM (candidatos a pass-the-hash)", ja: "NTLMネットワークログオン(pass-the-hash候補)", zh: "NTLM网络登录(疑似传递哈希)" },
  },
  {
    id: "kerberoasting",
    category: "credential",
    mitre: "T1558.003",
    query: "EventID:4769 TicketEncryptionType:0x17",
    name: { en: "Kerberoasting: RC4 service tickets", fr: "Kerberoasting : tickets de service RC4", de: "Kerberoasting: RC4-Diensttickets", es: "Kerberoasting: tickets de servicio RC4", it: "Kerberoasting: ticket di servizio RC4", pt: "Kerberoasting: tickets de serviço RC4", ja: "Kerberoasting: RC4サービスチケット", zh: "Kerberoasting:RC4服务票据" },
  },
  {
    id: "asrep",
    category: "credential",
    mitre: "T1558.004",
    query: "EventID:4768 PreAuthType:0",
    name: { en: "AS-REP roasting: TGTs without pre-authentication", fr: "AS-REP roasting : TGT sans pré-authentification", de: "AS-REP Roasting: TGTs ohne Vorabauthentifizierung", es: "AS-REP roasting: TGT sin autenticación previa", it: "AS-REP roasting: TGT senza pre-autenticazione", pt: "AS-REP roasting: TGTs sem pré-autenticação", ja: "AS-REP roasting: 事前認証なしのTGT", zh: "AS-REP Roasting:无预身份验证的TGT" },
  },
  {
    id: "lsass-access",
    category: "credential",
    mitre: "T1003.001",
    query: "Provider:*Sysmon* EventID:10 TargetImage:*\\lsass.exe",
    name: { en: "LSASS memory access (credential dumping)", fr: "Accès mémoire LSASS (extraction d'identifiants)", de: "LSASS-Speicherzugriff (Credential Dumping)", es: "Acceso a memoria LSASS (extracción de credenciales)", it: "Accesso alla memoria LSASS (estrazione credenziali)", pt: "Acesso à memória do LSASS (extração de credenciais)", ja: "LSASSメモリアクセス(資格情報のダンプ)", zh: "LSASS内存访问(凭据转储)" },
  },
  {
    id: "new-services",
    category: "persistence",
    mitre: "T1543.003",
    query: "EventID:7045 OR EventID:4697",
    name: { en: "New services installed", fr: "Nouveaux services installés", de: "Neue Dienste installiert", es: "Nuevos servicios instalados", it: "Nuovi servizi installati", pt: "Novos serviços instalados", ja: "新規サービスのインストール", zh: "新安装的服务" },
  },
  {
    id: "scheduled-tasks",
    category: "persistence",
    mitre: "T1053.005",
    query:
      "EventID:4698 OR EventID:4702 OR Provider:*TaskScheduler* EventID:106 OR Provider:*TaskScheduler* EventID:140",
    name: { en: "Scheduled tasks created or changed", fr: "Tâches planifiées créées ou modifiées", de: "Geplante Aufgaben erstellt oder geändert", es: "Tareas programadas creadas o modificadas", it: "Attività pianificate create o modificate", pt: "Tarefas agendadas criadas ou alteradas", ja: "スケジュールタスクの作成・変更", zh: "计划任务的创建或更改" },
  },
  {
    id: "accounts",
    category: "persistence",
    mitre: "T1136",
    query: "EventID:4720 OR EventID:4722 OR EventID:4724 OR EventID:4738",
    name: { en: "Accounts created, enabled or reset", fr: "Comptes créés, activés ou réinitialisés", de: "Konten erstellt, aktiviert oder zurückgesetzt", es: "Cuentas creadas, habilitadas o restablecidas", it: "Account creati, abilitati o reimpostati", pt: "Contas criadas, habilitadas ou redefinidas", ja: "アカウントの作成・有効化・リセット", zh: "账户的创建、启用或重置" },
  },
  {
    id: "priv-groups",
    category: "persistence",
    mitre: "T1098",
    query: "EventID:4728 OR EventID:4732 OR EventID:4756",
    name: { en: "Members added to security groups", fr: "Membres ajoutés à des groupes de sécurité", de: "Mitglieder zu Sicherheitsgruppen hinzugefügt", es: "Miembros añadidos a grupos de seguridad", it: "Membri aggiunti a gruppi di sicurezza", pt: "Membros adicionados a grupos de segurança", ja: "セキュリティグループへのメンバー追加", zh: "添加到安全组的成员" },
  },
  {
    id: "wmi-persistence",
    category: "persistence",
    mitre: "T1546.003",
    query:
      "Provider:*WMI-Activity* EventID:5861 OR Provider:*Sysmon* EventID:19 OR Provider:*Sysmon* EventID:20 OR Provider:*Sysmon* EventID:21",
    name: { en: "WMI event-subscription persistence", fr: "Persistance par abonnement d'événements WMI", de: "WMI-Ereignisabonnement-Persistenz", es: "Persistencia mediante suscripción de eventos WMI", it: "Persistenza tramite sottoscrizione di eventi WMI", pt: "Persistência por assinatura de eventos WMI", ja: "WMIイベントサブスクリプションによる永続化", zh: "WMI事件订阅持久化" },
  },
  {
    id: "encoded-commands",
    category: "execution",
    mitre: "T1059.001",
    query:
      "EventID:4688 CommandLine:*-enc* OR EventID:4688 CommandLine:*FromBase64String* OR Provider:*Sysmon* EventID:1 CommandLine:*-enc* OR Provider:*Sysmon* EventID:1 CommandLine:*FromBase64String*",
    name: { en: "Encoded / obfuscated command lines", fr: "Lignes de commande encodées / obfusquées", de: "Codierte / verschleierte Befehlszeilen", es: "Líneas de comandos codificadas / ofuscadas", it: "Righe di comando codificate / offuscate", pt: "Linhas de comando codificadas / ofuscadas", ja: "エンコード・難読化されたコマンドライン", zh: "编码/混淆的命令行" },
  },
  {
    id: "powershell-suspicious",
    category: "execution",
    mitre: "T1059.001",
    query:
      "EventID:4104 ScriptBlockText:*DownloadString* OR EventID:4104 ScriptBlockText:*FromBase64String* OR EventID:4104 ScriptBlockText:*Invoke-Expression* OR EventID:4104 ScriptBlockText:*IEX* OR EventID:4104 ScriptBlockText:*Net.WebClient* OR EventID:4104 ScriptBlockText:*-bxor*",
    name: { en: "Suspicious PowerShell script blocks", fr: "Blocs de script PowerShell suspects", de: "Verdächtige PowerShell-Skriptblöcke", es: "Bloques de script de PowerShell sospechosos", it: "Blocchi di script PowerShell sospetti", pt: "Blocos de script PowerShell suspeitos", ja: "不審なPowerShellスクリプトブロック", zh: "可疑的PowerShell脚本块" },
  },
  {
    id: "lolbins",
    category: "execution",
    mitre: "T1218",
    query:
      "NewProcessName:*\\certutil.exe OR NewProcessName:*\\mshta.exe OR NewProcessName:*\\regsvr32.exe OR NewProcessName:*\\rundll32.exe OR NewProcessName:*\\bitsadmin.exe OR NewProcessName:*\\wmic.exe OR Image:*\\certutil.exe OR Image:*\\mshta.exe OR Image:*\\regsvr32.exe OR Image:*\\bitsadmin.exe OR Image:*\\wmic.exe",
    name: { en: "LOLBin execution (certutil, mshta, regsvr32…)", fr: "Exécution de LOLBins (certutil, mshta, regsvr32…)", de: "LOLBin-Ausführung (certutil, mshta, regsvr32…)", es: "Ejecución de LOLBins (certutil, mshta, regsvr32…)", it: "Esecuzione di LOLBin (certutil, mshta, regsvr32…)", pt: "Execução de LOLBins (certutil, mshta, regsvr32…)", ja: "LOLBin実行(certutil、mshta、regsvr32…)", zh: "LOLBin执行(certutil、mshta、regsvr32…)" },
  },
  {
    id: "admin-shares",
    category: "lateral",
    mitre: "T1021.002",
    query: "EventID:5140 ShareName:*ADMIN$ OR EventID:5140 ShareName:*C$ OR EventID:5145 ShareName:*ADMIN$ OR EventID:5145 ShareName:*C$",
    name: { en: "Admin share access (ADMIN$, C$)", fr: "Accès aux partages d'administration (ADMIN$, C$)", de: "Zugriff auf Admin-Freigaben (ADMIN$, C$)", es: "Acceso a recursos compartidos administrativos (ADMIN$, C$)", it: "Accesso alle condivisioni amministrative (ADMIN$, C$)", pt: "Acesso a compartilhamentos administrativos (ADMIN$, C$)", ja: "管理共有へのアクセス(ADMIN$、C$)", zh: "管理共享访问(ADMIN$、C$)" },
  },
  {
    id: "log-cleared",
    category: "evasion",
    mitre: "T1070.001",
    query: "EventID:1102 OR Provider:*Eventlog* EventID:104",
    name: { en: "Event logs cleared", fr: "Journaux d'événements effacés", de: "Ereignisprotokolle gelöscht", es: "Registros de eventos borrados", it: "Log degli eventi cancellati", pt: "Logs de eventos apagados", ja: "イベントログのクリア", zh: "事件日志被清除" },
  },
  {
    id: "audit-tampering",
    category: "evasion",
    mitre: "T1562.002",
    query: "EventID:4719",
    name: { en: "Audit policy changed", fr: "Stratégie d'audit modifiée", de: "Überwachungsrichtlinie geändert", es: "Directiva de auditoría modificada", it: "Criteri di controllo modificati", pt: "Política de auditoria alterada", ja: "監査ポリシーの変更", zh: "审核策略变更" },
  },
  {
    id: "time-change",
    category: "evasion",
    mitre: "T1070.006",
    query: "EventID:4616 -ProcessName:*\\svchost.exe",
    name: { en: "System time changed (not by the time service)", fr: "Heure système modifiée (hors service de temps)", de: "Systemzeit geändert (nicht durch den Zeitdienst)", es: "Hora del sistema modificada (no por el servicio de hora)", it: "Ora di sistema modificata (non dal servizio orario)", pt: "Hora do sistema alterada (não pelo serviço de horário)", ja: "システム時刻の変更(時刻サービス以外)", zh: "系统时间变更(非时间服务所致)" },
  },
  {
    id: "defender",
    category: "evasion",
    mitre: "T1562.001",
    query:
      "Provider:*Defender* EventID:1116 OR Provider:*Defender* EventID:1117 OR Provider:*Defender* EventID:5001 OR Provider:*Defender* EventID:5007",
    name: { en: "Defender detections, disabled protection, config changes", fr: "Détections Defender, protection désactivée, changements de config", de: "Defender-Erkennungen, deaktivierter Schutz, Konfigurationsänderungen", es: "Detecciones de Defender, protección deshabilitada, cambios de configuración", it: "Rilevamenti Defender, protezione disabilitata, modifiche alla configurazione", pt: "Detecções do Defender, proteção desativada, alterações de configuração", ja: "Defenderの検出、保護の無効化、設定変更", zh: "Defender检测、保护禁用、配置变更" },
  },
];
