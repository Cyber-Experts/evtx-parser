// Ready-made hunts: one-click searches for common attacker activity, written
// in the search-box query language (lib/search-query.ts) so the analyst can
// read, tweak and extend them. OR binds loosest: each OR-branch is an AND
// group, so provider constraints are repeated per branch.

import type { LocaleContent } from "@/lib/landing/locale-content";

export type HuntCategory =
  | "initial"
  | "credential"
  | "discovery"
  | "lateral"
  | "persistence"
  | "execution"
  | "evasion"
  | "impact"
  | "c2";

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
  {
    id: "external-rdp",
    category: "initial",
    mitre: "T1133",
    query:
      "EventID:4624 LogonType:10 -IpAddress:10.* -IpAddress:192.168.* -IpAddress:172.16.* -IpAddress:172.17.* -IpAddress:172.18.* -IpAddress:172.19.* -IpAddress:172.20.* -IpAddress:172.21.* -IpAddress:172.22.* -IpAddress:172.23.* -IpAddress:172.24.* -IpAddress:172.25.* -IpAddress:172.26.* -IpAddress:172.27.* -IpAddress:172.28.* -IpAddress:172.29.* -IpAddress:172.30.* -IpAddress:172.31.* -IpAddress:127.* -IpAddress:::1 -IpAddress:- -IpAddress:fe80* -IpAddress:169.254.*",
    name: { en: "RDP logons from public IP addresses", fr: "Connexions RDP depuis des adresses IP publiques", de: "RDP-Anmeldungen von öffentlichen IP-Adressen", es: "Inicios de sesión RDP desde direcciones IP públicas", it: "Accessi RDP da indirizzi IP pubblici", pt: "Logons RDP de endereços IP públicos", ja: "パブリックIPアドレスからのRDPログオン", zh: "来自公网IP地址的RDP登录" },
  },
  {
    id: "external-network",
    category: "initial",
    mitre: "T1078",
    query:
      "EventID:4624 LogonType:3 -IpAddress:10.* -IpAddress:192.168.* -IpAddress:172.16.* -IpAddress:172.17.* -IpAddress:172.18.* -IpAddress:172.19.* -IpAddress:172.20.* -IpAddress:172.21.* -IpAddress:172.22.* -IpAddress:172.23.* -IpAddress:172.24.* -IpAddress:172.25.* -IpAddress:172.26.* -IpAddress:172.27.* -IpAddress:172.28.* -IpAddress:172.29.* -IpAddress:172.30.* -IpAddress:172.31.* -IpAddress:127.* -IpAddress:::1 -IpAddress:- -IpAddress:fe80* -IpAddress:169.254.*",
    name: { en: "Network logons from public IP addresses", fr: "Connexions réseau depuis des adresses IP publiques", de: "Netzwerkanmeldungen von öffentlichen IP-Adressen", es: "Inicios de sesión de red desde direcciones IP públicas", it: "Accessi di rete da indirizzi IP pubblici", pt: "Logons de rede de endereços IP públicos", ja: "パブリックIPアドレスからのネットワークログオン", zh: "来自公网IP地址的网络登录" },
  },
  {
    id: "dcsync",
    category: "credential",
    mitre: "T1003.006",
    query:
      "EventID:4662 Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* -SubjectUserName:*$ OR EventID:4662 Properties:*89e95b76-444d-4c62-991a-0facbeda640c* -SubjectUserName:*$",
    name: { en: "DCSync: directory replication by a non-DC account", fr: "DCSync : réplication d'annuaire par un compte non-DC", de: "DCSync: Verzeichnisreplikation durch ein Nicht-DC-Konto", es: "DCSync: replicación de directorio por una cuenta que no es DC", it: "DCSync: replica della directory da un account non DC", pt: "DCSync: replicação de diretório por uma conta que não é DC", ja: "DCSync: 非DCアカウントによるディレクトリレプリケーション", zh: "DCSync:非DC账户发起的目录复制" },
  },
  {
    id: "sam-dump",
    category: "credential",
    mitre: "T1003.002",
    query:
      "CommandLine:*save*hklm\\sam* OR CommandLine:*save*hklm\\security* OR CommandLine:*save*hklm\\system*",
    name: { en: "SAM / LSA secrets saved from the registry", fr: "Secrets SAM / LSA enregistrés depuis le registre", de: "SAM-/LSA-Geheimnisse aus der Registrierung gespeichert", es: "Secretos SAM / LSA guardados desde el registro", it: "Segreti SAM / LSA salvati dal registro", pt: "Segredos SAM / LSA salvos do registro", ja: "レジストリからのSAM / LSAシークレットの保存", zh: "从注册表保存的SAM/LSA机密" },
  },
  {
    id: "ntds-dump",
    category: "credential",
    mitre: "T1003.003",
    query:
      "CommandLine:*ntdsutil* OR CommandLine:*vssadmin*create*shadow* OR CommandLine:*\\ntds.dit*",
    name: { en: "NTDS.dit extraction (ntdsutil, shadow copies)", fr: "Extraction de NTDS.dit (ntdsutil, clichés instantanés)", de: "NTDS.dit-Extraktion (ntdsutil, Schattenkopien)", es: "Extracción de NTDS.dit (ntdsutil, copias de sombra)", it: "Estrazione di NTDS.dit (ntdsutil, copie shadow)", pt: "Extração do NTDS.dit (ntdsutil, cópias de sombra)", ja: "NTDS.ditの抽出(ntdsutil、シャドウコピー)", zh: "NTDS.dit提取(ntdsutil、卷影副本)" },
  },
  {
    id: "mimikatz",
    category: "credential",
    mitre: "T1003",
    query:
      "CommandLine:*sekurlsa* OR CommandLine:*mimikatz* OR CommandLine:*kerberos::* OR CommandLine:*lsadump::* OR ScriptBlockText:*Invoke-Mimikatz* OR ScriptBlockText:*sekurlsa* OR process:*\\mimikatz.exe",
    name: { en: "Mimikatz traces", fr: "Traces de Mimikatz", de: "Mimikatz-Spuren", es: "Rastros de Mimikatz", it: "Tracce di Mimikatz", pt: "Vestígios do Mimikatz", ja: "Mimikatzの痕跡", zh: "Mimikatz痕迹" },
  },
  {
    id: "ntlmv1",
    category: "credential",
    mitre: "T1557",
    query:
      "EventID:4624 LmPackageName:\"NTLM V1\"",
    name: { en: "NTLMv1 logons (downgrade, relay risk)", fr: "Connexions NTLMv1 (rétrogradation, risque de relais)", de: "NTLMv1-Anmeldungen (Downgrade, Relay-Risiko)", es: "Inicios de sesión NTLMv1 (degradación, riesgo de relay)", it: "Accessi NTLMv1 (downgrade, rischio di relay)", pt: "Logons NTLMv1 (downgrade, risco de relay)", ja: "NTLMv1ログオン(ダウングレード、リレーリスク)", zh: "NTLMv1登录(降级、中继风险)" },
  },
  {
    id: "kerb-preauth-fail",
    category: "credential",
    mitre: "T1110.003",
    query:
      "EventID:4771 Status:0x18",
    name: { en: "Kerberos pre-auth failures (password spraying)", fr: "Échecs de pré-authentification Kerberos (password spraying)", de: "Kerberos-Vorabauthentifizierungsfehler (Password Spraying)", es: "Fallos de preautenticación Kerberos (password spraying)", it: "Errori di pre-autenticazione Kerberos (password spraying)", pt: "Falhas de pré-autenticação Kerberos (password spraying)", ja: "Kerberos事前認証の失敗(パスワードスプレー)", zh: "Kerberos预身份验证失败(密码喷洒)" },
  },
  {
    id: "recon-commands",
    category: "discovery",
    mitre: "T1087",
    query:
      "process:*\\whoami.exe OR process:*\\nltest.exe OR process:*\\systeminfo.exe OR process:*\\net.exe OR process:*\\net1.exe OR process:*\\quser.exe OR process:*\\qwinsta.exe OR process:*\\arp.exe OR process:*\\route.exe OR process:*\\netstat.exe",
    name: { en: "Discovery commands (whoami, net, nltest, systeminfo\u2026)", fr: "Commandes de découverte (whoami, net, nltest, systeminfo…)", de: "Erkundungsbefehle (whoami, net, nltest, systeminfo…)", es: "Comandos de descubrimiento (whoami, net, nltest, systeminfo…)", it: "Comandi di discovery (whoami, net, nltest, systeminfo…)", pt: "Comandos de descoberta (whoami, net, nltest, systeminfo…)", ja: "探索コマンド(whoami、net、nltest、systeminfo…)", zh: "侦察命令(whoami、net、nltest、systeminfo…)" },
  },
  {
    id: "ad-recon-tools",
    category: "discovery",
    mitre: "T1087.002",
    query:
      "process:*\\adfind.exe OR CommandLine:*sharphound* OR CommandLine:*bloodhound* OR ScriptBlockText:*Invoke-BloodHound* OR ScriptBlockText:*Get-DomainUser* OR ScriptBlockText:*Get-NetUser*",
    name: { en: "AD recon tools (AdFind, BloodHound, PowerView)", fr: "Outils de reconnaissance AD (AdFind, BloodHound, PowerView)", de: "AD-Aufklärungstools (AdFind, BloodHound, PowerView)", es: "Herramientas de reconocimiento de AD (AdFind, BloodHound, PowerView)", it: "Strumenti di ricognizione AD (AdFind, BloodHound, PowerView)", pt: "Ferramentas de reconhecimento de AD (AdFind, BloodHound, PowerView)", ja: "AD偵察ツール(AdFind、BloodHound、PowerView)", zh: "AD侦察工具(AdFind、BloodHound、PowerView)" },
  },
  {
    id: "group-enum",
    category: "discovery",
    mitre: "T1069",
    query:
      "EventID:4799 -CallerProcessName:*\\services.exe -CallerProcessName:*\\svchost.exe -SubjectUserName:*$",
    name: { en: "Group membership enumerated by a user", fr: "Appartenance à un groupe énumérée par un utilisateur", de: "Gruppenmitgliedschaft von einem Benutzer aufgezählt", es: "Pertenencia a grupos enumerada por un usuario", it: "Appartenenza a gruppi enumerata da un utente", pt: "Associação a grupo enumerada por um usuário", ja: "ユーザーによるグループメンバーシップの列挙", zh: "用户枚举组成员身份" },
  },
  {
    id: "psexec",
    category: "lateral",
    mitre: "T1569.002",
    query:
      "EventID:7045 ServiceName:PSEXESVC OR EventID:7045 ImagePath:*PSEXESVC* OR EventID:4697 ServiceName:PSEXESVC OR EventID:5145 RelativeTargetName:*PSEXESVC* OR process:*\\PSEXESVC.exe",
    name: { en: "PsExec service execution", fr: "Exécution du service PsExec", de: "PsExec-Dienstausführung", es: "Ejecución del servicio PsExec", it: "Esecuzione del servizio PsExec", pt: "Execução do serviço PsExec", ja: "PsExecサービスの実行", zh: "PsExec服务执行" },
  },
  {
    id: "winrm",
    category: "lateral",
    mitre: "T1021.006",
    query:
      "Provider:*WinRM* EventID:91 OR parent:*\\wsmprovhost.exe OR process:*\\wsmprovhost.exe",
    name: { en: "WinRM / PowerShell remoting", fr: "WinRM / PowerShell à distance", de: "WinRM / PowerShell-Remoting", es: "WinRM / PowerShell remoto", it: "WinRM / PowerShell remoto", pt: "WinRM / PowerShell remoto", ja: "WinRM / PowerShellリモーティング", zh: "WinRM/PowerShell远程" },
  },
  {
    id: "wmi-exec",
    category: "lateral",
    mitre: "T1047",
    query:
      "parent:*\\WmiPrvSE.exe process:*\\cmd.exe OR parent:*\\WmiPrvSE.exe process:*\\powershell.exe OR parent:*\\WmiPrvSE.exe process:*\\rundll32.exe",
    name: { en: "Remote WMI execution (WmiPrvSE spawning shells)", fr: "Exécution WMI distante (WmiPrvSE lançant des shells)", de: "Remote-WMI-Ausführung (WmiPrvSE startet Shells)", es: "Ejecución remota de WMI (WmiPrvSE generando shells)", it: "Esecuzione WMI remota (WmiPrvSE che avvia shell)", pt: "Execução remota via WMI (WmiPrvSE gerando shells)", ja: "リモートWMI実行(WmiPrvSEによるシェル起動)", zh: "远程WMI执行(WmiPrvSE生成shell)" },
  },
  {
    id: "remote-task",
    category: "lateral",
    mitre: "T1053.005",
    query:
      "EventID:5145 RelativeTargetName:atsvc",
    name: { en: "Remote scheduled task creation (atsvc pipe)", fr: "Création de tâche planifiée à distance (pipe atsvc)", de: "Erstellung geplanter Aufgaben aus der Ferne (atsvc-Pipe)", es: "Creación remota de tareas programadas (pipe atsvc)", it: "Creazione remota di attività pianificate (pipe atsvc)", pt: "Criação remota de tarefa agendada (pipe atsvc)", ja: "リモートスケジュールタスクの作成(atsvcパイプ)", zh: "远程创建计划任务(atsvc管道)" },
  },
  {
    id: "overpass-the-hash",
    category: "lateral",
    mitre: "T1550.002",
    query:
      "EventID:4624 LogonType:9 LogonProcessName:seclogo",
    name: { en: "NewCredentials logons (runas /netonly, overpass-the-hash)", fr: "Connexions NewCredentials (runas /netonly, overpass-the-hash)", de: "NewCredentials-Anmeldungen (runas /netonly, Overpass-the-Hash)", es: "Inicios de sesión NewCredentials (runas /netonly, overpass-the-hash)", it: "Accessi NewCredentials (runas /netonly, overpass-the-hash)", pt: "Logons NewCredentials (runas /netonly, overpass-the-hash)", ja: "NewCredentialsログオン(runas /netonly、overpass-the-hash)", zh: "NewCredentials登录(runas /netonly、overpass-the-hash)" },
  },
  {
    id: "run-keys",
    category: "persistence",
    mitre: "T1547.001",
    query:
      "Provider:*Sysmon* EventID:13 TargetObject:*\\CurrentVersion\\Run* OR EventID:4657 ObjectName:*\\CurrentVersion\\Run*",
    name: { en: "Registry Run / RunOnce keys modified", fr: "Clés de registre Run / RunOnce modifiées", de: "Registrierungsschlüssel Run / RunOnce geändert", es: "Claves de registro Run / RunOnce modificadas", it: "Chiavi di registro Run / RunOnce modificate", pt: "Chaves de registro Run / RunOnce modificadas", ja: "レジストリのRun / RunOnceキーの変更", zh: "注册表Run/RunOnce键被修改" },
  },
  {
    id: "startup-folder",
    category: "persistence",
    mitre: "T1547.001",
    query:
      "Provider:*Sysmon* EventID:11 TargetFilename:\"*\\Start Menu\\Programs\\Startup\\*\"",
    name: { en: "Files dropped in a Startup folder", fr: "Fichiers déposés dans un dossier Startup", de: "Dateien in einem Startup-Ordner abgelegt", es: "Archivos colocados en una carpeta Startup", it: "File depositati in una cartella Startup", pt: "Arquivos colocados em uma pasta Startup", ja: "Startupフォルダーへのファイル配置", zh: "在Startup文件夹中投放的文件" },
  },
  {
    id: "ifeo",
    category: "persistence",
    mitre: "T1546.012",
    query:
      "Provider:*Sysmon* EventID:13 TargetObject:\"*\\Image File Execution Options\\*\"",
    name: { en: "Image File Execution Options changed (debugger hijack)", fr: "Image File Execution Options modifiées (détournement de débogueur)", de: "Image File Execution Options geändert (Debugger-Hijack)", es: "Image File Execution Options modificadas (secuestro de depurador)", it: "Image File Execution Options modificate (dirottamento del debugger)", pt: "Image File Execution Options alteradas (sequestro de depurador)", ja: "Image File Execution Optionsの変更(デバッガーハイジャック)", zh: "Image File Execution Options被更改(调试器劫持)" },
  },
  {
    id: "suspicious-service-path",
    category: "persistence",
    mitre: "T1543.003",
    query:
      "EventID:7045 ImagePath:*\\Temp\\* OR EventID:7045 ImagePath:*\\AppData\\* OR EventID:7045 ImagePath:*\\Users\\Public\\* OR EventID:7045 ImagePath:*cmd.exe* OR EventID:7045 ImagePath:*powershell* OR EventID:4697 ServiceFileName:*\\Temp\\* OR EventID:4697 ServiceFileName:*powershell*",
    name: { en: "Services running from temp folders or shells", fr: "Services exécutés depuis des dossiers temporaires ou des shells", de: "Dienste, die aus temporären Ordnern oder Shells ausgeführt werden", es: "Servicios ejecutados desde carpetas temporales o shells", it: "Servizi eseguiti da cartelle temporanee o shell", pt: "Serviços executados a partir de pastas temporárias ou shells", ja: "一時フォルダーやシェルから実行されるサービス", zh: "从临时文件夹或shell运行的服务" },
  },
  {
    id: "pwd-never-expires",
    category: "persistence",
    mitre: "T1098",
    query:
      "EventID:4738 UserAccountControl:*%%2089* OR EventID:4720 UserAccountControl:*%%2089*",
    name: { en: "Password set to never expire", fr: "Mot de passe défini pour ne jamais expirer", de: "Kennwort auf 'läuft nie ab' gesetzt", es: "Contraseña configurada para no caducar nunca", it: "Password impostata per non scadere mai", pt: "Senha definida para nunca expirar", ja: "パスワードを無期限に設定", zh: "密码设置为永不过期" },
  },
  {
    id: "bits-jobs",
    category: "persistence",
    mitre: "T1197",
    query:
      "Provider:*Bits-Client* EventID:59 OR process:*\\bitsadmin.exe",
    name: { en: "BITS transfer jobs", fr: "Tâches de transfert BITS", de: "BITS-Übertragungsaufträge", es: "Trabajos de transferencia BITS", it: "Processi di trasferimento BITS", pt: "Tarefas de transferência BITS", ja: "BITS転送ジョブ", zh: "BITS传输作业" },
  },
  {
    id: "office-child",
    category: "execution",
    mitre: "T1204.002",
    query:
      "parent:*\\winword.exe OR parent:*\\excel.exe OR parent:*\\powerpnt.exe OR parent:*\\outlook.exe OR parent:*\\onenote.exe OR parent:*\\mspub.exe",
    name: { en: "Processes started by Office apps (malicious documents)", fr: "Processus démarrés par des applications Office (documents malveillants)", de: "Von Office-Anwendungen gestartete Prozesse (bösartige Dokumente)", es: "Procesos iniciados por aplicaciones de Office (documentos maliciosos)", it: "Processi avviati da applicazioni Office (documenti dannosi)", pt: "Processos iniciados por aplicativos do Office (documentos maliciosos)", ja: "Officeアプリから起動されたプロセス(悪意のある文書)", zh: "由Office应用启动的进程(恶意文档)" },
  },
  {
    id: "script-hosts",
    category: "execution",
    mitre: "T1059.005",
    query:
      "process:*\\wscript.exe OR process:*\\cscript.exe OR process:*\\hh.exe",
    name: { en: "Script hosts (wscript, cscript, hh)", fr: "Hôtes de script (wscript, cscript, hh)", de: "Skript-Hosts (wscript, cscript, hh)", es: "Hosts de scripts (wscript, cscript, hh)", it: "Host di script (wscript, cscript, hh)", pt: "Hosts de script (wscript, cscript, hh)", ja: "スクリプトホスト(wscript、cscript、hh)", zh: "脚本宿主(wscript、cscript、hh)" },
  },
  {
    id: "temp-exec",
    category: "execution",
    mitre: "T1204",
    query:
      "process:*\\AppData\\Local\\Temp\\*.exe OR process:*\\Users\\Public\\*.exe OR process:*\\Windows\\Temp\\*.exe OR process:*\\Downloads\\*.exe",
    name: { en: "Executables run from Temp, Public or Downloads", fr: "Exécutables lancés depuis Temp, Public ou Downloads", de: "Ausführbare Dateien aus Temp, Public oder Downloads gestartet", es: "Ejecutables ejecutados desde Temp, Public o Downloads", it: "Eseguibili avviati da Temp, Public o Downloads", pt: "Executáveis executados a partir de Temp, Public ou Downloads", ja: "Temp、Public、Downloadsから実行された実行ファイル", zh: "从Temp、Public或Downloads运行的可执行文件" },
  },
  {
    id: "download-cradle",
    category: "execution",
    mitre: "T1105",
    query:
      "CommandLine:*DownloadString* OR CommandLine:*DownloadFile* OR CommandLine:*Invoke-WebRequest* OR CommandLine:\"*iwr *http*\" OR CommandLine:*curl*http* OR CommandLine:*wget*http* OR CommandLine:*certutil*-urlcache*",
    name: { en: "Download cradles in command lines", fr: "Download cradles dans les lignes de commande", de: "Download-Cradles in Befehlszeilen", es: "Download cradles en líneas de comandos", it: "Download cradle nelle righe di comando", pt: "Download cradles em linhas de comando", ja: "コマンドライン内のDownload Cradle", zh: "命令行中的Download Cradle" },
  },
  {
    id: "amsi-bypass",
    category: "evasion",
    mitre: "T1562.001",
    query:
      "ScriptBlockText:*AmsiUtils* OR ScriptBlockText:*amsiInitFailed* OR ScriptBlockText:*AmsiScanBuffer*",
    name: { en: "AMSI bypass attempts", fr: "Tentatives de contournement AMSI", de: "AMSI-Bypass-Versuche", es: "Intentos de evasión de AMSI", it: "Tentativi di bypass AMSI", pt: "Tentativas de bypass do AMSI", ja: "AMSIバイパスの試行", zh: "AMSI绕过尝试" },
  },
  {
    id: "wevtutil-clear",
    category: "evasion",
    mitre: "T1070.001",
    query:
      "CommandLine:\"*wevtutil*cl *\" OR CommandLine:*Clear-EventLog* OR ScriptBlockText:*Clear-EventLog*",
    name: { en: "Log clearing commands (wevtutil cl, Clear-EventLog)", fr: "Commandes d'effacement de journaux (wevtutil cl, Clear-EventLog)", de: "Protokolllöschbefehle (wevtutil cl, Clear-EventLog)", es: "Comandos de borrado de registros (wevtutil cl, Clear-EventLog)", it: "Comandi di cancellazione dei log (wevtutil cl, Clear-EventLog)", pt: "Comandos de limpeza de logs (wevtutil cl, Clear-EventLog)", ja: "ログクリアコマンド(wevtutil cl、Clear-EventLog)", zh: "日志清除命令(wevtutil cl、Clear-EventLog)" },
  },
  {
    id: "firewall-off",
    category: "evasion",
    mitre: "T1562.004",
    query:
      "CommandLine:*advfirewall*state*off* OR CommandLine:*firewall*set*opmode*disable* OR ScriptBlockText:*Set-NetFirewallProfile*-Enabled*False*",
    name: { en: "Firewall disabled from the command line", fr: "Pare-feu désactivé depuis la ligne de commande", de: "Firewall über die Befehlszeile deaktiviert", es: "Firewall deshabilitado desde la línea de comandos", it: "Firewall disabilitato dalla riga di comando", pt: "Firewall desativado pela linha de comando", ja: "コマンドラインからのファイアウォール無効化", zh: "通过命令行禁用防火墙" },
  },
  {
    id: "defender-tamper",
    category: "evasion",
    mitre: "T1562.001",
    query:
      "CommandLine:*Set-MpPreference*-Disable* OR ScriptBlockText:*Set-MpPreference*-Disable* OR CommandLine:*Add-MpPreference*-ExclusionPath* OR ScriptBlockText:*Add-MpPreference*-Exclusion*",
    name: { en: "Defender disabled or exclusions added", fr: "Defender désactivé ou exclusions ajoutées", de: "Defender deaktiviert oder Ausnahmen hinzugefügt", es: "Defender deshabilitado o exclusiones añadidas", it: "Defender disabilitato o esclusioni aggiunte", pt: "Defender desativado ou exclusões adicionadas", ja: "Defenderの無効化または除外の追加", zh: "Defender被禁用或添加了排除项" },
  },
  {
    id: "service-disabled",
    category: "evasion",
    mitre: "T1562.001",
    query:
      "EventID:7040 param3:disabled",
    name: { en: "Service start type set to disabled", fr: "Type de démarrage du service défini sur désactivé", de: "Diensttyp auf 'Deaktiviert' gesetzt", es: "Tipo de inicio del servicio establecido en deshabilitado", it: "Tipo di avvio del servizio impostato su disabilitato", pt: "Tipo de inicialização do serviço definido como desativado", ja: "サービスの開始種別を無効に設定", zh: "服务启动类型设置为禁用" },
  },
  {
    id: "sysmon-tamper",
    category: "evasion",
    mitre: "T1562.006",
    query:
      "Provider:*Sysmon* EventID:16 OR Provider:*Sysmon* EventID:4",
    name: { en: "Sysmon configuration or service state changed", fr: "Configuration Sysmon ou état du service modifié", de: "Sysmon-Konfiguration oder Dienststatus geändert", es: "Configuración de Sysmon o estado del servicio modificado", it: "Configurazione di Sysmon o stato del servizio modificato", pt: "Configuração do Sysmon ou estado do serviço alterado", ja: "Sysmonの設定またはサービス状態の変更", zh: "Sysmon配置或服务状态变更" },
  },
  {
    id: "timestomp",
    category: "evasion",
    mitre: "T1070.006",
    query:
      "Provider:*Sysmon* EventID:2",
    name: { en: "File creation time changed (timestomping)", fr: "Date de création de fichier modifiée (timestomping)", de: "Dateierstellungszeit geändert (Timestomping)", es: "Fecha de creación de archivo modificada (timestomping)", it: "Data di creazione del file modificata (timestomping)", pt: "Data de criação de arquivo alterada (timestomping)", ja: "ファイル作成日時の変更(timestomping)", zh: "文件创建时间被更改(timestomping)" },
  },
  {
    id: "remote-thread",
    category: "evasion",
    mitre: "T1055",
    query:
      "Provider:*Sysmon* EventID:8",
    name: { en: "Remote thread creation (process injection)", fr: "Création de thread distant (injection de processus)", de: "Erstellung eines Remote-Threads (Process Injection)", es: "Creación de hilo remoto (inyección de procesos)", it: "Creazione di thread remoto (process injection)", pt: "Criação de thread remota (injeção de processo)", ja: "リモートスレッドの作成(プロセスインジェクション)", zh: "远程线程创建(进程注入)" },
  },
  {
    id: "shadow-delete",
    category: "impact",
    mitre: "T1490",
    query:
      "CommandLine:*vssadmin*delete*shadows* OR CommandLine:*shadowcopy*delete* OR CommandLine:*wbadmin*delete* OR CommandLine:*bcdedit*recoveryenabled*no* OR ScriptBlockText:*Win32_ShadowCopy*Delete*",
    name: { en: "Shadow copies or backups deleted (ransomware)", fr: "Suppression de clichés instantanés ou de sauvegardes (rançongiciel)", de: "Schattenkopien oder Backups gelöscht (Ransomware)", es: "Copias de sombra o copias de seguridad eliminadas (ransomware)", it: "Copie shadow o backup eliminati (ransomware)", pt: "Cópias de sombra ou backups excluídos (ransomware)", ja: "シャドウコピーまたはバックアップの削除(ランサムウェア)", zh: "卷影副本或备份被删除(勒索软件)" },
  },
  {
    id: "sid-history",
    category: "persistence",
    mitre: "T1134.005",
    query:
      "EventID:4765 OR EventID:4766",
    name: { en: "SID History added to an account", fr: "SID History ajouté à un compte", de: "SID-Verlauf zu einem Konto hinzugefügt", es: "Historial de SID añadido a una cuenta", it: "Cronologia SID aggiunta a un account", pt: "Histórico de SID adicionado a uma conta", ja: "アカウントへのSID履歴の追加", zh: "向账户添加 SID 历史记录" },
  },
  {
    id: "dsrm-password",
    category: "persistence",
    mitre: "T1098",
    query:
      "EventID:4794",
    name: { en: "DSRM administrator password set", fr: "Mot de passe administrateur DSRM défini", de: "DSRM-Administratorkennwort festgelegt", es: "Contraseña de administrador DSRM establecida", it: "Password amministratore DSRM impostata", pt: "Senha de administrador DSRM definida", ja: "DSRM管理者パスワードの設定", zh: "设置 DSRM 管理员密码" },
  },
  {
    id: "computer-account-created",
    category: "persistence",
    mitre: "T1136.002",
    query:
      "EventID:4741",
    name: { en: "Computer accounts created (MachineAccountQuota abuse)", fr: "Comptes ordinateur créés (abus de MachineAccountQuota)", de: "Computerkonten erstellt (MachineAccountQuota-Missbrauch)", es: "Cuentas de equipo creadas (abuso de MachineAccountQuota)", it: "Account computer creati (abuso di MachineAccountQuota)", pt: "Contas de computador criadas (abuso de MachineAccountQuota)", ja: "コンピューターアカウントの作成(MachineAccountQuotaの悪用)", zh: "创建计算机账户(滥用 MachineAccountQuota)" },
  },
  {
    id: "dollar-user",
    category: "persistence",
    mitre: "T1136.001",
    query:
      "EventID:4720 TargetUserName:*$",
    name: { en: "User account created with a trailing $ (hidden account)", fr: "Compte utilisateur créé avec un $ final (compte caché)", de: "Benutzerkonto mit abschließendem $ erstellt (verstecktes Konto)", es: "Cuenta de usuario creada con $ final (cuenta oculta)", it: "Account utente creato con $ finale (account nascosto)", pt: "Conta de usuário criada com $ no final (conta oculta)", ja: "末尾に$が付いたユーザーアカウントの作成(隠しアカウント)", zh: "创建以 $ 结尾的用户账户(隐藏账户)" },
  },
  {
    id: "net-user-add",
    category: "persistence",
    mitre: "T1136.001",
    query:
      "CommandLine:\"*net* user * /add*\" OR CommandLine:\"*net* localgroup administrators * /add*\" OR ScriptBlockText:*New-LocalUser* OR ScriptBlockText:*Add-LocalGroupMember*",
    name: { en: "Local users or admins added from the command line", fr: "Utilisateurs ou admins locaux ajoutés en ligne de commande", de: "Lokale Benutzer oder Admins per Befehlszeile hinzugefügt", es: "Usuarios o administradores locales añadidos por línea de comandos", it: "Utenti o amministratori locali aggiunti da riga di comando", pt: "Usuários ou administradores locais adicionados por linha de comando", ja: "コマンドラインによるローカルユーザー・管理者の追加", zh: "通过命令行添加本地用户或管理员" },
  },
  {
    id: "gpo-changes",
    category: "persistence",
    mitre: "T1484.001",
    query:
      "EventID:5136 ObjectClass:groupPolicyContainer OR EventID:5136 AttributeLDAPDisplayName:gPCFileSysPath OR EventID:5136 AttributeLDAPDisplayName:gPLink",
    name: { en: "Group Policy objects modified or linked", fr: "Objets de stratégie de groupe modifiés ou liés", de: "Gruppenrichtlinienobjekte geändert oder verknüpft", es: "Objetos de directiva de grupo modificados o vinculados", it: "Oggetti Criteri di gruppo modificati o collegati", pt: "Objetos de Política de Grupo modificados ou vinculados", ja: "グループポリシーオブジェクトの変更またはリンク", zh: "组策略对象被修改或链接" },
  },
  {
    id: "spn-set",
    category: "credential",
    mitre: "T1558.003",
    query:
      "EventID:5136 AttributeLDAPDisplayName:servicePrincipalName",
    name: { en: "SPN added to an account (targeted Kerberoasting)", fr: "SPN ajouté à un compte (Kerberoasting ciblé)", de: "SPN zu einem Konto hinzugefügt (gezieltes Kerberoasting)", es: "SPN añadido a una cuenta (Kerberoasting dirigido)", it: "SPN aggiunto a un account (Kerberoasting mirato)", pt: "SPN adicionado a uma conta (Kerberoasting direcionado)", ja: "アカウントへのSPN追加(標的型Kerberoasting)", zh: "向账户添加 SPN(定向 Kerberoasting)" },
  },
  {
    id: "shadow-credentials",
    category: "credential",
    mitre: "T1556",
    query:
      "EventID:5136 AttributeLDAPDisplayName:msDS-KeyCredentialLink",
    name: { en: "Shadow Credentials: msDS-KeyCredentialLink modified", fr: "Shadow Credentials : msDS-KeyCredentialLink modifié", de: "Shadow Credentials: msDS-KeyCredentialLink geändert", es: "Shadow Credentials: msDS-KeyCredentialLink modificado", it: "Shadow Credentials: msDS-KeyCredentialLink modificato", pt: "Shadow Credentials: msDS-KeyCredentialLink modificado", ja: "Shadow Credentials: msDS-KeyCredentialLinkの変更", zh: "Shadow Credentials:msDS-KeyCredentialLink 被修改" },
  },
  {
    id: "rbcd",
    category: "lateral",
    mitre: "T1134",
    query:
      "EventID:5136 AttributeLDAPDisplayName:msDS-AllowedToActOnBehalfOfOtherIdentity OR EventID:5136 AttributeLDAPDisplayName:msDS-AllowedToDelegateTo",
    name: { en: "Kerberos delegation changed (RBCD, constrained)", fr: "Délégation Kerberos modifiée (RBCD, contrainte)", de: "Kerberos-Delegierung geändert (RBCD, eingeschränkt)", es: "Delegación Kerberos modificada (RBCD, restringida)", it: "Delega Kerberos modificata (RBCD, vincolata)", pt: "Delegação Kerberos alterada (RBCD, restrita)", ja: "Kerberos委任の変更(RBCD、制約付き)", zh: "Kerberos 委派被修改(RBCD、约束委派)" },
  },
  {
    id: "adcs-san",
    category: "credential",
    mitre: "T1649",
    query:
      "EventID:4887 Attributes:*SAN:* OR EventID:4886 Attributes:*SAN:*",
    name: { en: "Certificates requested with a custom SAN (AD CS ESC1)", fr: "Certificats demandés avec un SAN personnalisé (AD CS ESC1)", de: "Zertifikate mit eigenem SAN angefordert (AD CS ESC1)", es: "Certificados solicitados con SAN personalizado (AD CS ESC1)", it: "Certificati richiesti con SAN personalizzato (AD CS ESC1)", pt: "Certificados solicitados com SAN personalizado (AD CS ESC1)", ja: "カスタムSAN付き証明書の要求(AD CS ESC1)", zh: "使用自定义 SAN 申请证书(AD CS ESC1)" },
  },
  {
    id: "lsass-dump-tools",
    category: "credential",
    mitre: "T1003.001",
    query:
      "CommandLine:*comsvcs*MiniDump* OR CommandLine:*procdump*lsass* OR CommandLine:*rdrleakdiag* OR CommandLine:*sqldumper*lsass* OR ScriptBlockText:*Out-Minidump*",
    name: { en: "LSASS dumped with built-in or signed tools (comsvcs, procdump)", fr: "Dump de LSASS via des outils intégrés ou signés (comsvcs, procdump)", de: "LSASS-Dump mit Bordmitteln oder signierten Tools (comsvcs, procdump)", es: "Volcado de LSASS con herramientas integradas o firmadas (comsvcs, procdump)", it: "Dump di LSASS con strumenti integrati o firmati (comsvcs, procdump)", pt: "Dump do LSASS com ferramentas nativas ou assinadas (comsvcs, procdump)", ja: "標準・署名済みツールによるLSASSダンプ(comsvcs、procdump)", zh: "使用内置或已签名工具转储 LSASS(comsvcs、procdump)" },
  },
  {
    id: "wdigest",
    category: "credential",
    mitre: "T1112",
    query:
      "TargetObject:*\\WDigest\\UseLogonCredential* OR CommandLine:*UseLogonCredential* OR ScriptBlockText:*UseLogonCredential*",
    name: { en: "WDigest cleartext credentials enabled", fr: "Identifiants WDigest en clair activés", de: "WDigest-Klartext-Anmeldeinformationen aktiviert", es: "Credenciales en texto claro de WDigest habilitadas", it: "Credenziali in chiaro WDigest abilitate", pt: "Credenciais em texto claro do WDigest habilitadas", ja: "WDigestの平文資格情報の有効化", zh: "启用 WDigest 明文凭据" },
  },
  {
    id: "rubeus",
    category: "credential",
    mitre: "T1558",
    query:
      "CommandLine:*rubeus* OR CommandLine:*asktgt* OR CommandLine:*kerberos::ptt* OR CommandLine:*kerberos::golden* OR ScriptBlockText:*Invoke-Rubeus* OR process:*\\Rubeus.exe",
    name: { en: "Kerberos ticket tooling (Rubeus, pass-the-ticket, golden ticket)", fr: "Outils de tickets Kerberos (Rubeus, pass-the-ticket, golden ticket)", de: "Kerberos-Ticket-Tools (Rubeus, Pass-the-Ticket, Golden Ticket)", es: "Herramientas de tickets Kerberos (Rubeus, pass-the-ticket, golden ticket)", it: "Strumenti per ticket Kerberos (Rubeus, pass-the-ticket, golden ticket)", pt: "Ferramentas de tickets Kerberos (Rubeus, pass-the-ticket, golden ticket)", ja: "Kerberosチケット攻撃ツール(Rubeus、Pass-the-Ticket、ゴールデンチケット)", zh: "Kerberos 票据工具(Rubeus、传递票据、黄金票据)" },
  },
  {
    id: "impacket",
    category: "lateral",
    mitre: "T1047",
    query:
      "CommandLine:*127.0.0.1\\ADMIN$\\__* OR CommandLine:*\\\\127.0.0.1\\C$\\__output* OR EventID:7045 ImagePath:*__output* OR EventID:7045 ImagePath:*\\execute.bat*",
    name: { en: "Impacket wmiexec / smbexec / atexec traces", fr: "Traces Impacket wmiexec / smbexec / atexec", de: "Impacket-Spuren (wmiexec / smbexec / atexec)", es: "Rastros de Impacket wmiexec / smbexec / atexec", it: "Tracce di Impacket wmiexec / smbexec / atexec", pt: "Rastros de Impacket wmiexec / smbexec / atexec", ja: "Impacketのwmiexec / smbexec / atexecの痕跡", zh: "Impacket wmiexec / smbexec / atexec 痕迹" },
  },
  {
    id: "rdp-hijack",
    category: "lateral",
    mitre: "T1563.002",
    query:
      "process:*\\tscon.exe OR CommandLine:*tscon* OR CommandLine:*mstsc*/shadow*",
    name: { en: "RDP session hijacking or shadowing (tscon)", fr: "Détournement ou observation de session RDP (tscon)", de: "RDP-Sitzungsübernahme oder -Spiegelung (tscon)", es: "Secuestro u observación de sesión RDP (tscon)", it: "Dirottamento o shadowing di sessione RDP (tscon)", pt: "Sequestro ou espelhamento de sessão RDP (tscon)", ja: "RDPセッションの乗っ取り・シャドウイング(tscon)", zh: "RDP 会话劫持或影子监控(tscon)" },
  },
  {
    id: "rdp-enabled",
    category: "lateral",
    mitre: "T1021.001",
    query:
      "TargetObject:*fDenyTSConnections* OR CommandLine:*fDenyTSConnections* OR ScriptBlockText:*fDenyTSConnections*",
    name: { en: "Remote Desktop enabled through the registry", fr: "Bureau à distance activé via le registre", de: "Remotedesktop über die Registry aktiviert", es: "Escritorio remoto habilitado mediante el registro", it: "Desktop remoto abilitato tramite registro", pt: "Área de Trabalho Remota habilitada pelo registro", ja: "レジストリによるリモートデスクトップの有効化", zh: "通过注册表启用远程桌面" },
  },
  {
    id: "accessibility-backdoor",
    category: "persistence",
    mitre: "T1546.008",
    query:
      "parent:*\\sethc.exe OR parent:*\\utilman.exe OR parent:*\\osk.exe OR parent:*\\Magnify.exe OR parent:*\\Narrator.exe OR parent:*\\DisplaySwitch.exe",
    name: { en: "Accessibility feature backdoor (sticky keys, utilman)", fr: "Porte dérobée via l'accessibilité (touches rémanentes, utilman)", de: "Backdoor über Bedienungshilfen (Einrastfunktion, utilman)", es: "Puerta trasera de accesibilidad (teclas especiales, utilman)", it: "Backdoor tramite accessibilità (tasti permanenti, utilman)", pt: "Backdoor de acessibilidade (teclas de aderência, utilman)", ja: "ユーザー補助機能のバックドア(固定キー、utilman)", zh: "辅助功能后门(粘滞键、utilman)" },
  },
  {
    id: "uac-bypass",
    category: "evasion",
    mitre: "T1548.002",
    query:
      "TargetObject:*\\ms-settings\\shell\\open\\command* OR TargetObject:*\\mscfile\\shell\\open\\command* OR TargetObject:*\\exefile\\shell\\open\\command* OR process:*\\fodhelper.exe OR process:*\\computerdefaults.exe",
    name: { en: "UAC bypass (fodhelper, ms-settings hijack)", fr: "Contournement de l'UAC (fodhelper, détournement ms-settings)", de: "UAC-Umgehung (fodhelper, ms-settings-Hijack)", es: "Omisión de UAC (fodhelper, secuestro de ms-settings)", it: "Bypass UAC (fodhelper, hijack di ms-settings)", pt: "Bypass do UAC (fodhelper, sequestro de ms-settings)", ja: "UACバイパス(fodhelper、ms-settingsハイジャック)", zh: "UAC 绕过(fodhelper、ms-settings 劫持)" },
  },
  {
    id: "lsa-protection-off",
    category: "evasion",
    mitre: "T1562.001",
    query:
      "TargetObject:*\\Control\\Lsa\\RunAsPPL* OR CommandLine:*RunAsPPL* OR CommandLine:*DisableRestrictedAdmin*",
    name: { en: "LSA protection (RunAsPPL) tampered", fr: "Protection LSA (RunAsPPL) altérée", de: "LSA-Schutz (RunAsPPL) manipuliert", es: "Protección LSA (RunAsPPL) manipulada", it: "Protezione LSA (RunAsPPL) manomessa", pt: "Proteção do LSA (RunAsPPL) adulterada", ja: "LSA保護(RunAsPPL)の改ざん", zh: "LSA 保护(RunAsPPL)被篡改" },
  },
  {
    id: "proxy-execution",
    category: "evasion",
    mitre: "T1127.001",
    query:
      "process:*\\MSBuild.exe OR process:*\\InstallUtil.exe OR process:*\\RegAsm.exe OR process:*\\RegSvcs.exe OR process:*\\msxsl.exe OR process:*\\odbcconf.exe",
    name: { en: "Signed binary proxy execution (MSBuild, InstallUtil, RegAsm)", fr: "Exécution par binaire signé (MSBuild, InstallUtil, RegAsm)", de: "Proxy-Ausführung über signierte Binärdateien (MSBuild, InstallUtil, RegAsm)", es: "Ejecución mediante binarios firmados (MSBuild, InstallUtil, RegAsm)", it: "Esecuzione tramite binari firmati (MSBuild, InstallUtil, RegAsm)", pt: "Execução via binários assinados (MSBuild, InstallUtil, RegAsm)", ja: "署名済みバイナリによるプロキシ実行(MSBuild、InstallUtil、RegAsm)", zh: "已签名二进制代理执行(MSBuild、InstallUtil、RegAsm)" },
  },
  {
    id: "mshta-regsvr32-remote",
    category: "execution",
    mitre: "T1218",
    query:
      "CommandLine:*mshta*http* OR CommandLine:*mshta*javascript:* OR CommandLine:*mshta*vbscript:* OR CommandLine:*regsvr32*/i:http* OR CommandLine:*regsvr32*scrobj.dll*",
    name: { en: "mshta / regsvr32 running remote scripts (Squiblydoo)", fr: "mshta / regsvr32 exécutant des scripts distants (Squiblydoo)", de: "mshta / regsvr32 führt entfernte Skripte aus (Squiblydoo)", es: "mshta / regsvr32 ejecutando scripts remotos (Squiblydoo)", it: "mshta / regsvr32 che eseguono script remoti (Squiblydoo)", pt: "mshta / regsvr32 executando scripts remotos (Squiblydoo)", ja: "mshta / regsvr32によるリモートスクリプト実行(Squiblydoo)", zh: "mshta / regsvr32 执行远程脚本(Squiblydoo)" },
  },
  {
    id: "schtasks-cmd",
    category: "persistence",
    mitre: "T1053.005",
    query:
      "CommandLine:\"*schtasks* /create*\" OR ScriptBlockText:*Register-ScheduledTask*",
    name: { en: "Scheduled tasks created from the command line", fr: "Tâches planifiées créées en ligne de commande", de: "Geplante Aufgaben per Befehlszeile erstellt", es: "Tareas programadas creadas por línea de comandos", it: "Attività pianificate create da riga di comando", pt: "Tarefas agendadas criadas por linha de comando", ja: "コマンドラインによるスケジュールタスクの作成", zh: "通过命令行创建计划任务" },
  },
  {
    id: "sc-create",
    category: "persistence",
    mitre: "T1543.003",
    query:
      "process:*\\sc.exe CommandLine:*create* OR process:*\\sc.exe CommandLine:*config*binpath*",
    name: { en: "Services created or re-pointed with sc.exe", fr: "Services créés ou redirigés avec sc.exe", de: "Dienste mit sc.exe erstellt oder umgeleitet", es: "Servicios creados o redirigidos con sc.exe", it: "Servizi creati o reindirizzati con sc.exe", pt: "Serviços criados ou redirecionados com sc.exe", ja: "sc.exeによるサービスの作成・パス変更", zh: "使用 sc.exe 创建或重定向服务" },
  },
  {
    id: "remote-access-tools",
    category: "c2",
    mitre: "T1219",
    query:
      "process:*\\AnyDesk.exe OR process:*\\TeamViewer.exe OR process:*\\ScreenConnect* OR process:*\\AteraAgent.exe OR process:*\\Splashtop* OR process:*\\rustdesk.exe OR process:*\\meshagent.exe OR ServiceName:*AnyDesk* OR ServiceName:*ScreenConnect*",
    name: { en: "Remote access software (AnyDesk, ScreenConnect, Atera…)", fr: "Logiciels d'accès à distance (AnyDesk, ScreenConnect, Atera…)", de: "Fernzugriffssoftware (AnyDesk, ScreenConnect, Atera…)", es: "Software de acceso remoto (AnyDesk, ScreenConnect, Atera…)", it: "Software di accesso remoto (AnyDesk, ScreenConnect, Atera…)", pt: "Software de acesso remoto (AnyDesk, ScreenConnect, Atera…)", ja: "リモートアクセスソフトウェア(AnyDesk、ScreenConnect、Atera…)", zh: "远程访问软件(AnyDesk、ScreenConnect、Atera…)" },
  },
  {
    id: "tunnels",
    category: "c2",
    mitre: "T1572",
    query:
      "process:*\\ngrok.exe OR process:*\\plink.exe OR process:*\\chisel* OR process:*\\cloudflared.exe OR CommandLine:*portproxy*add* OR QueryName:*ngrok* OR QueryName:*trycloudflare.com",
    name: { en: "Tunnels and port forwarding (ngrok, plink, chisel, portproxy)", fr: "Tunnels et redirection de ports (ngrok, plink, chisel, portproxy)", de: "Tunnel und Portweiterleitung (ngrok, plink, chisel, portproxy)", es: "Túneles y reenvío de puertos (ngrok, plink, chisel, portproxy)", it: "Tunnel e port forwarding (ngrok, plink, chisel, portproxy)", pt: "Túneis e redirecionamento de portas (ngrok, plink, chisel, portproxy)", ja: "トンネルとポートフォワーディング(ngrok、plink、chisel、portproxy)", zh: "隧道与端口转发(ngrok、plink、chisel、portproxy)" },
  },
  {
    id: "c2-pipes",
    category: "c2",
    mitre: "T1071",
    query:
      "Provider:*Sysmon* EventID:17 PipeName:*MSSE-* OR Provider:*Sysmon* EventID:17 PipeName:*msagent_* OR Provider:*Sysmon* EventID:17 PipeName:*postex_* OR Provider:*Sysmon* EventID:17 PipeName:*status_* OR Provider:*Sysmon* EventID:18 PipeName:*msagent_*",
    name: { en: "Named pipes used by C2 frameworks (Cobalt Strike defaults)", fr: "Canaux nommés utilisés par des frameworks C2 (Cobalt Strike par défaut)", de: "Named Pipes von C2-Frameworks (Cobalt-Strike-Standards)", es: "Canalizaciones con nombre de frameworks C2 (Cobalt Strike por defecto)", it: "Named pipe usate da framework C2 (default di Cobalt Strike)", pt: "Pipes nomeados usados por frameworks C2 (padrões do Cobalt Strike)", ja: "C2フレームワークの名前付きパイプ(Cobalt Strikeの既定値)", zh: "C2 框架使用的命名管道(Cobalt Strike 默认值)" },
  },
  {
    id: "exfil-tools",
    category: "c2",
    mitre: "T1567",
    query:
      "process:*\\rclone.exe OR CommandLine:*rclone* OR CommandLine:*megacmd* OR process:*\\MEGAsync.exe OR CommandLine:*transfer.sh* OR QueryName:*mega.nz OR QueryName:*transfer.sh",
    name: { en: "Exfiltration tools and services (rclone, MEGA, transfer.sh)", fr: "Outils et services d'exfiltration (rclone, MEGA, transfer.sh)", de: "Exfiltrationstools und -dienste (rclone, MEGA, transfer.sh)", es: "Herramientas y servicios de exfiltración (rclone, MEGA, transfer.sh)", it: "Strumenti e servizi di esfiltrazione (rclone, MEGA, transfer.sh)", pt: "Ferramentas e serviços de exfiltração (rclone, MEGA, transfer.sh)", ja: "持ち出しツール・サービス(rclone、MEGA、transfer.sh)", zh: "数据外传工具与服务(rclone、MEGA、transfer.sh)" },
  },
  {
    id: "archive-staging",
    category: "c2",
    mitre: "T1560.001",
    query:
      "CommandLine:\"*7z* a *\" OR CommandLine:\"*rar* a *-hp*\" OR CommandLine:*Compress-Archive* OR ScriptBlockText:*Compress-Archive*",
    name: { en: "Data staged in archives (7-Zip, WinRAR, Compress-Archive)", fr: "Données préparées en archives (7-Zip, WinRAR, Compress-Archive)", de: "Daten in Archiven bereitgestellt (7-Zip, WinRAR, Compress-Archive)", es: "Datos preparados en archivos comprimidos (7-Zip, WinRAR, Compress-Archive)", it: "Dati preparati in archivi (7-Zip, WinRAR, Compress-Archive)", pt: "Dados preparados em arquivos compactados (7-Zip, WinRAR, Compress-Archive)", ja: "アーカイブによるデータのステージング(7-Zip、WinRAR、Compress-Archive)", zh: "将数据打包暂存(7-Zip、WinRAR、Compress-Archive)" },
  },
  {
    id: "ransomware-cmds",
    category: "impact",
    mitre: "T1486",
    query:
      "CommandLine:*cipher*/w:* OR CommandLine:\"*bcdedit*bootstatuspolicy*ignoreallfailures*\" OR CommandLine:*wmic*shadowcopy* OR CommandLine:\"*icacls* /grant Everyone:F*\"",
    name: { en: "Ransomware pre-encryption commands (cipher /w, bcdedit, icacls)", fr: "Commandes pré-chiffrement de rançongiciel (cipher /w, bcdedit, icacls)", de: "Ransomware-Befehle vor der Verschlüsselung (cipher /w, bcdedit, icacls)", es: "Comandos previos al cifrado de ransomware (cipher /w, bcdedit, icacls)", it: "Comandi pre-cifratura del ransomware (cipher /w, bcdedit, icacls)", pt: "Comandos de pré-criptografia de ransomware (cipher /w, bcdedit, icacls)", ja: "ランサムウェアの暗号化前コマンド(cipher /w、bcdedit、icacls)", zh: "勒索软件加密前命令(cipher /w、bcdedit、icacls)" },
  },
  {
    id: "mass-service-stop",
    category: "impact",
    mitre: "T1489",
    query:
      "CommandLine:\"*net* stop *\" OR CommandLine:*Stop-Service* OR CommandLine:*taskkill*/f* OR EventID:7036 param2:stopped param1:*SQL*",
    name: { en: "Services or processes killed (net stop, taskkill, SQL stopped)", fr: "Services ou processus arrêtés (net stop, taskkill, SQL arrêté)", de: "Dienste oder Prozesse beendet (net stop, taskkill, SQL gestoppt)", es: "Servicios o procesos detenidos (net stop, taskkill, SQL detenido)", it: "Servizi o processi terminati (net stop, taskkill, SQL arrestato)", pt: "Serviços ou processos encerrados (net stop, taskkill, SQL parado)", ja: "サービス・プロセスの強制停止(net stop、taskkill、SQL停止)", zh: "服务或进程被终止(net stop、taskkill、SQL 停止)" },
  },
];
