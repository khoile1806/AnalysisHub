// Compliance Audit checklist — read-only configuration queries mapped to the
// common controls of ISO 27001 / SOC 2 / PCI-DSS / NIST 800-53 / CIS v8.
// Dispatched to an agent through the same checklist engine as forensic
// collection; captured output is the audit *evidence* for each control.
//
// Organised by the 6 audit hunting domains (IAM, Network, Endpoint, Data &
// Secrets, Logging & Monitoring, Change Management). Each item carries:
//   - purpose         : what the check is for / why it matters
//   - suggestedTools  : external tools/platforms for deeper or more accurate results
//   - frameworks/control : compliance mapping
// Items with executable:false are manual / external-platform checks (e.g. cloud,
// Git secrets, MFA console) that cannot be answered by a single host command.
//
// Shapes are structurally compatible with CollectionChecklist's ChecklistItem.

export type CompliancePriority = 'critical' | 'high' | 'medium'
export type Framework = 'ISO 27001' | 'SOC 2' | 'PCI-DSS' | 'NIST'

export interface ComplianceItem {
  id: string
  subsection: string
  subsectionLabel: string
  label: string
  commands: string[]
  priority: CompliancePriority
  executable: boolean
  frameworks: Framework[]
  control: string
  purpose: string
  suggestedTools?: string[]
}

export interface ComplianceSection {
  id: string
  phase: string
  label: string
  optional?: boolean
  items: { win: ComplianceItem[]; linux: ComplianceItem[] }
}

const ALL: Framework[] = ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST']

// ── A. Identity & Access Management ─────────────────────────────────────────
const IAM_WIN: ComplianceItem[] = [
  { id: 'c-iam-w1', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.9.4.3 · PCI 8.2 · NIST IA-5 · CIS 5.2',
    label: 'Password policy (length, history, max age, complexity)',
    purpose: 'Xác minh chính sách mật khẩu đáp ứng yêu cầu framework (độ dài, lịch sử, hạn, độ phức tạp).',
    suggestedTools: ['CIS-CAT Pro', 'Microsoft Security Compliance Toolkit', 'PingCastle'],
    commands: ['net accounts', 'powershell -c "secedit /export /cfg %TEMP%\\sec.cfg >NUL & findstr /i \\"PasswordComplexity MinimumPasswordLength PasswordHistorySize MaximumPasswordAge LockoutBadCount\\" %TEMP%\\sec.cfg"'] },
  { id: 'c-iam-w2', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.9.2.3 · PCI 7.1 · NIST AC-6 · CIS 5.4',
    label: 'Local administrator group membership (least privilege)',
    purpose: 'Phát hiện tài khoản có quyền Admin thừa / không được quản lý (over-privileged).',
    suggestedTools: ['BloodHound', 'PingCastle', 'Microsoft LAPS (quản lý local admin pwd)'],
    commands: ['net localgroup Administrators'] },
  { id: 'c-iam-w3', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.9.2.1 · PCI 8.1.4 · NIST AC-2 · CIS 5.3',
    label: 'Enabled accounts, last logon & password age (stale accounts >90d)',
    purpose: 'Tìm tài khoản không dùng >90 ngày vẫn active, hoặc password không xoay vòng.',
    suggestedTools: ['PingCastle', 'AD audit (Get-ADUser)', 'ManageEngine ADAudit Plus'],
    commands: ['powershell -c "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired | Format-Table -AutoSize"'] },
  { id: 'c-iam-w4', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.9.4.2 · PCI 8.1.6 · NIST AC-7 · CIS 6.2',
    label: 'Account lockout policy (brute-force resistance)',
    purpose: 'Đảm bảo có khoá tài khoản sau N lần sai để chống brute-force.',
    suggestedTools: ['CIS-CAT Pro'],
    commands: ['net accounts | findstr /i "lockout"'] },
  { id: 'c-iam-w5', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.9.4.2 · PCI 8.3 · NIST IA-2(1)',
    label: 'MFA bật cho privileged users (kiểm tra thủ công)',
    purpose: 'Xác nhận MFA đã bật cho admin/privileged — không kiểm được bằng lệnh host đơn lẻ.',
    suggestedTools: ['Entra ID / Azure AD admin', 'Okta', 'Duo', 'Google Workspace admin'],
    commands: [] },
]

const IAM_LIN: ComplianceItem[] = [
  { id: 'c-iam-l1', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.9.4.3 · PCI 8.2 · NIST IA-5 · CIS 5.2',
    label: 'Password policy (login.defs + PAM pwquality)',
    purpose: 'Xác minh chính sách mật khẩu (độ dài, hạn, độ phức tạp) cấu hình đúng.',
    suggestedTools: ['Lynis', 'OpenSCAP (ssg)', 'CIS-CAT Pro'],
    commands: ['grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE" /etc/login.defs 2>/dev/null', 'grep -E "minlen|dcredit|ucredit|ocredit|lcredit|retry" /etc/security/pwquality.conf 2>/dev/null'] },
  { id: 'c-iam-l2', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.9.2.3 · PCI 7.1 · NIST AC-6 · CIS 5.4',
    label: 'UID 0 accounts & sudoers (privileged access)',
    purpose: 'Phát hiện tài khoản quyền root thừa & cấu hình sudo lỏng lẻo.',
    suggestedTools: ['Lynis', 'OpenSCAP'],
    commands: ['awk -F: "($3==0){print $1}" /etc/passwd', 'cat /etc/sudoers 2>/dev/null | grep -vE "^#|^$"', 'ls -l /etc/sudoers.d/ 2>/dev/null'] },
  { id: 'c-iam-l3', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.9.2.1 · PCI 8.1.4 · NIST AC-2 · CIS 5.3',
    label: 'Accounts, shells & last login (stale accounts >90d)',
    purpose: 'Tìm tài khoản người dùng không hoạt động lâu / shell bất thường.',
    suggestedTools: ['Lynis', 'auditd'],
    commands: ['awk -F: "$3>=1000{print $1\\" shell=\\"$7}" /etc/passwd', 'lastlog 2>/dev/null | head -40'] },
  { id: 'c-iam-l4', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'critical', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.9.4.2 · PCI 8.2.4 · NIST IA-5',
    label: 'Accounts with empty passwords',
    purpose: 'Phát hiện tài khoản không có mật khẩu (rủi ro nghiêm trọng).',
    suggestedTools: ['Lynis', 'John the Ripper (kiểm thử mật khẩu yếu — có phê duyệt)'],
    commands: ['awk -F: "($2==\\"\\"){print $1\\" HAS NO PASSWORD\\"}" /etc/shadow 2>/dev/null'] },
  { id: 'c-iam-l5', subsection: 'A', subsectionLabel: 'Identity & Access', priority: 'high', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.9.4.2 · PCI 8.3 · NIST IA-2(1)',
    label: 'MFA cho SSH / privileged (kiểm tra thủ công)',
    purpose: 'Xác nhận MFA (pam_google_authenticator/Duo) cho truy cập đặc quyền.',
    suggestedTools: ['Duo Unix', 'Google Authenticator PAM', 'IdP console'],
    commands: [] },
]

// ── B. Network & Infrastructure ─────────────────────────────────────────────
const NET_WIN: ComplianceItem[] = [
  { id: 'c-net-w1', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.13.1.1 · PCI 1.2 · NIST SC-7 · CIS 4.4',
    label: 'Listening ports & owning process (cổng thừa: 3389/445/...)',
    purpose: 'Liệt kê cổng đang mở để phát hiện dịch vụ phơi nhiễm không cần thiết.',
    suggestedTools: ['Nmap', 'Nessus', 'OpenVAS/Greenbone', 'Shodan (đối chiếu phơi nhiễm Internet)'],
    commands: ['netstat -ano | findstr LISTENING'] },
  { id: 'c-net-w2', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.13.1.1 · PCI 1.1 · NIST SC-7 · CIS 4.5',
    label: 'Firewall trạng thái + rule (phát hiện allow-all/lỗi thời)',
    purpose: 'Kiểm tra firewall bật & rule không quá rộng (allow any-any).',
    suggestedTools: ['Nmap', 'Firewall analyzer', 'CIS-CAT'],
    commands: ['netsh advfirewall show allprofiles state', 'netsh advfirewall firewall show rule name=all dir=in | findstr /i "Rule Name: Action: LocalPort:"'] },
  { id: 'c-net-w3', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.13.1.3 · PCI 2.2.2 · NIST CM-7 · CIS 4.8',
    label: 'SMBv1 & SMB signing (giao thức không an toàn)',
    purpose: 'Phát hiện SMBv1 (legacy, dễ bị khai thác) và thiếu ký SMB.',
    suggestedTools: ['Nmap (smb-protocols)', 'CIS-CAT'],
    commands: ['powershell -c "Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature,EncryptData"'] },
  { id: 'c-net-w4', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.13.1 · PCI 1.2.3 · NIST CM-8',
    label: 'Rogue devices / endpoint trái phép trên mạng (quét chủ động)',
    purpose: 'Phát hiện thiết bị lạ chưa được phê duyệt trong cùng phân đoạn mạng.',
    suggestedTools: ['Nmap sweep', 'arp-scan', 'NAC (Cisco ISE / Forescout)', 'netdisco'],
    commands: [] },
  { id: 'c-net-w5', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.13.1.3 · PCI 1.3 · NIST AC-3',
    label: 'Cloud storage public (S3/GCS/Blob) — kiểm tra trên cloud',
    purpose: 'Phát hiện bucket/blob để public lộ dữ liệu — kiểm trên nền tảng cloud, không phải host.',
    suggestedTools: ['Prowler', 'ScoutSuite', 'CloudSploit', 'AWS/GCP/Azure Security Hub'],
    commands: [] },
]

const NET_LIN: ComplianceItem[] = [
  { id: 'c-net-l1', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.13.1.1 · PCI 1.2 · NIST SC-7 · CIS 4.4',
    label: 'Listening ports & owning process (cổng thừa: 22/...)',
    purpose: 'Liệt kê cổng mở để phát hiện dịch vụ phơi nhiễm không cần thiết.',
    suggestedTools: ['Nmap', 'OpenVAS', 'Shodan'],
    commands: ['ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null'] },
  { id: 'c-net-l2', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.13.1.1 · PCI 1.1 · NIST SC-7 · CIS 4.5',
    label: 'Firewall trạng thái + rule (ufw/iptables/nft)',
    purpose: 'Kiểm tra firewall bật & rule không allow-all.',
    suggestedTools: ['Nmap', 'Lynis'],
    commands: ['(command -v ufw >/dev/null && ufw status verbose 2>/dev/null)', '(command -v nft >/dev/null && nft list ruleset 2>/dev/null | head -40)', 'iptables -S 2>/dev/null | head -40'] },
  { id: 'c-net-l3', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.13.2.1 · PCI 4.1 · NIST SC-8 · CIS 4.x',
    label: 'Dịch vụ không mã hoá (telnet/ftp/http)',
    purpose: 'Phát hiện dịch vụ truyền dữ liệu rõ (cleartext) cần thay bằng phiên bản mã hoá.',
    suggestedTools: ['Nmap', 'testssl.sh', 'Wireshark (xác minh cleartext)'],
    commands: ['ss -tlnp 2>/dev/null | grep -E ":23 |:21 |:80 |:25 " ', 'systemctl list-units --type=service --state=running 2>/dev/null | grep -Ei "telnet|vsftpd|ftp"'] },
  { id: 'c-net-l4', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.13.1 · PCI 1.2.3 · NIST CM-8',
    label: 'Rogue devices / endpoint trái phép (quét chủ động)',
    purpose: 'Phát hiện thiết bị lạ chưa phê duyệt trên mạng.',
    suggestedTools: ['arp-scan', 'Nmap sweep', 'NAC', 'netdisco'],
    commands: [] },
  { id: 'c-net-l5', subsection: 'B', subsectionLabel: 'Network & Infrastructure', priority: 'critical', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.13.1.3 · PCI 1.3 · NIST AC-3',
    label: 'Cloud storage public — kiểm tra trên cloud',
    purpose: 'Phát hiện bucket/blob public lộ dữ liệu.',
    suggestedTools: ['Prowler', 'ScoutSuite', 'CloudSploit'],
    commands: [] },
]

// ── C. Endpoint & System ────────────────────────────────────────────────────
const EPP_WIN: ComplianceItem[] = [
  { id: 'c-epp-w1', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.12.6.1 · PCI 6.2 · NIST SI-2 · CIS 7.x',
    label: 'Patch level — hotfix & ngày vá gần nhất',
    purpose: 'Phát hiện OS/phần mềm chưa vá lỗ hổng (đặc biệt KEV).',
    suggestedTools: ['Nessus', 'Qualys', 'OpenVAS', 'WSUS/SCCM'],
    commands: ['powershell -c "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID,InstalledOn | Format-Table -AutoSize"'] },
  { id: 'c-epp-w2', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.12.2.1 · PCI 5.1 · NIST SI-3 · CIS 10.x',
    label: 'AV/EDR status & signature freshness (coverage gap)',
    purpose: 'Xác nhận anti-malware bật, real-time, signature mới — phát hiện máy thiếu bảo vệ.',
    suggestedTools: ['EDR console (Defender/CrowdStrike/SentinelOne)', 'OSQuery fleet'],
    commands: ['powershell -c "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated | Format-List"'] },
  { id: 'c-epp-w3', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'medium', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.8.3.1 · PCI 9.x · NIST MP-7 · CIS 10.3',
    label: 'USB/removable media policy',
    purpose: 'Kiểm soát thiết bị lưu trữ rời (exfil / lây nhiễm).',
    suggestedTools: ['GPO audit', 'CIS-CAT', 'DLP endpoint'],
    commands: ['powershell -c "(Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\' -Name Start -EA SilentlyContinue).Start"'] },
  { id: 'c-epp-w4', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.5.1 · NIST CM-8 · CIS 2.x',
    label: 'Inventory phần mềm đã cài (phát hiện shadow IT)',
    purpose: 'Liệt kê phần mềm để đối chiếu với danh mục được phê duyệt.',
    suggestedTools: ['OSQuery', 'Lansweeper', 'PDQ Inventory', 'Microsoft SCCM'],
    commands: ['powershell -c "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -EA SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher | Where-Object DisplayName | Sort-Object DisplayName | Format-Table -AutoSize"'] },
]

const EPP_LIN: ComplianceItem[] = [
  { id: 'c-epp-l1', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.12.6.1 · PCI 6.2 · NIST SI-2 · CIS 7.x',
    label: 'Pending security updates',
    purpose: 'Phát hiện gói chưa vá lỗ hổng bảo mật.',
    suggestedTools: ['OpenVAS', 'Lynis', 'Nessus'],
    commands: ['(command -v apt >/dev/null && apt-get -s upgrade 2>/dev/null | grep -i security | head -30)', '(command -v dnf >/dev/null && dnf updateinfo list security 2>/dev/null | head -30)'] },
  { id: 'c-epp-l2', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.12.2.1 · PCI 5.1 · NIST SI-3',
    label: 'Anti-malware (ClamAV) & DB freshness',
    purpose: 'Xác nhận có giải pháp chống mã độc & cập nhật.',
    suggestedTools: ['Wazuh', 'OSQuery', 'ClamAV'],
    commands: ['command -v clamscan && systemctl is-active clamav-freshclam 2>/dev/null', 'ls -l /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null'] },
  { id: 'c-epp-l3', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'NIST'], control: 'ISO A.12.6.2 · NIST CM-7 · CIS 4.1',
    label: 'SELinux / AppArmor enforcement',
    purpose: 'Xác nhận MAC (kiểm soát truy cập bắt buộc) đang enforce.',
    suggestedTools: ['Lynis', 'OpenSCAP'],
    commands: ['getenforce 2>/dev/null', 'aa-status 2>/dev/null | head -5'] },
  { id: 'c-epp-l4', subsection: 'C', subsectionLabel: 'Endpoint & System', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.5.1 · NIST CM-8 · CIS 2.x',
    label: 'Inventory gói đã cài (phát hiện shadow IT)',
    purpose: 'Liệt kê gói để đối chiếu danh mục phê duyệt.',
    suggestedTools: ['OSQuery', 'Lynis'],
    commands: ['(command -v dpkg >/dev/null && dpkg -l 2>/dev/null | awk "/^ii/{print $2\\" \\"$3}" | head -60)', '(command -v rpm >/dev/null && rpm -qa 2>/dev/null | head -60)'] },
]

// ── D. Data & Secrets ───────────────────────────────────────────────────────
const DATA_WIN: ComplianceItem[] = [
  { id: 'c-dat-w1', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.10.1.1 · PCI 3.4 · NIST SC-28 · CIS 3.x',
    label: 'Disk encryption status (BitLocker) — dữ liệu nghỉ',
    purpose: 'Xác nhận ổ đĩa chứa dữ liệu nhạy cảm được mã hoá at-rest.',
    suggestedTools: ['Native (manage-bde)', 'MBAM/Intune'],
    commands: ['powershell -c "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod | Format-Table -AutoSize"', 'manage-bde -status 2>NUL'] },
  { id: 'c-dat-w2', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.10.1.1 · PCI 4.1 · NIST SC-8',
    label: 'Giao thức TLS yếu bật (SCHANNEL) — dữ liệu truyền',
    purpose: 'Phát hiện SSLv3/TLS1.0/1.1 còn bật (vi phạm PCI 4.x).',
    suggestedTools: ['testssl.sh', 'sslyze', 'Nmap ssl-enum-ciphers'],
    commands: ['powershell -c "Get-ChildItem \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\' -Recurse -EA SilentlyContinue | ForEach-Object { $_.PSChildName ; (Get-ItemProperty $_.PSPath -EA SilentlyContinue).Enabled }"'] },
  { id: 'c-dat-w3', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'critical', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.9.4.3 · PCI 6.3.1 · NIST IA-5(7)',
    label: 'Hardcoded secrets / API keys trong source & config',
    purpose: 'Phát hiện credential/API key nhúng trong code, config, repo (rủi ro lộ bí mật).',
    suggestedTools: ['gitleaks', 'trufflehog', 'detect-secrets', 'GitHub Secret Scanning'],
    commands: [] },
  { id: 'c-dat-w4', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'high', executable: false,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.12.4.1 · PCI 3.3 · NIST AU-9',
    label: 'Log chứa dữ liệu nhạy cảm (password/token/PAN)',
    purpose: 'Đảm bảo log không ghi mật khẩu/token/số thẻ.',
    suggestedTools: ['grep/Select-String', 'DLP', 'Microsoft Presidio (PII detection)'],
    commands: [] },
]

const DATA_LIN: ComplianceItem[] = [
  { id: 'c-dat-l1', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.10.1.1 · PCI 3.4 · NIST SC-28 · CIS 3.x',
    label: 'Disk encryption status (LUKS) — dữ liệu nghỉ',
    purpose: 'Xác nhận mã hoá at-rest cho ổ chứa dữ liệu nhạy cảm.',
    suggestedTools: ['Native (cryptsetup)', 'Vault (quản lý key)'],
    commands: ['lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null', 'ls /dev/mapper/ 2>/dev/null | grep -v control'] },
  { id: 'c-dat-l2', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.9.2.3 · PCI 7.1 · NIST AC-6',
    label: 'SUID/SGID binaries (privilege-escalation surface)',
    purpose: 'Liệt kê binary đặc quyền để soát file bất thường.',
    suggestedTools: ['Lynis', 'LinPEAS (kiểm thử có phê duyệt)'],
    commands: ['find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -50'] },
  { id: 'c-dat-l3', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'critical', executable: true,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.9.4.3 · PCI 6.3.1 · NIST IA-5(7)',
    label: 'Hardcoded secrets trong config/script hệ thống',
    purpose: 'Quét nhanh credential lộ trong file cấu hình phổ biến (bổ sung bằng gitleaks/trufflehog cho repo).',
    suggestedTools: ['gitleaks', 'trufflehog', 'detect-secrets'],
    commands: ['grep -RInsE "(password|passwd|secret|api[_-]?key|token|aws_secret)" /etc /opt /srv /var/www 2>/dev/null | grep -vE "\\.sample|EXAMPLE" | head -30'] },
  { id: 'c-dat-l4', subsection: 'D', subsectionLabel: 'Data & Secrets', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.13.2.1 · PCI 4.1 · NIST SC-8',
    label: 'TLS/cipher của dịch vụ đang lắng nghe',
    purpose: 'Kiểm tra TLS yếu trên dịch vụ web/mail nội bộ.',
    suggestedTools: ['testssl.sh', 'sslyze', 'Nmap ssl-enum-ciphers'],
    commands: ['echo "Dùng testssl.sh / sslyze tới host:port để xác minh ciphers"', 'ss -tlnp 2>/dev/null | grep -E ":443 |:8443 |:465 |:993 "'] },
]

// ── E. Logging & Monitoring ─────────────────────────────────────────────────
const LOG_WIN: ComplianceItem[] = [
  { id: 'c-log-w1', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.12.4.1 · PCI 10.2 · NIST AU-2 · CIS 8.2',
    label: 'Audit policy — sự kiện nào được ghi',
    purpose: 'Xác nhận audit logging bật cho các sự kiện bảo mật quan trọng.',
    suggestedTools: ['CIS-CAT', 'Sysmon (tăng độ phủ)'],
    commands: ['auditpol /get /category:*'] },
  { id: 'c-log-w2', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.12.4.2 · PCI 10.7 · NIST AU-4 · CIS 8.3',
    label: 'Kích thước & retention event log (yêu cầu ≥90 ngày)',
    purpose: 'Đảm bảo log đủ dung lượng/thời gian lưu cho điều tra & tuân thủ.',
    suggestedTools: ['SIEM (ELK/Splunk/Wazuh)'],
    commands: ['powershell -c "Get-WinEvent -ListLog Security,System,Application | Select-Object LogName,IsEnabled,LogMode,@{N=\'MaxMB\';E={[math]::Round($_.MaximumSizeInBytes/1MB)}} | Format-Table -AutoSize"'] },
  { id: 'c-log-w3', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.12.4.1 · PCI 10.5.4 · NIST AU-6 · CIS 8.9',
    label: 'Log forwarding / SIEM agent hiện diện (SIEM coverage)',
    purpose: 'Phát hiện máy chưa gửi log về SIEM (mù điểm giám sát).',
    suggestedTools: ['Windows Event Forwarding', 'Splunk UF', 'Elastic Agent', 'Wazuh agent'],
    commands: ['powershell -c "Get-Service WinRM,wecsvc,WazuhSvc,SplunkForwarder,Elastic* -EA SilentlyContinue | Select Name,Status,StartType | Format-Table -AutoSize"'] },
  { id: 'c-log-w4', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.4 · NIST AU-6 · CIS 8.11',
    label: 'Alerting phủ MITRE ATT&CK tactics (đánh giá detection)',
    purpose: 'Đánh giá độ phủ phát hiện so với ATT&CK — không kiểm được bằng lệnh host.',
    suggestedTools: ['MITRE ATT&CK Navigator', 'Atomic Red Team', 'DeTT&CT', 'Sigma rules'],
    commands: [] },
]

const LOG_LIN: ComplianceItem[] = [
  { id: 'c-log-l1', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'critical', executable: true,
    frameworks: ALL, control: 'ISO A.12.4.1 · PCI 10.2 · NIST AU-2 · CIS 8.2',
    label: 'auditd active + rules loaded',
    purpose: 'Xác nhận auditd bật và có luật ghi sự kiện bảo mật.',
    suggestedTools: ['OpenSCAP', 'auditd best-practice rules (Neo23x0)'],
    commands: ['systemctl is-active auditd 2>/dev/null', 'auditctl -s 2>/dev/null', 'auditctl -l 2>/dev/null | head -40'] },
  { id: 'c-log-l2', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'high', executable: true,
    frameworks: ALL, control: 'ISO A.12.4.2 · PCI 10.7 · NIST AU-4 · CIS 8.3',
    label: 'Logging service & retention',
    purpose: 'Xác nhận rsyslog/journald chạy + retention đủ.',
    suggestedTools: ['SIEM'],
    commands: ['systemctl is-active rsyslog systemd-journald 2>/dev/null', 'grep -E "^SystemMaxUse|^MaxRetentionSec" /etc/systemd/journald.conf 2>/dev/null'] },
  { id: 'c-log-l3', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.12.4.1 · PCI 10.5.4 · NIST AU-6 · CIS 8.9',
    label: 'Remote log forwarding configured (SIEM coverage)',
    purpose: 'Phát hiện máy chưa gửi log về SIEM.',
    suggestedTools: ['rsyslog @@', 'Filebeat', 'Wazuh agent', 'Fluent Bit'],
    commands: ['grep -RhsE "^[^#]*@@?[0-9A-Za-z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null', 'systemctl is-active wazuh-agent filebeat 2>/dev/null'] },
  { id: 'c-log-l4', subsection: 'E', subsectionLabel: 'Logging & Monitoring', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.4 · NIST AU-6 · CIS 8.11',
    label: 'Alerting phủ MITRE ATT&CK tactics',
    purpose: 'Đánh giá độ phủ phát hiện so với ATT&CK.',
    suggestedTools: ['ATT&CK Navigator', 'Atomic Red Team', 'Sigma'],
    commands: [] },
]

// ── F. Change Management ────────────────────────────────────────────────────
const CHG_WIN: ComplianceItem[] = [
  { id: 'c-chg-w1', subsection: 'F', subsectionLabel: 'Change Management', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.12.1.2 · PCI 11.5 · NIST SI-7 · CIS 3.14',
    label: 'File Integrity Monitoring hiện diện (phát hiện thay đổi trái phép)',
    purpose: 'Xác nhận có FIM giám sát thay đổi file hệ thống.',
    suggestedTools: ['Wazuh FIM', 'OSSEC', 'Tripwire'],
    commands: ['powershell -c "Get-Service WazuhSvc,OSSEC* -EA SilentlyContinue | Select Name,Status"', 'powershell -c "(Get-ItemProperty \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\' -EA SilentlyContinue | Where DisplayName -match \'Tripwire|Wazuh\').DisplayName"'] },
  { id: 'c-chg-w2', subsection: 'F', subsectionLabel: 'Change Management', priority: 'high', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.12.1.2 · PCI 6.4 · NIST CM-3',
    label: 'Bản ghi phê duyệt thay đổi production',
    purpose: 'Mọi thay đổi prod phải có record phê duyệt (đối chiếu ticket).',
    suggestedTools: ['Jira / ServiceNow', 'Git history / PR approvals', 'CAB records'],
    commands: [] },
  { id: 'c-chg-w3', subsection: 'F', subsectionLabel: 'Change Management', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.1.2 · NIST CM-2 · CIS 4.2',
    label: 'Config drift dev/staging/prod',
    purpose: 'Phát hiện lệch cấu hình giữa môi trường (thiếu kiểm soát thay đổi).',
    suggestedTools: ['Ansible/Chef/Puppet', 'OSQuery', 'Terraform state diff'],
    commands: [] },
]

const CHG_LIN: ComplianceItem[] = [
  { id: 'c-chg-l1', subsection: 'F', subsectionLabel: 'Change Management', priority: 'high', executable: true,
    frameworks: ['ISO 27001', 'PCI-DSS', 'NIST'], control: 'ISO A.12.1.2 · PCI 11.5 · NIST SI-7 · CIS 3.14',
    label: 'File Integrity Monitoring (AIDE/Tripwire/Wazuh)',
    purpose: 'Xác nhận có FIM giám sát thay đổi file hệ thống.',
    suggestedTools: ['AIDE', 'Tripwire', 'Wazuh FIM', 'OSSEC'],
    commands: ['command -v aide && systemctl is-active aidecheck.timer 2>/dev/null', 'command -v tripwire', 'systemctl is-active wazuh-agent 2>/dev/null'] },
  { id: 'c-chg-l2', subsection: 'F', subsectionLabel: 'Change Management', priority: 'high', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST'], control: 'ISO A.12.1.2 · PCI 6.4 · NIST CM-3',
    label: 'Bản ghi phê duyệt thay đổi production',
    purpose: 'Mọi thay đổi prod phải có record phê duyệt.',
    suggestedTools: ['Jira / ServiceNow', 'Git PR approvals'],
    commands: [] },
  { id: 'c-chg-l3', subsection: 'F', subsectionLabel: 'Change Management', priority: 'medium', executable: false,
    frameworks: ['ISO 27001', 'SOC 2', 'NIST'], control: 'ISO A.12.1.2 · NIST CM-2 · CIS 4.2',
    label: 'Config drift dev/staging/prod',
    purpose: 'Phát hiện lệch cấu hình giữa môi trường.',
    suggestedTools: ['Ansible/Chef/Puppet', 'OSQuery', 'Terraform'],
    commands: [] },
]

export const COMPLIANCE_SECTIONS: ComplianceSection[] = [
  { id: 'cmp-a', phase: 'A', label: 'Identity & Access Management', items: { win: IAM_WIN, linux: IAM_LIN } },
  { id: 'cmp-b', phase: 'B', label: 'Network & Infrastructure', items: { win: NET_WIN, linux: NET_LIN } },
  { id: 'cmp-c', phase: 'C', label: 'Endpoint & System', items: { win: EPP_WIN, linux: EPP_LIN } },
  { id: 'cmp-d', phase: 'D', label: 'Data & Secrets', items: { win: DATA_WIN, linux: DATA_LIN } },
  { id: 'cmp-e', phase: 'E', label: 'Logging & Monitoring', items: { win: LOG_WIN, linux: LOG_LIN } },
  { id: 'cmp-f', phase: 'F', label: 'Change Management', items: { win: CHG_WIN, linux: CHG_LIN } },
]

export const COMPLIANCE_FRAMEWORKS: Framework[] = ['ISO 27001', 'SOC 2', 'PCI-DSS', 'NIST']

// Flat lookup of every compliance item by id — used to enrich a checklist run's
// batch outputs with control/framework/purpose metadata when sending to AI assess.
export const COMPLIANCE_ITEM_MAP: Record<string, ComplianceItem> = (() => {
  const m: Record<string, ComplianceItem> = {}
  for (const s of COMPLIANCE_SECTIONS) {
    for (const it of [...s.items.win, ...s.items.linux]) m[it.id] = it
  }
  return m
})()
