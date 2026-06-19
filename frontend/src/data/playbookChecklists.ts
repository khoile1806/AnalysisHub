export type PlaybookPriority = 'critical' | 'high' | 'medium'

export interface PlaybookChecklistItem {
  id: string
  subsection: string
  subsectionLabel: string
  label: string
  commands: string[]
  priority: PlaybookPriority
  executable: boolean
  purpose: string
  suggestedTools?: string[]
}

export interface PlaybookChecklistSection {
  id: string
  phase: string
  label: string
  optional?: boolean
  items: { win: PlaybookChecklistItem[]; linux: PlaybookChecklistItem[] }
}

const RANSOMWARE_WIN: PlaybookChecklistItem[] = [
  { id: 'rw-w1', subsection: '1', subsectionLabel: 'Identification', priority: 'critical', executable: true,
    label: 'Tìm tiến trình mã hóa (high CPU/IO)',
    purpose: 'Xác định tiến trình nghi ngờ đang thực hiện mã hóa file hàng loạt.',
    suggestedTools: ['Process Explorer', 'Sysmon'],
    commands: ['powershell -c "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"'] },
  { id: 'rw-w2', subsection: '1', subsectionLabel: 'Identification', priority: 'critical', executable: true,
    label: 'Kiểm tra file ransom note',
    purpose: 'Tìm kiếm tệp văn bản hướng dẫn chuộc tiền thường được sinh ra trên Desktop hoặc C:\\.',
    commands: ['dir /s /b C:\\*readme*.txt C:\\*decrypt*.txt C:\\*restore*.txt 2>NUL'] },
  { id: 'rw-w3', subsection: '2', subsectionLabel: 'Containment', priority: 'critical', executable: true,
    label: 'Kiểm tra trạng thái Firewall & SMB',
    purpose: 'Đảm bảo SMB đã bị đóng hoặc cô lập để tránh ransomware lan truyền ngang (lateral movement).',
    commands: ['netsh advfirewall show currentprofile', 'powershell -c "Get-SmbServerConfiguration | Select EnableSMB1Protocol,EnableSMB2Protocol"'] },
  { id: 'rw-w4', subsection: '3', subsectionLabel: 'Evidence Collection', priority: 'high', executable: true,
    label: 'Trích xuất cấu hình Autorun / Persistence',
    purpose: 'Ransomware thường tạo persistence để tiếp tục mã hóa sau khi reboot.',
    commands: ['reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'schtasks /query /fo csv /v'] }
]

const RANSOMWARE_LIN: PlaybookChecklistItem[] = [
  { id: 'rw-l1', subsection: '1', subsectionLabel: 'Identification', priority: 'critical', executable: true,
    label: 'Tìm tiến trình ngốn CPU/IO',
    purpose: 'Phát hiện tiến trình đang thực hiện mã hóa (ví dụ: ESXiArgs, Cheerscrypt).',
    commands: ['top -b -n 1 | head -n 20', 'iotop -b -n 1 | head -n 20 2>/dev/null'] },
  { id: 'rw-l2', subsection: '1', subsectionLabel: 'Identification', priority: 'critical', executable: true,
    label: 'Tìm file có phần mở rộng bị đổi lạ',
    purpose: 'Tìm các tệp gần đây đã bị đổi tên (dấu hiệu mã hóa).',
    commands: ['find / -type f -mtime -1 -name "*.locked" -o -name "*.crypt" 2>/dev/null | head -n 20'] }
]

// ── Security Assessment & Hunting ───────────────────────────────────────────
const HUNT_WIN: PlaybookChecklistItem[] = [
  { id: 'sh-w1', subsection: '1', subsectionLabel: 'System & Patches', priority: 'high', executable: true,
    label: 'Bản vá đã cài (đối chiếu CVE)',
    purpose: 'Máy thiếu bản vá quan trọng là bề mặt tấn công dễ bị khai thác.',
    suggestedTools: ['Get-HotFix', 'Nessus'],
    commands: ['powershell -c "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,InstalledOn -First 15 | Format-Table -AutoSize"'] },
  { id: 'sh-w2', subsection: '2', subsectionLabel: 'Identity', priority: 'critical', executable: true,
    label: 'Thành viên nhóm Administrators',
    purpose: 'Phát hiện tài khoản có quyền admin trái phép / thừa.',
    commands: ['net localgroup administrators'] },
  { id: 'sh-w3', subsection: '3', subsectionLabel: 'Process & Network', priority: 'critical', executable: true,
    label: 'Tiến trình + kết nối mạng (C2 beaconing)',
    purpose: 'Soi process không có path, parent bất thường, kết nối lặp ra IP lạ.',
    suggestedTools: ['Process Explorer', 'TCPView'],
    commands: ['powershell -c "Get-Process | Where-Object {$_.Path -ne $null} | Select Id,Name,Path | Format-Table -AutoSize"', 'netstat -ano'] },
  { id: 'sh-w4', subsection: '4', subsectionLabel: 'Persistence', priority: 'critical', executable: true,
    label: 'Registry Run keys + Scheduled Tasks',
    purpose: 'Cơ chế mã độc tự khởi động cùng máy.',
    commands: ['reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"'] },
  { id: 'sh-w5', subsection: '5', subsectionLabel: 'Logs', priority: 'high', executable: true,
    label: 'Quick hunt Event ID (4624/4625/4697/4104)',
    purpose: 'Logon thành/bại, cài service mới (backdoor), script PowerShell đáng ngờ.',
    suggestedTools: ['Hayabusa', 'DeepBlueCLI'],
    commands: ['powershell -c "Get-WinEvent -FilterHashtable @{LogName=\'Security\';ID=4624,4625} -MaxEvents 30 | Select TimeCreated,Id | Format-Table -AutoSize"', 'powershell -c "Get-WinEvent -FilterHashtable @{LogName=\'System\';ID=4697} -EA SilentlyContinue | Select TimeCreated,Message | Format-List"'] }
]

const HUNT_LIN: PlaybookChecklistItem[] = [
  { id: 'sh-l1', subsection: '1', subsectionLabel: 'System & Config', priority: 'high', executable: true,
    label: 'Cấu hình an toàn SSH (sshd_config)',
    purpose: 'PermitRootLogin/PasswordAuthentication "yes" = cửa brute-force phổ biến.',
    suggestedTools: ['Lynis', 'ssh-audit'],
    commands: ['grep -Ei "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|MaxAuthTries)" /etc/ssh/sshd_config 2>/dev/null'] },
  { id: 'sh-l2', subsection: '2', subsectionLabel: 'Identity', priority: 'critical', executable: true,
    label: 'Quyền sudo/wheel + failed login (lastb)',
    purpose: 'Tài khoản được nâng quyền bất thường & dấu hiệu brute-force SSH.',
    suggestedTools: ['fail2ban'],
    commands: ['grep -E "^(sudo|wheel|adm)" /etc/group', 'lastb -20 2>/dev/null', 'awk -F: "($3==0){print $1}" /etc/passwd'] },
  { id: 'sh-l3', subsection: '3', subsectionLabel: 'Process & Network', priority: 'critical', executable: true,
    label: 'Tiến trình + cổng/kết nối (reverse shell)',
    purpose: 'Phát hiện process con của web/sshd kết nối ra ngoài (reverse shell).',
    suggestedTools: ['pstree', 'ss'],
    commands: ['ps auxef | head -n 60', 'ss -antup 2>/dev/null'] },
  { id: 'sh-l4', subsection: '4', subsectionLabel: 'Persistence', priority: 'critical', executable: true,
    label: 'Cron + systemd + authorized_keys',
    purpose: 'Cơ chế persistence phổ biến: cron, service, SSH key cấy lén.',
    commands: ['crontab -l 2>/dev/null', 'cat /etc/crontab', 'systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 30', 'cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null'] },
  { id: 'sh-l5', subsection: '5', subsectionLabel: 'Logs', priority: 'high', executable: true,
    label: 'Auth log + bash history',
    purpose: 'Điều tra brute-force/leo quyền và lệnh kẻ tấn công đã chạy.',
    commands: ['tail -n 100 /var/log/auth.log 2>/dev/null', 'tail -n 100 /var/log/secure 2>/dev/null', 'tail -n 50 ~/.bash_history 2>/dev/null'] }
]

// ── Compliance & Security Audit ─────────────────────────────────────────────
const COMPLIANCE_WIN: PlaybookChecklistItem[] = [
  { id: 'cp-w1', subsection: '1', subsectionLabel: 'IAM', priority: 'critical', executable: true,
    label: 'Chính sách mật khẩu + nhóm Admin',
    purpose: 'Xác minh độ dài/hạn mật khẩu & phát hiện admin thừa.',
    suggestedTools: ['CIS-CAT', 'PingCastle'],
    commands: ['net accounts', 'net localgroup administrators'] },
  { id: 'cp-w2', subsection: '2', subsectionLabel: 'Network', priority: 'critical', executable: true,
    label: 'Cổng mở + trạng thái Firewall',
    purpose: 'Phát hiện dịch vụ phơi nhiễm (3389/445) & firewall allow-all.',
    suggestedTools: ['Nmap'],
    commands: ['netstat -ano | findstr LISTENING', 'netsh advfirewall show allprofiles state'] },
  { id: 'cp-w3', subsection: '3', subsectionLabel: 'Endpoint & Data', priority: 'critical', executable: true,
    label: 'AV/EDR + mã hóa đĩa (BitLocker)',
    purpose: 'Coverage gap bảo vệ & dữ liệu at-rest chưa mã hóa.',
    commands: ['powershell -c "Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated | Format-List"', 'manage-bde -status 2>NUL'] },
  { id: 'cp-w4', subsection: '4', subsectionLabel: 'Logging', priority: 'high', executable: true,
    label: 'Audit policy + retention log',
    purpose: 'Đảm bảo ghi log đủ & lưu ≥90 ngày phục vụ audit.',
    commands: ['auditpol /get /category:*', 'powershell -c "Get-WinEvent -ListLog Security,System | Select LogName,LogMode,@{N=\'MaxMB\';E={[math]::Round($_.MaximumSizeInBytes/1MB)}} | Format-Table -AutoSize"'] }
]

const COMPLIANCE_LIN: PlaybookChecklistItem[] = [
  { id: 'cp-l1', subsection: '1', subsectionLabel: 'IAM', priority: 'critical', executable: true,
    label: 'Chính sách mật khẩu + UID0/sudoers',
    purpose: 'Xác minh chính sách mật khẩu & phát hiện quyền root thừa.',
    suggestedTools: ['Lynis', 'OpenSCAP'],
    commands: ['grep -E "PASS_MAX_DAYS|PASS_MIN_LEN" /etc/login.defs 2>/dev/null', 'awk -F: "($3==0){print $1}" /etc/passwd', 'cat /etc/sudoers 2>/dev/null | grep -vE "^#|^$"'] },
  { id: 'cp-l2', subsection: '2', subsectionLabel: 'Network', priority: 'critical', executable: true,
    label: 'Cổng mở + Firewall',
    purpose: 'Phát hiện dịch vụ phơi nhiễm & firewall allow-all.',
    suggestedTools: ['Nmap'],
    commands: ['ss -tulpn 2>/dev/null', 'ufw status verbose 2>/dev/null', 'iptables -S 2>/dev/null | head -n 30'] },
  { id: 'cp-l3', subsection: '3', subsectionLabel: 'Endpoint & Data', priority: 'high', executable: true,
    label: 'Patch + mã hóa đĩa (LUKS) + SELinux',
    purpose: 'Lỗ hổng chưa vá, dữ liệu chưa mã hóa, MAC chưa enforce.',
    suggestedTools: ['OpenVAS', 'Lynis'],
    commands: ['lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null', 'getenforce 2>/dev/null', '(command -v apt >/dev/null && apt-get -s upgrade 2>/dev/null | grep -i security | head)'] },
  { id: 'cp-l4', subsection: '4', subsectionLabel: 'Logging', priority: 'high', executable: true,
    label: 'auditd + log forwarding (SIEM)',
    purpose: 'Đảm bảo audit logging bật & gửi log về SIEM.',
    commands: ['systemctl is-active auditd 2>/dev/null', 'auditctl -l 2>/dev/null | head', 'systemctl is-active rsyslog wazuh-agent filebeat 2>/dev/null'] }
]

export const PLAYBOOK_CHECKLISTS: Record<string, PlaybookChecklistSection[]> = {
  'ransomware': [
    { id: 'rw-sec1', phase: '1', label: 'Ransomware Response Checklist', items: { win: RANSOMWARE_WIN, linux: RANSOMWARE_LIN } }
  ],
  'webshell': [
    { id: 'wb-sec1', phase: '1', label: 'Webshell Hunting Checklist', items: { 
      win: [
        { id: 'wb-w1', subsection: '1', subsectionLabel: 'Web Logs', priority: 'critical', executable: true, label: 'Quét file PHP/ASPX mới tạo trong thư mục Web', purpose: 'Phát hiện webshell mới được tải lên', commands: ['dir /s /b /o:d C:\\inetpub\\wwwroot\\*.aspx'] }
      ], 
      linux: [
        { id: 'wb-l1', subsection: '1', subsectionLabel: 'Web Logs', priority: 'critical', executable: true, label: 'Tìm file PHP mới trong /var/www', purpose: 'Phát hiện shell', commands: ['find /var/www -name "*.php" -mtime -7 2>/dev/null'] }
      ] 
    }}
  ],
  'generic-dfir': [
    { id: 'dfir-sec1', phase: '1', label: 'Generic DFIR Collection', items: {
      win: [
        { id: 'dfir-w1', subsection: '1', subsectionLabel: 'System', priority: 'high', executable: true, label: 'Lấy thông tin hệ thống chung', purpose: 'Thu thập base state', commands: ['systeminfo'] }
      ],
      linux: [
        { id: 'dfir-l1', subsection: '1', subsectionLabel: 'System', priority: 'high', executable: true, label: 'Lấy thông tin hệ thống chung', purpose: 'Thu thập base state', commands: ['uname -a'] }
      ]
    }}
  ],
  'security-hunting': [
    { id: 'sh-sec1', phase: '1', label: 'Security Assessment & Hunting Checklist', items: { win: HUNT_WIN, linux: HUNT_LIN } }
  ],
  'compliance': [
    { id: 'cp-sec1', phase: '1', label: 'Compliance Audit Checklist', items: { win: COMPLIANCE_WIN, linux: COMPLIANCE_LIN } }
  ]
}
