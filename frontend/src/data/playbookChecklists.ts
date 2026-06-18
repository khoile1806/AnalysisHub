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
  ]
}
