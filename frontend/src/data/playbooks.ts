export interface PlaybookStep {
  title: string
  content: string
  icon?: string
}

export interface PlaybookReference {
  title: string
  url: string
}

export interface Playbook {
  id: string
  title: string
  description: string
  type: string
  platforms: string[]
  mitre: string
  color: string
  icon: string
  goals: string[]
  steps: PlaybookStep[]
  references: PlaybookReference[]
}

export const PLAYBOOKS: Playbook[] = [
  {
    id: 'ransomware',
    title: 'Ransomware Response & Recovery',
    description: 'Quy trình chuẩn ứng phó khẩn cấp với sự cố mã độc tống tiền (Ransomware). Kịch bản này hướng dẫn chi tiết từ bước cô lập hệ thống, phân tích tĩnh/động để tìm công cụ giải mã, cho tới việc khôi phục và đánh giá rủi ro hậu sự cố.',
    type: 'Malware Response',
    platforms: ['Windows', 'Linux', 'ESXi'],
    mitre: 'T1486 (Data Encrypted for Impact)',
    color: 'rose',
    icon: 'ShieldAlert',
    goals: [
      'Visibility: Xác định chính xác "bán kính vụ nổ" (blast radius) của Ransomware trên toàn mạng.',
      'Containment: Cô lập khẩn cấp các máy chủ/phân vùng chưa bị lây nhiễm, ngăn chặn hành vi Lateral Movement.',
      'Identification: Thu thập mẫu mã độc (Sample) và Ransom Note để định danh chủng loại (e.g. LockBit, BlackBasta) và tìm Decryptor.',
      'Evidence Collection: Dump RAM khẩn cấp để trích xuất khóa giải mã (nếu còn) và thu thập Windows Event Logs (4624, 4625).',
      'Recovery & Remediation: Đảm bảo môi trường sạch sẽ (Eradication) trước khi khôi phục dữ liệu từ bản sao lưu (Backup) offline.'
    ],
    steps: [
      {
        title: 'Bước 1: Cô lập & Bảo toàn Hiện trường (Containment)',
        content: '**Hành động ngay lập tức:**\n- **Ngắt mạng vật lý/logic:** Rút dây mạng, disable NIC trên vCenter/Hyper-V, hoặc chuyển máy vào VLAN cô lập (Quarantine VLAN).\n- **KHÔNG TẮT NGUỒN:** Việc khởi động lại máy có thể xóa mất khóa giải mã trên RAM hoặc kích hoạt các đoạn mã phá hủy dữ liệu (Wiper) của hacker.\n- **Khóa tài khoản:** Tạm khóa toàn bộ tài khoản Admin, Service Accounts nghi ngờ bị lộ lọt (Compromised). Tắt giao thức RDP (Port 3389) và SMB (Port 445) trên các segment mạng liên quan.',
        icon: 'Lock'
      },
      {
        title: 'Bước 2: Phân loại & Thu thập Thông tin Nhanh (Triage)',
        content: '**Thu thập các chỉ dấu (IOCs):**\n- Chụp ảnh màn hình (Screenshot) thông điệp đòi tiền chuộc (Ransom Note).\n- Tìm file bị mã hóa gần nhất để xác định phần mở rộng (Extension) (VD: .locked, .enc).\n- Upload một file nhỏ đã bị mã hóa và Ransom Note lên [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) để nhận diện dòng mã độc.\n- Ghi nhận các tiến trình (Processes) đang tiêu tốn I/O Disk hoặc CPU cao bất thường (có thể quá trình mã hóa vẫn đang diễn ra).',
        icon: 'Search'
      },
      {
        title: 'Bước 3: Memory Dump & Triage Collection',
        content: '**Bảo tồn chứng cứ dễ bay hơi (Volatile Data):**\n- Sử dụng công cụ **WinPmem** hoặc **DumpIt** để sao chụp toàn bộ bộ nhớ RAM vào một ổ đĩa USB cắm ngoài. (RAM có thể chứa Key giải mã dạng plaintext).\n- Thực thi **Evidence Collection Checklist (Phase 1)** để tự động xuất danh sách: Network Connections, Running Processes, Autoruns, và DNS Cache.\n- Chạy **KAPE (Kroll Artifact Parser and Extractor)** để thu thập nhanh Registry Hives, MFT, và Event Logs.',
        icon: 'Cpu'
      },
      {
        title: 'Bước 4: Điều tra Nguyên nhân Gốc (Root Cause Analysis)',
        content: '**Tìm điểm xâm nhập (Initial Access):**\n- Phân tích Firewall/VPN Logs để tìm hành vi Brute-force hoặc lỗ hổng chưa vá (VD: FortiGate, Pulse Secure).\n- Phân tích Email Gateway Logs tìm các chiến dịch Phishing có chứa payload.\n- Phân tích **Security.evtx** (Event ID 4624, 4625) để xem hacker đã dùng tài khoản nào đăng nhập và từ IP nào.\n- Kiểm tra các công cụ RMM (AnyDesk, TeamViewer) bị cài đặt lén lút (Shadow IT).',
        icon: 'Target'
      },
      {
        title: 'Bước 5: Báo cáo & Lên kế hoạch Khắc phục',
        content: '**Cấu trúc Báo cáo Cần Có:**\n- **Executive Summary:** Đánh giá thiệt hại kinh doanh và trạng thái hiện tại.\n- **Timeline Sự kiện:** Từ lúc xâm nhập đầu tiên đến lúc kích hoạt mã hóa.\n- **IOCs (Indicators of Compromise):** Danh sách IP, Domain C2, File Hashes.\n- **Hành động Khắc phục:** Xóa sạch hệ thống, cài lại OS mới hoàn toàn, patch lỗ hổng, kích hoạt EDR/MDR trước khi đưa vào hoạt động.',
        icon: 'FileText'
      }
    ],
    references: [
      { title: 'CISA: Kế hoạch Ứng phó Ransomware', url: 'https://www.cisa.gov/stopransomware/ransomware-guide' },
      { title: 'Dự án No More Ransom (Công cụ Giải mã Miễn phí)', url: 'https://www.nomoreransom.org/' },
      { title: 'NIST SP 1800-26: Quản lý Rủi ro Ransomware', url: 'https://csrc.nist.gov/publications/detail/sp/1800-26/final' }
    ]
  },
  {
    id: 'webshell',
    title: 'Webshell & Backdoor Hunting',
    description: 'Quy trình chuyên sâu về săn lùng và phân tích mã độc ẩn náu trên máy chủ Web (IIS, Nginx, Apache). Kịch bản này giúp phát hiện các đoạn mã thực thi trái phép (Webshell) lợi dụng lỗ hổng ứng dụng (File Upload, RCE).',
    type: 'Threat Hunting',
    platforms: ['Windows', 'Linux'],
    mitre: 'T1505.003 (Web Shell)',
    color: 'emerald',
    icon: 'TerminalSquare',
    goals: [
      'Visibility: Giám sát toàn bộ lưu lượng web và các tập tin được tạo ra trên thư mục Web Root.',
      'Detection: Phát hiện mã độc PHP/JSP/ASPX lẩn trốn dưới các đuôi file ảnh (.jpg, .png) hoặc bị mã hóa rườm rà (Obfuscation).',
      'Analysis: Phân tích Web Access Logs để tìm ra IP của kẻ tấn công và thời điểm khai thác (Exploit).',
      'Eradication: Loại bỏ tận gốc Webshell và các cửa hậu (Backdoor) liên quan trong hệ điều hành.',
      'Prevention: Đề xuất các bản vá cho mã nguồn ứng dụng Web và cấu hình WAF (Web Application Firewall).'
    ],
    steps: [
      {
        title: 'Bước 1: Quét tệp hệ thống Web Root (File System Scan)',
        content: '**Xác định các tệp tin bất thường:**\n- Sử dụng công cụ YARA hoặc Thor Scanner để quét các thư mục chứa mã nguồn (VD: `C:\\inetpub\\wwwroot` hoặc `/var/www/html`).\n- Tìm các tệp tin `.php`, `.aspx`, `.jsp` được sửa đổi (Modified) trong khoảng thời gian xảy ra sự cố.\n- Lệnh kiểm tra Linux: `find /var/www -name "*.php" -mtime -7` (Tìm file PHP sửa đổi 7 ngày qua).\n- Tìm kiếm các hàm thực thi lệnh ẩn giấu: `eval()`, `base64_decode()`, `system()`, `shell_exec()`.',
        icon: 'Scan'
      },
      {
        title: 'Bước 2: Phân tích Web Access & Error Logs',
        content: '**Săn lùng dấu vết trong Logs:**\n- Thu thập toàn bộ Access Logs của Apache/Nginx hoặc IIS Logs.\n- Tìm kiếm các HTTP POST requests với tần suất thấp (Low Frequency) tới các file cụ thể.\n- Tìm các yêu cầu trả về mã trạng thái HTTP 200 từ các URL đáng ngờ hoặc các tệp tin nằm sâu trong thư mục tải lên (`/uploads/`, `/images/`).\n- Kiểm tra các tham số User-Agent lạ hoặc các chuỗi tấn công (SQLi, Path Traversal) trong URI.',
        icon: 'FileText'
      },
      {
        title: 'Bước 3: Phân tích Tiến trình Con (Child Processes Anomaly)',
        content: '**Kiểm tra hành vi của Web Server:**\n- Thông thường các tiến trình web server (`w3wp.exe`, `nginx`, `httpd`, `tomcat`) chỉ xử lý logic web.\n- Nếu phát hiện các tiến trình này sinh ra (spawn) các tiến trình shell hệ thống như `cmd.exe`, `powershell.exe`, `bash`, hoặc `sh` -> **ĐÂY LÀ DẤU HIỆU CỦA WEBSHELL / RCE.**\n- Kiểm tra công cụ Netstat/SS để xem web server có đang tạo các kết nối Reverse Shell ra ngoài Internet qua các port lạ (e.g. 4444, 8080) hay không.',
        icon: 'Activity'
      },
      {
        title: 'Bước 4: Loại bỏ và Ngăn chặn (Remediation)',
        content: '**Vá lỗ hổng và khôi phục:**\n- Xóa bỏ tập tin Webshell hoặc khôi phục mã nguồn từ kho lưu trữ (Git/SVN) sạch.\n- Đánh giá mã nguồn (Source Code Review) để tìm và vá lỗi Unrestricted File Upload.\n- Cấu hình phân quyền thư mục (Permissions): Ngăn chặn thư mục `/uploads/` được quyền thực thi script (Disable execution).\n- Bật các rules bảo vệ trên thiết bị WAF/IPS.',
        icon: 'Target'
      }
    ],
    references: [
      { title: 'NSA & CISA: Phát hiện và Giảm thiểu Web Shells', url: 'https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/csi-web-shells.pdf' },
      { title: 'MITRE ATT&CK: Web Shell (T1505.003)', url: 'https://attack.mitre.org/techniques/T1505/003/' },
      { title: 'OWASP File Upload Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html' }
    ]
  },
  {
    id: 'generic-dfir',
    title: 'Generic DFIR Workflow',
    description: 'Quy trình thu thập và phản ứng chung, toàn diện cho mọi sự kiện an ninh mạng (Malware, Data Breach, Insider Threat). Áp dụng khi chưa phân loại được cụ thể nguyên nhân sự cố.',
    type: 'Incident Response',
    platforms: ['Windows', 'Linux', 'macOS'],
    mitre: 'Multiple Tactics',
    color: 'blue',
    icon: 'Briefcase',
    goals: [
      'Triage & Scope: Đánh giá nhanh mức độ nghiêm trọng và khoanh vùng các hệ thống bị ảnh hưởng.',
      'Volatile Data Preservation: Thu thập khẩn cấp dữ liệu biến động trên RAM, cache trước khi tắt máy.',
      'Chain of Custody: Đảm bảo tính toàn vẹn của bằng chứng pháp y để phục vụ mục đích kiện tụng nếu cần.',
      'Forensic Imaging: Tạo bản sao vật lý bit-by-bit để phân tích chuyên sâu ngoại tuyến (Offline Analysis).'
    ],
    steps: [
      {
        title: 'Bước 1: Chẩn đoán & Secure the Scene',
        content: '**Bảo vệ hiện trường:**\n- Hạn chế quyền truy cập vật lý và logic vào thiết bị/máy chủ bị nghi ngờ xâm nhập.\n- Nếu là máy ảo (VM), hãy ngay lập tức tạo Snapshot có bao gồm cả tùy chọn Memory.\n- Không tắt nóng hệ thống (trừ khi hệ thống đang xóa dữ liệu ồ ạt) để tránh mất dấu vết lưu trên RAM.\n- Ghi lại thông tin người phát hiện, thời điểm phát hiện và triệu chứng ban đầu.',
        icon: 'Lock'
      },
      {
        title: 'Bước 2: Thu thập Dữ liệu Trực tiếp (Live Response Data)',
        content: '**Sử dụng Checklist Tự động:**\n- Khởi chạy DFIR Collection Checklist trên nền tảng (Phase 1) để trích xuất:\n  + Các tiến trình đang chạy (Processes) và thư viện DLL được nạp.\n  + Kết nối mạng mở, bảng định tuyến (Routing), ARP cache.\n  + Danh sách Users đang đăng nhập, nhóm quyền cục bộ.\n  + Autoruns, Scheduled Tasks, và Services đang chạy.\n- Xuất kết quả ra file txt/csv có mã băm (Hash) để chứng minh tính nguyên bản.',
        icon: 'Download'
      },
      {
        title: 'Bước 3: Disk & Memory Imaging',
        content: '**Lấy bản sao pháp y vật lý:**\n- **RAM:** Sử dụng DumpIt / FTK Imager / winpmem / LiME (Linux) để lấy ảnh bộ nhớ.\n- **Đĩa cứng:** Sử dụng thiết bị chặn ghi (Write-Blocker) nếu lấy ổ đĩa vật lý.\n- Sử dụng phần mềm FTK Imager / Guymager để xuất file ảnh đĩa theo định dạng E01 hoặc DD/RAW.\n- **Bắt buộc:** Phải tính toán mã băm MD5 và SHA-256 cho file Image ngay sau khi tạo xong.',
        icon: 'HardDrive'
      },
      {
        title: 'Bước 4: Phân tích Ngoại tuyến (Offline Analysis)',
        content: '**Điều tra bằng công cụ chuyên dụng:**\n- Mount file ảnh đĩa vào các công cụ phân tích (Autopsy, X-Ways, Axiom).\n- Thu thập MFT (Master File Table) để phân tích Timeline và phục hồi file đã bị xóa.\n- Phân tích Registry Hives (SAM, SYSTEM, SOFTWARE) để tìm kiếm bằng chứng thực thi (Shimcache, Amcache) và USB ngoại vi.\n- Tổng hợp Timeline để vẽ nên toàn bộ quá trình xâm nhập của kẻ tấn công.',
        icon: 'Activity'
      }
    ],
    references: [
      { title: 'SANS: Quy trình Ứng phó Sự cố (PICERL)', url: 'https://www.sans.org/white-papers/33901/' },
      { title: 'RFC 3227: Hướng dẫn Thu thập Bằng chứng', url: 'https://datatracker.ietf.org/doc/html/rfc3227' },
      { title: 'NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide', url: 'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final' }
    ]
  },
  {
    id: 'compliance',
    title: 'Compliance & Security Audit',
    description: 'Quy trình rà quét, kiểm tra sự tuân thủ bảo mật theo các khung tiêu chuẩn quốc tế (ISO 27001, SOC 2, PCI-DSS, NIST). Trọng tâm của quá trình này là Đánh giá Gap (Gap Detection) và Sẵn sàng cho quá trình Audit thực tế.',
    type: 'Security Audit',
    platforms: ['Windows', 'Linux', 'Cloud'],
    mitre: 'Compliance Controls',
    color: 'emerald',
    icon: 'ShieldAlert',
    goals: [
      'Visibility: Biết chính xác ai đang làm gì, có quyền gì trên từng hệ thống cụ thể.',
      'Gap Detection: Tìm khoảng cách giữa chính sách bảo mật (Policy) và thực tế triển khai dưới hạ tầng.',
      'Threat Exposure: Phát hiện sớm các cấu hình sai lệch rủi ro cao trước khi bị tin tặc khai thác (VD: port mở public, mật khẩu yếu).',
      'Regulatory Readiness: Sẵn sàng hồ sơ, bằng chứng (Audit Trail) để đối mặt với các đợt kiểm tra đánh giá chứng nhận quốc tế.'
    ],
    steps: [
      {
        title: 'Bước 1: Rà soát Quản lý Định danh & Truy cập (IAM)',
        content: '**Kiểm tra các rủi ro về Tài khoản:**\n- Lọc danh sách các tài khoản nhân viên không đăng nhập quá 90 ngày (Stale Accounts).\n- Soát xét lại quyền Admin: Các tài khoản Service hoặc User có bị gán quyền Admin cục bộ quá mức cần thiết (Over-privileged) không.\n- Kiểm tra xem MFA (Xác thực 2 bước) đã được bắt buộc áp dụng cho toàn bộ VPN và Cloud Services chưa.\n- Chính sách quay vòng mật khẩu (Password Rotation) và thời hạn phiên làm việc (Session Expiry).',
        icon: 'Lock'
      },
      {
        title: 'Bước 2: Rà soát Mạng & Hạ tầng (Network & Infrastructure)',
        content: '**Kiểm tra phân vùng mạng và kết nối:**\n- Quét các cổng mạng mở nguy hiểm (22 SSH, 3389 RDP, 445 SMB) ra ngoài Internet.\n- Đánh giá luật tường lửa (Firewall Rules): Loại bỏ các rule lỗi thời hoặc có thiết lập rủi ro "Allow All".\n- Xác minh việc truyền tải dữ liệu nội bộ được mã hóa an toàn (Sử dụng HTTPS/TLS thay vì HTTP/Telnet).\n- Rà soát các thiết bị không xác định (Rogue devices) và các thiết bị ngoại vi không đăng ký.',
        icon: 'Target'
      },
      {
        title: 'Bước 3: Rà soát Endpoint & Quản lý Dữ liệu Nhạy cảm (Data & Secrets)',
        content: '**Kiểm tra máy trạm, máy chủ và Kho dữ liệu:**\n- Patch Level: Xác minh hệ điều hành và phần mềm bên thứ 3 đã được vá các CVE điểm CVSS cao chưa.\n- AV/EDR Coverage: Đảm bảo 100% các máy có cài đặt và chạy ngầm Agent phòng chống mã độc.\n- Quét rò rỉ dữ liệu (Secrets Scanning): Tìm kiếm các Hardcoded API Keys, mật khẩu trong Source Code (Git) hoặc Config files.\n- Dữ liệu PII/PCI: Xác minh dữ liệu nhạy cảm của khách hàng đang được mã hóa ở trạng thái nghỉ (Data at Rest).',
        icon: 'Search'
      },
      {
        title: 'Bước 4: Rà soát Logs, Monitoring & Change Management',
        content: '**Bảo đảm khả năng giám sát và kiểm soát thay đổi:**\n- Kiểm tra thời gian lưu trữ Log: Event Logs và System Logs có được giữ tối thiểu 90 ngày (hoặc 1 năm theo PCI-DSS) không.\n- Xác minh tính đầy đủ của Audit Logs: Liệu các hành vi tạo user mới, cấp quyền admin có sinh ra cảnh báo trên SIEM không.\n- Quản lý Thay đổi (Change Management): Việc triển khai cấu hình mới lên Production có record phê duyệt (Approval) trên hệ thống Jira/Ticketing không.',
        icon: 'FileText'
      },
      {
        title: 'Bước 5: Lập báo cáo Gap Analysis & Remediation',
        content: '**Xuất báo cáo cho các bên liên quan:**\n- **Executive Summary:** Tổng quan điểm Compliance Score và Top 5 rủi ro nghiêm trọng (dành cho Ban Giám đốc).\n- **Technical Findings:** Mô tả chi tiết từng lỗ hổng, mức độ rủi ro, kèm theo ID của Framework (VD: NIST SP 800-53 AC-2).\n- **Remediation Roadmap:** Bảng lộ trình khắc phục với Deadline rõ ràng (VD: Critical fix trong 24h, High trong 7 ngày) và Gán đúng Owner chịu trách nhiệm.',
        icon: 'Activity'
      }
    ],
    references: [
      { title: 'ISO/IEC 27001:2022 Standard', url: 'https://www.iso.org/isoiec-27001-information-security.html' },
      { title: 'NIST Cybersecurity Framework 2.0', url: 'https://www.nist.gov/cyberframework' },
      { title: 'PCI Security Standards', url: 'https://www.pcisecuritystandards.org/' },
      { title: 'CIS Controls v8', url: 'https://www.cisecurity.org/controls/v8' }
    ]
  },
  {
    id: 'security-hunting',
    title: 'Security Assessment & Hunting',
    description: 'Quy trình chủ động thu thập bằng chứng và săn tìm dấu hiệu xâm nhập (Threat Hunting) trên Windows và Linux. Áp dụng để rà soát an toàn định kỳ hoặc xác minh một nghi ngờ chưa rõ — thu thập snapshot toàn diện về tiến trình, mạng, tài khoản, persistence và log.',
    type: 'Threat Hunting',
    platforms: ['Windows', 'Linux'],
    mitre: 'Multiple Tactics (Discovery, Persistence, C2)',
    color: 'blue',
    icon: 'Crosshair',
    goals: [
      'Visibility: Ảnh chụp toàn diện trạng thái hệ thống (process, mạng, account, persistence).',
      'Detection: Phát hiện tiến trình lạ, kết nối C2 (Beaconing), tài khoản trái phép, backdoor.',
      'Evidence Collection: Thu thập bằng chứng có mốc thời gian để dựng Timeline tấn công.',
      'Threat Hunting: Trích xuất IOC để săn tìm trên diện rộng (SIEM/ELK).'
    ],
    steps: [
      {
        title: 'Bước 1: Chuẩn bị & Khoanh vùng (Scope)',
        content: '**Xác định phạm vi và mục tiêu:**\n- Tạo một Case mới trong Case Manager để gom toàn bộ bằng chứng.\n- Xác định danh sách máy cần rà soát (scope) và gán Agent tương ứng.\n- Mở **Evidence & Compliance** với profile **Forensic Collection** — bộ check đã có sẵn note "Phục vụ" và gợi ý tool cho từng mục.',
        icon: 'Target'
      },
      {
        title: 'Bước 2: Thu thập trên Windows',
        content: '**5 nhóm bằng chứng:**\n- **System & Patches:** `systeminfo`, `Get-HotFix` — đối chiếu CVE để tìm máy thiếu bản vá.\n- **Identity:** `net user`, `net localgroup administrators`, `query user` — tìm account lạ / admin trái phép.\n- **Process & Network:** `Get-Process` (lọc Path) + `Get-NetTCPConnection` map process — soi process không path, parent bất thường, beaconing.\n- **Persistence:** `schtasks`, Registry Run keys (HKLM/HKCU), scheduled tasks non-Microsoft.\n- **Event hunt:** ID 4624/4625 (logon), 4697 (cài service = backdoor), 4104 (PowerShell script đáng ngờ).',
        icon: 'Server'
      },
      {
        title: 'Bước 3: Thu thập trên Linux',
        content: '**5 nhóm bằng chứng:**\n- **System:** `uname -a`, firewall (`iptables`/`ufw`), `sshd_config` (PermitRootLogin/PasswordAuthentication = cấu hình lỏng).\n- **Identity:** `/etc/passwd` (shell), nhóm sudo/wheel, `last`/`lastb` — bùng nổ failed login = brute-force.\n- **Process & Network:** `ps auxef`/`pstree`, `ss -antup` — phát hiện reverse shell.\n- **Persistence:** crontab, systemd enabled, `authorized_keys` lạ, LD_PRELOAD, SUID/SGID bất thường.\n- **Logs:** `auth.log`/`secure`, bash_history.',
        icon: 'TerminalSquare'
      },
      {
        title: 'Bước 4: Phân tích & Dựng Timeline',
        content: '**Biến bằng chứng thành kết luận:**\n- Dùng **AI Analysis** để tóm tắt phát hiện và đánh giá bất thường từ output đã thu.\n- Đưa IOC (IP, hash, path) vào **ELK Threat Hunting** để săn trên diện rộng.\n- Promote hits + **AI Extract/Rebuild** vào **Attack Timeline** của case để dựng dòng sự kiện chuẩn.\n- Khi xác định loại tấn công cụ thể → chuyển sang playbook chuyên sâu (Webshell/Ransomware).',
        icon: 'Activity'
      },
      {
        title: 'Bước 5: Tự động hóa & Quy mô lớn',
        content: '**Khi cần rà soát hàng trăm máy:**\n- **KAPE / CyLR** (Windows) và **UAC** (Linux): tự động đóng gói artifact của từng máy.\n- **Hayabusa / DeepBlueCLI / Chainsaw:** phân tích nhanh Windows Event Logs tìm dấu hiệu tấn công.\n- **Velociraptor (khuyên dùng):** triển khai agent đa nền tảng, viết truy vấn VQL để hunt & thu thập bằng chứng từ hàng ngàn máy qua web console tập trung.\n- **OSQuery / Wazuh:** truy vấn trạng thái endpoint dạng SQL trên toàn fleet.',
        icon: 'Download'
      }
    ],
    references: [
      { title: 'MITRE ATT&CK Framework', url: 'https://attack.mitre.org/' },
      { title: 'Velociraptor — Digital Forensic & Incident Response', url: 'https://docs.velociraptor.app/' },
      { title: 'SANS Threat Hunting Resources', url: 'https://www.sans.org/blog/threat-hunting-resources/' }
    ]
  }
]
