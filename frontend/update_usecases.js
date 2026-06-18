import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:8080/api' });

const PLAYBOOKS = {
  webshell: `## Mục tiêu (Goals)
Visibility: Giám sát toàn bộ lưu lượng web và các tập tin được tạo ra trên thư mục Web Root.
Detection: Phát hiện mã độc PHP/JSP/ASPX lẩn trốn dưới các đuôi file ảnh (.jpg, .png) hoặc bị mã hóa rườm rà (Obfuscation).
Analysis: Phân tích Web Access Logs để tìm ra IP của kẻ tấn công và thời điểm khai thác.
Eradication: Loại bỏ tận gốc Webshell và các cửa hậu (Backdoor).
Prevention: Đề xuất các bản vá cho mã nguồn ứng dụng Web.

## Các bước xử lý (Steps)
**Bước 1: Quét tệp hệ thống Web Root**
- Sử dụng công cụ YARA hoặc Thor Scanner để quét các thư mục chứa mã nguồn.
- Tìm các tệp tin \`.php\`, \`.aspx\`, \`.jsp\` được sửa đổi (Modified) trong khoảng thời gian xảy ra sự cố.
- Lệnh kiểm tra Linux: \`find /var/www -name "*.php" -mtime -7\`.
- Tìm kiếm các hàm thực thi lệnh ẩn giấu: \`eval()\`, \`base64_decode()\`, \`system()\`.

**Bước 2: Phân tích Web Access & Error Logs**
- Thu thập toàn bộ Access Logs của Apache/Nginx hoặc IIS Logs.
- Tìm kiếm các HTTP POST requests với tần suất thấp tới các file cụ thể.
- Tìm các yêu cầu trả về mã trạng thái HTTP 200 từ các URL đáng ngờ hoặc sâu trong \`/uploads/\`.

**Bước 3: Phân tích Tiến trình Con (Child Processes)**
- Web server (\`w3wp.exe\`, \`nginx\`) sinh ra các tiến trình shell hệ thống như \`cmd.exe\`, \`bash\` -> **ĐÂY LÀ WEBSHELL / RCE.**
- Kiểm tra Netstat xem web server có kết nối Reverse Shell ra Internet qua các port lạ (4444, 8080).

**Bước 4: Loại bỏ và Ngăn chặn**
- Xóa bỏ tập tin Webshell hoặc khôi phục mã nguồn sạch.
- Cấu hình phân quyền: Ngăn chặn thư mục \`/uploads/\` được quyền thực thi script.
- Bật các rules bảo vệ trên thiết bị WAF.`,

  ransomware: `## Mục tiêu (Goals)
Visibility: Xác định chính xác "bán kính vụ nổ" (blast radius) của Ransomware trên toàn mạng.
Containment: Cô lập khẩn cấp các máy chủ chưa bị lây nhiễm, ngăn chặn Lateral Movement.
Identification: Thu thập mẫu mã độc và Ransom Note để định danh chủng loại.
Evidence Collection: Dump RAM khẩn cấp để trích xuất khóa giải mã và thu thập Windows Event Logs.
Recovery: Đảm bảo môi trường sạch sẽ trước khi khôi phục dữ liệu từ Backup.

## Các bước xử lý (Steps)
**Bước 1: Cô lập & Bảo toàn Hiện trường**
- **Ngắt mạng vật lý/logic:** Rút dây mạng, disable NIC trên vCenter/Hyper-V, đưa vào Quarantine VLAN.
- **KHÔNG TẮT NGUỒN:** Tránh mất khóa giải mã trên RAM hoặc kích hoạt Wiper.
- **Khóa tài khoản:** Khóa tài khoản Admin nghi ngờ lộ lọt. Tắt RDP/SMB trên mạng.

**Bước 2: Phân loại & Thu thập Thông tin**
- Chụp ảnh màn hình Ransom Note. Tìm file bị mã hóa gần nhất để xác định Extension (.locked).
- Upload file bị mã hóa lên ID Ransomware để nhận diện dòng mã độc.
- Ghi nhận các tiến trình đang tiêu tốn CPU/IO cao.

**Bước 3: Memory Dump & Triage**
- Dùng WinPmem/DumpIt sao chụp RAM.
- Chạy Evidence Collection Checklist tự động để trích xuất Network Connections, Processes, Autoruns.
- Thu thập nhanh Registry Hives, MFT, và Event Logs bằng KAPE.

**Bước 4: Điều tra Nguyên nhân Gốc**
- Phân tích Firewall/VPN/Email Gateway Logs tìm điểm xâm nhập (Phishing, Brute-force).
- Phân tích Event ID 4624/4625 để xem nguồn đăng nhập.
- Kiểm tra các công cụ RMM (AnyDesk) cài lén lút.

**Bước 5: Báo cáo & Lên kế hoạch Khắc phục**
- Tổng hợp Executive Summary, Timeline Sự kiện, IOCs (IP, Domain, Hash).
- Xóa sạch hệ thống, cài OS mới, vá lỗ hổng trước khi hoạt động lại.`,

  generic: `## Mục tiêu (Goals)
Triage & Scope: Đánh giá nhanh mức độ nghiêm trọng và khoanh vùng ảnh hưởng.
Volatile Data Preservation: Thu thập khẩn cấp dữ liệu biến động trên RAM, cache trước khi tắt máy.
Chain of Custody: Đảm bảo tính toàn vẹn của bằng chứng pháp y.
Forensic Imaging: Tạo bản sao vật lý bit-by-bit để phân tích ngoại tuyến.

## Các bước xử lý (Steps)
**Bước 1: Chẩn đoán & Secure the Scene**
- Hạn chế quyền truy cập vật lý và logic.
- Nếu là máy ảo (VM), tạo Snapshot có bao gồm Memory.
- Không tắt nóng hệ thống để tránh mất dấu vết trên RAM. Ghi lại triệu chứng ban đầu.

**Bước 2: Thu thập Dữ liệu Trực tiếp (Live Response)**
- Khởi chạy DFIR Collection Checklist tự động trích xuất:
  - Tiến trình đang chạy và DLL được nạp.
  - Kết nối mạng, ARP cache, Routing table.
  - Danh sách Users đăng nhập.
  - Autoruns, Scheduled Tasks, Services.

**Bước 3: Disk & Memory Imaging**
- Dùng DumpIt/FTK Imager lấy ảnh RAM.
- Dùng Write-Blocker lấy ảnh đĩa vật lý (E01/DD).
- Tính toán mã băm MD5/SHA-256 cho file Image ngay sau khi tạo để bảo vệ tính toàn vẹn.

**Bước 4: Phân tích Ngoại tuyến**
- Mount file ảnh đĩa vào Autopsy/Axiom.
- Thu thập MFT phân tích Timeline, phục hồi file bị xóa.
- Phân tích Registry Hives (SAM, SYSTEM) tìm chứng cứ thực thi và thiết bị ngoại vi.`,

  'compliance-audit': `## Mục tiêu (Goals)
Visibility: Biết rõ ai đang làm gì, có quyền gì trên hệ thống.
Gap Detection: Tìm khoảng cách giữa policy và thực tế triển khai hạ tầng.
Threat Exposure: Phát hiện sớm rủi ro (port public, mật khẩu yếu) trước khi bị khai thác.
Regulatory Readiness: Sẵn sàng hồ sơ Audit Trail cho ISO 27001, SOC 2, PCI-DSS, NIST.

## Các bước xử lý (Steps)
**Bước 1: Rà soát Định danh & Truy cập (IAM)**
- Lọc tài khoản không đăng nhập >90 ngày.
- Soát xét quyền Admin cục bộ, Over-privileged users.
- Đảm bảo MFA áp dụng toàn bộ VPN/Cloud. Password Rotation.

**Bước 2: Rà soát Mạng & Hạ tầng**
- Quét port nguy hiểm (22, 3389, 445) ra Internet.
- Đánh giá Firewall rules, loại bỏ rule "Allow All".
- Xác minh dữ liệu nội bộ dùng HTTPS/TLS. Rà soát Rogue devices.

**Bước 3: Rà soát Endpoint & Dữ liệu**
- Patch Level: Xác minh hệ điều hành/phần mềm đã vá CVE điểm cao.
- AV/EDR Coverage: 100% máy chạy Agent bảo mật.
- Quét Hardcoded API Keys/Passwords trong mã nguồn (Git).
- Xác minh dữ liệu PCI/PII được mã hóa Data at Rest.

**Bước 4: Rà soát Logs & Change Management**
- Kiểm tra Event Logs/System Logs lưu đủ tối thiểu 90 ngày.
- Đảm bảo Audit Logs sinh cảnh báo trên SIEM khi tạo user/cấp quyền.
- Quản lý Thay đổi (FIM): Triển khai cấu hình Production có record phê duyệt trên Jira.

**Bước 5: Lập báo cáo Gap Analysis**
- Tổng hợp Executive Summary, Compliance Score.
- Lập bảng Technical Findings chi tiết (Severity, ID Framework, Remediation).
- Gán Remediation Roadmap với Deadline và Owner cụ thể.`
};

async function run() {
  const { data } = await api.get('/dashboard/usecases');
  const usecases = data.data;
  
  for (const u of usecases) {
    const newPlaybook = PLAYBOOKS[u.slug];
    if (newPlaybook) {
      console.log('Updating ' + u.slug + '...');
      await api.put('/dashboard/usecases/' + u.id, {
        ...u,
        playbook: newPlaybook
      });
      console.log('Updated ' + u.slug + ' successfully.');
    }
  }
}

run().catch(console.error);
