package database

import (
	"log"

	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// seedDashboardUsecases inserts a few default incident-type dashboard views the
// first time the table is empty. Idempotent: skips when any usecase exists, so
// operators can freely edit/delete the defaults without them reappearing.
func seedDashboardUsecases(db *gorm.DB) {
	var count int64
	if err := db.Model(&models.DashboardUsecase{}).Count(&count).Error; err != nil {
		return
	}
	if count > 0 {
		return
	}

	defaults := []models.DashboardUsecase{
		{
			Name:         "Webshell Incident",
			Slug:         "webshell",
			IncidentType: "webshell",
			Description:  "Web server compromise via uploaded webshell.",
			Icon:         "Shield",
			Color:        "emerald",
			Widgets:      `["agents-stat","jobs-stat","iocs-stat","recent-jobs","elk-results","playbook"]`,
			Playbook: "## Mục tiêu (Goals)\n" +
				"Visibility: Giám sát toàn bộ lưu lượng web và các tập tin được tạo ra trên thư mục Web Root.\n" +
				"Detection: Phát hiện mã độc PHP/JSP/ASPX lẩn trốn dưới các đuôi file ảnh (.jpg, .png) hoặc bị mã hóa rườm rà (Obfuscation).\n" +
				"Analysis: Phân tích Web Access Logs để tìm ra IP của kẻ tấn công và thời điểm khai thác.\n" +
				"Eradication: Loại bỏ tận gốc Webshell và các cửa hậu (Backdoor).\n" +
				"Prevention: Đề xuất các bản vá cho mã nguồn ứng dụng Web.\n\n" +
				"## Các bước xử lý (Steps)\n" +
				"**Bước 1: Quét tệp hệ thống Web Root**\n" +
				"- Sử dụng công cụ YARA hoặc Thor Scanner để quét các thư mục chứa mã nguồn.\n" +
				"- Tìm các tệp tin `.php`, `.aspx`, `.jsp` được sửa đổi (Modified) trong khoảng thời gian xảy ra sự cố.\n" +
				"- Tìm kiếm các hàm thực thi lệnh ẩn giấu: `eval()`, `base64_decode()`, `system()`.\n\n" +
				"**Bước 2: Phân tích Web Access & Error Logs**\n" +
				"- Thu thập toàn bộ Access Logs của Apache/Nginx hoặc IIS Logs.\n" +
				"- Tìm kiếm các HTTP POST requests với tần suất thấp tới các file cụ thể.\n" +
				"- Tìm các yêu cầu trả về mã trạng thái HTTP 200 từ các URL đáng ngờ hoặc sâu trong `/uploads/`.\n\n" +
				"**Bước 3: Phân tích Tiến trình Con (Child Processes)**\n" +
				"- Web server (`w3wp.exe`, `nginx`) sinh ra các tiến trình shell hệ thống như `cmd.exe`, `bash` -> **ĐÂY LÀ DẤU HIỆU CỦA WEBSHELL.**\n" +
				"- Kiểm tra Netstat xem web server có kết nối Reverse Shell ra Internet qua các port lạ không.\n\n" +
				"**Bước 4: Loại bỏ và Ngăn chặn**\n" +
				"- Xóa bỏ tập tin Webshell hoặc khôi phục mã nguồn sạch.\n" +
				"- Cấu hình phân quyền: Ngăn chặn thư mục `/uploads/` được quyền thực thi script.\n\n" +
				"## Công cụ ForensicHub\n" +
				"Webshell Scanner · Loki · Autoruns · TCPView · ELK Threat Hunting · Attack Timeline.\n\n" +
				"*Chi tiết: docs/playbooks/webshell.md*",
			SortOrder: 1,
		},
		{
			Name:         "Ransomware",
			Slug:         "ransomware",
			IncidentType: "ransomware",
			Description:  "File-encrypting malware outbreak.",
			Icon:         "Lock",
			Color:        "rose",
			Widgets:      `["agents-stat","jobs-stat","iocs-stat","cves-stat","recent-jobs","kev-cves","playbook"]`,
			Playbook: "## Mục tiêu (Goals)\n" +
				"Visibility: Xác định chính xác \"bán kính vụ nổ\" (blast radius) của Ransomware trên toàn mạng.\n" +
				"Containment: Cô lập khẩn cấp các máy chủ chưa bị lây nhiễm, ngăn chặn Lateral Movement.\n" +
				"Identification: Thu thập mẫu mã độc và Ransom Note để định danh chủng loại.\n" +
				"Evidence Collection: Dump RAM khẩn cấp để trích xuất khóa giải mã và thu thập Windows Event Logs.\n" +
				"Recovery: Đảm bảo môi trường sạch sẽ trước khi khôi phục dữ liệu từ Backup.\n\n" +
				"## Các bước xử lý (Steps)\n" +
				"**Bước 1: Cô lập & Bảo toàn Hiện trường**\n" +
				"- **Ngắt mạng:** Rút dây mạng, disable NIC trên vCenter/Hyper-V, đưa vào Quarantine VLAN.\n" +
				"- **KHÔNG TẮT NGUỒN:** Tránh mất khóa giải mã trên RAM hoặc kích hoạt Wiper.\n" +
				"- **Khóa tài khoản:** Khóa tài khoản Admin nghi ngờ lộ lọt. Tắt RDP/SMB trên mạng.\n\n" +
				"**Bước 2: Phân loại & Thu thập Thông tin**\n" +
				"- Chụp ảnh màn hình Ransom Note. Tìm file bị mã hóa gần nhất để xác định Extension (.locked).\n" +
				"- Upload file bị mã hóa lên ID Ransomware để nhận diện dòng mã độc.\n\n" +
				"**Bước 3: Memory Dump & Triage**\n" +
				"- Dùng WinPmem/DumpIt sao chụp RAM.\n" +
				"- Chạy Evidence Collection Checklist tự động để trích xuất Network Connections, Processes.\n" +
				"- Thu thập nhanh Registry Hives, MFT, và Event Logs bằng KAPE.\n\n" +
				"**Bước 4: Điều tra Nguyên nhân Gốc**\n" +
				"- Phân tích Firewall/VPN/Email Gateway Logs tìm điểm xâm nhập.\n" +
				"- Phân tích Event ID 4624/4625 để xem nguồn đăng nhập.\n\n" +
				"## Công cụ ForensicHub\n" +
				"DumpIt · Redline · MBAR · Loki · Autoruns · Vulnerability Search · ELK Hunting · Attack Timeline.\n\n" +
				"*Chi tiết: docs/playbooks/ransomware.md*",
			SortOrder: 2,
		},
		{
			Name:         "Generic DFIR",
			Slug:         "generic",
			IncidentType: "generic",
			Description:  "General-purpose incident triage.",
			Icon:         "Activity",
			Color:        "sky",
			Widgets:      `["agents-stat","jobs-stat","cves-stat","iocs-stat","recent-jobs","kev-cves","iocs-list","playbook"]`,
			Playbook: "## Mục tiêu (Goals)\n" +
				"Triage & Scope: Đánh giá nhanh mức độ nghiêm trọng và khoanh vùng ảnh hưởng.\n" +
				"Volatile Data Preservation: Thu thập khẩn cấp dữ liệu biến động trên RAM, cache trước khi tắt máy.\n" +
				"Chain of Custody: Đảm bảo tính toàn vẹn của bằng chứng pháp y.\n" +
				"Forensic Imaging: Tạo bản sao vật lý bit-by-bit để phân tích ngoại tuyến.\n\n" +
				"## Các bước xử lý (Steps)\n" +
				"**Bước 1: Chẩn đoán & Secure the Scene**\n" +
				"- Hạn chế quyền truy cập vật lý và logic.\n" +
				"- Nếu là máy ảo (VM), tạo Snapshot có bao gồm Memory.\n" +
				"- Không tắt nóng hệ thống để tránh mất dấu vết trên RAM.\n\n" +
				"**Bước 2: Thu thập Dữ liệu Trực tiếp (Live Response)**\n" +
				"- Khởi chạy DFIR Collection Checklist tự động trích xuất:\n" +
				"  - Tiến trình đang chạy và DLL được nạp.\n" +
				"  - Kết nối mạng, ARP cache, Routing table.\n" +
				"  - Danh sách Users đăng nhập.\n" +
				"  - Autoruns, Scheduled Tasks, Services.\n\n" +
				"**Bước 3: Disk & Memory Imaging**\n" +
				"- Dùng DumpIt/FTK Imager lấy ảnh RAM.\n" +
				"- Dùng Write-Blocker lấy ảnh đĩa vật lý (E01/DD).\n" +
				"- Tính toán mã băm MD5/SHA-256 ngay sau khi tạo.\n\n" +
				"**Bước 4: Phân tích Ngoại tuyến**\n" +
				"- Mount file ảnh đĩa vào Autopsy/Axiom.\n" +
				"- Thu thập MFT phân tích Timeline, phục hồi file bị xóa.\n" +
				"- Phân tích Registry Hives (SAM, SYSTEM).\n\n" +
				"## Công cụ ForensicHub\n" +
				"Evidence Checklist · DumpIt · Redline · Loki · Autoruns · AI Analysis · ELK Hunting.\n\n" +
				"*Chi tiết: docs/playbooks/generic-dfir.md*",
			SortOrder: 3,
		},
		{
			Name:         "Compliance Audit",
			Slug:         "compliance-audit",
			IncidentType: "compliance",
			Description:  "Audit readiness: ISO 27001 / SOC 2 / PCI-DSS / NIST.",
			Icon:         "ShieldAlert",
			Color:        "amber",
			Widgets:      `["agents-stat","jobs-stat","open-cases","recent-jobs","playbook"]`,
			Playbook: "## Mục tiêu (Goals)\n" +
				"Visibility: Biết rõ ai đang làm gì, có quyền gì trên hệ thống.\n" +
				"Gap Detection: Tìm khoảng cách giữa policy và thực tế triển khai hạ tầng.\n" +
				"Threat Exposure: Phát hiện sớm rủi ro (port public, mật khẩu yếu) trước khi bị khai thác.\n" +
				"Regulatory Readiness: Sẵn sàng hồ sơ Audit Trail cho ISO 27001, SOC 2, PCI-DSS, NIST.\n\n" +
				"## Các bước xử lý (Steps)\n" +
				"**Bước 1: Rà soát Định danh & Truy cập (IAM)**\n" +
				"- Lọc tài khoản không đăng nhập >90 ngày. Soát xét quyền Admin cục bộ, Over-privileged users.\n" +
				"- Đảm bảo MFA áp dụng toàn bộ VPN/Cloud. Password Rotation.\n\n" +
				"**Bước 2: Rà soát Mạng & Hạ tầng**\n" +
				"- Quét port nguy hiểm (22, 3389, 445) ra Internet.\n" +
				"- Đánh giá Firewall rules, loại bỏ rule `Allow All`.\n" +
				"- Xác minh dữ liệu nội bộ dùng HTTPS/TLS. Rà soát Rogue devices.\n\n" +
				"**Bước 3: Rà soát Endpoint & Dữ liệu**\n" +
				"- Patch Level: Xác minh hệ điều hành/phần mềm đã vá CVE điểm cao.\n" +
				"- AV/EDR Coverage: 100% máy chạy Agent bảo mật.\n" +
				"- Xác minh dữ liệu PCI/PII được mã hóa Data at Rest.\n\n" +
				"**Bước 4: Rà soát Logs & Change Management**\n" +
				"- Kiểm tra Event Logs/System Logs lưu đủ tối thiểu 90 ngày.\n" +
				"- Quản lý Thay đổi (FIM): Triển khai cấu hình Production có record phê duyệt trên Jira.\n\n" +
				"**Bước 5: Lập báo cáo Gap Analysis**\n" +
				"- Tổng hợp Executive Summary, Compliance Score.\n" +
				"- Lập bảng Technical Findings chi tiết (Severity, ID Framework, Remediation).\n\n" +
				"*Chi tiết: docs/playbooks/compliance-audit.md · Lộ trình: docs/compliance-audit-research.md*",
			SortOrder: 4,
		},
	}

	if err := db.Create(&defaults).Error; err != nil {
		log.Printf("[db] seed dashboard usecases: %v", err)
		return
	}
	log.Printf("[db] seeded %d dashboard usecases", len(defaults))
}
