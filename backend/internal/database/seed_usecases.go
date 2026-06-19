package database

import (
	"log"

	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// seedDashboardUsecases inserts a few default incident-type dashboard views the
// first time the table is empty. Idempotent: skips when any usecase exists, so
// operators can freely edit/delete the defaults without them reappearing.
//
// The Playbook field here is intentionally a SHORT summary — the full, detailed
// playbooks live on the dedicated Playbooks page (/playbooks).
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
			Playbook: "**Mục tiêu:** Phát hiện & xử lý mã độc webshell trên web server.\n\n" +
				"Soi file lạ trong web root, log POST bất thường, process con của web server (cmd/bash), dựng timeline khai thác.\n\n" +
				"→ Quy trình đầy đủ (goals, các bước, references) tại tab **Playbooks → Webshell & Backdoor Hunting**.",
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
			Playbook: "**Mục tiêu:** Ứng phó mã độc tống tiền & khôi phục an toàn.\n\n" +
				"Cô lập (KHÔNG tắt nguồn) → dump RAM tìm khóa → định danh chủng → tìm điểm xâm nhập → khôi phục từ backup sạch.\n\n" +
				"→ Quy trình đầy đủ tại tab **Playbooks → Ransomware Response & Recovery**.",
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
			Playbook: "**Mục tiêu:** Triage tổng quát cho sự cố chưa rõ loại.\n\n" +
				"Bảo toàn dữ liệu volatile (RAM) → live response → disk/memory imaging → phân tích offline → phân loại sự cố.\n\n" +
				"→ Quy trình đầy đủ tại tab **Playbooks → Generic DFIR Workflow**.",
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
			Playbook: "**Mục tiêu:** Rà soát tuân thủ & sẵn sàng audit (ISO/SOC2/PCI/NIST).\n\n" +
				"Soát IAM · Network · Endpoint · Data & Secrets · Logging · Change Mgmt → tìm gap → lập báo cáo Gap Analysis.\n\n" +
				"→ Quy trình đầy đủ tại tab **Playbooks → Compliance & Security Audit**.",
			SortOrder: 4,
		},
		{
			Name:         "Security Assessment & Hunting",
			Slug:         "security-hunting",
			IncidentType: "hunting",
			Description:  "Chủ động thu thập bằng chứng & săn dấu hiệu xâm nhập (Windows + Linux).",
			Icon:         "Crosshair",
			Color:        "violet",
			Widgets:      `["agents-stat","jobs-stat","iocs-stat","recent-jobs","elk-results","playbook"]`,
			Playbook: "**Mục tiêu:** Chủ động săn dấu hiệu xâm nhập & thu thập bằng chứng.\n\n" +
				"5 nhóm: System & Patches · Identity · Process/Network · Persistence · Logs (Windows + Linux). Trích IOC → hunt rộng.\n\n" +
				"→ Quy trình đầy đủ tại tab **Playbooks → Security Assessment & Hunting**.",
			SortOrder: 5,
		},
	}

	if err := db.Create(&defaults).Error; err != nil {
		log.Printf("[db] seed dashboard usecases: %v", err)
		return
	}
	log.Printf("[db] seeded %d dashboard usecases", len(defaults))
}
