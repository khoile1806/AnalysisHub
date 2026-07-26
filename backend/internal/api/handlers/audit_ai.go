package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/gin-gonic/gin"
)

// auditSummaryMaxRows bounds how many actions feed the model. An operator with
// tens of thousands of rows would blow the context window; the most recent slice
// is what a "what has this person been doing" check actually needs.
const auditSummaryMaxRows = 600

// SummarizeUserActivity produces a natural-language account of what one user has
// done, for the accountability question "what did this operator do up to now".
// It reads the user's audit trail, hands it to the configured AI provider, and
// returns a plain-language summary — grounded strictly in the recorded actions.
//
// POST /api/v1/audit/summarize   { "user_id": "...", "from": "", "to": "", "provider_id": "" }
func (h *AIHandler) SummarizeUserActivity(c *gin.Context) {
	var body struct {
		UserID     string `json:"user_id"`
		From       string `json:"from"`
		To         string `json:"to"`
		ProviderID string `json:"provider_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	q := h.db.Table("audit_logs AS a").
		Select(`a.action, a.resource, a.detail, a.ip, a.created_at,
			COALESCE(ag.hostname, '') AS agent_host`).
		Joins("LEFT JOIN agents ag ON ag.id = a.agent_id")

	// A specific user, or the system/automated actor when user_id is blank.
	if strings.TrimSpace(body.UserID) != "" {
		q = q.Where("a.user_id = ?", body.UserID)
	} else {
		q = q.Where("a.user_id IS NULL")
	}
	if from := parseAuditTime(body.From); !from.IsZero() {
		q = q.Where("a.created_at >= ?", from)
	}
	if to := parseAuditTime(body.To); !to.IsZero() {
		q = q.Where("a.created_at <= ?", to)
	}

	type actRow struct {
		Action    string
		Resource  string
		Detail    string
		IP        string
		AgentHost string
		CreatedAt time.Time
	}
	var rows []actRow
	// Newest-first for the cap, so a busy user's *recent* activity is what's kept.
	q.Order("a.id desc").Limit(auditSummaryMaxRows).Scan(&rows)

	if len(rows) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
			"summary":       "No recorded activity for this user in the selected window.",
			"actions_count": 0,
		}})
		return
	}

	// Resolve the AI provider up front so a missing/misconfigured provider is a
	// clean error rather than a half-built prompt.
	_, client, err := h.resolveProvider(body.ProviderID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Present the log oldest-first to the model so the narrative reads forward.
	var b strings.Builder
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		line := r.CreatedAt.UTC().Format("2006-01-02 15:04:05") + "  " + r.Action
		if r.AgentHost != "" {
			line += "  agent=" + r.AgentHost
		}
		if r.Resource != "" {
			line += "  resource=" + truncate(r.Resource, 80)
		}
		if r.Detail != "" {
			line += "  " + truncate(r.Detail, 160)
		}
		if r.IP != "" {
			line += "  ip=" + r.IP
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	summary, _, err := analysis.Chat(ctx, client, buildActivitySummaryPrompt(body.UserID, rows[len(rows)-1].CreatedAt, rows[0].CreatedAt, len(rows), b.String()),
		ai.Options{MaxTokens: 1200, Temperature: 0.2})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "AI summary failed: " + err.Error()})
		return
	}

	summary = strings.TrimSpace(summary)

	// Persist the narrative itself, not just the fact that a summary ran, so it
	// can be re-read from the activity log later instead of being lost when the
	// modal closes. Capped so one row can't dominate the table.
	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, h.db, &uid, nil, "audit.summarize", body.UserID, truncate(summary, 8000))
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"summary":       summary,
		"actions_count": len(rows),
		"capped":        len(rows) >= auditSummaryMaxRows,
		"from":          rows[len(rows)-1].CreatedAt,
		"to":            rows[0].CreatedAt,
	}})
}

// buildActivitySummaryPrompt frames the task tightly: describe, do not
// speculate, and flag anything that stands out for a data-safety review. The
// output is written in Vietnamese because the operators reading this
// accountability briefing work in Vietnamese; the audit data it is grounded in
// stays in its original form.
func buildActivitySummaryPrompt(userID string, first, last time.Time, n int, log string) string {
	who := userID
	if strings.TrimSpace(who) == "" {
		who = "hệ thống / tác vụ tự động"
	}
	return fmt.Sprintf(`Bạn là trợ lý bảo mật và tuân thủ cho một nền tảng DFIR (điều tra số và ứng cứu sự cố). Một quản trị viên đang xem lại hoạt động được ghi nhận của một người dùng để trả lời câu hỏi trách nhiệm: "người này đã làm những gì trên hệ thống".

Dưới đây là nhật ký hoạt động của người dùng đó (%d hành động, từ %s đến %s UTC), mỗi dòng một hành động: thời gian, tên hành động, và khi có liên quan là agent đích, mã tài nguyên, chi tiết, và IP nguồn. Đây là NGUỒN SỰ THẬT DUY NHẤT — tuyệt đối không bịa, không suy diễn, không thêm bất cứ điều gì không có trong các dòng này.

Hãy viết một bản mô tả bằng TIẾNG VIỆT, dạng văn xuôi dễ đọc, gồm các phần sau (in đậm tiêu đề từng phần):
1. **Tổng quan** — 2-3 câu mô tả người dùng này đã làm gì và trong khoảng thời gian nào.
2. **Dữ liệu đã truy cập / lấy đi** — đã đụng tới máy agent nào, đã thu thập hoặc tải file/bằng chứng nào ra khỏi endpoint (đây là ưu tiên trách nhiệm). Nêu đích danh tên agent.
3. **Các thao tác đã thực hiện** — các lần quét, truy vấn, job, và thay đổi cấu hình, nhóm lại hợp lý.
4. **Điểm cần lưu ý** — bất cứ điều gì người soát an toàn dữ liệu nên kiểm tra kỹ (ví dụ: bằng chứng bị tải về máy cá nhân, thao tác xóa, thay đổi cấu hình/thông tin xác thực, truy cập nhiều máy). Nếu không có gì bất thường, hãy nói thẳng. KHÔNG được tạo ra mối lo không có thật.

Trình bày chính xác và cụ thể. Trích đúng tên agent và số lượng từ nhật ký. Không đưa vào những hành động không có trong nhật ký.

--- NHẬT KÝ HOẠT ĐỘNG của %s ---
%s
--- HẾT ---`, n, first.UTC().Format("2006-01-02 15:04"), last.UTC().Format("2006-01-02 15:04"), who, log)
}
