package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/forensichub/backend/internal/ai"
	"github.com/forensichub/backend/internal/models"
)

// triageCluster mirrors one entry of the AI triage JSON. Used only to validate
// that the model returned parseable, useful output before persisting.
type triageCluster struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

type triageResult struct {
	Summary  string          `json:"summary"`
	Clusters []triageCluster `json:"clusters"`
}

// TriageELKResult runs AI triage over the raw hits of a saved ELK hunt result.
// It ranks/clusters the hits by suspicion so an analyst reads a handful of
// prioritized leads instead of sifting thousands of raw hits by hand. The
// deterministic hits in ELKHuntResult.Results remain the source of truth; the
// triage is stored separately as an AI assessment layer.
//
// POST /api/v1/elk/hunt/results/:id/triage  { "provider_id": "<uuid>" }
func (h *AIHandler) TriageELKResult(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid result id"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	providerID, err := uuid.Parse(input.ProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider_id"})
		return
	}
	var provider models.AIProvider
	if err := h.db.First(&provider, "id = ?", providerID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider not found"})
		return
	}
	client, clientErr := h.newDecryptedClient(&provider)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": clientErr.Error()})
		return
	}

	var result models.ELKHuntResult
	if err := h.db.First(&result, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "hunt result not found"})
		return
	}
	if strings.TrimSpace(result.Results) == "" || result.TotalHits == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "hunt result has no hits to triage"})
		return
	}

	// Budget the raw hits the same way the analysis path does.
	hits := result.Results
	budget := envIntKB("AI_CONTENT_CAP_KB", 128) * 1024
	truncated := false
	if len(hits) > budget {
		hits = hits[:budget]
		truncated = true
	}

	prompt := buildELKTriagePrompt(result.Title, result.TotalHits, hits, truncated)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 180*time.Second)
	defer cancel()

	raw, usage, aiErr := collectChat(ctx, client, prompt, provider.MaxTokens)
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	jsonStr := ai.ExtractJSON(raw)
	var parsed triageResult
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil || (parsed.Summary == "" && len(parsed.Clusters) == 0) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "AI returned no parseable triage",
			"raw":     raw,
		})
		return
	}

	now := time.Now()
	h.db.Model(&result).Updates(map[string]interface{}{
		"triage":     jsonStr,
		"triaged_at": now,
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"triage":     json.RawMessage(jsonStr),
			"clusters":   len(parsed.Clusters),
			"triaged_at": now,
			"tokens":     usage.Total(),
		},
	})
}

// collectChat runs a single non-streamed completion and returns the full text
// plus usage. Used by action endpoints (triage) that want one JSON answer
// rather than a live token stream.
func collectChat(ctx context.Context, client ai.Client, prompt string, maxTok int) (string, ai.Usage, error) {
	tokenCh := make(chan string, 256)
	usageCh := make(chan ai.Usage, 1)
	errCh := make(chan error, 1)
	go func() {
		u, err := client.StreamChat(ctx, []ai.Message{{Role: "user", Content: prompt}}, ai.Options{MaxTokens: maxTok, JSON: true}, tokenCh)
		close(tokenCh)
		usageCh <- u
		errCh <- err
	}()
	var sb strings.Builder
	for tok := range tokenCh {
		sb.WriteString(tok)
	}
	usage := <-usageCh
	return sb.String(), usage, <-errCh
}

func buildELKTriagePrompt(title string, totalHits int, hits string, truncated bool) string {
	note := ""
	if truncated {
		note = "\n\n⚠️ Dữ liệu hit đã bị cắt bớt do giới hạn kích thước; chỉ phần đầu được phân tích."
	}
	return fmt.Sprintf(`Bạn là chuyên gia Threat Hunting / DFIR. Dưới đây là kết quả thô của một lần săn IOC trên SIEM (Elasticsearch). Tên hunt: %q. Tổng số hit: %d.

NHIỆM VỤ: Phân loại (triage) các hit này thành các CỤM (cluster) có ý nghĩa điều tra, xếp hạng theo mức độ nghi ngờ, để analyst đọc vài lead ưu tiên thay vì lọc tay hàng nghìn hit.

QUY TẮC BẮT BUỘC:
- CHỈ dựa trên dữ liệu hit thực tế bên dưới. KHÔNG bịa thêm IOC/host không có trong dữ liệu.
- Gom các hit liên quan (cùng host, cùng IP, cùng chiến dịch) vào một cụm.
- Gắn cờ false_positive=true cho lưu lượng hợp lệ lặp lại / nhiễu nền rõ ràng.
- severity ∈ {critical, high, medium, low, info}; confidence ∈ {high, medium, low}.
- Ưu tiên dấu hiệu: beaconing/C2, đăng nhập ngoài giờ, brute-force, tiến trình con bất thường, lateral movement.

CHỈ TRẢ VỀ JSON hợp lệ theo schema sau, KHÔNG kèm văn bản nào khác:
{
  "summary": "tổng quan ngắn 1-3 câu về mức độ rủi ro chung",
  "total_clusters": <số nguyên>,
  "clusters": [
    {
      "title": "tên cụm ngắn gọn",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "rationale": "vì sao cụm này đáng điều tra, trích dẫn bằng chứng cụ thể",
      "iocs": ["ioc1", "ioc2"],
      "hosts": ["host1"],
      "hit_count": <số nguyên ước lượng>,
      "false_positive": false,
      "recommended_action": "hành động điều tra/khắc phục tiếp theo"
    }
  ]
}

Sắp xếp clusters theo severity giảm dần.%s

=== DỮ LIỆU HIT (JSON) ===
%s`, title, totalHits, note, hits)
}
