package handlers

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// maxPageLimit caps how many rows a single paginated request may return, so a
// caller can't ask for an unbounded page.
const maxPageLimit = 500

// writeTotalCount counts the rows matching q (conditions only — call this BEFORE
// adding Preload/Order/Limit) and exposes the total via the X-Total-Count header
// so a paginated client can compute the number of pages. It is best-effort: a
// count error simply omits the header.
//
// IMPORTANT: pass a conditions-only query built fresh from db (e.g.
// db.Model(&X{}).Where(...)). Do not reuse the same *gorm.DB instance for the
// subsequent Find — build a second chain — to avoid GORM carrying the count
// SELECT into the data query.
func writeTotalCount(c *gin.Context, q *gorm.DB) {
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return
	}
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))
	c.Header("Access-Control-Expose-Headers", "X-Total-Count")
}

// applyLimitOffset reads the optional ?limit and ?offset query parameters and
// applies them to q. When limit is absent or <= 0 the query is returned
// UNCHANGED, so existing clients that don't paginate keep receiving the full
// result set — this keeps the change fully backward compatible. limit is capped
// at maxPageLimit.
func applyLimitOffset(c *gin.Context, q *gorm.DB) *gorm.DB {
	limit := 0
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit <= 0 {
		return q
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	offset := 0
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return q.Limit(limit).Offset(offset)
}
