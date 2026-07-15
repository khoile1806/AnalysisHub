package handlers

import "github.com/gin-gonic/gin"

// setInlineSafeHeaders hardens a response that serves user/agent-supplied content
// inline in the browser against stored XSS:
//
//   - X-Content-Type-Options: nosniff stops the browser MIME-sniffing a text or
//     binary blob into executable HTML.
//   - Content-Security-Policy: sandbox (allow-same-origin) disables scripts,
//     forms and plugins so an uploaded .html/.svg cannot run JavaScript or reach
//     the app's cookies/API, while KEEPING the document's real origin so our own
//     Report Viewer iframe can still embed and display it. (Bare `sandbox` gives
//     the response an opaque origin, which browsers refuse to frame.)
//
// Use on any endpoint that serves stored evidence/artifacts or generated report
// HTML inline. Endpoints that force a download (Content-Disposition: attachment)
// do not need it.
func setInlineSafeHeaders(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "sandbox allow-same-origin")
}
