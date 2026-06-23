//go:build windows

package main

import (
	"github.com/jchv/go-webview2"
)

// openNativeWindow opens the offline-agent UI in a REAL native Windows
// application window (its own title bar, icon and taskbar entry) using the Edge
// WebView2 control - not a browser tab. It blocks until the window is closed and
// returns true. If the WebView2 runtime is unavailable it returns false so the
// caller can fall back to lorca / the system browser.
func openNativeWindow(url, title string) bool {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  title,
			Width:  1180,
			Height: 800,
			Center: true,
		},
	})
	if w == nil {
		return false // WebView2 runtime not installed - fall back
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run() // blocks until the window is closed
	return true
}
