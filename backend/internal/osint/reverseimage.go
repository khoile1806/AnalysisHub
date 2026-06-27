package osint

import (
	"net/url"

	"github.com/forensichub/backend/internal/models"
)

// reverseimage.go — reverse image search. Finding the same photo/avatar
// elsewhere on the web is a powerful de-anonymisation step (it links a handle to
// other profiles or to the original source of a picture). The result pages of
// the major engines are JS-walled and not freely scrapable from a server, so we
// hand the analyst exact deep-links that submit the image URL to each engine -
// the honest, free approach (same pattern as the assisted search-link collector).

// ReverseImageEngine is one reverse-image lookup link.
type ReverseImageEngine struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ReverseImageLinks builds reverse-image-search deep-links for a public image
// URL across the engines that accept a URL parameter (the image is submitted for
// the analyst automatically).
func ReverseImageLinks(imageURL string) []ReverseImageEngine {
	if imageURL == "" {
		return nil
	}
	e := url.QueryEscape(imageURL)
	return []ReverseImageEngine{
		{"Google Lens", "https://lens.google.com/uploadbyurl?url=" + e},
		{"Yandex Images", "https://yandex.com/images/search?rpt=imageview&url=" + e},
		{"Bing Visual Search", "https://www.bing.com/images/search?q=imgurl:" + e + "&view=detailv2&iss=sbi"},
		{"TinEye", "https://tineye.com/search?url=" + e},
	}
}

// FaceSearchEngines are face-recognition search services. They are the strongest
// way to put a real name to an avatar, but their result pages require uploading
// the image in their own UI (no URL parameter), so these are landing pages the
// analyst opens and drops the picture into.
func FaceSearchEngines() []ReverseImageEngine {
	return []ReverseImageEngine{
		{"PimEyes (face search — upload there)", "https://pimeyes.com/en"},
		{"FaceCheck.id (face search — upload there)", "https://facecheck.id/"},
		{"Lenso.ai (AI image/face — upload there)", "https://lenso.ai/en"},
	}
}

// avatarReverseFindings emits reverse-image lookups for a known avatar URL, so an
// analyst can pivot from the picture to wherever else it appears.
func avatarReverseFindings(source, avatarURL string) []models.OsintFinding {
	engines := ReverseImageLinks(avatarURL)
	out := make([]models.OsintFinding, 0, len(engines))
	for _, en := range engines {
		f := newFinding(source, "social", "Reverse image search ("+en.Name+")", en.URL)
		f.Severity = "low"
		f.SourceURL = en.URL
		f.VerifyNote = "open to find where this avatar appears elsewhere (de-anonymisation)"
		out = append(out, f)
	}
	return out
}
