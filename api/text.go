package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gobuffalo/packr"
)

// Text contains static overridable texts used in explorer
var Text struct {
	BlockbookAbout, TOSLink string
}

func init() {
	box := packr.NewBox("../build/text")
	if about, err := box.MustString("about"); err == nil {
		Text.BlockbookAbout = strings.TrimSpace(about)
	} else {
		Text.BlockbookAbout = "Blockbook - blockchain indexer for Trezor wallet https://trezor.io/. Do not use for any other purpose."
	}

	tosLink, err := box.MustString("tos_link")
	if err == nil {
		tosLink = strings.TrimSpace(tosLink)
	} else {
		tosLink = "https://wallet.trezor.io/tos.pdf"
	}
	if _, err := url.ParseRequestURI(tosLink); err == nil {
		Text.TOSLink = tosLink
	} else {
		panic(fmt.Sprint("tos_link is not valid URL:", err.Error()))
	}
}
