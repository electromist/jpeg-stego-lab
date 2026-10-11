// cmd/jpegzip/main.go
//
// JPEG + ZIP Stack Polyglot Builder
// ══════════════════════════════════
// Produces a single file that is simultaneously a valid JPEG image AND a valid
// ZIP archive. This is the "stack" polyglot layout described in the Corkami /
// Mitra polyglot research and seen in real-world malware campaigns.
//
// ─── WHAT IS A POLYGLOT FILE? ───────────────────────────────────────────────
//
//  A polyglot is a file that is legally valid in two (or more) different formats
//  at the same time. Each format's parser accepts the file because both parsers
//  have complementary "blind spots":
//
//    JPEG parser → reads FORWARD from offset 0 until it finds FF D9 (EOI).
//                  Everything after FF D9 is ignored.
//
//    ZIP  parser → reads BACKWARD from EOF to find the EOCD record signature
//                  (50 4B 05 06), then locates the central directory.
//                  Everything before the first local file header is ignored.
//
//  By placing JPEG data first and ZIP data second, both parsers are satisfied:
//
//    [  JPEG bytes  |  FF D9  |  ZIP local headers  |  ZIP central dir  |  EOCD  ]
//     ←── JPEG parser reads this ──→ stops
//                              ←──────────── ZIP parser reads this ───────────────→
//
// ─── THE OFFSET PATCHING PROBLEM ────────────────────────────────────────────
//
//  A standard ZIP file assumes its own byte 0 is the start of the archive.
//  Local file header offsets stored in the Central Directory (CD) are relative
//  to ZIP's byte 0.
//
//  When we PREPEND a JPEG (say, 853,950 bytes), every local file header has
//  moved forward by 853,950 bytes. Any ZIP tool that seeks to the stored
//  offset will land in the middle of the JPEG data instead.
//
//  We must patch every "relative offset of local file header" field in the
//  Central Directory, and the "offset of start of central directory" field in
//  the EOCD record:
//
//    CD entry  offset field (4 bytes LE) += jpegSize
//    EOCD      CD  start   offset (4 bytes LE) += jpegSize
//
// ─── ZIP FILE FORMAT LAYOUT ─────────────────────────────────────────────────
//
//  Local File Header (per file in the archive):
//    50 4B 03 04  ← signature
//    [26 bytes of metadata]
//    [filename]
//    [extra field]
//    [file data]
//
//  Central Directory Entry (per file, near end):
//    50 4B 01 02  ← signature
//    [26 bytes of metadata]
//    [4 bytes] relative offset of local file header  ← WE PATCH THIS
//    [filename]
//    [extra field]
//    [comment]
//
//  End Of Central Directory (EOCD):
//    50 4B 05 06  ← signature
//    [12 bytes of metadata]
//    [4 bytes] offset of start of central directory  ← WE PATCH THIS
//    [2 bytes] comment length
//    [comment]
//
// ─── TECH STACK ─────────────────────────────────────────────────────────────
//  Language  : Go (standard library only)
//  Packages  : os, flag, encoding/binary, bytes, fmt, log, archive/zip, io
//  Build     : CGO_ENABLED=0 go build -o jpegzip.exe ./cmd/jpegzip

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// ZIP magic signatures (4 bytes each, little-endian in the spec).
const (
	sigLocalFile   = 0x04034B50 // PK\x03\x04 — local file header
	sigCentralDir  = 0x02014B50 // PK\x01\x02 — central directory entry
	sigEOCD        = 0x06054B50 // PK\x05\x06 — end of central directory
)

func main() {
	jpgPath := flag.String("jpg", "",      "Input JPEG carrier file")
	addFile := flag.String("add", "",      "File to pack into the ZIP layer")
	out     := flag.String("out", "poly.jpg", "Output polyglot file")
	flag.Parse()

	if *jpgPath == "" || *addFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// ── 1. Read the JPEG ──────────────────────────────────────────────────
	jpegData, err := os.ReadFile(*jpgPath)
	if err != nil {
		log.Fatalf("[JPEGZIP] Cannot read JPEG: %v", err)
	}
	if len(jpegData) < 2 || jpegData[0] != 0xFF || jpegData[1] != 0xD8 {
		log.Fatal("[JPEGZIP] Input is not a JPEG (missing FF D8 SOI).")
	}

	// Find the EOI marker (FF D9) — the true end of the JPEG image data.
	// Everything we append after this is ignored by image parsers.
	eoiOffset := -1
	for i := len(jpegData) - 2; i >= 0; i-- {
		if jpegData[i] == 0xFF && jpegData[i+1] == 0xD9 {
			eoiOffset = i
			break
		}
	}
	if eoiOffset < 0 {
		log.Fatal("[JPEGZIP] Could not find JPEG EOI marker (FF D9).")
	}
	// Trim any trailing bytes after EOI; the JPEG part ends at eoiOffset+2.
	jpegPart := jpegData[:eoiOffset+2]

	// ── 2. Build the ZIP layer in memory ──────────────────────────────────
	// archive/zip writes a self-contained, well-formed ZIP stream.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	// Add the file to the ZIP archive.
	fileData, err := os.ReadFile(*addFile)
	if err != nil {
		log.Fatalf("[JPEGZIP] Cannot read file to add: %v", err)
	}
	w, err := zw.Create(filepath.Base(*addFile)) // filename inside ZIP
	if err != nil {
		log.Fatalf("[JPEGZIP] zip.Create: %v", err)
	}
	if _, err = w.Write(fileData); err != nil {
		log.Fatalf("[JPEGZIP] zip.Write: %v", err)
	}
	if err = zw.Close(); err != nil { // finalises central dir + EOCD
		log.Fatalf("[JPEGZIP] zip.Close: %v", err)
	}
	zipData := zipBuf.Bytes()

	// ── 3. Patch ZIP offsets to account for the JPEG prefix ──────────────
	//
	// The ZIP layer was built assuming it starts at byte 0. We are going to
	// prepend len(jpegPart) bytes of JPEG, so every absolute offset stored
	// inside the ZIP's central directory needs to be incremented by that amount.
	jpegSize := uint32(len(jpegPart))
	patchZIPOffsets(zipData, jpegSize)

	// ── 4. Concatenate JPEG + ZIP ─────────────────────────────────────────
	result := append(jpegPart, zipData...)
	if err := os.WriteFile(*out, result, 0o644); err != nil {
		log.Fatalf("[JPEGZIP] Cannot write output: %v", err)
	}

	fmt.Printf("[JPEGZIP] JPEG: %d bytes total, EOI at offset %d\n", len(jpegPart), eoiOffset)
	fmt.Printf("[JPEGZIP] Done.\n")
	fmt.Printf("  JPEG part  : %d bytes\n", len(jpegPart))
	fmt.Printf("  ZIP  part  : %d bytes  (contains: %s, %d bytes)\n",
		len(zipData), *addFile, len(fileData))
	fmt.Printf("  Total      : %d bytes -> %s\n", len(result), *out)
	fmt.Printf("\n")
	fmt.Printf("  Named .jpg  -> image viewer opens it  (stops at FF D9 EOI) [OK]\n")
	fmt.Printf("  Named .zip  -> unzip reads from bottom, extracts payload    [OK]\n")
}

// patchZIPOffsets walks the raw ZIP bytes and increments every "local file
// header relative offset" field in Central Directory entries, as well as the
// "offset of start of central directory" field in the EOCD record.
//
// All multi-byte integers in ZIP are little-endian (opposite of JPEG).
func patchZIPOffsets(data []byte, delta uint32) {
	i := 0
	for i < len(data)-4 {
		// Read the 4-byte signature at this position.
		sig := binary.LittleEndian.Uint32(data[i : i+4])

		switch sig {
		case sigLocalFile:
			// Local File Header — 30 bytes fixed + variable filename + extra.
			// We don't need to patch anything here (offsets are in the CD).
			if i+30 > len(data) {
				return
			}
			fnLen    := int(binary.LittleEndian.Uint16(data[i+26 : i+28]))
			extraLen := int(binary.LittleEndian.Uint16(data[i+28 : i+30]))
			i += 30 + fnLen + extraLen
			// Skip over the actual compressed file data.
			// (archive/zip uses data descriptors; we just scan forward for next sig)

		case sigCentralDir:
			// Central Directory Entry — 46 bytes fixed + variable fields.
			// Bytes 42-45 (relative to entry start): local file header offset.
			if i+46 > len(data) {
				return
			}
			// Read current offset, add delta, write back.
			oldOff := binary.LittleEndian.Uint32(data[i+42 : i+46])
			binary.LittleEndian.PutUint32(data[i+42:], oldOff+delta)

			fnLen      := int(binary.LittleEndian.Uint16(data[i+28 : i+30]))
			extraLen   := int(binary.LittleEndian.Uint16(data[i+30 : i+32]))
			commentLen := int(binary.LittleEndian.Uint16(data[i+32 : i+34]))
			i += 46 + fnLen + extraLen + commentLen

		case sigEOCD:
			// End Of Central Directory — 22 bytes fixed + variable comment.
			// Bytes 16-19: offset of start of central directory — patch it.
			if i+22 > len(data) {
				return
			}
			oldOff := binary.LittleEndian.Uint32(data[i+16 : i+20])
			binary.LittleEndian.PutUint32(data[i+16:], oldOff+delta)
			return // EOCD is always the last structure; nothing follows

		default:
			// Unknown byte — advance one byte and keep scanning.
			// This handles the compressed file data between local headers.
			i++
		}
	}
}

// End of file.
