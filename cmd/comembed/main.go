// cmd/comembed/main.go
//
// JPEG COM Marker Embedder
// ════════════════════════
// Injects an arbitrary string (e.g. a URL or script) into a JPEG file's
// Comment (COM) marker segment without altering any pixel data.
//
// ─── JPEG FILE FORMAT PRIMER ────────────────────────────────────────────────
//
//  A JPEG file is a stream of "markers". Every marker is 2 bytes starting
//  with 0xFF followed by a 1-byte marker code:
//
//     FF D8          ← SOI  (Start Of Image) — must be the first 2 bytes
//     FF E0 [len]    ← APP0 / JFIF header
//     FF E1 [len]    ← APP1 / Exif metadata
//     FF DB [len]    ← DQT  (quantization table)
//     FF C0 [len]    ← SOF0 (baseline DCT frame header)
//     FF C4 [len]    ← DHT  (Huffman table)
//     FF DA [len]    ← SOS  (Start Of Scan — compressed image data follows)
//     FF D9          ← EOI  (End Of Image) — last 2 bytes
//
//  Segments with a length field have this layout:
//
//     [FF] [marker] [len_hi] [len_lo] [data ...]
//                   └──────────────┘
//                   Big-endian uint16.
//                   INCLUDES the 2 length bytes themselves.
//                   Does NOT include the FF + marker prefix.
//
//  So data bytes span: offset+4 .. offset+4+(segLen-2)-1
//
// ─── COM MARKER (0xFF 0xFE) ─────────────────────────────────────────────────
//
//  COM is defined in ISO/IEC 10918-1 §B.2.4.5 as an ancillary segment for
//  human-readable comments. Image decoders MUST skip it if they don't need it.
//  This makes it a perfect steganographic carrier:
//
//     Image viewer → sees FF D8 SOI → renders pixels → skips FF FE → done.
//     patch.exe    → reads raw bytes → walks markers → finds FF FE → reads string.
//
//  No pixels are changed. The image looks 100% identical before and after.
//
// ─── EMBEDDING LAYOUT ───────────────────────────────────────────────────────
//
//  Output file byte layout:
//
//     [0]      FF D8           ← original SOI (preserved)
//     [2]      FF FE           ← COM marker
//     [4..5]   uint16 BE       ← len(payload)+2  (the +2 counts itself)
//     [6..N]   payload bytes   ← the string we injected (e.g. the URL)
//     [N+1..] rest of original JPEG starting from its byte 2
//
//  We insert the COM segment right after SOI so it is the first thing any
//  parser encounters after the mandatory magic bytes. This maximises
//  compatibility — nothing shifts the Exif/JFIF headers' internal offsets.
//
// ─── TECH STACK ─────────────────────────────────────────────────────────────
//  Language  : Go (standard library only)
//  Packages  : os, flag, encoding/binary, fmt, log
//  Build     : CGO_ENABLED=0 go build -o comembed.exe ./cmd/comembed

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	// ── CLI flags ──────────────────────────────────────────────────────────
	jpgIn  := flag.String("jpg",    "",           "Input JPEG carrier file")
	script := flag.String("script", "",           "String to hide in the COM marker")
	out    := flag.String("out",    "output.jpg", "Output JPEG file path")
	flag.Parse()

	if *jpgIn == "" || *script == "" {
		flag.Usage()
		os.Exit(1)
	}

	// ── 1. Read the carrier JPEG ───────────────────────────────────────────
	data, err := os.ReadFile(*jpgIn)
	if err != nil {
		log.Fatalf("[COMEMBED] Cannot read JPEG: %v", err)
	}

	// Verify the JPEG magic bytes (SOI = FF D8).
	// If these aren't the first 2 bytes, no image viewer — or our launcher —
	// will recognise this as a JPEG.
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		log.Fatal("[COMEMBED] File does not start with JPEG SOI (FF D8).")
	}

	// ── 2. Build the COM segment ───────────────────────────────────────────
	scriptBytes := []byte(*script)

	// The COM length field is a big-endian uint16 that counts itself (2 bytes)
	// plus the payload. Maximum possible payload = 65535 - 2 = 65533 bytes.
	if len(scriptBytes)+2 > 65535 {
		log.Fatalf("[COMEMBED] Script too large for one COM marker (max 65533 bytes).")
	}
	payloadLen := uint16(len(scriptBytes) + 2)

	// Allocate: FF + FE (2 bytes) + length field (2 bytes) + payload.
	com := make([]byte, 4+len(scriptBytes))
	com[0] = 0xFF          // marker prefix — always FF
	com[1] = 0xFE          // COM marker code
	binary.BigEndian.PutUint16(com[2:], payloadLen) // length field
	copy(com[4:], scriptBytes)                       // payload

	// ── 3. Assemble the output file ────────────────────────────────────────
	// Layout: SOI (2 bytes) | COM segment | original JPEG from byte 2 onwards.
	//
	// We use append with a capacity hint to avoid repeated allocations.
	// data[:2]  = FF D8
	// com       = FF FE [len] [payload]
	// data[2:]  = rest of original JPEG (APP0/APP1/... through EOI)
	result := make([]byte, 0, 2+len(com)+len(data)-2)
	result = append(result, data[:2]...) // SOI
	result = append(result, com...)      // COM segment we just built
	result = append(result, data[2:]...) // rest of the original JPEG

	// ── 4. Write output ────────────────────────────────────────────────────
	if err := os.WriteFile(*out, result, 0o644); err != nil {
		log.Fatalf("[COMEMBED] Cannot write output: %v", err)
	}

	fmt.Printf("[COMEMBED] Done.\n")
	fmt.Printf("  Input   : %s (%d bytes)\n", *jpgIn, len(data))
	fmt.Printf("  Payload : %d bytes at offset 6 inside COM marker\n", len(scriptBytes))
	fmt.Printf("  Output  : %s (%d bytes)\n", *out, len(result))
	fmt.Printf("  Byte[0..1] = FF D8  (SOI — image viewers open normally)\n")
	fmt.Printf("  Byte[2..3] = FF FE  (COM — skipped by all image parsers)\n")
}
