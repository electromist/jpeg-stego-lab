// cmd/embed/main.go
//
// LSB (Least Significant Bit) Steganography Tool
// ═══════════════════════════════════════════════
// Hides a binary payload inside a carrier image by modifying only the
// LOWEST BIT of each carrier byte. The visual change per pixel is at most 1
// intensity step out of 255 — completely invisible to the human eye.
//
// ─── LSB TECHNIQUE ──────────────────────────────────────────────────────────
//
//  Every byte in the carrier file contributes 1 bit of hidden data.
//  We encode bits MSB-first (most-significant bit first), 1 bit per byte:
//
//    carrier byte 0xAB = 1010 1011
//                                └── LSB: bit we overwrite with our data
//
//  To write bit value B into carrier byte C:
//    C = (C & 0xFE) | B
//        └── clears bit 0, then ORs in B (0 or 1)
//
//  To read bit B back from carrier byte C:
//    B = C & 1
//
// ─── WIRE FORMAT ────────────────────────────────────────────────────────────
//
//  Starting at byte offset `skip` of the carrier (skip=2 for JPEG to preserve
//  the FF D8 SOI magic bytes), we write:
//
//    bits  0 –  31  : 32-bit big-endian unsigned int = payload length in bytes
//    bits 32 –  …   : payload bytes, 8 bits each (= 8 carrier bytes per payload byte)
//
//  Minimum carrier size (usable bytes after skip):
//    32 + payloadLen * 8
//
//  Example: 12-byte payload needs at least 32 + 96 = 128 carrier bytes.
//
// ─── WHY SKIP=2 FOR JPEG ────────────────────────────────────────────────────
//
//  JPEG parsers check that bytes 0-1 are FF D8. If we embed starting at byte
//  0, bit 0 of the length header is written into byte 0. Since the 32-bit
//  length 0x0000000C has its MSB = 0, byte 0 would become FE (FF with bit0
//  cleared) → invalid SOI → image viewer rejects the file.
//
//  By starting at byte 2 we leave FF D8 untouched. The next bytes (FF E0 APP0
//  or FF E1 APP1) have their LSBs changed, which may corrupt JPEG header
//  markers. For purely raw carrier files (BMP, raw bytes) use skip=0.
//
// ─── DIFFERENCE FROM COM MARKER METHOD ──────────────────────────────────────
//
//  COM marker embedding (comembed.exe):
//   + Zero visual change            + Payload is plainly readable in the file
//   + Arbitrary string, no bit math - Visible in any hex editor / EXIF reader
//
//  LSB embedding (this tool):
//   + Payload is distributed across ALL bytes — harder to spot visually
//   + Works for binary payloads (shellcode, etc.), not just strings
//   - Corrupts JPEG header markers if skip value is wrong
//   - Requires a matching extractor that knows skip and length-header format
//
// ─── TECH STACK ─────────────────────────────────────────────────────────────
//  Language  : Go (standard library only)
//  Packages  : os, flag, encoding/binary, fmt, log
//  Build     : CGO_ENABLED=0 go build -o embed.exe ./cmd/embed

// Wire format written into carrier LSBs (MSB-first within each bit group):
//   bits  0 –  31              : 32-bit big-endian payload length (bytes)
//   bits 32 –  32+payloadLen*8 : payload bytes, 1 bit per carrier byte
//
// -skip N (default 2): number of leading carrier bytes to leave untouched.
// Set to 2 for JPEG so the SOI magic FF D8 is never modified.
// The extractor must use the same skip value.

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	carrier := flag.String("carrier", "", "Path to the carrier image (source, not overwritten)")
	payload := flag.String("payload", "", "Path to the binary payload to embed")
	out     := flag.String("out", "stego.jpg", "Output path for the stego file")
	skip    := flag.Int("skip", 2, "Leading carrier bytes to leave untouched (2 = preserve JPEG FF D8 SOI)")
	flag.Parse()

	if *carrier == "" || *payload == "" {
		flag.Usage()
		os.Exit(1)
	}

	carrierData, err := os.ReadFile(*carrier)
	if err != nil {
		log.Fatalf("[EMBED] Cannot read carrier: %v", err)
	}

	payloadData, err := os.ReadFile(*payload)
	if err != nil {
		log.Fatalf("[EMBED] Cannot read payload: %v", err)
	}

	// ── Capacity check ────────────────────────────────────────────────────
	// Each carrier byte holds exactly 1 bit. We need:
	//   32 bits for the length header + payloadLen*8 bits for the data.
	// The first *skip bytes are reserved (not used for embedding).
	bitsNeeded := 32 + len(payloadData)*8
	available  := len(carrierData) - *skip
	if available < bitsNeeded {
		log.Fatalf("[EMBED] Carrier too small: need %d usable bytes (after skip=%d), have %d.",
			bitsNeeded, *skip, available)
	}

	// Work on a copy — never mutate the original file in place.
	stego := make([]byte, len(carrierData))
	copy(stego, carrierData)

	// ── writeBits ─────────────────────────────────────────────────────────
	// Writes `n` bits of `val` (MSB first) into carrier bytes starting at
	// absolute byte offset (*skip + off).
	//
	// For example, writeBits(0, 0x0000000C, 32) writes the 32-bit value 12
	// into carrier bytes [skip..skip+31], 1 bit per byte.
	writeBits := func(off int, val uint64, n int) {
		base := *skip + off
		for i := 0; i < n; i++ {
			// Extract bit (n-1-i) of val (MSB first).
			bit := byte((val >> uint(n-1-i)) & 1)
			// Write into the LSB of the carrier byte; preserve all other bits.
			stego[base+i] = (stego[base+i] & 0xFE) | bit
		}
	}

	// ── Embed 32-bit length header ────────────────────────────────────────
	// Store payload length as a 4-byte big-endian integer split across 32
	// carrier bytes (1 bit per byte).
	var lenHeader [4]byte
	binary.BigEndian.PutUint32(lenHeader[:], uint32(len(payloadData)))
	var lenVal uint64
	for _, b := range lenHeader {
		lenVal = (lenVal << 8) | uint64(b)
	}
	writeBits(0, lenVal, 32) // bits 0-31

	// ── Embed payload bytes ───────────────────────────────────────────────
	// Each payload byte occupies 8 consecutive carrier bytes (1 bit each).
	for i, b := range payloadData {
		writeBits(32+i*8, uint64(b), 8) // bits 32, 40, 48, …
	}

	// ── Write output ──────────────────────────────────────────────────────
	if err := os.WriteFile(*out, stego, 0o644); err != nil {
		log.Fatalf("[EMBED] Cannot write output: %v", err)
	}

	fmt.Printf("[EMBED] Done.\n")
	fmt.Printf("  Carrier  : %s (%d bytes)\n", *carrier, len(carrierData))
	fmt.Printf("  Payload  : %s (%d bytes)\n", *payload, len(payloadData))
	fmt.Printf("  Output   : %s (%d bytes)\n", *out, len(stego))
	fmt.Printf("  Bits used: %d / %d (%.2f%% capacity)\n",
		bitsNeeded, available,
		float64(bitsNeeded)/float64(available)*100)
}
