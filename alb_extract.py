#!/usr/bin/env python3
"""
alb_extract.py — Dreamcast WinCE ALB → BMP extractor

Reverse-engineered from the game's decoder:
- ALB file consists of packets. Each packet starts with an 8-byte header:
    [h0,h1,h2,h3,h4,h5,h6,h7]
    comp_len  = uint16le(h4,h5)  # number of bytes in the compressed stream
    dict_mode = h6               # 0 = literal 256 pairs, nonzero = RLE-mode
    rle_marker= h7               # used when dict_mode != 0
  Followed by a 256-entry dictionary of pairs (x,y), each a byte:
    - if dict_mode == 0: read 512 bytes literally (256 (x,y) pairs)
    - else: read pairs; if (a == rle_marker and b != 0) replicate b entries as (index, 0);
            else store (a,b). Continue until 256 entries are filled.
  Then read 'comp_len' bytes as the compressed code stream and expand:
    For each input byte b (or items popped from a local stack):
      (x,y) = dict[b]
      if x == b: emit b
      else: push y, then x (so x is expanded first)
- Concatenate outputs from all packets. In this title, the resulting bytestream
  is a standard Windows BMP file (16bpp, BI_RGB with 40-byte BITMAPINFOHEADER).
  The engine then copies from offset 0x36 into a 512×512 texture page.

Usage:
  python alb_extract.py <file_or_glob> [<more> ...] [-o OUTDIR] [--raw-too] [--strict]

Examples:
  python alb_extract.py GRPDATA/*.ALB -o out/
  python alb_extract.py RULETEXT.ALB SYSTEM1.ALB
"""

import argparse, os, sys, glob

def decode_alb_to_bytes(alb_bytes):
    data = memoryview(alb_bytes)
    pos = 0
    n = len(data)

    # Optional signature "ALB1.10\0"
    if n >= 8 and bytes(data[:8]) == b"ALB1.10\x00":
        pos = 8

    out = bytearray()
    packets = 0
    while pos + 8 <= n:
        # Read header
        h0,h1,h2,h3,h4,h5,h6,h7 = data[pos:pos+8].tolist()
        pos += 8
        comp_len  = h4 | (h5 << 8)
        dict_mode = h6
        rle_marker= h7

        # Build dictionary of 256 pairs (x,y)
        dict_bytes = bytearray(512)
        di = 0
        if dict_mode == 0:
            if pos + 512 > n: break
            dict_bytes[:] = data[pos:pos+512].tobytes()
            pos += 512
        else:
            while di < 256 and pos + 2 <= n:
                a = data[pos]; b = data[pos+1]; pos += 2
                if a == rle_marker and b != 0:
                    # replicate 'b' entries as (index, 0)
                    for _ in range(b):
                        if di >= 256: break
                        dict_bytes[di*2 + 0] = di & 0xFF
                        dict_bytes[di*2 + 1] = 0
                        di += 1
                else:
                    dict_bytes[di*2 + 0] = a
                    dict_bytes[di*2 + 1] = b
                    di += 1
            # If stream ended early, stop
            if di < 256:
                break

        # Decompress 'comp_len' bytes
        if pos + comp_len > n: break
        src = data[pos:pos+comp_len]
        pos += comp_len

        view = memoryview(dict_bytes)
        stack = []
        si = 0
        while si < comp_len or stack:
            if not stack:
                if si >= comp_len: break
                b = src[si]; si += 1
            else:
                b = stack.pop()
            x = view[b*2 + 0]
            y = view[b*2 + 1]
            if x == b:
                out.append(b)
            else:
                # Expand x first (push y then x)
                stack.append(y)
                stack.append(x)

        packets += 1

    return bytes(out), packets

def is_bmp(b):
    if len(b) < 54: return False
    if b[:2] != b"BM": return False
    # BITMAPFILEHEADER[10:14] is bfOffBits; [14:18] should be 40 (0x28) for BITMAPINFOHEADER
    if b[14:18] != b"\x28\x00\x00\x00": return False
    return True

def run(paths, outdir, raw_too=False, strict=False):
    os.makedirs(outdir, exist_ok=True)
    results = []
    files = []
    for p in paths:
        if any(ch in p for ch in "*?[]"):
            files.extend(glob.glob(p))
        else:
            files.append(p)
    if not files:
        print("No input files.", file=sys.stderr); return 2
    files = sorted(set(files))

    for src in files:
        name = os.path.basename(src)
        try:
            alb = open(src, "rb").read()
        except Exception as e:
            print(f"[ERR] {name}: {e}", file=sys.stderr); continue

        if strict and not (len(alb) >= 8 and alb[:8] == b'ALB1.10\x00'):
            print(f"[SKIP] {name}: missing ALB1.10 signature", file=sys.stderr); continue

        out_bytes, packets = decode_alb_to_bytes(alb)
        # Default outputs
        base = os.path.splitext(name)[0].upper()
        wrote = []

        if is_bmp(out_bytes):
            bmp_path = os.path.join(outdir, f"{base}.BMP")
            with open(bmp_path, "wb") as f:
                f.write(out_bytes)
            wrote.append(bmp_path)
            print(f"[OK]  {name} → {os.path.basename(bmp_path)}  (packets={packets})")
            if raw_too:
                raw_path = os.path.join(outdir, f"{name}.raw")
                with open(raw_path, "wb") as f:
                    f.write(out_bytes)
                wrote.append(raw_path)
        else:
            # Not a BMP — still save raw
            raw_path = os.path.join(outdir, f"{name}.bin")
            with open(raw_path, "wb") as f:
                f.write(out_bytes)
            wrote.append(raw_path)
            print(f"[RAW] {name} → {os.path.basename(raw_path)}  (packets={packets}, not BM)")

        results.append((src, wrote, packets))

    # Simple summary
    ok = sum(1 for _,w,_ in results if any(p.lower().endswith(".bmp") for p in w))
    bad= len(results) - ok
    print(f"\nDone. {ok} BMP(s), {bad} raw bytestream(s) out of {len(results)} ALB(s).")
    return 0

def main():
    ap = argparse.ArgumentParser(description="Decode Dreamcast WinCE ALB files into BMPs.")
    ap.add_argument("inputs", nargs="+", help="ALB files or globs (e.g. GRPDATA/*.ALB)")
    ap.add_argument("-o","--outdir", default="alb_out", help="Output directory (default: alb_out)")
    ap.add_argument("--raw-too", action="store_true", help="Also save raw bytestream even if BMP was detected")
    ap.add_argument("--strict", action="store_true", help="Require ALB1.10 signature")
    args = ap.parse_args()
    try:
        return run(args.inputs, args.outdir, raw_too=args.raw_too, strict=args.strict)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
