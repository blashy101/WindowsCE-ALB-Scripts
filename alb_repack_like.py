#!/usr/bin/env python3
# Repack a BMP into ALB using an ORIGINAL.ALB as a template:
# - Matches packetization (4KB decoded per packet) by using the same window size
# - Reuses each packet's RLE marker byte from the original (when possible)
# - Writes proper 'PH' packet headers with dict_len/comp_len
# - Preserves any prefix before the first packet and any tail after the last packet
# - Optionally normalizes the BMP to 16bpp RGB555 (BI_RGB) and/or copies the original BMP header
#
# Usage:
#   python -u alb_repack_like.py ORIGINAL.ALB NEW.bmp -o OUT.ALB [--normalize555] [--copy-header]
#
# Requires: Python 3.8+

import argparse, os
from collections import Counter

def parse_alb_template(path):
    """Robust packet parser: find the first 'PH' anywhere, then iterate packets.
    Preserves prefix/tail so we can write them back exactly for variants that
    don't start with 'ALB1.10\\x00' or that carry padding."""
    b = open(path, "rb").read()
    off0 = b.find(b"PH")
    if off0 < 0:
        raise ValueError("Original ALB missing signature: no 'PH' anywhere in file")

    pkts = []
    p = off0
    while p + 8 <= len(b) and b[p:p+2] == b"PH":
        dict_len = int.from_bytes(b[p+2:p+4], "little")
        comp_len = int.from_bytes(b[p+4:p+6], "little")
        dict_mode = b[p+6]
        marker = b[p+7]

        # basic sanity
        end = p + 8 + dict_len + comp_len
        if dict_len < 0 or comp_len < 0 or end > len(b):
            raise ValueError(f"Corrupt packet at 0x{p:X}: dict_len={dict_len}, comp_len={comp_len}")

        pkts.append({
            "offset": p,
            "dict_len": dict_len,
            "comp_len": comp_len,
            "dict_mode": dict_mode,
            "marker": marker,
        })

        p = end
        # Allow zero padding between packets
        while p < len(b) and b[p] == 0:
            p += 1

    return {
        "prefix": b[:off0],
        "first_pkt_off": off0,
        "packets": pkts,
        "end_off": p,
        "tail": b[p:],
    }

# ---- ALB decode helpers (for header copy & verify) ----

def _decode_first_n_bytes(alb_bytes, start_off, want_n):
    """Decode ALB stream starting at start_off, returning first want_n bytes (or less if shorter)."""
    data = memoryview(alb_bytes)[start_off:]
    pos = 0
    out = bytearray()
    while pos + 8 <= len(data) and len(out) < want_n:
        h0,h1,h2,h3,h4,h5,h6,h7 = data[pos:pos+8].tolist(); pos += 8
        dlen = h2 | (h3<<8); clen = h4 | (h5<<8); mode=h6; m=h7

        # dictionary
        di=0; dict_bytes = bytearray(512)
        if mode==0:
            dict_bytes[:] = data[pos:pos+512].tobytes(); pos += 512
        else:
            start = pos
            while di < 256:
                a = data[pos]; b2 = data[pos+1]; pos += 2
                if a == m and b2 != 0:
                    for _ in range(b2):
                        if di >= 256: break
                        dict_bytes[di*2] = di & 0xFF; dict_bytes[di*2+1] = 0; di += 1
                else:
                    dict_bytes[di*2] = a; dict_bytes[di*2+1] = b2; di += 1

        code = data[pos:pos+clen]; pos += clen

        # expand with small stack
        view = memoryview(dict_bytes); stack=[]; si=0
        while si < clen or stack:
            if not stack:
                if si >= clen: break
                bval = code[si]; si += 1
            else:
                bval = stack.pop()
            x = view[bval*2]; y = view[bval*2+1]
            if x == bval:
                out.append(bval)
                if len(out) >= want_n: break
            else:
                stack.append(int(y)); stack.append(int(x))
    return bytes(out)

def verify_decode(payload, want):
    """Exact verifier for our packed payload (sequence of PH packets)."""
    data = memoryview(payload)
    pos = 0; out = bytearray()
    while pos + 8 <= len(data):
        h0,h1,h2,h3,h4,h5,h6,h7 = data[pos:pos+8].tolist(); pos += 8
        dlen = h2 | (h3<<8); clen = h4 | (h5<<8); mode=h6; m=h7
        if mode not in (0,1): return False
        # dict
        di = 0; dict_bytes = bytearray(512)
        if mode==0:
            if pos + 512 > len(data): return False
            dict_bytes[:] = data[pos:pos+512].tobytes(); pos += 512
        else:
            start = pos
            while di < 256:
                if pos + 2 > len(data): return False
                a = data[pos]; b = data[pos+1]; pos += 2
                if a == m and b != 0:
                    for _ in range(b):
                        if di >= 256: break
                        dict_bytes[di*2]   = di & 0xFF
                        dict_bytes[di*2+1] = 0
                        di += 1
                else:
                    dict_bytes[di*2]   = a
                    dict_bytes[di*2+1] = b
                    di += 1
        if pos + clen > len(data): return False
        code = data[pos:pos+clen]; pos += clen

        view = memoryview(dict_bytes); stack=[]; si=0
        while si < clen or stack:
            if not stack:
                if si >= clen: break
                b = code[si]; si += 1
            else:
                b = stack.pop()
            x = view[b*2]; y = view[b*2+1]
            if x == b: out.append(b)
            else: stack.append(int(y)); stack.append(int(x))
    return bytes(out) == want

# ---- BPE compressor (safe IDs) + packet writer ----

def greedy_bpe_safe(tokens, max_rules=220, forbidden_ids=None):
    tokens = list(tokens)
    rules = {}
    if forbidden_ids is None: forbidden_ids = set()

    def avail_ids():
        return [i for i in range(256) if (i not in forbidden_ids) and (i not in rules)]

    def replace_all(seq, a, b, S):
        out = []; i = 0; L = len(seq); rep = 0
        while i < L-1:
            if seq[i]==a and seq[i+1]==b: out.append(S); i+=2; rep+=1
            else: out.append(seq[i]); i+=1
        if i==L-1: out.append(seq[-1])
        return out, rep

    for _ in range(max_rules):
        from collections import Counter
        pairs = Counter(zip(tokens, tokens[1:]))
        if not pairs: break
        (x,y), cnt = pairs.most_common(1)[0]
        if cnt < 2: break
        avail = avail_ids()
        if not avail: break
        S = avail[0]
        tokens2, rep = replace_all(tokens, x, y, S)
        if rep <= 1: break
        tokens = tokens2
        rules[S] = (x, y)
    return tokens, rules

def choose_marker(rules, forced=None):
    used_x = {x for (x,_) in rules.values()}
    if forced is not None and forced not in used_x:
        return forced
    for m in [3,1,2,4,5,6,7,8,9,10]:
        if m not in used_x: return m
    for m in range(11,256):
        if m not in used_x: return m
    return 0xFF

def encode_dict_rle(rules, marker):
    stream = bytearray(); i = 0
    while i < 256:
        if i in rules:
            x,y = rules[i]
            if x == marker and y != 0:
                raise ValueError("marker collision")
            stream.append(x & 0xFF); stream.append(y & 0xFF)
            i += 1
        else:
            run = 0
            while i < 256 and (i not in rules) and run < 255:
                run += 1; i += 1
            stream.append(marker & 0xFF); stream.append(run & 0xFF)
    return bytes(stream)

def encode_packet(tokens, rules, forced_marker=None):
    code = bytes(tokens)
    marker = choose_marker(rules, forced=forced_marker)
    dict_stream = encode_dict_rle(rules, marker)
    dlen = len(dict_stream)
    # mode=1 (RLE dict). Some original packets use mode=0, but we can always use 1 for new packets.
    header = bytes([0x50,0x48, dlen & 0xFF, (dlen>>8)&0xFF, len(code)&0xFF, (len(code)>>8)&0xFF, 1, marker])
    return header + dict_stream + code

# ---- BMP helpers ----

def read_bmp(path):
    b = open(path, "rb").read()
    if b[:2] != b"BM":
        raise ValueError("Not a BMP")
    dib = int.from_bytes(b[14:18], "little")
    if dib != 40:
        raise ValueError("Only BITMAPINFOHEADER BMPs (40-byte) supported")
    width  = int.from_bytes(b[18:22], "little", signed=True)
    height = int.from_bytes(b[22:26], "little", signed=True)
    planes = int.from_bytes(b[26:28], "little")
    bpp    = int.from_bytes(b[28:30], "little")
    comp   = int.from_bytes(b[30:34], "little")  # 0 = BI_RGB
    off    = int.from_bytes(b[10:14], "little")
    return {
        "bytes": b, "off": off, "width": width, "height": height, "bpp": bpp, "comp": comp
    }

def convert_to_rgb555(bmp):
    b = bmp["bytes"]
    w, h, off = bmp["width"], bmp["height"], bmp["off"]
    bpp = bmp["bpp"]; comp = bmp["comp"]
    if bpp == 16 and comp == 0:
        return b  # already 16bpp BI_RGB
    # Accept 24/32 bpp and convert
    if bpp not in (24, 32):
        raise ValueError(f"Unsupported source bpp={bpp}; please provide 16/24/32-bpp BMP")
    # Build new header (keep same width/height, BI_RGB, 16bpp)
    row_in = ((w * (bpp//8) + 3) // 4) * 4
    row_out = ((w * 2 + 3) // 4) * 4
    pixel_out = bytearray(row_out * abs(h))
    # BMP bottom-up if height>0
    bottom_up = h > 0
    for row in range(abs(h)):
        src_y = row if not bottom_up else row
        dst_y = row
        src_off = off + src_y * row_in
        dst_off = dst_y * row_out
        for x in range(w):
            if bpp == 24:
                B = b[src_off + x*3 + 0]
                G = b[src_off + x*3 + 1]
                R = b[src_off + x*3 + 2]
            else:  # 32bpp BGRA
                B = b[src_off + x*4 + 0]
                G = b[src_off + x*4 + 1]
                R = b[src_off + x*4 + 2]
            R5 = (R >> 3) & 0x1F
            G5 = (G >> 3) & 0x1F
            B5 = (B >> 3) & 0x1F
            px = (R5 << 10) | (G5 << 5) | (B5 << 0)  # RGB555
            pixel_out[dst_off + x*2 + 0] = px & 0xFF
            pixel_out[dst_off + x*2 + 1] = (px >> 8) & 0xFF
        # pad already inherent in row_out calc
    # Build BMP file with 40-byte DIB
    fsize = 14 + 40 + len(pixel_out)
    hdr = bytearray(b[:14+40])  # copy header+info and then patch
    hdr[2:6]  = fsize.to_bytes(4, "little")
    hdr[10:14]= (14+40).to_bytes(4, "little")
    hdr[14:18]= (40).to_bytes(4, "little")
    hdr[18:22]= int(w).to_bytes(4, "little", signed=True)
    hdr[22:26]= int(h).to_bytes(4, "little", signed=True)
    hdr[26:28]= (1).to_bytes(2, "little")       # planes
    hdr[28:30]= (16).to_bytes(2, "little")      # bpp
    hdr[30:34]= (0).to_bytes(4, "little")       # BI_RGB
    hdr[34:38]= (0).to_bytes(4, "little")       # sizeImage (can be 0 for BI_RGB)
    return bytes(hdr) + bytes(pixel_out)

def splice_pixels_with_header(src_bmp_bytes, header_from_other):
    # Use 54-byte header from 'other', keep pixel data from 'src'
    if header_from_other[:2] != b"BM" or src_bmp_bytes[:2] != b"BM":
        raise ValueError("BMP headers missing 'BM'")
    return header_from_other[:54] + src_bmp_bytes[54:]

# ---- Main repack ----

def repack_like(orig_alb, bmp_path, out_alb, normalize555=False, copy_header=False):
    template = parse_alb_template(orig_alb)
    bmp = read_bmp(bmp_path)
    src = bmp["bytes"]
    if normalize555:
        src = convert_to_rgb555(bmp)

    # Copy original BMP's 54-byte header (from decoded ALB) if requested
    if copy_header:
        ob = open(orig_alb, "rb").read()
        header54 = _decode_first_n_bytes(ob, template["first_pkt_off"], 54)
        if len(header54) < 54:
            raise RuntimeError("Could not recover 54-byte BMP header from original ALB")
        src = splice_pixels_with_header(src, header54)

    # Build new payload packet-by-packet (4k decoded slices)
    payload = b""
    pos = 0
    slice_len = 4096
    pkt_index = 0
    while pos < len(src):
        pkt_index += 1
        chunk = src[pos:pos+slice_len]; pos += len(chunk)
        forbidden = set(chunk)
        tokens, rules = greedy_bpe_safe(chunk, max_rules=220, forbidden_ids=forbidden)
        forced_marker = None
        if pkt_index-1 < len(template["packets"]) and template["packets"][pkt_index-1]["dict_mode"] == 1:
            forced_marker = template["packets"][pkt_index-1]["marker"]
        # encode packet
        try:
            pkt = encode_packet(tokens, rules, forced_marker=forced_marker)
        except ValueError:
            pkt = encode_packet(tokens, rules, forced_marker=None)
        payload += pkt

    # Verify exact round-trip before writing
    if not verify_decode(payload, src):
        raise RuntimeError("Round-trip verify failed; refusing to write ALB")

    # Write out: prefix + payload + tail (preserve exact framing)
    with open(out_alb, "wb") as f:
        f.write(template["prefix"])
        f.write(payload)
        f.write(template["tail"])
    print(f"[OK] wrote {out_alb}  packets≈{pkt_index}, bytes={len(template['prefix'])+len(payload)+len(template['tail'])}")
    return 0

def main():
    ap = argparse.ArgumentParser(description="Repack BMP into ALB using original ALB as a template (packetization/markers).")
    ap.add_argument("original_alb", help="Original ALB to mimic (packetization/markers)")
    ap.add_argument("bmp", help="New BMP to pack")
    ap.add_argument("-o","--out", required=True, help="Output ALB path")
    ap.add_argument("--normalize555", action="store_true", help="Convert input BMP to 16bpp RGB555 (BI_RGB)")
    ap.add_argument("--copy-header", action="store_true", help="Copy the original BMP's 54-byte header onto the new pixels")
    args = ap.parse_args()
    return repack_like(args.original_alb, args.bmp, args.out, normalize555=args.normalize555, copy_header=args.copy_header)

if __name__ == "__main__":
    raise SystemExit(main())
