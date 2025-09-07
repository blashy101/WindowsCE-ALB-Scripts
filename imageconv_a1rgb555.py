
#!/usr/bin/env python3
import argparse

BASE = 14  # BMP file header is 14 bytes; DIB starts at offset 14

def u16(b,o): return int.from_bytes(b[o:o+2], "little")
def u32(b,o): return int.from_bytes(b[o:o+4], "little")

def read_bmp_header(b):
    if b[:2] != b"BM":
        raise ValueError("Not a BMP (missing 'BM')")
    off       = u32(b, 10)
    dib       = u32(b, BASE+0)
    if dib not in (40,52,56,108,124):
        raise ValueError(f"Unsupported DIB header size {dib}; need 40/52/56/108/124")
    width     = int.from_bytes(b[BASE+4:BASE+8], "little", signed=True)
    height    = int.from_bytes(b[BASE+8:BASE+12], "little", signed=True)
    planes    = u16(b, BASE+12)
    bpp       = u16(b, BASE+14)
    comp      = u32(b, BASE+16)  # 0=BI_RGB, 3=BI_BITFIELDS
    size_img  = u32(b, BASE+20)
    xppm      = int.from_bytes(b[BASE+24:BASE+28], "little", signed=True)
    yppm      = int.from_bytes(b[BASE+28:BASE+32], "little", signed=True)
    clr_used  = u32(b, BASE+32)
    clr_imp   = u32(b, BASE+36)
    red_mask = green_mask = blue_mask = alpha_mask = 0
    if comp == 3 and dib >= 52:
        red_mask   = u32(b, BASE+40)
        green_mask = u32(b, BASE+44)
        blue_mask  = u32(b, BASE+48)
        if dib >= 56:
            alpha_mask = u32(b, BASE+52)
    return {
        "off": off, "dib": dib, "width": width, "height": height, "planes": planes, "bpp": bpp,
        "comp": comp, "size_img": size_img, "xppm": xppm, "yppm": yppm,
        "clr_used": clr_used, "clr_imp": clr_imp,
        "red_mask": red_mask, "green_mask": green_mask, "blue_mask": blue_mask, "alpha_mask": alpha_mask
    }

def mask_info(mask):
    if mask == 0: return (0,0,0)
    shift = (mask & -mask).bit_length() - 1
    m = mask >> shift
    bits = m.bit_length()
    while bits>0 and (m & 1)==0:
        m >>= 1; shift += 1; bits -= 1
    maxv = (1<<bits) - 1 if bits>0 else 0
    return shift, bits, maxv

def extract_to_5(px, mask, mi):
    if mask == 0: return 0
    shift, bits, maxv = mi
    if bits == 0: return 0
    v = (px & mask) >> shift
    return (v * 31 + (maxv//2)) // max(1, maxv)

def to_a1rgb555(in_bytes, assume565=True, passthrough16=False, keep_height_sign=True, dpi=2835, stats=False):
    h = read_bmp_header(in_bytes)
    w, ht, bpp, comp, off = h["width"], h["height"], h["bpp"], h["comp"], h["off"]
    abs_h = abs(ht)
    if bpp not in (16,24,32):
        raise ValueError(f"Input bpp {bpp} not supported; use 16/24/32bpp BMP.")
    if bpp == 16 and comp not in (0,3):
        raise ValueError("16bpp input must be BI_RGB or BI_BITFIELDS")

    in_stride  = ((w * (bpp // 8) + 3) // 4) * 4
    out_stride = ((w * 2 + 3) // 4) * 4
    out_pixels = bytearray(out_stride * abs_h)

    zeros = 0; bit15 = 0
    bottom_up = (ht > 0)

    # BITFIELDS masks if present
    rmi=gmi=bmi=None
    if comp == 3:
        rm = h["red_mask"]   or (0xF800 if bpp==16 else 0x00FF0000)
        gm = h["green_mask"] or (0x07E0 if bpp==16 else 0x0000FF00)
        bm = h["blue_mask"]  or (0x001F   if bpp==16 else 0x000000FF)
        rmi = mask_info(rm); gmi = mask_info(gm); bmi = mask_info(bm)

    for row in range(abs_h):
        src_y = row if bottom_up else row
        s = off + src_y * in_stride
        d = row * out_stride

        if bpp == 16 and comp == 0:
            if passthrough16:
                # leave low 15 bits as-is; just set bit 15 on non-zero
                for x in range(w):
                    px = in_bytes[s + x*2] | (in_bytes[s + x*2 + 1] << 8)
                    out = px & 0x7FFF
                    if out != 0: out |= 0x8000; bit15 += 1
                    else: zeros += 1
                    out_pixels[d + x*2 + 0] = out & 0xFF
                    out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF
            else:
                # interpret as 565 or 555 explicitly
                if assume565:
                    for x in range(w):
                        px = in_bytes[s + x*2] | (in_bytes[s + x*2 + 1] << 8)
                        r5 = (px >> 11) & 0x1F
                        g6 = (px >> 5)  & 0x3F
                        g5 = (g6 * 31 + 31//2)//63
                        b5 =  px        & 0x1F
                        out = (r5 << 10) | (g5 << 5) | b5
                        if out == 0: zeros += 1
                        else: out |= 0x8000; bit15 += 1
                        out_pixels[d + x*2 + 0] = out & 0xFF
                        out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF
                else:
                    for x in range(w):
                        px = in_bytes[s + x*2] | (in_bytes[s + x*2 + 1] << 8)
                        r5 = (px >> 10) & 0x1F
                        g5 = (px >> 5)  & 0x1F
                        b5 =  px        & 0x1F
                        out = (r5 << 10) | (g5 << 5) | b5
                        if out == 0: zeros += 1
                        else: out |= 0x8000; bit15 += 1
                        out_pixels[d + x*2 + 0] = out & 0xFF
                        out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF

        elif bpp == 16 and comp == 3:
            # Use explicit masks
            rm = h["red_mask"]   or 0xF800
            gm = h["green_mask"] or 0x07E0
            bm = h["blue_mask"]  or 0x001F
            rmi = mask_info(rm); gmi = mask_info(gm); bmi = mask_info(bm)
            for x in range(w):
                px = in_bytes[s + x*2] | (in_bytes[s + x*2 + 1] << 8)
                r5 = extract_to_5(px, rm, rmi)
                g5 = extract_to_5(px, gm, gmi)
                b5 = extract_to_5(px, bm, bmi)
                out = (r5 << 10) | (g5 << 5) | b5
                if out == 0: zeros += 1
                else: out |= 0x8000; bit15 += 1
                out_pixels[d + x*2 + 0] = out & 0xFF
                out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF

        elif bpp == 24:
            for x in range(w):
                B = in_bytes[s + x*3 + 0]
                G = in_bytes[s + x*3 + 1]
                R = in_bytes[s + x*3 + 2]
                r5 = (R >> 3) & 0x1F; g5 = (G >> 3) & 0x1F; b5 = (B >> 3) & 0x1F
                out = (r5 << 10) | (g5 << 5) | b5
                if out == 0: zeros += 1
                else: out |= 0x8000; bit15 += 1
                out_pixels[d + x*2 + 0] = out & 0xFF
                out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF

        else:  # 32bpp
            if comp == 3:
                rm = h["red_mask"]   or 0x00FF0000
                gm = h["green_mask"] or 0x0000FF00
                bm = h["blue_mask"]  or 0x000000FF
                rmi = mask_info(rm); gmi = mask_info(gm); bmi = mask_info(bm)
                for x in range(w):
                    px = int.from_bytes(in_bytes[s + x*4: s + x*4 + 4], "little")
                    r5 = extract_to_5(px, rm, rmi); g5 = extract_to_5(px, gm, gmi); b5 = extract_to_5(px, bm, bmi)
                    out = (r5 << 10) | (g5 << 5) | b5
                    if out == 0: zeros += 1
                    else: out |= 0x8000; bit15 += 1
                    out_pixels[d + x*2 + 0] = out & 0xFF
                    out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF
            else:
                for x in range(w):
                    B = in_bytes[s + x*4 + 0]
                    G = in_bytes[s + x*4 + 1]
                    R = in_bytes[s + x*4 + 2]
                    r5 = (R >> 3) & 0x1F; g5 = (G >> 3) & 0x1F; b5 = (B >> 3) & 0x1F
                    out = (r5 << 10) | (g5 << 5) | b5
                    if out == 0: zeros += 1
                    else: out |= 0x8000; bit15 += 1
                    out_pixels[d + x*2 + 0] = out & 0xFF
                    out_pixels[d + x*2 + 1] = (out >> 8) & 0xFF

    # Build 16bpp BI_RGB BMP
    out_h = ht if keep_height_sign else abs_h
    file_header = bytearray(14)
    dib_header  = bytearray(40)
    pixel_offset = 14 + 40
    file_size = pixel_offset + len(out_pixels)

    file_header[0:2]  = b"BM"
    file_header[2:6]  = file_size.to_bytes(4, "little")
    file_header[6:8]  = (0).to_bytes(2, "little")
    file_header[8:10] = (0).to_bytes(2, "little")
    file_header[10:14]= pixel_offset.to_bytes(4, "little")

    dib_header[0:4]   = (40).to_bytes(4, "little")
    dib_header[4:8]   = int(w).to_bytes(4, "little", signed=True)
    dib_header[8:12]  = int(out_h).to_bytes(4, "little", signed=True)
    dib_header[12:14] = (1).to_bytes(2, "little")
    dib_header[14:16] = (16).to_bytes(2, "little")
    dib_header[16:20] = (0).to_bytes(4, "little")  # BI_RGB
    dib_header[20:24] = (0).to_bytes(4, "little")
    dib_header[24:28] = (2835).to_bytes(4, "little", signed=True)
    dib_header[28:32] = (2835).to_bytes(4, "little", signed=True)
    dib_header[32:36] = (0).to_bytes(4, "little")
    dib_header[36:40] = (0).to_bytes(4, "little")

    out_bytes = bytes(file_header) + bytes(dib_header) + bytes(out_pixels)

    if stats:
        total = w * abs_h
        print(f"[stats] {w}x{abs_h} 16bpp BI_RGB")
        print(f"[stats] zeros (0x0000): {zeros} / {total} = {zeros/total*100:.2f}%")
        print(f"[stats] bit15 set     : {bit15} / {total} = {bit15/total*100:.2f}%")

    return out_bytes

def main():
    ap = argparse.ArgumentParser(description="Convert BMP (16/24/32bpp) to 16bpp BI_RGB A1R5G5B5. Keeps 0x0000 as colorkey; sets bit15 on nonzero. For 16bpp BI_RGB, use --assume555/--assume565 or --passthrough16 to just set the top bit without channel remap.")
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--assume555", action="store_true", help="Treat 16bpp BI_RGB input as X1R5G5B5")
    ap.add_argument("--assume565", action="store_true", help="Treat 16bpp BI_RGB input as RGB565 (default if neither flag is given)")
    ap.add_argument("--passthrough16", action="store_true", help="For 16bpp BI_RGB input, do not remap channels; just set bit15 on non‑zero pixels")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    src = open(args.input, "rb").read()
    assume565 = True if args.assume565 or (not args.assume555 and not args.passthrough16) else False
    out = to_a1rgb555(src, assume565=assume565, passthrough16=args.passthrough16, stats=args.stats)
    with open(args.output, "wb") as f:
        f.write(out)
    if args.stats:
        print(f"[ok] wrote {args.output} ({len(out)} bytes)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
