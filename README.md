# WindowsCE-ALB-Scripts

Python scripts for decompressing/compressing (and converting .bmp to correct format) .ALB files found in 2 (possibly more?) Sega Dreamcast games built with Windows CE: Hello Kitty Waku Waku Cookies and Hello Kitty Lovely Fruit Park.

Use examples:

python alb_extract.py GAME1.ALB -o outdir

python imageconv_a1rgb555.py GAME1.bmp game1fix.bmp --stats

python alb_repack_like.py game1Original.ALB game1fix.bmp -o GAME1.ALB --copy-header

Run --help for more details on each script.
