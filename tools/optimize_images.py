# -*- coding: utf-8 -*-
"""
把 Markdown 里的图片链接转成带懒加载的 <img> 标签。

为什么需要：Jekyll 渲染 `![](x.png)` 时生成的是光秃秃的 <img src="x.png">，
浏览器会一次性并发拉取页面上所有图片。图片多的文章（几十张截图、总量数 MB）
打开就会卡很久。改成 <img loading="lazy"> 后浏览器只加载视口附近的。

顺带写入 width/height（读 PNG 头得到），让浏览器提前预留高度，
否则图片逐张加载时页面会不停跳动。CSS 里得配 height:auto 才不会变形。

脚本是幂等的：已经是 <img> 标签的部分不会被再次处理。

用法:  python tools/optimize_images.py _posts/2026-10-13-CVE-2026-8260.md
"""
import os
import re
import struct
import sys

BLOG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def png_size(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(26)
        if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        return struct.unpack(">II", head[16:24])
    except OSError:
        return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    target = sys.argv[1]
    if not os.path.isabs(target):
        target = os.path.join(BLOG, target)

    with open(target, encoding="utf-8") as fh:
        text = fh.read()

    stat = {"done": 0, "nosize": 0, "skip": 0}

    def repl(m):
        alt, url = m.group(1), m.group(2)
        if not re.search(r"\.(png|jpe?g|gif|webp)$", url, re.I):
            stat["skip"] += 1
            return m.group(0)

        local = os.path.join(BLOG, url.lstrip("/")) if url.startswith("/") else None
        size = png_size(local) if local else None
        if size:
            wh = ' width="%d" height="%d"' % size
        else:
            wh = ""
            stat["nosize"] += 1
        stat["done"] += 1
        return '<img src="%s" alt="%s"%s loading="lazy" decoding="async" />' % (
            url,
            alt.replace('"', "&quot;"),
            wh,
        )

    text, total = re.subn(r"!\[([^\]]*)\]\(([^)]+)\)", repl, text)

    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    print("文件:     %s" % target)
    print("识别图片: %d 个" % total)
    print("已转换:   %d 个（写入尺寸 %d 个，未读到尺寸 %d 个）"
          % (stat["done"], stat["done"] - stat["nosize"], stat["nosize"]))
    print("跳过:     %d 个（非图片链接）" % stat["skip"])


if __name__ == "__main__":
    main()
