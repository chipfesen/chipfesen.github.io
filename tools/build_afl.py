# -*- coding: utf-8 -*-
"""
把归档的 AFL 文档转换成可发布的页面。

做两件事：

1. 还原空行排版
   Markdown 规范会把连续空行折叠成一个，原稿里 3/5/7/9 个空行在网页上完全
   看不出差别。这里把 N 个连续空行（N>=2）替换成指定高度的占位 <div>。

2. 图片懒加载
   原稿 63 张图共 5.3MB，若不声明 loading="lazy"，浏览器一进页面就会并发
   拉取全部图片。这里直接把图片转成带 loading="lazy" 的 <img> 标签，并写入
   width/height（读取 PNG 头得到），避免懒加载引起的高度跳动。

源文件保持原样，只生成发布版。改完原稿重跑本脚本即可。

用法:  python tools/build_afl.py
"""
import os
import re
import struct

BLOG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BLOG, "md", "AFL", "AFL源码分析.md")
DST = os.path.join(BLOG, "md", "AFL", "index.md")
IMG_DIR = os.path.join(BLOG, "md", "AFL", "AFL_img")

FRONT_MATTER = """---
layout: post
title: "AFL 源码分析"
date: 2026-09-08 21:40:00 +0800
permalink: /AFL/
toc: true
---

"""

# 每多一个空行增加的高度（em）。1em = 16px
EM_PER_BLANK = 1.0


def png_size(path):
    """读取 PNG 宽高，读不到就返回 None"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(26)
        if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        w, h = struct.unpack(">II", head[16:24])
        return w, h
    except OSError:
        return None


def convert(text):
    lines = text.split("\n")
    out = []
    in_code = False
    i = 0
    gaps = 0

    while i < len(lines):
        line = lines[i]

        # 代码块内一律原样保留（C 源码的换行本来就是排版的一部分）
        if line.startswith("```"):
            in_code = not in_code
            out.append(line)
            i += 1
            continue
        if in_code:
            out.append(line)
            i += 1
            continue

        # 连续空行 -> 占位元素
        if line.strip() == "":
            j = i
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            n_blank = j - i
            if n_blank >= 2:
                out.append("")
                out.append(
                    '<div class="blank-gap" style="height:%.2fem"></div>'
                    % ((n_blank - 1) * EM_PER_BLANK)
                )
                out.append("")
                gaps += 1
            else:
                out.append("")
            i = j
            continue

        out.append(line)
        i += 1

    text = "\n".join(out)

    # 图片：转成带懒加载的 <img>，归档的相对路径换成站点绝对路径
    missing = []

    def to_img(m):
        alt, name = m.group(1), m.group(2)
        alt = alt.replace('"', "&quot;")
        size = png_size(os.path.join(IMG_DIR, name))
        if size:
            wh = ' width="%d" height="%d"' % size
        else:
            wh = ""
            missing.append(name)
        return (
            '<img src="/md/AFL/AFL_img/%s" alt="%s"%s loading="lazy" decoding="async" />'
            % (name, alt, wh)
        )

    text, n_img = re.subn(r"!\[([^\]]*)\]\(AFL_img/([^)]+)\)", to_img, text)

    # 正文首个 H1 与页面标题重复，去掉（其余标题层级全部保留）
    text, n_h1 = re.subn(r"^#\s+AFL源码分析[ \t]*\n", "", text, count=1, flags=re.M)

    return FRONT_MATTER + text.lstrip("\n"), gaps, n_img, n_h1, missing


def main():
    with open(SRC, encoding="utf-8") as fh:
        src = fh.read()

    body, gaps, n_img, n_h1, missing = convert(src)

    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)

    print("源文件:   %s" % SRC)
    print("输出:     %s" % DST)
    print("空行占位: %d 处（N>=2 的连续空行）" % gaps)
    print("图片改写: %d 处（已加 loading=lazy）" % n_img)
    print("  其中读到尺寸: %d 张" % (n_img - len(missing)))
    if missing:
        print("  未读到尺寸: %s" % ", ".join(missing[:5]))
    print("去掉正文重复 H1: %d 处" % n_h1)
    print("输出大小: %.1f KB" % (len(body.encode("utf-8")) / 1024))


if __name__ == "__main__":
    main()
