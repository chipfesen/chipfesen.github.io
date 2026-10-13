# -*- coding: utf-8 -*-
"""
把归档的 AFL 文档转换成可发布的页面。

为什么需要这一步：Markdown 规范会把连续空行折叠成一个，原稿里 3/5/7/9 个空行
在网页上完全看不出差别。此脚本把 N 个连续空行（N>=2）替换成指定高度的占位
<div>，从而还原原稿的段落疏密。

源文件保持原样，只生成发布版。改完原稿重跑本脚本即可。

用法:  python tools/build_afl.py
"""
import os
import re

BLOG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BLOG, "md", "AFL", "AFL源码分析.md")
DST = os.path.join(BLOG, "md", "AFL", "index.md")

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

        # 连续空行
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

    # 图片：归档用相对路径，发布版要换成站点绝对路径
    text, n_img = re.subn(
        r"!\[([^\]]*)\]\(AFL_img/([^)]+)\)", r"![\1](/md/AFL/AFL_img/\2)", text
    )

    # 正文首个 H1 与页面标题重复，去掉（其余标题层级全部保留）
    text, n_h1 = re.subn(r"^#\s+AFL源码分析[ \t]*\n", "", text, count=1, flags=re.M)

    return FRONT_MATTER + text.lstrip("\n"), gaps, n_img, n_h1


def main():
    with open(SRC, encoding="utf-8") as fh:
        src = fh.read()

    body, gaps, n_img, n_h1 = convert(src)

    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)

    print("源文件:   %s" % SRC)
    print("输出:     %s" % DST)
    print("空行占位: %d 处（N>=2 的连续空行）" % gaps)
    print("图片改写: %d 处 -> /md/AFL/AFL_img/" % n_img)
    print("去掉正文重复 H1: %d 处" % n_h1)
    print("输出大小: %.1f KB" % (len(body.encode("utf-8")) / 1024))


if __name__ == "__main__":
    main()
