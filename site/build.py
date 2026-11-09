# /// script
# requires-python = ">=3.10"
# dependencies = ["markdown-it-py==4.0.0"]
# ///
"""Build the Colophon website from the files in this repository.

The site has no content of its own. The home page is README.md and the
specification page is colophon-v0.md, rendered as they are, so the site
cannot drift from the repository.

    uv run site/build.py            # writes _site/
    uv run site/build.py --out DIR
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
import subprocess
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/fluxtopus/colophon-protocol"
SPEC_SOURCE = "colophon-v0.md"
SPEC_PATH = "v0/"

_md = MarkdownIt("commonmark", {"html": False}).enable("table")

_HEADING = re.compile(r"<h([23])>(.*?)</h\1>", re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
# Text outside <pre>, <code>, <a> and headings may get cross-reference links.
_SKIP = re.compile(
    r"(<pre>.*?</pre>|<code>.*?</code>|<a [^>]*>.*?</a>|<h[1-6][^>]*>.*?</h[1-6]>)", re.DOTALL
)
_SECTION_REF = re.compile(r"§(\d+(?:\.\d+)*)")
_APPENDIX_REF = re.compile(r"\bAppendix ([A-E])\b")
_RFC_REF = re.compile(r"\bRFC (\d{3,5})(?: §(\d+(?:\.\d+)*))?")


def heading_id(text: str) -> str:
    """Stable anchors: section-7.2, appendix-a, or a slug for other headings."""
    if m := re.match(r"(\d+(?:\.\d+)*)\.?\s", text):
        return f"section-{m.group(1)}"
    if m := re.match(r"Appendix ([A-Z])\b", text):
        return f"appendix-{m.group(1).lower()}"
    return re.sub(r"[^a-z0-9.]+", "-", text.lower()).strip("-")


def add_heading_ids(body: str) -> tuple[str, list[tuple[int, str, str]]]:
    toc: list[tuple[int, str, str]] = []

    def repl(m: re.Match[str]) -> str:
        level, inner = int(m.group(1)), m.group(2)
        text = html.unescape(_TAG.sub("", inner)).strip()
        anchor = heading_id(text)
        toc.append((level, anchor, inner))
        return (
            f'<h{level} id="{anchor}">{inner}'
            f'<a class="anchor" href="#{anchor}" aria-label="Link to this section">#</a></h{level}>'
        )

    return _HEADING.sub(repl, body), toc


def _outside_skipped(body: str, fn) -> str:
    parts = _SKIP.split(body)
    return "".join(p if i % 2 else fn(p) for i, p in enumerate(parts))


def _rfc_link(m: re.Match[str]) -> str:
    number, section = m.group(1), m.group(2)
    href = f"https://www.rfc-editor.org/rfc/rfc{number}"
    if section:
        return f'<a href="{href}#section-{section}">RFC {number} §{section}</a>'
    return f'<a href="{href}">RFC {number}</a>'


def link_references(body: str, spec_href: str) -> str:
    """Link RFC citations to rfc-editor.org, then this spec's own § and Appendix references."""
    body = _outside_skipped(body, lambda chunk: _RFC_REF.sub(_rfc_link, chunk))

    def own(chunk: str) -> str:
        chunk = _SECTION_REF.sub(
            lambda m: f'<a href="{spec_href}#section-{m.group(1)}">§{m.group(1)}</a>', chunk
        )
        return _APPENDIX_REF.sub(
            lambda m: (
                f'<a href="{spec_href}#appendix-{m.group(1).lower()}">Appendix {m.group(1)}</a>'
            ),
            chunk,
        )

    return _outside_skipped(body, own)


def link_contents(source: str) -> str:
    """Turn the spec's plain Contents list into links."""

    def repl(m: re.Match[str]) -> str:
        block = m.group(0)
        block = re.sub(r"^(\d+)\. (.+)$", r"\1. [\2](#section-\1)", block, flags=re.MULTILINE)
        return re.sub(
            r"^- ([A-E])\. (.+)$",
            lambda n: f"- {n.group(1)}. [{n.group(2)}](#appendix-{n.group(1).lower()})",
            block,
            flags=re.MULTILINE,
        )

    return re.sub(r"(?<=## Contents\n).*?(?=\n## )", repl, source, count=1, flags=re.DOTALL)


def wrap_tables(body: str) -> str:
    return body.replace("<table>", '<div class="table-wrap"><table>').replace(
        "</table>", "</table></div>"
    )


def rewrite_readme_links(source: str) -> str:
    source = source.replace(f"]({SPEC_SOURCE})", f"]({SPEC_PATH})")
    source = source.replace("](reference/", f"]({SPEC_PATH}reference/")
    return re.sub(r"\]\(((?:CONTRIBUTING|SECURITY)\.md)\)", rf"]({REPO_URL}/blob/main/\1)", source)


def commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def toc_html(toc: list[tuple[int, str, str]]) -> str:
    items = []
    for level, anchor, inner in toc:
        if anchor in ("abstract", "contents"):
            continue
        items.append(f'<li class="l{level}"><a href="#{anchor}">{_TAG.sub("", inner)}</a></li>')
    return (
        '<nav class="toc" aria-label="Sections"><p>Sections</p><ol>'
        + "".join(items)
        + "</ol></nav>"
    )


def page(
    *, title: str, description: str, body: str, root: str, toc: str = "", sha: str = "", source: str
) -> str:
    source_link = f"{REPO_URL}/blob/{sha or 'main'}/{source}"
    built = (
        f'Built from <a href="{REPO_URL}/commit/{sha}"><code>{sha[:7]}</code></a>.' if sha else ""
    )
    layout = "with-toc" if toc else "single"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(description)}">
<link rel="icon" href="data:,">
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header class="site">
  <a class="brand" href="{root}">Colophon</a>
  <nav>
    <a href="{root}{SPEC_PATH}">Specification</a>
    <a href="{root}{SPEC_PATH}reference/vectors.json">Test vectors</a>
    <a href="{REPO_URL}">Repository</a>
  </nav>
</header>
<div class="layout {layout}">
{toc}
<main>
{body}
</main>
</div>
<footer class="site">
  <p>Apache 2.0. {built} <a href="{source_link}">View the source</a> · <a href="{REPO_URL}/issues">Comment or report an issue</a></p>
</footer>
</body>
</html>
"""


def build(out: Path) -> None:
    sha = commit()
    if out.exists():
        shutil.rmtree(out)
    (out / SPEC_PATH).mkdir(parents=True)
    shutil.copy(ROOT / "site" / "style.css", out / "style.css")
    shutil.copytree(ROOT / "reference", out / SPEC_PATH / "reference")

    spec_src = (ROOT / SPEC_SOURCE).read_text(encoding="utf-8")
    spec_title = spec_src.splitlines()[0].lstrip("# ").strip()
    spec_body, spec_toc = add_heading_ids(_md.render(link_contents(spec_src)))
    spec_body = wrap_tables(link_references(spec_body, ""))
    (out / SPEC_PATH / "index.html").write_text(
        page(
            title=spec_title,
            description="The Colophon v0 specification: agent signatures for email.",
            body=spec_body,
            root="../",
            toc=toc_html(spec_toc),
            sha=sha,
            source=SPEC_SOURCE,
        ),
        encoding="utf-8",
    )

    readme = rewrite_readme_links((ROOT / "README.md").read_text(encoding="utf-8"))
    home_body, _ = add_heading_ids(_md.render(readme))
    home_body = wrap_tables(link_references(home_body, SPEC_PATH))
    (out / "index.html").write_text(
        page(
            title="Colophon: agent signatures for email",
            description="Colophon lets an AI agent sign the email it sends. An open protocol, draft v0.",
            body=home_body,
            root="",
            sha=sha,
            source="README.md",
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "_site")
    build(parser.parse_args().out)
