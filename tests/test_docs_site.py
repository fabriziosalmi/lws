"""
The documentation site's metadata has to agree with the repository.

The site states the released version, lists its pages in a sidebar, and gives
each page the description search engines show under its title. All three are
written by hand in different files, so each can drift on its own:

    docs/_config.yml            lws_version, shown on the home page and in JSON-LD
    docs/_data/navigation.yml   sidebar, previous/next links, llms.txt
    docs/_<collection>/*.md     front matter: title, seo_title, description

These tests do not build the site (the docs workflow does that, with Jekyll and
a link checker). They read the sources and check what a build would not report.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
CONFIG = yaml.safe_load((DOCS / "_config.yml").read_text(encoding="utf-8"))
NAVIGATION = yaml.safe_load((DOCS / "_data" / "navigation.yml").read_text(encoding="utf-8"))

# What Google shows: a title is cut at roughly 60 characters, a description at
# roughly 155-160. Below 50 a description is usually too thin to be used.
TITLE_MAX = 60
DESCRIPTION_RANGE = (50, 160)


def _front_matter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, f"{path.relative_to(REPO_ROOT)} has no front matter."
    return yaml.safe_load(match.group(1)) or {}


def _collection_pages() -> dict:
    """URL -> (source path, front matter) for every page in an output collection."""
    pages = {}
    for label, settings in (CONFIG.get("collections") or {}).items():
        if not settings.get("output"):
            continue
        prefix = settings["permalink"].split(":name")[0]
        for source in sorted((DOCS / f"_{label}").glob("*.md")):
            pages[f"{prefix}{source.stem}.html"] = (source, _front_matter(source))
    return pages


PAGES = _collection_pages()
NAV_URLS = [item["url"] for section in NAVIGATION for item in section["items"]]


def test_site_version_matches_pyproject():
    match = re.search(r'^version\s*=\s*"([^"]+)"', (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    assert match, "pyproject.toml has no version."
    assert str(CONFIG.get("lws_version")) == match.group(1), (
        f"docs/_config.yml says lws_version {CONFIG.get('lws_version')!r}, pyproject.toml "
        f"says {match.group(1)!r}. Update the site when bumping the release."
    )


def test_theme_is_disabled_explicitly():
    """Without `theme: null`, GitHub Pages applies jekyll-theme-primer, whose
    stylesheet is written over assets/css/style.css."""
    assert "theme" in CONFIG and CONFIG["theme"] is None


def test_navigation_points_at_existing_pages():
    missing = [url for url in NAV_URLS if url not in PAGES]
    assert not missing, f"navigation.yml links to pages that do not exist: {missing}"
    duplicates = {url for url in NAV_URLS if NAV_URLS.count(url) > 1}
    assert not duplicates, f"navigation.yml lists these pages twice: {sorted(duplicates)}"


def test_every_page_is_in_the_navigation():
    """A page left out of navigation.yml has no sidebar entry, no previous/next
    links and is missing from llms.txt."""
    orphans = [str(source.relative_to(REPO_ROOT)) for url, (source, _) in PAGES.items() if url not in NAV_URLS]
    assert not orphans, f"Add these pages to docs/_data/navigation.yml: {orphans}"


@pytest.mark.parametrize("url", sorted(PAGES))
def test_page_has_search_metadata(url):
    source, meta = PAGES[url]
    name = source.relative_to(REPO_ROOT)
    assert meta.get("title"), f"{name} has no title."
    title = meta.get("seo_title") or meta["title"]
    assert len(title) <= TITLE_MAX, f"{name}: title is {len(title)} characters, keep it within {TITLE_MAX}."
    description = meta.get("description") or ""
    low, high = DESCRIPTION_RANGE
    assert low <= len(description) <= high, (
        f"{name}: description is {len(description)} characters; write one of {low}-{high}."
    )


def test_descriptions_and_titles_are_unique():
    seen = {}
    for url, (_, meta) in PAGES.items():
        for key in ("description", "seo_title"):
            value = meta.get(key)
            if value:
                assert value not in seen, f"{url} and {seen[value]} share the same {key}."
                seen[value] = url
