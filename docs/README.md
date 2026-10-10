# LWS documentation site

The source of [fabriziosalmi.github.io/lws](https://fabriziosalmi.github.io/lws/).
GitHub Pages builds it with Jekyll from the `docs/` folder of `main`. This file
is excluded from the build.

## Layout

```
docs/
├── _config.yml           Site settings, collections, version shown on the site
├── _data/navigation.yml  Sidebar order, previous/next links, llms.txt
├── _layouts/
│   ├── base.html         HTML skeleton: head, header, footer
│   └── default.html      Documentation page: sidebar, "On this page", prev/next
├── _includes/
│   ├── head.html         Title, description, canonical, Open Graph, JSON-LD, CSP
│   ├── header.html       Top bar and search box
│   ├── footer.html
│   └── toc-items.html    Builds "On this page" from the page's h2/h3 headings
├── _pages/               Documentation pages (URL: /lws/pages/<name>.html)
├── index.html            Home page
├── 404.html
├── search.json           Search index, generated from the pages at build time
├── llms.txt              Generated page list for language models
├── llms-full.txt         Generated full text of every page
└── assets/
    ├── css/style.css     Tokens (light and dark), base, header, footer, home
    ├── css/docs.css      Documentation layout, Markdown, code highlighting
    ├── js/main.js        Copy buttons, heading anchors, current section, search
    ├── fonts/            Inter, self-hosted (one variable font per subset)
    └── img/              Favicon, touch icon, social preview image
```

Everything is served from this site. There are no third-party scripts, fonts
or stylesheets, and the Content-Security-Policy in `_includes/head.html`
allows none: no inline scripts or styles either.

## Adding a page

1. Create `_pages/<name>.md` with front matter:

   ```yaml
   ---
   title: Short title used in the sidebar and breadcrumb
   seo_title: "Title for search results, at most 60 characters"
   description: "What the page covers, 50 to 160 characters."
   ---
   ```

2. Add it to `_data/navigation.yml`. The sidebar, the previous/next links,
   `llms.txt` and `llms-full.txt` all follow that file.

`tests/test_docs_site.py` fails if a page is missing from the navigation, if a
navigation entry points nowhere, or if a title or description is missing, too
long or duplicated. `tests/test_docs_examples.py` parses every `lws` command
in a code block against the real CLI, so an example with a wrong option or
size name fails the test suite.

## Previewing locally

```bash
cd docs
bundle install
bundle exec jekyll serve
# open http://localhost:4000/lws/
```

The `Gemfile` pins the `github-pages` gem, so the local build matches the one
GitHub runs. To run the same checks as CI:

```bash
bundle exec jekyll build --destination _site/lws --baseurl /lws
LANG=C.UTF-8 bundle exec htmlproofer _site --root-dir _site --disable-external \
  --swap-urls '^https\://fabriziosalmi\.github\.io/lws/:/lws/'
```

## Releasing

When the version in `pyproject.toml` changes, update `lws_version` in
`_config.yml`; `tests/test_docs_site.py` fails until the two match.
