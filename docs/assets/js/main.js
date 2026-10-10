/*
 * LWS documentation site.
 *
 * Everything here is an enhancement: the pages are complete without it.
 * - copy buttons on code blocks
 * - anchor links on headings
 * - highlights the current section in "On this page"
 * - the search box in the header (reads search.json, built by Jekyll)
 *
 * Loaded with `defer`, so the DOM is parsed when this runs. No inline
 * scripts or styles: the Content-Security-Policy allows neither.
 */
(() => {
    'use strict';

    const COPY_LABEL = 'Copy';
    const COPIED_LABEL = 'Copied';
    const COPY_FAILED_LABEL = 'Press Ctrl+C';
    const COPY_RESET_MS = 1800;
    const COPIED_MESSAGE = 'Code copied to clipboard';
    const COPY_FAILED_MESSAGE = 'Code selected, press Control C to copy';
    const NO_RESULTS_MESSAGE = 'No results';
    const MAX_RESULTS = 12;
    const MIN_QUERY_LENGTH = 2;
    const SNIPPET_BEFORE = 50;
    const SNIPPET_LENGTH = 160;
    const STATUS_DELAY_MS = 400;
    const ELLIPSIS = '…';
    const SCORE = { headingStart: 12, heading: 8, page: 2, text: 1 };

    // --- Live region ---------------------------------------------------------
    // One polite region for messages that have no visible place to go.
    let announcer = null;
    const announce = (message) => {
        if (!announcer) {
            announcer = document.createElement('p');
            announcer.className = 'visually-hidden';
            announcer.setAttribute('role', 'status');
            document.body.appendChild(announcer);
        }
        announcer.textContent = '';
        window.setTimeout(() => { announcer.textContent = message; }, 50);
    };

    // --- Copy buttons --------------------------------------------------------
    const copyText = (text) => {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        return Promise.reject(new Error('Clipboard API unavailable'));
    };

    const selectContents = (node) => {
        const range = document.createRange();
        range.selectNodeContents(node);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
    };

    const showCopyResult = (button, copied) => {
        button.textContent = copied ? COPIED_LABEL : COPY_FAILED_LABEL;
        button.setAttribute('data-copied', '');
        announce(copied ? COPIED_MESSAGE : COPY_FAILED_MESSAGE);
        window.setTimeout(() => {
            button.textContent = COPY_LABEL;
            button.removeAttribute('data-copied');
        }, COPY_RESET_MS);
    };

    const addCopyButtons = () => {
        document.querySelectorAll('pre').forEach((pre) => {
            const code = pre.querySelector('code') || pre;
            let container = pre.closest('.highlighter-rouge');
            if (!container) {
                container = document.createElement('div');
                pre.before(container);
                container.appendChild(pre);
            }
            container.classList.add('code-block');

            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'copy-button';
            button.textContent = COPY_LABEL;
            button.setAttribute('aria-label', 'Copy code to clipboard');
            button.addEventListener('click', () => {
                copyText(code.textContent.replace(/\n$/, '')).then(
                    () => showCopyResult(button, true),
                    () => {
                        showCopyResult(button, false);
                        selectContents(code);
                    },
                );
            });
            container.appendChild(button);
        });
    };

    // --- Heading anchors -----------------------------------------------------
    const addHeadingAnchors = () => {
        document.querySelectorAll('.markdown-body :is(h2, h3, h4)[id]').forEach((heading) => {
            const link = document.createElement('a');
            link.className = 'heading-anchor';
            link.href = `#${heading.id}`;
            // Mouse convenience only: keyboard and screen reader users reach
            // sections through "On this page", and a link inside the heading
            // would be read as part of the heading text.
            link.setAttribute('aria-hidden', 'true');
            link.tabIndex = -1;
            link.textContent = '#';
            heading.appendChild(link);
        });
    };

    // --- "On this page": current section -------------------------------------
    // Chromium does this natively with scroll-target-group and :target-current
    // (see docs.css); elsewhere a scroll listener sets the same state.
    // aria-current mirrors it for screen readers in both cases.
    const trackCurrentSection = () => {
        const toc = document.querySelector('.toc-aside');
        if (!toc) {
            return;
        }
        const links = [...toc.querySelectorAll('a[href^="#"]')];
        const native = window.CSS?.supports?.('scroll-target-group: auto') ?? false;

        const mark = (current) => {
            links.forEach((link) => {
                const active = link === current;
                link.classList.toggle('is-current', active && !native);
                if (active) {
                    link.setAttribute('aria-current', 'true');
                } else {
                    link.removeAttribute('aria-current');
                }
            });
        };

        if (native) {
            const sync = () => mark(toc.querySelector('a:target-current'));
            sync();
            document.addEventListener('scrollend', sync);
            return;
        }
        // Fallback: the current section is the last heading that has scrolled
        // past the top of the viewport (below the sticky header).
        const pairs = links
            .map((link) => [document.getElementById(decodeURIComponent(link.hash.slice(1))), link])
            .filter(([heading]) => heading);
        const headings = pairs.map(([heading]) => heading);
        const linkFor = new Map(pairs);
        const topOffset = () => (parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0) + 8;
        let isScheduled = false;
        const update = () => {
            isScheduled = false;
            const limit = topOffset();
            let current = headings[0];
            for (const heading of headings) {
                if (heading.getBoundingClientRect().top > limit) {
                    break;
                }
                current = heading;
            }
            mark(linkFor.get(current));
        };
        window.addEventListener('scroll', () => {
            if (!isScheduled) {
                isScheduled = true;
                window.requestAnimationFrame(update);
            }
        }, { passive: true });
        update();
    };

    // --- Search --------------------------------------------------------------
    const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const scoreEntry = (entry, terms) => {
        let total = 0;
        for (const term of terms) {
            const inHeading = entry.headingLower.indexOf(term);
            const inText = entry.textLower.indexOf(term);
            const inPage = entry.pageLower.indexOf(term);
            if (inHeading === -1 && inText === -1 && inPage === -1) {
                return 0;
            }
            if (inHeading === 0) {
                total += SCORE.headingStart;
            } else if (inHeading > 0) {
                total += SCORE.heading;
            }
            if (inPage !== -1) {
                total += SCORE.page;
            }
            if (inText !== -1) {
                total += SCORE.text;
            }
        }
        // Among equal matches, prefer short headings: they are usually one command.
        return total + Math.max(0, 3 - entry.heading.length / 30);
    };

    const snippet = (text, terms) => {
        const lower = text.toLowerCase();
        const at = terms.map((t) => lower.indexOf(t)).find((i) => i !== -1) ?? -1;
        if (at === -1) {
            return text.slice(0, SNIPPET_LENGTH);
        }
        const start = Math.max(0, at - SNIPPET_BEFORE);
        const end = start + SNIPPET_LENGTH;
        const prefix = start > 0 ? ELLIPSIS : '';
        const suffix = end < text.length ? ELLIPSIS : '';
        return prefix + text.slice(start, end) + suffix;
    };

    // Text with the matched terms wrapped in <mark>, built without innerHTML.
    const highlighted = (text, terms) => {
        const fragment = document.createDocumentFragment();
        const pattern = new RegExp(`(${terms.map(escapeRegExp).join('|')})`, 'gi');
        text.split(pattern).forEach((part, i) => {
            if (i % 2 === 1) {
                const mark = document.createElement('mark');
                mark.textContent = part;
                fragment.appendChild(mark);
            } else if (part) {
                fragment.appendChild(document.createTextNode(part));
            }
        });
        return fragment;
    };

    const toEntries = (pages) => pages.flatMap((page) => page.s.map((section) => {
        const heading = section.h || page.t;
        const text = section.x || '';
        return {
            page: page.t,
            heading,
            url: section.a ? `${page.u}#${section.a}` : page.u,
            text,
            headingLower: heading.toLowerCase(),
            textLower: text.toLowerCase(),
            pageLower: page.t.toLowerCase(),
        };
    }));

    const resultItem = (entry, terms, index) => {
        const item = document.createElement('li');
        item.id = `search-result-${index}`;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', 'false');

        const link = document.createElement('a');
        link.href = entry.url;
        link.tabIndex = -1;

        const title = document.createElement('span');
        title.className = 'search-result-title';
        title.appendChild(highlighted(entry.heading, terms));
        link.appendChild(title);

        if (entry.heading !== entry.page) {
            const page = document.createElement('span');
            page.className = 'search-result-page';
            page.textContent = entry.page;
            link.appendChild(page);
        }
        if (entry.text) {
            const text = document.createElement('span');
            text.className = 'search-result-text';
            text.appendChild(highlighted(snippet(entry.text, terms), terms));
            link.appendChild(text);
        }
        item.appendChild(link);
        return item;
    };

    const setUpSearch = () => {
        const box = document.querySelector('.site-search');
        if (!box || !window.fetch) {
            return;
        }
        const input = box.querySelector('input');
        const list = box.querySelector('[role="listbox"]');
        const status = box.querySelector('[data-search-status]');
        const indexUrl = box.getAttribute('data-search-index');
        let entries = [];
        let loading = null;
        let active = -1;
        let statusTimer = 0;

        box.hidden = false;

        const load = () => {
            if (!loading) {
                loading = fetch(indexUrl, { credentials: 'same-origin' })
                    .then((response) => {
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}`);
                        }
                        return response.json();
                    })
                    .then((pages) => { entries = toEntries(pages); })
                    .catch(() => {
                        // Leave search empty and let the next keystroke retry.
                        loading = null;
                    });
            }
            return loading;
        };

        const setStatus = (message) => {
            window.clearTimeout(statusTimer);
            statusTimer = window.setTimeout(() => { status.textContent = message; }, STATUS_DELAY_MS);
        };

        const options = () => list.querySelectorAll('[role="option"]');

        const close = () => {
            list.hidden = true;
            input.setAttribute('aria-expanded', 'false');
            input.removeAttribute('aria-activedescendant');
            active = -1;
        };

        const setActive = (index) => {
            const all = options();
            if (!all.length) {
                return;
            }
            active = (index + all.length) % all.length;
            all.forEach((option, i) => option.setAttribute('aria-selected', String(i === active)));
            input.setAttribute('aria-activedescendant', all[active].id);
            all[active].scrollIntoView({ block: 'nearest' });
        };

        const render = () => {
            const query = input.value.trim().toLowerCase();
            list.textContent = '';
            active = -1;
            input.removeAttribute('aria-activedescendant');
            if (query.length < MIN_QUERY_LENGTH) {
                close();
                status.textContent = '';
                return;
            }
            const terms = query.split(/\s+/).filter(Boolean);
            const results = entries
                .map((entry) => ({ entry, score: scoreEntry(entry, terms) }))
                .filter((r) => r.score > 0)
                .sort((a, b) => b.score - a.score)
                .slice(0, MAX_RESULTS);

            if (results.length) {
                results.forEach((r, i) => list.appendChild(resultItem(r.entry, terms, i)));
                const noun = results.length === 1 ? 'result' : 'results';
                setStatus(`${results.length} ${noun}, use the arrow keys to move through them`);
            } else {
                const empty = document.createElement('li');
                empty.className = 'search-empty';
                empty.setAttribute('role', 'presentation');
                empty.textContent = `No results for “${input.value.trim()}”`;
                list.appendChild(empty);
                setStatus(NO_RESULTS_MESSAGE);
            }
            list.hidden = false;
            input.setAttribute('aria-expanded', 'true');
        };

        const go = (link) => {
            window.location.href = link.href;
        };

        input.addEventListener('focus', load, { once: true });
        input.addEventListener('input', () => { load().then(render); });
        input.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                if (!list.hidden) {
                    event.preventDefault();
                    setActive(active + (event.key === 'ArrowDown' ? 1 : -1));
                }
            } else if (event.key === 'Enter') {
                const links = list.querySelectorAll('[role="option"] a');
                const target = links[Math.max(active, 0)];
                if (target && !list.hidden) {
                    event.preventDefault();
                    go(target);
                }
            } else if (event.key === 'Escape') {
                if (list.hidden) {
                    input.value = '';
                } else {
                    event.preventDefault();
                    close();
                }
            }
        });
        // Keep focus in the input so the list does not close before the click lands.
        list.addEventListener('mousedown', (event) => event.preventDefault());
        list.addEventListener('click', (event) => {
            const link = event.target.closest('a');
            if (link) {
                event.preventDefault();
                go(link);
            }
        });
        input.addEventListener('blur', () => { window.setTimeout(close, 100); });

        // "/" focuses the search box, unless the user is typing somewhere.
        document.addEventListener('keydown', (event) => {
            if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) {
                return;
            }
            const el = document.activeElement;
            if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) {
                return;
            }
            event.preventDefault();
            input.focus();
        });
    };

    addCopyButtons();
    addHeadingAnchors();
    trackCurrentSection();
    setUpSearch();
})();
