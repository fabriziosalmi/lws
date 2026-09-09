/**
 * LWS Documentation - Main JavaScript
 */

// Smooth scroll for in-page navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// Subtle shadow on the sticky navbar once the page scrolls
const navbar = document.querySelector('.navbar');
if (navbar) {
    window.addEventListener('scroll', () => {
        navbar.style.boxShadow = window.scrollY > 10 ? '0 1px 3px rgba(0, 0, 0, 0.06)' : 'none';
    });
}

// Copy-to-clipboard button on code blocks
document.querySelectorAll('pre code').forEach(block => {
    const pre = block.parentElement;
    pre.style.position = 'relative';

    const button = document.createElement('button');
    button.className = 'copy-button';
    button.type = 'button';
    button.textContent = 'Copy';
    button.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 4px 10px;
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 4px;
        color: #e5e7eb;
        cursor: pointer;
        font-size: 0.78rem;
        line-height: 1.4;
    `;

    button.addEventListener('click', () => {
        navigator.clipboard.writeText(block.textContent).then(() => {
            button.textContent = 'Copied';
            setTimeout(() => { button.textContent = 'Copy'; }, 1500);
        });
    });

    pre.appendChild(button);
});
