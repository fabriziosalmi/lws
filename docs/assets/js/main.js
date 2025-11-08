/**
 * LWS Documentation - Main JavaScript
 */

// Smooth scroll for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Navbar background on scroll
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';
    } else {
        navbar.style.boxShadow = 'none';
    }
});

// Enhanced Intersection Observer for scroll-triggered animations
const observerOptions = {
    threshold: 0.15,
    rootMargin: '0px 0px -100px 0px'
};

const animationObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            // Unobserve after animation to prevent re-triggering
            animationObserver.unobserve(entry.target);
        }
    });
}, observerOptions);

// Apply animations to different sections
document.querySelectorAll('.feature-card').forEach((card, index) => {
    card.classList.add('fade-in-on-scroll');
    card.style.transitionDelay = `${index * 0.1}s`;
    animationObserver.observe(card);
});

document.querySelectorAll('.doc-card').forEach((card, index) => {
    card.classList.add('scale-in');
    card.style.transitionDelay = `${index * 0.1}s`;
    animationObserver.observe(card);
});

document.querySelectorAll('.step').forEach((step, index) => {
    step.classList.add(index % 2 === 0 ? 'slide-in-left' : 'slide-in-right');
    animationObserver.observe(step);
});

document.querySelectorAll('.workflow-step').forEach((step, index) => {
    step.classList.add('fade-in-on-scroll');
    step.style.transitionDelay = `${index * 0.2}s`;
    animationObserver.observe(step);
});

// Animate stat items
document.querySelectorAll('.stat-item').forEach((item, index) => {
    item.classList.add('scale-in');
    item.style.transitionDelay = `${index * 0.15}s`;
    animationObserver.observe(item);
});

// Copy code to clipboard
document.querySelectorAll('pre code').forEach(block => {
    block.parentElement.style.position = 'relative';

    const button = document.createElement('button');
    button.className = 'copy-button';
    button.textContent = 'Copy';
    button.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 5px 10px;
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 4px;
        color: white;
        cursor: pointer;
        font-size: 0.8rem;
        transition: all 0.3s ease;
    `;

    button.addEventListener('click', () => {
        const code = block.textContent;
        navigator.clipboard.writeText(code).then(() => {
            button.textContent = 'Copied!';
            setTimeout(() => {
                button.textContent = 'Copy';
            }, 2000);
        });
    });

    button.addEventListener('mouseenter', () => {
        button.style.background = 'rgba(255, 255, 255, 0.2)';
    });

    button.addEventListener('mouseleave', () => {
        button.style.background = 'rgba(255, 255, 255, 0.1)';
    });

    block.parentElement.appendChild(button);
});

// Stats counter animation
const animateValue = (element, start, end, duration) => {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const value = Math.floor(progress * (end - start) + start);
        element.textContent = value + (end === 100 ? '%' : '+');
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
};

// Observe stats section
const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            document.querySelectorAll('.stat-number').forEach((stat, index) => {
                const text = stat.textContent;
                if (text.includes('+')) {
                    const num = parseInt(text);
                    stat.textContent = '0+';
                    setTimeout(() => animateValue(stat, 0, num, 2000), index * 100);
                } else if (text.includes('%')) {
                    stat.textContent = '0%';
                    setTimeout(() => animateValue(stat, 0, 100, 2000), index * 100);
                }
            });
            statsObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

const statsSection = document.querySelector('.stats');
if (statsSection) {
    statsObserver.observe(statsSection);
}

// Parallax effect for hero background
let ticking = false;
window.addEventListener('scroll', () => {
    if (!ticking) {
        window.requestAnimationFrame(() => {
            const scrolled = window.pageYOffset;
            const heroBackground = document.querySelector('.hero-background');
            if (heroBackground && scrolled < window.innerHeight) {
                heroBackground.style.transform = `translateY(${scrolled * 0.5}px)`;
            }
            ticking = false;
        });
        ticking = true;
    }
});

// Mouse tracking effect for workflow steps
document.querySelectorAll('.workflow-step').forEach(step => {
    step.addEventListener('mousemove', (e) => {
        const rect = step.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        const centerX = rect.width / 2;
        const centerY = rect.height / 2;

        const rotateX = (y - centerY) / 20;
        const rotateY = (centerX - x) / 20;

        step.style.transform = `translateY(-10px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    });

    step.addEventListener('mouseleave', () => {
        step.style.transform = '';
    });
});

// Enhanced cursor effect for feature and doc cards
const createRipple = (e, card) => {
    const ripple = document.createElement('div');
    const rect = card.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;

    ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(99, 102, 241, 0.3), transparent);
        left: ${x}px;
        top: ${y}px;
        pointer-events: none;
        transform: scale(0);
        animation: rippleEffect 0.6s ease-out;
    `;

    card.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
};

// Add ripple effect styles
if (!document.querySelector('#ripple-animation')) {
    const style = document.createElement('style');
    style.id = 'ripple-animation';
    style.textContent = `
        @keyframes rippleEffect {
            to {
                transform: scale(2);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
}

document.querySelectorAll('.feature-card, .doc-card').forEach(card => {
    card.addEventListener('mouseenter', (e) => createRipple(e, card));
});

// Animated gradient background for unified platform section
const unifiedPlatform = document.querySelector('.unified-platform');
if (unifiedPlatform) {
    let hue = 0;
    setInterval(() => {
        hue = (hue + 0.5) % 360;
        const before = window.getComputedStyle(unifiedPlatform, '::before');
        // Subtle hue rotation for ambient glow effect
    }, 50);
}

// Console easter egg
console.log('%c🐧 LWS - Linux Web Services', 'font-size: 20px; font-weight: bold; color: #6366f1;');
console.log('%cInterested in contributing? Check out https://github.com/fabriziosalmi/lws', 'font-size: 12px; color: #6b7280;');
console.log('%c✨ Wow, you found the console! You must be a developer. We love developers!', 'font-size: 14px; color: #ec4899;');
