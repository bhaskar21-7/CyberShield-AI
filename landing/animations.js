/**
 * Counter Animations for Statistics Section
 * Animates numbers counting up to their target values
 */

class CounterAnimation {
    constructor(element, target, duration = 2000, isDecimal = false) {
        this.element = element;
        this.target = target;
        this.duration = duration;
        this.isDecimal = isDecimal;
        this.current = 0;
        this.hasAnimated = false;
    }

    start() {
        if (this.hasAnimated) return;
        
        const startTime = Date.now();
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / this.duration, 1);
            
            // Easing function (ease-out)
            const easeProgress = 1 - Math.pow(1 - progress, 3);
            this.current = Math.floor(this.target * easeProgress);
            
            let displayValue = this.current.toString();
            if (this.isDecimal && displayValue.length >= 4) {
                displayValue = displayValue.slice(0, -2) + '.' + displayValue.slice(-2);
            }
            
            this.element.textContent = displayValue;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                this.hasAnimated = true;
            }
        };
        
        requestAnimationFrame(animate);
    }
}

// Initialize counters when they come into view
function initializeCounters() {
    const counters = document.querySelectorAll('.stat-number');
    
    const observerOptions = {
        threshold: 0.5,
        rootMargin: '0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = parseInt(entry.target.dataset.target) || 0;
                const isDecimal = entry.target.classList.contains('counter-decimal');
                
                const counter = new CounterAnimation(entry.target, target, 2000, isDecimal);
                counter.start();
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    counters.forEach(counter => observer.observe(counter));
}

// Handle scroll animations for sections
function initializeScrollAnimations() {
    const animationElements = document.querySelectorAll(
        '.feature-card, .stat-card, .tech-category'
    );
    
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    animationElements.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        element.style.transition = 'all 0.6s ease-out';
        observer.observe(element);
    });
}

// Handle navbar scroll effect
function initializeNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// Smooth scroll for anchor links
function initializeSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                const offsetTop = targetElement.offsetTop - 80;
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Add parallax effect to hero section
function initializeParallax() {
    const hero = document.querySelector('.hero');
    const orbs = document.querySelectorAll('.glow-orb');
    
    window.addEventListener('mousemove', (e) => {
        const x = e.clientX / window.innerWidth;
        const y = e.clientY / window.innerHeight;
        
        orbs.forEach((orb, index) => {
            const moveX = (x - 0.5) * 20 * (index + 1);
            const moveY = (y - 0.5) * 20 * (index + 1);
            orb.style.transform = `translate(${moveX}px, ${moveY}px)`;
        });
    });
}

// Button ripple effect
function initializeButtonRipples() {
    const buttons = document.querySelectorAll('.btn');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const ripple = document.createElement('span');
            ripple.style.position = 'absolute';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.style.width = '0';
            ripple.style.height = '0';
            ripple.style.borderRadius = '50%';
            ripple.style.background = 'rgba(255, 255, 255, 0.6)';
            ripple.style.pointerEvents = 'none';
            ripple.style.transform = 'translate(-50%, -50%)';
            ripple.style.animation = 'ripple 0.6s ease-out';
            
            this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            
            setTimeout(() => ripple.remove(), 600);
        });
    });
}

// Add ripple animation keyframe
const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            width: 300px;
            height: 300px;
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Initialize all animations when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            initializeCounters();
            initializeScrollAnimations();
            initializeNavbarScroll();
            initializeSmoothScroll();
            initializeParallax();
            initializeButtonRipples();
        }, 100);
    });
} else {
    setTimeout(() => {
        initializeCounters();
        initializeScrollAnimations();
        initializeNavbarScroll();
        initializeSmoothScroll();
        initializeParallax();
        initializeButtonRipples();
    }, 100);
}