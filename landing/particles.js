/**
 * Particle System for Hero Background
 * Creates animated particles that float across the screen
 */

class ParticleSystem {
    constructor(container) {
        this.container = container;
        this.particles = [];
        this.particleCount = window.innerWidth > 768 ? 50 : 30;
        this.init();
        window.addEventListener('resize', () => this.handleResize());
    }

    init() {
        const canvas = document.createElement('canvas');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.position = 'absolute';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvas.style.zIndex = '1';
        this.container.appendChild(canvas);
        
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        
        // Create particles
        for (let i = 0; i < this.particleCount; i++) {
            this.particles.push(this.createParticle());
        }
        
        this.animate();
    }

    createParticle() {
        return {
            x: Math.random() * this.canvas.width,
            y: Math.random() * this.canvas.height,
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            radius: Math.random() * 1.5 + 0.5,
            opacity: Math.random() * 0.5 + 0.2,
            color: Math.random() > 0.5 ? '#00D9FF' : '#0969DA'
        };
    }

    animate() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.particles.forEach(particle => {
            // Update position
            particle.x += particle.vx;
            particle.y += particle.vy;
            
            // Wrap around edges
            if (particle.x < 0) particle.x = this.canvas.width;
            if (particle.x > this.canvas.width) particle.x = 0;
            if (particle.y < 0) particle.y = this.canvas.height;
            if (particle.y > this.canvas.height) particle.y = 0;
            
            // Draw particle
            this.ctx.fillStyle = particle.color;
            this.ctx.globalAlpha = particle.opacity;
            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
            this.ctx.fill();
            
            // Draw glow
            this.ctx.strokeStyle = particle.color;
            this.ctx.lineWidth = 0.5;
            this.ctx.globalAlpha = particle.opacity * 0.5;
            this.ctx.stroke();
        });
        
        this.ctx.globalAlpha = 1;
        requestAnimationFrame(() => this.animate());
    }

    handleResize() {
        const newWidth = window.innerWidth;
        const newHeight = window.innerHeight;
        
        if (this.canvas.width !== newWidth || this.canvas.height !== newHeight) {
            this.canvas.width = newWidth;
            this.canvas.height = newHeight;
            
            // Recreate particles on resize if count needs to change
            const newCount = newWidth > 768 ? 50 : 30;
            if (newCount !== this.particleCount) {
                this.particleCount = newCount;
                this.particles = [];
                for (let i = 0; i < this.particleCount; i++) {
                    this.particles.push(this.createParticle());
                }
            }
        }
    }
}

// Initialize particle system when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        const particlesContainer = document.getElementById('particles');
        if (particlesContainer) {
            new ParticleSystem(particlesContainer);
        }
    });
} else {
    const particlesContainer = document.getElementById('particles');
    if (particlesContainer) {
        new ParticleSystem(particlesContainer);
    }
}