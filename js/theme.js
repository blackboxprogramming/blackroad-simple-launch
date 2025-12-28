/**
 * BlackRoad OS - Theme System
 * Dark/Light mode toggle with system preference detection
 */

(function() {
  'use strict';

  const STORAGE_KEY = 'blackroad-theme';
  const THEMES = {
    DARK: 'dark',
    LIGHT: 'light',
    SYSTEM: 'system'
  };

  // Theme CSS variables
  const darkTheme = {
    '--bg-primary': '#0f172a',
    '--bg-secondary': '#1e293b',
    '--bg-tertiary': 'rgba(30, 41, 59, 0.5)',
    '--bg-card': 'rgba(30, 41, 59, 0.8)',
    '--text-primary': '#e2e8f0',
    '--text-secondary': '#94a3b8',
    '--text-muted': '#64748b',
    '--border-color': 'rgba(255, 255, 255, 0.1)',
    '--accent-primary': '#667eea',
    '--accent-secondary': '#764ba2',
    '--success': '#10b981',
    '--warning': '#f59e0b',
    '--danger': '#ef4444',
    '--shadow': '0 10px 30px rgba(0, 0, 0, 0.3)'
  };

  const lightTheme = {
    '--bg-primary': '#f8fafc',
    '--bg-secondary': '#ffffff',
    '--bg-tertiary': 'rgba(241, 245, 249, 0.8)',
    '--bg-card': '#ffffff',
    '--text-primary': '#1e293b',
    '--text-secondary': '#475569',
    '--text-muted': '#94a3b8',
    '--border-color': 'rgba(0, 0, 0, 0.1)',
    '--accent-primary': '#667eea',
    '--accent-secondary': '#764ba2',
    '--success': '#10b981',
    '--warning': '#f59e0b',
    '--danger': '#ef4444',
    '--shadow': '0 10px 30px rgba(0, 0, 0, 0.1)'
  };

  class ThemeManager {
    constructor() {
      this.currentTheme = this.getSavedTheme() || THEMES.SYSTEM;
      this.init();
    }

    init() {
      this.applyTheme(this.currentTheme);
      this.setupSystemThemeListener();
      this.injectToggleStyles();
    }

    getSavedTheme() {
      try {
        return localStorage.getItem(STORAGE_KEY);
      } catch (e) {
        return null;
      }
    }

    saveTheme(theme) {
      try {
        localStorage.setItem(STORAGE_KEY, theme);
      } catch (e) {
        console.warn('Could not save theme preference');
      }
    }

    getEffectiveTheme() {
      if (this.currentTheme === THEMES.SYSTEM) {
        return window.matchMedia('(prefers-color-scheme: dark)').matches
          ? THEMES.DARK
          : THEMES.LIGHT;
      }
      return this.currentTheme;
    }

    applyTheme(theme) {
      this.currentTheme = theme;
      this.saveTheme(theme);

      const effectiveTheme = this.getEffectiveTheme();
      const variables = effectiveTheme === THEMES.DARK ? darkTheme : lightTheme;

      // Apply CSS variables
      const root = document.documentElement;
      Object.entries(variables).forEach(([key, value]) => {
        root.style.setProperty(key, value);
      });

      // Set data attribute for CSS selectors
      document.body.setAttribute('data-theme', effectiveTheme);

      // Dispatch event for other components
      window.dispatchEvent(new CustomEvent('themechange', {
        detail: { theme: effectiveTheme }
      }));

      // Update toggle button if exists
      this.updateToggleButton();
    }

    toggle() {
      const effectiveTheme = this.getEffectiveTheme();
      const newTheme = effectiveTheme === THEMES.DARK ? THEMES.LIGHT : THEMES.DARK;
      this.applyTheme(newTheme);
      return newTheme;
    }

    setTheme(theme) {
      if (Object.values(THEMES).includes(theme)) {
        this.applyTheme(theme);
      }
    }

    setupSystemThemeListener() {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      mediaQuery.addEventListener('change', () => {
        if (this.currentTheme === THEMES.SYSTEM) {
          this.applyTheme(THEMES.SYSTEM);
        }
      });
    }

    updateToggleButton() {
      const toggleBtn = document.getElementById('theme-toggle');
      if (toggleBtn) {
        const effectiveTheme = this.getEffectiveTheme();
        toggleBtn.innerHTML = effectiveTheme === THEMES.DARK ? '☀️' : '🌙';
        toggleBtn.title = effectiveTheme === THEMES.DARK
          ? 'Switch to light mode'
          : 'Switch to dark mode';
      }
    }

    injectToggleStyles() {
      const style = document.createElement('style');
      style.textContent = `
        .theme-toggle {
          position: fixed;
          bottom: 20px;
          left: 20px;
          width: 50px;
          height: 50px;
          border-radius: 50%;
          border: none;
          background: var(--bg-card, #1e293b);
          color: var(--text-primary, #e2e8f0);
          font-size: 1.5rem;
          cursor: pointer;
          box-shadow: var(--shadow, 0 10px 30px rgba(0,0,0,0.3));
          transition: all 0.3s ease;
          z-index: 9999;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .theme-toggle:hover {
          transform: scale(1.1);
        }

        .theme-toggle:active {
          transform: scale(0.95);
        }

        /* Smooth transitions for theme changes */
        body, body * {
          transition: background-color 0.3s ease, color 0.2s ease, border-color 0.2s ease;
        }

        /* Light theme specific overrides */
        body[data-theme="light"] {
          background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        }

        body[data-theme="light"] .sidebar,
        body[data-theme="light"] .settings-sidebar {
          background: rgba(255, 255, 255, 0.9);
          border-color: rgba(0, 0, 0, 0.1);
        }

        body[data-theme="light"] .stat-card,
        body[data-theme="light"] .chart-card,
        body[data-theme="light"] .settings-card,
        body[data-theme="light"] .section,
        body[data-theme="light"] .team-section,
        body[data-theme="light"] .member-card,
        body[data-theme="light"] .webhook-card,
        body[data-theme="light"] .project-card {
          background: rgba(255, 255, 255, 0.9);
          border-color: rgba(0, 0, 0, 0.1);
        }

        body[data-theme="light"] input,
        body[data-theme="light"] select,
        body[data-theme="light"] textarea {
          background: rgba(241, 245, 249, 0.8);
          border-color: rgba(0, 0, 0, 0.1);
          color: #1e293b;
        }

        body[data-theme="light"] .nav-item {
          color: #475569;
        }

        body[data-theme="light"] .nav-item:hover {
          background: rgba(102, 126, 234, 0.1);
          color: #1e293b;
        }

        body[data-theme="light"] .nav-item.active {
          background: rgba(102, 126, 234, 0.15);
          color: #667eea;
        }

        body[data-theme="light"] .btn-secondary {
          background: rgba(0, 0, 0, 0.05);
          color: #475569;
        }

        body[data-theme="light"] .btn-secondary:hover {
          background: rgba(0, 0, 0, 0.1);
        }

        body[data-theme="light"] code,
        body[data-theme="light"] pre {
          background: rgba(241, 245, 249, 0.8);
        }

        body[data-theme="light"] .modal {
          background: #ffffff;
        }
      `;
      document.head.appendChild(style);
    }

    createToggleButton() {
      const btn = document.createElement('button');
      btn.id = 'theme-toggle';
      btn.className = 'theme-toggle';
      btn.title = 'Toggle theme';
      btn.innerHTML = this.getEffectiveTheme() === THEMES.DARK ? '☀️' : '🌙';
      btn.onclick = () => this.toggle();
      document.body.appendChild(btn);
      return btn;
    }
  }

  // Initialize and expose globally
  window.ThemeManager = ThemeManager;
  window.themeManager = new ThemeManager();

  // Auto-create toggle button when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      window.themeManager.createToggleButton();
    });
  } else {
    window.themeManager.createToggleButton();
  }
})();
