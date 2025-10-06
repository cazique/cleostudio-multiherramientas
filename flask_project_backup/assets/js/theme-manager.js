// Gestor de Temas

class ThemeManager {
    constructor() {
        this.currentTheme = this.loadTheme();
        this.applyTheme(this.currentTheme);
        this.initToggleButton();
    }

    loadTheme() {
        return localStorage.getItem('theme') || 'light';
    }

    saveTheme(theme) {
        localStorage.setItem('theme', theme);
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        this.saveTheme(theme);
        this.updateToggleButton();
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }

    initToggleButton() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleTheme());
        }
    }

    updateToggleButton() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.innerHTML = this.currentTheme === 'light'
                ? '🌙 Modo Oscuro'
                : '☀️ Modo Claro';
        }
    }
}

// Inicializar al cargar la página
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
});
