(function() {
  const getTheme = () => localStorage.getItem('theme') || 'dark';
  const setTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateIcon(theme);
    // Dispatch a custom event so other scripts can react if needed
    window.dispatchEvent(new Event('themeChanged'));
  };

  const updateIcon = (theme) => {
    const icon = document.getElementById('themeIcon');
    if (!icon) return;
    if (theme === 'light') {
      // Moon icon
      icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
    } else {
      // Sun icon
      icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
    }
  };

  // Initialize theme immediately to prevent flash
  const currentTheme = getTheme();
  document.documentElement.setAttribute('data-theme', currentTheme);

  // Expose toggle function
  window.toggleTheme = () => {
    const newTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
  };

  // Attach listener on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', () => {
    updateIcon(currentTheme);
    const btn = document.getElementById('themeToggle');
    if (btn) {
      btn.addEventListener('click', window.toggleTheme);
    }
  });
})();
