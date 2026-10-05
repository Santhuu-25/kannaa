// CodeShield Security Review Suite Client Logic

document.addEventListener('DOMContentLoaded', function () {
  console.log('CodeShield Security Audit Suite Initialized.');

  // Theme Toggle (Light / Dark Mode)
  const themeBtn = document.getElementById('theme-toggle-btn');
  const htmlEl = document.documentElement;

  // Restore saved theme or default to light
  const savedTheme = localStorage.getItem('codeshield_theme') || 'light';
  htmlEl.setAttribute('data-theme', savedTheme);
  updateThemeButton(savedTheme);

  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      const currentTheme = htmlEl.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      htmlEl.setAttribute('data-theme', newTheme);
      localStorage.setItem('codeshield_theme', newTheme);
      updateThemeButton(newTheme);
    });
  }

  function updateThemeButton(theme) {
    if (!themeBtn) return;
    if (theme === 'dark') {
      themeBtn.innerHTML = '☀️ Light Mode';
    } else {
      themeBtn.innerHTML = '🌙 Dark Mode';
    }
  }

  // Interactive Severity Filter for Vulnerability Findings
  const filterBtns = document.querySelectorAll('.filter-btn');
  const findingCards = document.querySelectorAll('.finding-card');

  if (filterBtns.length > 0) {
    filterBtns.forEach(btn => {
      btn.addEventListener('click', function () {
        filterBtns.forEach(b => b.classList.remove('active'));
        this.classList.add('active');

        const filter = this.getAttribute('data-filter');

        findingCards.forEach(card => {
          const severity = card.getAttribute('data-severity');
          if (filter === 'all' || severity === filter) {
            card.style.display = 'block';
          } else {
            card.style.display = 'none';
          }
        });
      });
    });
  }
});
