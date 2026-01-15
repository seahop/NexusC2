// Navigation and UI interactions

document.addEventListener('DOMContentLoaded', () => {
  // Smooth scroll for anchor links
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

  // Code block copy functionality
  document.querySelectorAll('pre code').forEach(codeBlock => {
    const wrapper = codeBlock.closest('.code-block') || codeBlock.closest('pre').parentElement;

    if (wrapper && !wrapper.querySelector('.copy-button')) {
      const button = document.createElement('button');
      button.className = 'copy-button';
      button.textContent = 'Copy';

      button.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(codeBlock.textContent);
          button.textContent = 'Copied!';
          button.classList.add('text-nexus-green-500');
          setTimeout(() => {
            button.textContent = 'Copy';
            button.classList.remove('text-nexus-green-500');
          }, 2000);
        } catch (err) {
          button.textContent = 'Failed';
          setTimeout(() => {
            button.textContent = 'Copy';
          }, 2000);
        }
      });

      // Make pre relative for absolute positioning of button
      const pre = codeBlock.closest('pre');
      if (pre) {
        pre.style.position = 'relative';
        pre.appendChild(button);
      }
    }
  });

  // Active navigation highlighting based on scroll
  const sections = document.querySelectorAll('h2[id], h3[id]');
  const navLinks = document.querySelectorAll('.sidebar-link');

  if (sections.length > 0 && navLinks.length > 0) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const id = entry.target.getAttribute('id');
            navLinks.forEach(link => {
              if (link.getAttribute('href') === `#${id}`) {
                link.classList.add('sidebar-link-active');
              } else {
                link.classList.remove('sidebar-link-active');
              }
            });
          }
        });
      },
      {
        rootMargin: '-100px 0px -66%',
        threshold: 0
      }
    );

    sections.forEach(section => observer.observe(section));
  }

  // Table wrapper for horizontal scroll on mobile
  document.querySelectorAll('table').forEach(table => {
    if (!table.closest('.table-wrapper')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'table-wrapper';
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  });

  // External link handling
  document.querySelectorAll('a[href^="http"]').forEach(link => {
    if (!link.host.includes(window.location.host)) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer');
    }
  });
});

// Command filtering functionality (for commands page)
function initCommandFilter() {
  const filterButtons = document.querySelectorAll('[data-filter]');
  const commandCards = document.querySelectorAll('[data-category]');

  if (filterButtons.length === 0 || commandCards.length === 0) return;

  filterButtons.forEach(button => {
    button.addEventListener('click', () => {
      const filter = button.dataset.filter;

      // Update active button state
      filterButtons.forEach(btn => btn.classList.remove('bg-nexus-green-500', 'text-black'));
      button.classList.add('bg-nexus-green-500', 'text-black');

      // Filter cards
      commandCards.forEach(card => {
        if (filter === 'all' || card.dataset.category === filter) {
          card.style.display = '';
          card.classList.add('animate-fade-in');
        } else {
          card.style.display = 'none';
        }
      });
    });
  });
}

// Command card expand/collapse
function initCommandCards() {
  document.querySelectorAll('.command-header').forEach(header => {
    header.addEventListener('click', () => {
      const card = header.closest('.command-card');
      const body = card.querySelector('.command-body');
      const icon = header.querySelector('.expand-icon');

      if (body.classList.contains('hidden')) {
        body.classList.remove('hidden');
        if (icon) icon.classList.add('rotate-180');
      } else {
        body.classList.add('hidden');
        if (icon) icon.classList.remove('rotate-180');
      }
    });
  });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initCommandFilter();
  initCommandCards();
});

// Back to top button
function initBackToTop() {
  const button = document.getElementById('back-to-top');
  if (!button) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 500) {
      button.classList.remove('opacity-0', 'pointer-events-none');
      button.classList.add('opacity-100');
    } else {
      button.classList.add('opacity-0', 'pointer-events-none');
      button.classList.remove('opacity-100');
    }
  });

  button.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

document.addEventListener('DOMContentLoaded', initBackToTop);
