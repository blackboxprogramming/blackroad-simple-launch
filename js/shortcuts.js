/**
 * BlackRoad OS - Keyboard Shortcuts
 * Power user keyboard navigation and commands
 */

(function() {
  'use strict';

  const SHORTCUTS = {
    // Navigation
    'g d': { action: () => navigate('/dashboard.html'), description: 'Go to Dashboard' },
    'g a': { action: () => navigate('/analytics.html'), description: 'Go to Analytics' },
    'g t': { action: () => navigate('/team.html'), description: 'Go to Team' },
    'g w': { action: () => navigate('/webhooks.html'), description: 'Go to Webhooks' },
    'g p': { action: () => navigate('/projects.html'), description: 'Go to Projects' },
    'g s': { action: () => navigate('/settings.html'), description: 'Go to Settings' },
    'g h': { action: () => navigate('/'), description: 'Go Home' },

    // Actions
    'c p': { action: () => triggerAction('create-project'), description: 'Create Project' },
    'c t': { action: () => triggerAction('create-team'), description: 'Invite Team Member' },
    'c w': { action: () => triggerAction('create-webhook'), description: 'Create Webhook' },

    // Quick actions
    '/': { action: () => focusSearch(), description: 'Focus Search' },
    'Escape': { action: () => closeModals(), description: 'Close Modal' },
    '?': { action: () => showShortcutsHelp(), description: 'Show Shortcuts' },

    // Theme
    't t': { action: () => window.themeManager?.toggle(), description: 'Toggle Theme' },

    // Misc
    'r r': { action: () => window.location.reload(), description: 'Refresh Page' },
    'Ctrl+k': { action: () => showCommandPalette(), description: 'Command Palette' },
    'Ctrl+/': { action: () => showShortcutsHelp(), description: 'Show Shortcuts' }
  };

  let keySequence = [];
  let sequenceTimeout = null;
  let isInputFocused = false;
  let commandPaletteVisible = false;

  function init() {
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('focusin', handleFocusIn);
    document.addEventListener('focusout', handleFocusOut);
    injectStyles();
  }

  function handleFocusIn(e) {
    const tag = e.target.tagName.toLowerCase();
    isInputFocused = ['input', 'textarea', 'select'].includes(tag) ||
                     e.target.isContentEditable;
  }

  function handleFocusOut() {
    isInputFocused = false;
  }

  function handleKeyDown(e) {
    // Allow Ctrl/Cmd shortcuts even in inputs
    const hasModifier = e.ctrlKey || e.metaKey;

    // Check for Ctrl+K (command palette)
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      showCommandPalette();
      return;
    }

    // Skip if in input (unless Escape)
    if (isInputFocused && e.key !== 'Escape') {
      return;
    }

    // Skip if modal input is focused
    if (commandPaletteVisible && e.key !== 'Escape') {
      return;
    }

    const key = e.key;

    // Handle single-key shortcuts
    if (SHORTCUTS[key]) {
      e.preventDefault();
      SHORTCUTS[key].action();
      return;
    }

    // Handle Ctrl/Cmd shortcuts
    if (hasModifier) {
      const shortcutKey = `Ctrl+${key}`;
      if (SHORTCUTS[shortcutKey]) {
        e.preventDefault();
        SHORTCUTS[shortcutKey].action();
        return;
      }
    }

    // Handle key sequences (e.g., 'g d' for go to dashboard)
    clearTimeout(sequenceTimeout);

    keySequence.push(key);
    const sequenceStr = keySequence.join(' ');

    if (SHORTCUTS[sequenceStr]) {
      e.preventDefault();
      SHORTCUTS[sequenceStr].action();
      keySequence = [];
      return;
    }

    // Check if any shortcut starts with current sequence
    const hasMatch = Object.keys(SHORTCUTS).some(s => s.startsWith(sequenceStr));
    if (!hasMatch) {
      keySequence = [];
    }

    // Reset sequence after timeout
    sequenceTimeout = setTimeout(() => {
      keySequence = [];
    }, 1000);
  }

  function navigate(path) {
    window.location.href = path;
  }

  function triggerAction(action) {
    // Try to find and click the corresponding button
    const btn = document.querySelector(`[data-action="${action}"]`) ||
                document.querySelector(`#${action}`) ||
                document.querySelector(`[onclick*="${action}"]`);

    if (btn) {
      btn.click();
    } else {
      // Dispatch custom event for the page to handle
      window.dispatchEvent(new CustomEvent('shortcut-action', {
        detail: { action }
      }));
    }
  }

  function focusSearch() {
    const search = document.querySelector('input[type="search"]') ||
                   document.querySelector('input[placeholder*="Search"]') ||
                   document.querySelector('#search');
    if (search) {
      search.focus();
      search.select();
    }
  }

  function closeModals() {
    // Close command palette
    const palette = document.getElementById('command-palette');
    if (palette) {
      palette.remove();
      commandPaletteVisible = false;
      return;
    }

    // Close any open modals
    document.querySelectorAll('.modal-overlay.active').forEach(modal => {
      modal.classList.remove('active');
    });

    // Try to find close buttons
    const closeBtn = document.querySelector('.modal-close') ||
                     document.querySelector('[onclick*="closeModal"]');
    if (closeBtn) {
      closeBtn.click();
    }
  }

  function showShortcutsHelp() {
    // Remove existing if present
    const existing = document.getElementById('shortcuts-help');
    if (existing) {
      existing.remove();
      return;
    }

    const helpHtml = `
      <div id="shortcuts-help" class="shortcuts-modal">
        <div class="shortcuts-content">
          <div class="shortcuts-header">
            <h2>⌨️ Keyboard Shortcuts</h2>
            <button onclick="this.parentElement.parentElement.parentElement.remove()">×</button>
          </div>
          <div class="shortcuts-body">
            <div class="shortcuts-section">
              <h3>Navigation</h3>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>d</kbd> <span>Dashboard</span></div>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>a</kbd> <span>Analytics</span></div>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>t</kbd> <span>Team</span></div>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>w</kbd> <span>Webhooks</span></div>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>p</kbd> <span>Projects</span></div>
              <div class="shortcut-item"><kbd>g</kbd> <kbd>s</kbd> <span>Settings</span></div>
            </div>
            <div class="shortcuts-section">
              <h3>Actions</h3>
              <div class="shortcut-item"><kbd>c</kbd> <kbd>p</kbd> <span>Create Project</span></div>
              <div class="shortcut-item"><kbd>c</kbd> <kbd>t</kbd> <span>Invite Member</span></div>
              <div class="shortcut-item"><kbd>c</kbd> <kbd>w</kbd> <span>Create Webhook</span></div>
              <div class="shortcut-item"><kbd>t</kbd> <kbd>t</kbd> <span>Toggle Theme</span></div>
            </div>
            <div class="shortcuts-section">
              <h3>General</h3>
              <div class="shortcut-item"><kbd>/</kbd> <span>Focus Search</span></div>
              <div class="shortcut-item"><kbd>Ctrl</kbd> <kbd>K</kbd> <span>Command Palette</span></div>
              <div class="shortcut-item"><kbd>Esc</kbd> <span>Close Modal</span></div>
              <div class="shortcut-item"><kbd>?</kbd> <span>Show Shortcuts</span></div>
              <div class="shortcut-item"><kbd>r</kbd> <kbd>r</kbd> <span>Refresh</span></div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', helpHtml);

    // Close on click outside
    document.getElementById('shortcuts-help').addEventListener('click', (e) => {
      if (e.target.id === 'shortcuts-help') {
        e.target.remove();
      }
    });
  }

  function showCommandPalette() {
    // Remove existing if present
    const existing = document.getElementById('command-palette');
    if (existing) {
      existing.remove();
      commandPaletteVisible = false;
      return;
    }

    const commands = [
      { icon: '📊', name: 'Go to Dashboard', action: () => navigate('/dashboard.html') },
      { icon: '📈', name: 'Go to Analytics', action: () => navigate('/analytics.html') },
      { icon: '👥', name: 'Go to Team', action: () => navigate('/team.html') },
      { icon: '🔗', name: 'Go to Webhooks', action: () => navigate('/webhooks.html') },
      { icon: '📁', name: 'Go to Projects', action: () => navigate('/projects.html') },
      { icon: '⚙️', name: 'Go to Settings', action: () => navigate('/settings.html') },
      { icon: '📚', name: 'Go to Docs', action: () => navigate('/docs.html') },
      { icon: '➕', name: 'Create Project', action: () => triggerAction('create-project') },
      { icon: '📧', name: 'Invite Team Member', action: () => triggerAction('create-team') },
      { icon: '🔗', name: 'Create Webhook', action: () => triggerAction('create-webhook') },
      { icon: '🌓', name: 'Toggle Theme', action: () => window.themeManager?.toggle() },
      { icon: '🔄', name: 'Refresh Page', action: () => window.location.reload() },
      { icon: '⌨️', name: 'Show Shortcuts', action: () => showShortcutsHelp() },
      { icon: '🚪', name: 'Logout', action: () => { window.BlackRoadSDK?.auth?.logout(); navigate('/login.html'); } }
    ];

    const paletteHtml = `
      <div id="command-palette" class="command-palette">
        <div class="command-palette-content">
          <input type="text" id="command-search" placeholder="Type a command..." autofocus>
          <div class="command-list" id="command-list">
            ${commands.map((cmd, i) => `
              <div class="command-item" data-index="${i}">
                <span class="command-icon">${cmd.icon}</span>
                <span class="command-name">${cmd.name}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', paletteHtml);
    commandPaletteVisible = true;

    const palette = document.getElementById('command-palette');
    const search = document.getElementById('command-search');
    const list = document.getElementById('command-list');
    let selectedIndex = 0;

    // Filter commands
    search.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      const items = list.querySelectorAll('.command-item');
      items.forEach((item, i) => {
        const name = commands[i].name.toLowerCase();
        item.style.display = name.includes(query) ? 'flex' : 'none';
      });
      selectedIndex = 0;
      updateSelection();
    });

    // Keyboard navigation
    search.addEventListener('keydown', (e) => {
      const visibleItems = Array.from(list.querySelectorAll('.command-item'))
        .filter(item => item.style.display !== 'none');

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIndex = Math.min(selectedIndex + 1, visibleItems.length - 1);
        updateSelection();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIndex = Math.max(selectedIndex - 1, 0);
        updateSelection();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (visibleItems[selectedIndex]) {
          const index = visibleItems[selectedIndex].dataset.index;
          palette.remove();
          commandPaletteVisible = false;
          commands[index].action();
        }
      } else if (e.key === 'Escape') {
        palette.remove();
        commandPaletteVisible = false;
      }
    });

    function updateSelection() {
      const items = list.querySelectorAll('.command-item');
      items.forEach((item, i) => {
        item.classList.toggle('selected', i === selectedIndex);
      });
    }

    // Click to execute
    list.addEventListener('click', (e) => {
      const item = e.target.closest('.command-item');
      if (item) {
        const index = item.dataset.index;
        palette.remove();
        commandPaletteVisible = false;
        commands[index].action();
      }
    });

    // Close on click outside
    palette.addEventListener('click', (e) => {
      if (e.target === palette) {
        palette.remove();
        commandPaletteVisible = false;
      }
    });

    updateSelection();
  }

  function injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .shortcuts-modal {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        animation: fadeIn 0.2s ease;
      }

      .shortcuts-content {
        background: var(--bg-secondary, #1e293b);
        border: 1px solid var(--border-color, rgba(255,255,255,0.1));
        border-radius: 16px;
        width: 100%;
        max-width: 600px;
        max-height: 80vh;
        overflow: hidden;
      }

      .shortcuts-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 20px 25px;
        border-bottom: 1px solid var(--border-color, rgba(255,255,255,0.1));
      }

      .shortcuts-header h2 {
        font-size: 1.3rem;
        color: var(--text-primary, #e2e8f0);
      }

      .shortcuts-header button {
        background: none;
        border: none;
        color: var(--text-muted, #64748b);
        font-size: 1.5rem;
        cursor: pointer;
      }

      .shortcuts-body {
        padding: 20px 25px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 25px;
        overflow-y: auto;
        max-height: 60vh;
      }

      .shortcuts-section h3 {
        font-size: 0.85rem;
        text-transform: uppercase;
        color: var(--text-muted, #64748b);
        margin-bottom: 15px;
        letter-spacing: 0.05em;
      }

      .shortcut-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 0;
        color: var(--text-secondary, #94a3b8);
        font-size: 0.9rem;
      }

      .shortcut-item kbd {
        background: var(--bg-tertiary, rgba(30,41,59,0.5));
        padding: 4px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.8rem;
        border: 1px solid var(--border-color, rgba(255,255,255,0.1));
      }

      .shortcut-item span {
        margin-left: auto;
        color: var(--text-muted, #64748b);
      }

      /* Command Palette */
      .command-palette {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: flex-start;
        justify-content: center;
        padding-top: 15vh;
        z-index: 10000;
        animation: fadeIn 0.15s ease;
      }

      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      .command-palette-content {
        background: var(--bg-secondary, #1e293b);
        border: 1px solid var(--border-color, rgba(255,255,255,0.1));
        border-radius: 12px;
        width: 100%;
        max-width: 500px;
        overflow: hidden;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      }

      .command-palette-content input {
        width: 100%;
        padding: 18px 20px;
        background: transparent;
        border: none;
        border-bottom: 1px solid var(--border-color, rgba(255,255,255,0.1));
        color: var(--text-primary, #e2e8f0);
        font-size: 1.1rem;
        outline: none;
      }

      .command-list {
        max-height: 400px;
        overflow-y: auto;
      }

      .command-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 20px;
        cursor: pointer;
        transition: background 0.1s;
      }

      .command-item:hover,
      .command-item.selected {
        background: var(--bg-tertiary, rgba(102, 126, 234, 0.1));
      }

      .command-icon {
        font-size: 1.2rem;
      }

      .command-name {
        color: var(--text-primary, #e2e8f0);
        font-size: 0.95rem;
      }
    `;
    document.head.appendChild(style);
  }

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose for external use
  window.KeyboardShortcuts = {
    showHelp: showShortcutsHelp,
    showCommandPalette: showCommandPalette
  };
})();
