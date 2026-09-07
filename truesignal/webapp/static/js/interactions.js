/**
 * TrueSignal UI Enhancements
 * Toasts, a loading overlay, and the taint-flow graph interaction --
 * everything here has an actual call site; nothing speculative.
 */
(function () {
  "use strict";

  // Toast Notifications System
  const Toast = {
    container: null,

    init() {
      if (!document.getElementById('toast-container')) {
        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
      } else {
        this.container = document.getElementById('toast-container');
      }
    },

    show(message, type = 'info', duration = 3000) {
      if (!this.container) this.init();

      const toast = document.createElement('div');
      toast.className = `toast ${type}`;

      const text = document.createElement('span');
      text.textContent = message;
      const closeBtn = document.createElement('button');
      closeBtn.className = 'toast-close';
      closeBtn.setAttribute('aria-label', 'Close');
      closeBtn.innerHTML = '&times;';
      toast.appendChild(text);
      toast.appendChild(closeBtn);

      this.container.appendChild(toast);

      let dismissed = false;
      const remove = () => {
        if (dismissed) return;
        dismissed = true;
        clearTimeout(autoDismiss);
        toast.classList.add('toast-leaving');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
      };

      closeBtn.addEventListener('click', remove);

      const autoDismiss = duration > 0 ? setTimeout(remove, duration) : null;

      return toast;
    },

    success(message, duration) {
      return this.show(message, 'success', duration);
    },

    error(message, duration) {
      return this.show(message, 'error', duration);
    },

    info(message, duration) {
      return this.show(message, 'info', duration);
    },

    warning(message, duration) {
      return this.show(message, 'warning', duration);
    }
  };

  // Loading State Manager
  const Loading = {
    show(message = 'Loading...') {
      let loader = document.getElementById('loader-overlay');
      if (!loader) {
        loader = document.createElement('div');
        loader.id = 'loader-overlay';
        loader.className = 'modal-overlay active';
        loader.innerHTML = `
          <div style="text-align: center;">
            <div class="spinner" style="margin-bottom: 16px;"></div>
            <p style="color: var(--text-dim);">${message}</p>
          </div>
        `;
        document.body.appendChild(loader);
      }
      loader.style.display = 'flex';
      return loader;
    },

    hide() {
      const loader = document.getElementById('loader-overlay');
      if (loader) {
        loader.style.display = 'none';
      }
    }
  };

  // API Helper with automatic loading states
  const API = {
    async request(url, options = {}) {
      const showLoading = options.showLoading !== false;
      if (showLoading) {
        Loading.show(options.loadingMessage || 'Loading...');
      }

      try {
        const response = await fetch(url, {
          method: options.method || 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...options.headers
          },
          body: options.body ? JSON.stringify(options.body) : undefined
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (showLoading) Loading.hide();

        if (options.onSuccess) {
          options.onSuccess(data);
        }

        return data;
      } catch (error) {
        if (showLoading) Loading.hide();
        Toast.error(error.message || 'Request failed');
        if (options.onError) {
          options.onError(error);
        }
        throw error;
      }
    },

    get(url, options = {}) {
      return this.request(url, { ...options, method: 'GET' });
    },

    post(url, body, options = {}) {
      return this.request(url, { ...options, method: 'POST', body });
    },

    put(url, body, options = {}) {
      return this.request(url, { ...options, method: 'PUT', body });
    },

    delete(url, options = {}) {
      return this.request(url, { ...options, method: 'DELETE' });
    }
  };

  // Utility: Copy to Clipboard
  const Clipboard = {
    copy(text) {
      navigator.clipboard.writeText(text).then(() => {
        Toast.success('Copied to clipboard');
      }).catch(() => {
        Toast.error('Failed to copy');
      });
    }
  };

  // Utility: Format Numbers
  const Format = {
    number(num) {
      return Number(num).toLocaleString();
    },

    percent(num, total) {
      if (total === 0) return '0%';
      return Math.round((num / total) * 100) + '%';
    },

    date(dateStr) {
      const date = new Date(dateStr);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    },

    time(milliseconds) {
      const seconds = Math.floor(milliseconds / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);

      if (hours > 0) return hours + 'h ' + (minutes % 60) + 'm';
      if (minutes > 0) return minutes + 'm ' + (seconds % 60) + 's';
      return seconds + 's';
    }
  };

  // Taint-flow graph (audit page): click a node in the graph to show its
  // code panel and highlight it; the rest of the app never depends on this,
  // so it's a no-op on any page without a #flow-graph.
  const FlowGraph = {
    init() {
      const graph = document.getElementById('flow-graph');
      if (!graph) return;
      const nodes = Array.from(graph.querySelectorAll('.flow-node'));
      nodes.forEach((node) => {
        node.addEventListener('click', () => this.select(nodes, node));
      });
    },

    select(nodes, selected) {
      nodes.forEach((node) => {
        const isSelected = node === selected;
        node.classList.toggle('active', isSelected);
        node.setAttribute('aria-expanded', String(isSelected));
        const panel = document.getElementById('flow-panel-' + node.dataset.flowIndex);
        if (panel) panel.hidden = !isSelected;
      });
    }
  };

  // Predefined-comment picker (audit page): "Browse comment bank" opens the
  // picker as a real separate page/tab (comment_bank_picker.html), not a
  // modal, so a reviewer can keep the audit page open side by side. Picking
  // a comment there posts it back to this window and closes itself; this
  // listener applies it to the audit comment textarea and syncs the
  // decision select, so a "confirmed" canned comment can't end up saved
  // under a mismatched decision. A no-op on any page without the picker.
  const CommentBankPicker = {
    MESSAGE_TYPE: 'truesignal-comment-bank-selection',

    init() {
      const openLink = document.getElementById('open-comment-bank-btn');
      if (!openLink) return;

      const textarea = document.getElementById('comment-textarea');
      const decision = document.querySelector('select[name="decision"]');
      const selectedLabel = document.getElementById('comment-bank-selected');

      window.addEventListener('message', (event) => {
        if (event.origin !== window.location.origin) return;
        const data = event.data;
        if (!data || data.type !== CommentBankPicker.MESSAGE_TYPE) return;
        if (textarea) textarea.value = data.text;
        if (decision && data.decision) decision.value = data.decision;
        if (selectedLabel) selectedLabel.textContent = 'Selected: ' + data.label;
      });
    }
  };

  // Comment-bank picker page itself (comment_bank_picker.html): clicking
  // "Use this comment" hands the comment back to the audit tab that opened
  // this page via window.opener, then closes this tab. A no-op on any page
  // without these buttons (i.e. everywhere except that page).
  const CommentBankBrowsePage = {
    init() {
      const buttons = document.querySelectorAll('.comment-bank-use-btn');
      if (!buttons.length || !window.opener) return;

      buttons.forEach((btn) => {
        btn.addEventListener('click', () => {
          window.opener.postMessage({
            type: CommentBankPicker.MESSAGE_TYPE,
            text: btn.dataset.text,
            decision: btn.dataset.decision,
            label: btn.dataset.label
          }, window.location.origin);
          window.close();
        });
      });
    }
  };

  // Export to global
  window.TrueSignal = {
    Toast,
    Loading,
    API,
    Clipboard,
    Format,
    FlowGraph,
    CommentBankPicker,
    CommentBankBrowsePage
  };

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', () => {
    Toast.init();
    FlowGraph.init();
    CommentBankPicker.init();
    CommentBankBrowsePage.init();
  });
})();
