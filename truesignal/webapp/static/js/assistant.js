/**
 * CxQL Assistant -- floating chat widget, present on every page once logged
 * in (see base.html). Backed by POST /api/assistant/chat (cxql_assistant.py),
 * grounded in the bundled CxQL API Guide.
 *
 * The panel itself always starts closed and only opens on an explicit tap of
 * the toggle button -- it never reopens itself. Message history still lives
 * in sessionStorage (tab-scoped, same idea as the existing localStorage theme
 * toggle) so a conversation survives this MPA's full page reloads between
 * navigations, but the open/closed state does not carry over. Per-page
 * "current finding" context is never persisted -- it's read fresh from
 * window.TS_ASSISTANT_CONTEXT (set per-page by base.html / audit.html) so it
 * never leaks from a page the user has since left.
 */
(function () {
  "use strict";

  const HISTORY_KEY = "ts-assistant-history";
  const SEEN_KEY = "ts-assistant-seen";
  const MAX_STORED_TURNS = 20;

  const QUICK_REPLIES = [
    "How do I find all SQL injection sinks?",
    "What does CxList.FindByName do?",
    "Suggest a query for this finding",
  ];

  const CAPABILITIES = [
    {
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="2"/><path d="M20 20l-3.2-3.2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      text: "Explain any CxQL / CxList method from the Checkmarx API Guide",
    },
    {
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M4 4h16v11H8l-4 4V4Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
      text: "Suggest a ready-to-use CxQL query, with a working example",
    },
    {
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 3v12M6 10l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 21h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      text: "Tailor a query to the real functions in a finding you're auditing",
    },
  ];

  function loadHistory() {
    try {
      return JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "[]");
    } catch (e) {
      return [];
    }
  }

  function saveHistory(history) {
    sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-MAX_STORED_TURNS)));
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function botAvatarSvg() {
    return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none">'
      + '<path d="M12 3.5c-4.7 0-8.5 3.1-8.5 7 0 2.16 1.19 4.1 3.06 5.4-.1.98-.42 2.02-1.1 3.02a.5.5 0 0 0 .58.76c1.6-.55 2.8-1.24 3.66-1.86.74.17 1.51.26 2.3.26 4.7 0 8.5-3.1 8.5-7.58s-3.8-7-8.5-7Z" fill="currentColor"/>'
      + '<circle cx="8.7" cy="10.5" r="1.1" fill="var(--accent)"/><circle cx="12" cy="10.5" r="1.1" fill="var(--accent)"/><circle cx="15.3" cy="10.5" r="1.1" fill="var(--accent)"/>'
      + "</svg>";
  }

  function init() {
    const root = document.getElementById("ts-assistant-root");
    if (!root) return;

    const toggleBtn = document.getElementById("ts-assistant-toggle");
    const ping = document.getElementById("ts-assistant-ping");
    const closeBtn = document.getElementById("ts-assistant-close");
    const clearBtn = document.getElementById("ts-assistant-clear");
    const panel = document.getElementById("ts-assistant-panel");
    const messagesEl = document.getElementById("ts-assistant-messages");
    const form = document.getElementById("ts-assistant-form");
    const input = document.getElementById("ts-assistant-input");

    if (sessionStorage.getItem(SEEN_KEY) === "1" && ping) ping.classList.add("is-dismissed");

    function renderWelcome() {
      const caps = CAPABILITIES.map((c) => `
        <li><span class="ts-assistant-cap-icon">${c.icon}</span><span>${escapeHtml(c.text)}</span></li>
      `).join("");
      const chips = QUICK_REPLIES.map((q) => `<button type="button" class="ts-assistant-chip" data-quick-reply="${escapeHtml(q)}">${escapeHtml(q)}</button>`).join("");
      const wrap = document.createElement("div");
      wrap.className = "ts-assistant-welcome";
      wrap.innerHTML = `
        <div class="ts-assistant-welcome-card">
          <div class="ts-assistant-welcome-avatar">${botAvatarSvg()}</div>
          <h4>Hi, I'm your CxQL Assistant</h4>
          <p>I'm grounded in the Checkmarx CxQL API Guide, so I can help you with:</p>
          <ul class="ts-assistant-capabilities">${caps}</ul>
          <p style="margin-bottom:8px">Try one of these, or ask me anything:</p>
          <div class="ts-assistant-chips">${chips}</div>
        </div>
      `;
      wrap.querySelectorAll("[data-quick-reply]").forEach((btn) => {
        btn.addEventListener("click", () => sendMessage(btn.dataset.quickReply));
      });
      messagesEl.appendChild(wrap);
    }

    function renderMessage(msg) {
      const row = document.createElement("div");
      row.className = "ts-assistant-msg ts-assistant-msg-" + msg.role;

      if (msg.role === "assistant") {
        const avatar = document.createElement("div");
        avatar.className = "ts-assistant-msg-avatar";
        avatar.innerHTML = botAvatarSvg();
        row.appendChild(avatar);
      }

      const col = document.createElement("div");
      col.className = "ts-assistant-msg-col";

      const bubble = document.createElement("div");
      bubble.className = "ts-assistant-bubble";
      bubble.innerHTML = escapeHtml(msg.content).replace(/\n/g, "<br>");
      col.appendChild(bubble);

      (msg.cxqlSnippets || []).forEach((snippet) => {
        const wrap = document.createElement("div");
        wrap.className = "ts-assistant-snippet-wrap";
        const pre = document.createElement("pre");
        pre.className = "snippet ts-assistant-snippet";
        pre.textContent = snippet;
        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "btn ts-assistant-copy-btn";
        copyBtn.textContent = "Copy query";
        copyBtn.addEventListener("click", () => {
          if (window.TrueSignal && window.TrueSignal.Clipboard) {
            window.TrueSignal.Clipboard.copy(snippet);
          } else {
            navigator.clipboard.writeText(snippet);
          }
        });
        wrap.appendChild(pre);
        wrap.appendChild(copyBtn);
        col.appendChild(wrap);
      });

      if (msg.sources && msg.sources.length) {
        const src = document.createElement("div");
        src.className = "ts-assistant-sources dim small";
        src.textContent = "Guide: " + msg.sources.map((s) => "p." + s.page + " " + s.heading).join(" · ");
        col.appendChild(src);
      }

      row.appendChild(col);
      messagesEl.appendChild(row);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function renderAll(history) {
      messagesEl.innerHTML = "";
      if (!history.length) {
        renderWelcome();
        return;
      }
      history.forEach(renderMessage);
    }

    function showTyping() {
      const row = document.createElement("div");
      row.className = "ts-assistant-msg ts-assistant-msg-assistant ts-assistant-typing";
      row.id = "ts-assistant-typing-row";
      const avatar = document.createElement("div");
      avatar.className = "ts-assistant-msg-avatar";
      avatar.innerHTML = botAvatarSvg();
      const col = document.createElement("div");
      col.className = "ts-assistant-msg-col";
      col.innerHTML = '<div class="ts-assistant-bubble"><span></span><span></span><span></span></div>';
      row.appendChild(avatar);
      row.appendChild(col);
      messagesEl.appendChild(row);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function hideTyping() {
      const row = document.getElementById("ts-assistant-typing-row");
      if (row) row.remove();
    }

    function setOpen(open) {
      panel.hidden = !open;
      toggleBtn.classList.toggle("is-open", open);
      toggleBtn.setAttribute("aria-expanded", String(open));
      if (open) {
        input.focus();
        if (ping) ping.classList.add("is-dismissed");
        sessionStorage.setItem(SEEN_KEY, "1");
      }
    }

    toggleBtn.addEventListener("click", () => setOpen(panel.hidden));
    closeBtn.addEventListener("click", () => setOpen(false));
    clearBtn.addEventListener("click", () => {
      saveHistory([]);
      renderAll([]);
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        form.requestSubmit();
      }
    });

    function sendMessage(message) {
      message = (message || "").trim();
      if (!message) return;

      const history = loadHistory();
      history.push({ role: "user", content: message });
      saveHistory(history);
      renderAll(history);
      input.value = "";
      showTyping();

      const apiHistory = history.slice(-9, -1).map((m) => ({ role: m.role, content: m.content }));

      const request = window.TrueSignal && window.TrueSignal.API
        ? window.TrueSignal.API.post("/api/assistant/chat",
            { message, history: apiHistory, context: window.TS_ASSISTANT_CONTEXT || null },
            { showLoading: false })
        : fetch("/api/assistant/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message, history: apiHistory, context: window.TS_ASSISTANT_CONTEXT || null }),
          }).then((r) => r.json());

      request
        .then((data) => {
          if (data.error) throw new Error(data.error);
          hideTyping();
          const updated = loadHistory();
          updated.push({
            role: "assistant",
            content: data.reply,
            cxqlSnippets: data.cxql_snippets || [],
            sources: data.sources || [],
          });
          saveHistory(updated);
          renderAll(updated);
        })
        .catch((err) => {
          hideTyping();
          const updated = loadHistory();
          updated.push({ role: "assistant", content: "Sorry -- " + (err.message || "something went wrong.") });
          saveHistory(updated);
          renderAll(updated);
        });
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      sendMessage(input.value);
    });

    // Always closed on load -- only an explicit tap of the toggle opens it.
    panel.hidden = true;
    renderAll(loadHistory());
  }

  document.addEventListener("DOMContentLoaded", init);
})();
