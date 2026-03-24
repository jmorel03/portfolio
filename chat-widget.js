(function () {
  const POLL_MS = 5000;

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatTime(value) {
    if (!value) {
      return '';
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '';
    }

    return parsed.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  }

  async function initChatWidget() {
    let me = null;
    try {
      const meResponse = await fetch('/api/me', { credentials: 'include' });
      if (!meResponse.ok) {
        return;
      }

      const meResult = await meResponse.json();
      me = meResult?.user || null;
      if (!me?.id) {
        return;
      }
    } catch {
      return;
    }

    const root = document.createElement('div');
    root.className = 'chat-widget-root';
    root.innerHTML = `
      <div class="chat-widget-panel hidden" aria-label="Chat panel">
        <div class="chat-widget-header">
          <span class="chat-widget-title">Team Chat</span>
          <button class="chat-widget-close" type="button" aria-label="Close chat">✕</button>
        </div>
        <div class="chat-widget-messages">
          <div class="chat-widget-empty">Loading messages...</div>
        </div>
        <form class="chat-widget-form">
          <input class="chat-widget-input" maxlength="800" placeholder="Type a message" />
          <button class="chat-widget-send" type="submit">Send</button>
        </form>
      </div>
      <button class="chat-widget-toggle" type="button" aria-label="Open chat">💬</button>
    `;

    document.body.appendChild(root);

    const panel = root.querySelector('.chat-widget-panel');
    const toggle = root.querySelector('.chat-widget-toggle');
    const closeBtn = root.querySelector('.chat-widget-close');
    const messagesWrap = root.querySelector('.chat-widget-messages');
    const form = root.querySelector('.chat-widget-form');
    const input = root.querySelector('.chat-widget-input');
    const sendBtn = root.querySelector('.chat-widget-send');

    let intervalId = null;

    function openPanel() {
      panel.classList.remove('hidden');
      input.focus();
    }

    function closePanel() {
      panel.classList.add('hidden');
    }

    function renderMessages(messages) {
      const entries = Array.isArray(messages) ? messages : [];
      if (!entries.length) {
        messagesWrap.innerHTML = '<div class="chat-widget-empty">No messages yet.</div>';
        return;
      }

      messagesWrap.innerHTML = entries.map((message) => {
        const isSelf = String(message?.userId || '') === String(me?.id || '');
        const userName = escapeHtml(message?.userName || 'Unknown user');
        const text = escapeHtml(message?.text || '');
        const time = escapeHtml(formatTime(message?.createdAt));
        return `
          <div class="chat-widget-message ${isSelf ? 'self' : ''}">
            <div class="chat-widget-message-top">
              <span class="chat-widget-author">${userName}</span>
              <span class="chat-widget-time">${time}</span>
            </div>
            <div class="chat-widget-text">${text}</div>
          </div>
        `;
      }).join('');

      messagesWrap.scrollTop = messagesWrap.scrollHeight;
    }

    async function refreshMessages() {
      try {
        const response = await fetch('/api/chat-messages', { credentials: 'include' });
        const result = await response.json();

        if (!response.ok) {
          return;
        }

        renderMessages(result?.messages || []);
      } catch {
      }
    }

    async function sendMessage(event) {
      event.preventDefault();
      const text = String(input.value || '').trim();
      if (!text) {
        return;
      }

      sendBtn.disabled = true;
      try {
        const response = await fetch('/api/chat-messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ text })
        });

        const result = await response.json();
        if (!response.ok) {
          return;
        }

        input.value = '';
        renderMessages(result?.messages || []);
      } catch {
      } finally {
        sendBtn.disabled = false;
      }
    }

    toggle.addEventListener('click', () => {
      if (panel.classList.contains('hidden')) {
        openPanel();
      } else {
        closePanel();
      }
    });

    closeBtn.addEventListener('click', closePanel);
    form.addEventListener('submit', sendMessage);

    await refreshMessages();
    intervalId = window.setInterval(refreshMessages, POLL_MS);

    window.addEventListener('beforeunload', () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChatWidget);
  } else {
    initChatWidget();
  }
})();
