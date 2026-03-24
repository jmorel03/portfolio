(function () {
  const POLL_MS = 5000;
  const ALL_CHAT_ID = '__all__';

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

  function getMessageId(message) {
    if (message?.id) {
      return String(message.id);
    }

    return [
      message?.senderUserId || '',
      message?.targetUserId || '',
      message?.createdAt || '',
      message?.text || ''
    ].join('|');
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
        <div class="chat-widget-target-wrap">
          <label class="chat-widget-target-label" for="chatWidgetTargetSelect">Conversation</label>
          <select id="chatWidgetTargetSelect" class="chat-widget-target-select"></select>
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
      <span class="chat-widget-badge hidden">0</span>
    `;

    document.body.appendChild(root);

    const panel = root.querySelector('.chat-widget-panel');
    const toggle = root.querySelector('.chat-widget-toggle');
    const closeBtn = root.querySelector('.chat-widget-close');
    const messagesWrap = root.querySelector('.chat-widget-messages');
    const form = root.querySelector('.chat-widget-form');
    const input = root.querySelector('.chat-widget-input');
    const sendBtn = root.querySelector('.chat-widget-send');
    const badge = root.querySelector('.chat-widget-badge');
    const targetSelect = root.querySelector('.chat-widget-target-select');

    let intervalId = null;
    let unreadCount = 0;
    let hasLoadedInitialMessages = false;
    let isPanelOpen = false;
    let activeTargetUserId = '';
    const knownMessageIds = new Set();

    function updateBadge() {
      if (!badge) {
        return;
      }

      if (unreadCount <= 0) {
        badge.textContent = '0';
        badge.classList.add('hidden');
        return;
      }

      badge.textContent = unreadCount > 99 ? '99+' : String(unreadCount);
      badge.classList.remove('hidden');
    }

    function clearUnread() {
      unreadCount = 0;
      updateBadge();
    }

    function rememberMessages(messages) {
      (Array.isArray(messages) ? messages : []).forEach((message) => {
        knownMessageIds.add(getMessageId(message));
      });
    }

    function countNewIncomingMessages(messages) {
      const entries = Array.isArray(messages) ? messages : [];
      let count = 0;

      entries.forEach((message) => {
        const id = getMessageId(message);
        if (knownMessageIds.has(id)) {
          return;
        }

        const fromMe = String(message?.senderUserId || '') === String(me?.id || '');
        if (!fromMe) {
          count += 1;
        }
      });

      return count;
    }

    function openPanel() {
      panel.classList.remove('hidden');
      isPanelOpen = true;
      clearUnread();
      input.focus();
    }

    function closePanel() {
      panel.classList.add('hidden');
      isPanelOpen = false;
    }

    function renderTargetUsers(users) {
      const entries = Array.isArray(users) ? users : [];
      const userOptions = entries.map((user) => {
        const id = escapeHtml(user.id || '');
        const name = escapeHtml(user.name || 'User');
        const role = escapeHtml(user.role || 'viewer');
        return `<option value="${id}">${name} (${role})</option>`;
      }).join('');

      targetSelect.innerHTML = `
        <option value="${ALL_CHAT_ID}">All chat (everyone)</option>
        ${userOptions}
      `;

      if (
        activeTargetUserId !== ALL_CHAT_ID
        && !entries.some((user) => String(user.id) === String(activeTargetUserId))
      ) {
        activeTargetUserId = ALL_CHAT_ID;
      }

      targetSelect.value = activeTargetUserId;
    }

    async function loadTargetUsers() {
      try {
        const response = await fetch('/api/chat-users', { credentials: 'include' });
        const result = await response.json();
        if (!response.ok) {
          renderTargetUsers([]);
          return;
        }

        renderTargetUsers(result?.users || []);
      } catch {
        renderTargetUsers([]);
      }
    }

    function renderMessages(messages) {
      const entries = Array.isArray(messages) ? messages : [];
      if (!activeTargetUserId) {
        messagesWrap.innerHTML = '<div class="chat-widget-empty">No user selected.</div>';
        return;
      }

      if (!entries.length) {
        messagesWrap.innerHTML = '<div class="chat-widget-empty">No messages yet.</div>';
        return;
      }

      messagesWrap.innerHTML = entries.map((message) => {
        const isSelf = String(message?.senderUserId || '') === String(me?.id || '');
        const userName = escapeHtml(message?.senderUserName || 'Unknown user');
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
      if (!activeTargetUserId) {
        renderMessages([]);
        return;
      }

      try {
        const response = await fetch(`/api/chat-messages?userId=${encodeURIComponent(activeTargetUserId)}`, { credentials: 'include' });
        const result = await response.json();

        if (!response.ok) {
          return;
        }

        const messages = Array.isArray(result?.messages) ? result.messages : [];

        if (!hasLoadedInitialMessages) {
          rememberMessages(messages);
          hasLoadedInitialMessages = true;
          renderMessages(messages);
          if (isPanelOpen) {
            clearUnread();
          }
          return;
        }

        const newIncomingCount = countNewIncomingMessages(messages);
        rememberMessages(messages);
        renderMessages(messages);

        if (isPanelOpen) {
          clearUnread();
          return;
        }

        if (newIncomingCount > 0) {
          unreadCount += newIncomingCount;
          updateBadge();
        }
      } catch {
      }
    }

    async function sendMessage(event) {
      event.preventDefault();
      const text = String(input.value || '').trim();
      if (!activeTargetUserId) {
        return;
      }

      if (!text) {
        return;
      }

      sendBtn.disabled = true;
      try {
        const response = await fetch('/api/chat-messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ targetUserId: activeTargetUserId, text })
        });

        const result = await response.json();
        if (!response.ok) {
          return;
        }

        rememberMessages(result?.messages || []);
        input.value = '';
        renderMessages(result?.messages || []);
        if (isPanelOpen) {
          clearUnread();
        }
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
    targetSelect.addEventListener('change', async () => {
      activeTargetUserId = String(targetSelect.value || '');
      hasLoadedInitialMessages = false;
      knownMessageIds.clear();
      clearUnread();
      await refreshMessages();
    });
    form.addEventListener('submit', sendMessage);

    await loadTargetUsers();
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
