document.addEventListener('DOMContentLoaded', ()=>{
  const form = document.getElementById('login-form');
  const code = document.getElementById('code');
  const message = document.getElementById('message');
  const visitorAccessBtn = document.getElementById('visitorAccessBtn');

  function showMessage(text, isError=true){
    message.textContent = text;
    message.style.color = isError ? getComputedStyle(document.documentElement).getPropertyValue('--danger') : '#0f5132';
  }

  function validate(){
    const inputCode = code.value.trim();
    if (!inputCode) { showMessage('Please enter the 4-digit code.'); code.focus(); return false; }
    if (!/^\d{4}$/.test(inputCode)) { showMessage('Code must be exactly 4 digits.'); code.focus(); return false; }
    return true;
  }

  form.addEventListener('submit', async (ev)=>{
    ev.preventDefault();
    message.textContent = '';
    if (!validate()) return;

    const btn = form.querySelector('.btn');
    btn.disabled = true;
    btn.textContent = 'Verifying...';

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: code.value.trim() })
      });

      const result = await response.json();
      if (result.ok) {
        window.location.href = '/pages/main.html';
      } else {
        showMessage(result.error || 'Login failed.');
        code.value = '';
        code.focus();
      }
    } catch (error) {
      showMessage('Network error, try again.');
      console.error(error);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  });

  if (visitorAccessBtn) {
    visitorAccessBtn.addEventListener('click', () => {
      window.location.href = '/pages/highlights.html';
    });
  }
});
