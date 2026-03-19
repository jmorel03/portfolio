document.addEventListener('DOMContentLoaded',()=>{
  const form = document.getElementById('login-form');
  const code = document.getElementById('code');
  const message = document.getElementById('message');
  const CORRECT_CODE = '1234';

  function showMessage(text, isError=true){
    message.textContent = text;
    message.style.color = isError ? getComputedStyle(document.documentElement).getPropertyValue('--danger') : '#0f5132';
  }

  function validate(){
    const inputCode = code.value.trim();
    if(!inputCode) { showMessage('Please enter the 4-digit code.'); code.focus(); return false }
    if(!/^\d{4}$/.test(inputCode)){ showMessage('Code must be exactly 4 digits.'); code.focus(); return false }
    if(inputCode !== CORRECT_CODE){ showMessage('Incorrect code. Try again.'); code.value = ''; code.focus(); return false }
    return true
  }

  form.addEventListener('submit', (ev)=>{
    ev.preventDefault();
    message.textContent = '';
    if(!validate()) return;

    // Successful login - redirect to main page
    const btn = form.querySelector('.btn');
    btn.disabled = true;
    btn.textContent = 'Unlocking...';

    setTimeout(()=>{
      // Set session flag and redirect
      sessionStorage.setItem('authenticated', 'true');
      window.location.href = 'pages/main.html';
    }, 600);
  });
});
