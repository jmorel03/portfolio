document.addEventListener('DOMContentLoaded',()=>{
  const form = document.getElementById('login-form');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  const message = document.getElementById('message');

  function showMessage(text, isError=true){
    message.textContent = text;
    message.style.color = isError ? getComputedStyle(document.documentElement).getPropertyValue('--danger') : '#0f5132';
  }

  function validate(){
    const e = username.value.trim();
    const p = password.value;
    if(!e) { showMessage('Please enter your username.'); username.focus(); return false }
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if(!re.test(e)){ showMessage('Please enter a valid username address.'); username.focus(); return false }
    if(!p) { showMessage('Please enter your password.'); password.focus(); return false }
    if(p.length < 6){ showMessage('Password must be at least 6 characters.'); password.focus(); return false }
    return true
  }

  form.addEventListener('submit', (ev)=>{
    ev.preventDefault();
    message.textContent = '';
    if(!validate()) return;

    // Demo: simulate login
    const btn = form.querySelector('.btn');
    btn.disabled = true;
    btn.textContent = 'Signing in...';

    setTimeout(()=>{
      btn.disabled = false;
      btn.textContent = 'Sign in';
      showMessage('Signed in successfully — welcome!', false);
      form.reset();
    }, 900);
  });
});
