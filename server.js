const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_CODE = process.env.AUTH_CODE || '1234';

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 30
  }
}));

// Serve static files (your frontend)
app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  return res.status(401).json({ ok: false, error: 'Unauthorized' });
}

app.post('/api/login', (req, res) => {
  const { code } = req.body;
  if (!code || !/^\d{4}$/.test(code)) {
    return res.status(400).json({ ok: false, error: 'Code must be 4 digits' });
  }

  if (code !== AUTH_CODE) {
    return res.status(401).json({ ok: false, error: 'Invalid code' });
  }

  req.session.authenticated = true;
  return res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/pages/main.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'main.html'));
});

app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
