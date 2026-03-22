const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');
const { execSync } = require('child_process');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
let AUTH_CODE = process.env.AUTH_CODE || '1234';
let DELETE_PASSWORD_HASH = '';

const CONFIG_FILE = path.join(__dirname, 'data', 'config.json');
const LOGIN_ACTIVITY_FILE = path.join(__dirname, 'data', 'login-activity.json');

function hashPassword(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function readConfig() {
  try {
    const raw = await fs.readFile(CONFIG_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

async function writeConfig(config) {
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
}

async function appendLoginActivity(req) {
  const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.get('user-agent') || 'unknown';
  const entry = {
    timestamp: new Date().toISOString(),
    ip,
    userAgent
  };

  let activity = [];
  try {
    const raw = await fs.readFile(LOGIN_ACTIVITY_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    activity = Array.isArray(parsed) ? parsed : [];
  } catch {
    activity = [];
  }

  activity.unshift(entry);
  const limited = activity.slice(0, 20);
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(LOGIN_ACTIVITY_FILE, JSON.stringify(limited, null, 2));
}

// Get last git commit info
function getGitInfo() {
  try {
    const hash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
    const message = execSync('git log -1 --pretty=format:%s', { encoding: 'utf8' }).trim();
    const timestamp = execSync('git log -1 --pretty=format:%aI', { encoding: 'utf8' }).trim();
    
    return { hash, message, timestamp };
  } catch (error) {
    console.log('Git info not available:', error.message);
    return { hash: 'unknown', message: 'unknown', timestamp: new Date().toISOString() };
  }
}

// Load saved AUTH_CODE from config file if it exists
(async () => {
  try {
    const config = await readConfig();
    if (config.AUTH_CODE) {
      AUTH_CODE = config.AUTH_CODE;
      console.log('Loaded saved AUTH_CODE from config file');
    }
    if (config.DELETE_PASSWORD_HASH) {
      DELETE_PASSWORD_HASH = config.DELETE_PASSWORD_HASH;
      console.log('Loaded delete password from config file');
    }
  } catch (error) {
    
  }
})();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'data', 'uploads');
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ storage: storage });

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

// Version endpoint (public)
app.get('/api/version', (req, res) => {
  const gitInfo = getGitInfo();
  res.json(gitInfo);
});

app.post('/api/login', async (req, res) => {
  const { code } = req.body;
  if (!code || !/^\d{4}$/.test(code)) {
    return res.status(400).json({ ok: false, error: 'Code must be 4 digits' });
  }

  if (code !== AUTH_CODE) {
    return res.status(401).json({ ok: false, error: 'Invalid code' });
  }

  try {
    await appendLoginActivity(req);
  } catch (error) {
    console.error('Failed to append login activity:', error);
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

app.get('/pages/settings.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'settings.html'));
});

// Data synchronization endpoints
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const dataDir = path.join(__dirname, 'data');
    const dataFile = path.join(dataDir, 'portfolio.json');
    
    // Create data directory if it doesn't exist
    await fs.mkdir(dataDir, { recursive: true });
    
    // Try to read existing data
    try {
      const data = await fs.readFile(dataFile, 'utf8');
      res.json(JSON.parse(data));
    } catch (error) {
      // Return empty data structure if file doesn't exist
      res.json({ folders: [], lastSync: new Date().toISOString() });
    }
  } catch (error) {
    console.error('Error reading data:', error);
    res.status(500).json({ error: 'Failed to read data' });
  }
});

app.post('/api/data', requireAuth, async (req, res) => {
  try {
    const dataDir = path.join(__dirname, 'data');
    const dataFile = path.join(dataDir, 'portfolio.json');
    
    // Create data directory if it doesn't exist
    await fs.mkdir(dataDir, { recursive: true });
    
    // Save the data
    const dataToSave = {
      ...req.body,
      lastSync: new Date().toISOString()
    };
    
    await fs.writeFile(dataFile, JSON.stringify(dataToSave, null, 2));
    res.json({ success: true, lastSync: dataToSave.lastSync });
  } catch (error) {
    console.error('Error saving data:', error);
    res.status(500).json({ error: 'Failed to save data' });
  }
});

// File upload endpoint
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Return file information
    const fileInfo = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      url: `/api/files/${req.file.filename}`
    };
    
    res.json(fileInfo);
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// Serve uploaded files
app.get('/api/files/:filename', requireAuth, async (req, res) => {
  try {
    const filePath = path.join(__dirname, 'data', 'uploads', req.params.filename);
    res.sendFile(filePath);
  } catch (error) {
    console.error('Error serving file:', error);
    res.status(404).json({ error: 'File not found' });
  }
});

app.get('/api/login-activity', requireAuth, async (req, res) => {
  try {
    const raw = await fs.readFile(LOGIN_ACTIVITY_FILE, 'utf8');
    const activity = JSON.parse(raw);
    res.json({ ok: true, activity: Array.isArray(activity) ? activity : [] });
  } catch {
    res.json({ ok: true, activity: [] });
  }
});

app.post('/api/delete-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body || {};

    if (!newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'New password and confirmation are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    if (String(newPassword).trim().length < 4) {
      return res.status(400).json({ error: 'Delete password must be at least 4 characters' });
    }

    if (DELETE_PASSWORD_HASH) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current delete password is required' });
      }

      if (hashPassword(String(currentPassword)) !== DELETE_PASSWORD_HASH) {
        return res.status(401).json({ error: 'Current delete password is incorrect' });
      }
    }

    DELETE_PASSWORD_HASH = hashPassword(String(newPassword));
    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH
    });

    return res.json({ ok: true, message: 'Delete password updated successfully' });
  } catch (error) {
    console.error('Error setting delete password:', error);
    return res.status(500).json({ error: 'Failed to update delete password' });
  }
});

app.delete('/api/data-all', requireAuth, async (req, res) => {
  try {
    const { password } = req.body || {};

    if (!DELETE_PASSWORD_HASH) {
      return res.status(400).json({ error: 'Delete password is not set yet' });
    }

    if (!password || hashPassword(String(password)) !== DELETE_PASSWORD_HASH) {
      return res.status(401).json({ error: 'Invalid delete password' });
    }

    const dataFile = path.join(__dirname, 'data', 'portfolio.json');
    const uploadsDir = path.join(__dirname, 'data', 'uploads');

    await fs.rm(dataFile, { force: true });
    await fs.rm(uploadsDir, { recursive: true, force: true });
    await fs.mkdir(uploadsDir, { recursive: true });

    return res.json({ ok: true, message: 'All portfolio data deleted' });
  } catch (error) {
    console.error('Error deleting all data:', error);
    return res.status(500).json({ error: 'Failed to delete all data' });
  }
});

// Change access code endpoint
app.post('/api/change-code', requireAuth, async (req, res) => {
  try {
    const { currentCode, newCode, confirmCode } = req.body;

    // Validate input
    if (!currentCode || !newCode || !confirmCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!/^\d{4}$/.test(currentCode) || !/^\d{4}$/.test(newCode)) {
      return res.status(400).json({ error: 'Codes must be exactly 4 digits' });
    }

    if (newCode !== confirmCode) {
      return res.status(400).json({ error: 'New codes do not match' });
    }

    if (currentCode !== AUTH_CODE) {
      return res.status(401).json({ error: 'Current code is incorrect' });
    }

    // Update AUTH_CODE in memory for this session
    AUTH_CODE = newCode;

    // Save to config file for persistence across restarts
    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE: newCode,
      DELETE_PASSWORD_HASH
    });

    res.json({ ok: true, message: 'Access code updated successfully' });
  } catch (error) {
    console.error('Error changing code:', error);
    res.status(500).json({ error: 'Failed to change access code' });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
