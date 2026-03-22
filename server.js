const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
let AUTH_CODE = process.env.AUTH_CODE || '1234';

// Load saved AUTH_CODE from config file if it exists
(async () => {
  try {
    const configFile = path.join(__dirname, 'data', 'config.json');
    const config = JSON.parse(await fs.readFile(configFile, 'utf8'));
    if (config.AUTH_CODE) {
      AUTH_CODE = config.AUTH_CODE;
      console.log('Loaded saved AUTH_CODE from config file');
    }
  } catch (error) {
    // Config file doesn't exist yet, using default
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
    const configFile = path.join(__dirname, 'data', 'config.json');
    await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
    await fs.writeFile(configFile, JSON.stringify({ AUTH_CODE: newCode }, null, 2));

    res.json({ ok: true, message: 'Access code updated successfully' });
  } catch (error) {
    console.error('Error changing code:', error);
    res.status(500).json({ error: 'Failed to change access code' });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
