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
let ACCESS_USERS = [];
const DELETE_PASSWORD_PEPPER = process.env.DELETE_PASSWORD_PEPPER || '';
const SCRYPT_KEYLEN = 64;
const SCRYPT_SALT_BYTES = 16;

const CONFIG_FILE = path.join(__dirname, 'data', 'config.json');
const LOGIN_ACTIVITY_FILE = path.join(__dirname, 'data', 'login-activity.json');
const HIGHLIGHTS_FILE = path.join(__dirname, 'data', 'highlights.json');
const USER_ACTIVITY_FILE = path.join(__dirname, 'data', 'user-activity.json');
const THREAD_POSTS_FILE = path.join(__dirname, 'data', 'thread-posts.json');
const CHAT_MESSAGES_FILE = path.join(__dirname, 'data', 'chat-messages.json');

function timingSafeEqualHex(a, b) {
  const aBuffer = Buffer.from(String(a), 'utf8');
  const bBuffer = Buffer.from(String(b), 'utf8');
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function hashPasswordLegacy(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function scryptAsync(password, salt, keylen) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(derivedKey);
    });
  });
}

async function hashPasswordSecure(value) {
  const salt = crypto.randomBytes(SCRYPT_SALT_BYTES);
  const material = `${String(value)}${DELETE_PASSWORD_PEPPER}`;
  const derived = await scryptAsync(material, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

async function verifyPasswordSecure(value, storedHash) {
  if (!storedHash) {
    return false;
  }

  if (storedHash.startsWith('scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) {
      return false;
    }

    const saltHex = parts[1];
    const expectedHex = parts[2];
    if (!saltHex || !expectedHex) {
      return false;
    }

    const material = `${String(value)}${DELETE_PASSWORD_PEPPER}`;
    const derived = await scryptAsync(material, Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN);
    return timingSafeEqualHex(derived.toString('hex'), expectedHex);
  }

  // Legacy SHA-256 support for previously stored values
  if (/^[a-f0-9]{64}$/i.test(storedHash)) {
    const legacy = hashPasswordLegacy(String(value));
    return timingSafeEqualHex(legacy, storedHash);
  }

  return false;
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

async function appendLoginActivity(req, user) {
  const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.get('user-agent') || 'unknown';
  const entry = {
    timestamp: new Date().toISOString(),
    ip,
    userAgent,
    userId: user?.id || 'unknown',
    userName: user?.name || 'Unknown user',
    userCode: user?.code || 'unknown',
    role: normalizeRole(user?.role)
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

const ROLE_LEVEL = {
  viewer: 1,
  editor: 2,
  admin: 3
};

function normalizeRole(role) {
  const value = String(role || '').toLowerCase();
  return ROLE_LEVEL[value] ? value : 'viewer';
}

function normalizeAccessUsers(users, fallbackCode) {
  if (!Array.isArray(users)) {
    return [{ id: 'admin', name: 'Admin', code: fallbackCode, role: 'admin' }];
  }

  const normalized = users
    .map((user, index) => {
      const code = String(user?.code || '').trim();
      if (!/^\d{4}$/.test(code)) {
        return null;
      }

      return {
        id: String(user?.id || `user-${index + 1}`),
        name: String(user?.name || `User ${index + 1}`),
        code,
        role: normalizeRole(user?.role)
      };
    })
    .filter(Boolean);

  if (!normalized.some((user) => user.role === 'admin')) {
    normalized.unshift({ id: 'admin', name: 'Admin', code: fallbackCode, role: 'admin' });
  }

  return normalized.length > 0 ? normalized : [{ id: 'admin', name: 'Admin', code: fallbackCode, role: 'admin' }];
}

function hasRole(actualRole, requiredRole) {
  return (ROLE_LEVEL[normalizeRole(actualRole)] || 0) >= (ROLE_LEVEL[normalizeRole(requiredRole)] || Number.MAX_SAFE_INTEGER);
}

function normalizeRequiredRole(requiredRole) {
  const value = String(requiredRole || '').trim().toLowerCase();
  if (!value || value === 'public' || value === 'all' || value === 'none') {
    return null;
  }

  return ROLE_LEVEL[value] ? value : null;
}

function normalizeAllowedUserIds(userIds) {
  if (!Array.isArray(userIds)) {
    return [];
  }

  const validIds = new Set(ACCESS_USERS.map((user) => String(user.id)));
  const normalized = userIds
    .map((userId) => String(userId || '').trim())
    .filter((userId) => userId && validIds.has(userId));

  return [...new Set(normalized)].slice(0, 20);
}

function getUploadMetaPath(filePath) {
  return `${filePath}.meta.json`;
}

async function readUploadMeta(filePath) {
  try {
    const raw = await fs.readFile(getUploadMetaPath(filePath), 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

async function writeUploadMeta(filePath, meta) {
  await fs.writeFile(getUploadMetaPath(filePath), JSON.stringify(meta || {}, null, 2));
}

function sanitizeAccessUsersForAdmin(users) {
  return (Array.isArray(users) ? users : []).map((user) => ({
    id: user.id,
    name: user.name,
    code: user.code,
    role: normalizeRole(user.role)
  }));
}

function generateUserId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  return `user-${crypto.randomBytes(8).toString('hex')}`;
}

function normalizeHighlights(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  return items
    .slice(0, 24)
    .map((item) => {
      const title = String(item?.title || '').trim().slice(0, 120);
      const description = String(item?.description || '').trim().slice(0, 300);
      const url = String(item?.url || '').trim().slice(0, 500);

      if (!title || !url) {
        return null;
      }

      return { title, description, url };
    })
    .filter(Boolean);
}

async function readHighlights() {
  try {
    const raw = await fs.readFile(HIGHLIGHTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return normalizeHighlights(parsed?.items || parsed);
  } catch {
    return [];
  }
}

async function writeHighlights(items) {
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(HIGHLIGHTS_FILE, JSON.stringify({ items: normalizeHighlights(items) }, null, 2));
}

function normalizeActivityAction(action) {
  const value = String(action || '').trim().toLowerCase();
  if (!value) {
    return null;
  }

  return value.slice(0, 40);
}

async function appendUserActivity(req, payload = {}) {
  const action = normalizeActivityAction(payload.action);
  if (!action) {
    return;
  }

  const target = String(payload.target || '').trim().slice(0, 200);
  const details = String(payload.details || '').trim().slice(0, 400);
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    target,
    details,
    userId: req.session?.userId || 'unknown',
    userName: req.session?.name || 'Unknown user',
    role: normalizeRole(req.session?.role),
    ip: (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || req.socket?.remoteAddress || 'unknown'
  };

  let activity = [];
  try {
    const raw = await fs.readFile(USER_ACTIVITY_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    activity = Array.isArray(parsed) ? parsed : [];
  } catch {
    activity = [];
  }

  activity.unshift(entry);
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(USER_ACTIVITY_FILE, JSON.stringify(activity.slice(0, 200), null, 2));
}

async function readUserActivity() {
  try {
    const raw = await fs.readFile(USER_ACTIVITY_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function normalizeThreadPosts(posts) {
  if (!Array.isArray(posts)) {
    return [];
  }

  return posts
    .slice(0, 200)
    .map((post) => {
      const id = String(post?.id || '').trim();
      const author = String(post?.author || '').trim().slice(0, 80);
      const role = normalizeRole(post?.role);
      const title = String(post?.title || '').trim().slice(0, 160);
      const content = String(post?.content || '').trim().slice(0, 4000);
      const createdAt = String(post?.createdAt || '').trim();

      if (!id || !author || !content || !createdAt) {
        return null;
      }

      return { id, author, role, title, content, createdAt };
    })
    .filter(Boolean);
}

async function readThreadPosts() {
  try {
    const raw = await fs.readFile(THREAD_POSTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return normalizeThreadPosts(parsed?.posts || parsed);
  } catch {
    return [];
  }
}

async function writeThreadPosts(posts) {
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(THREAD_POSTS_FILE, JSON.stringify({ posts: normalizeThreadPosts(posts) }, null, 2));
}

function normalizeChatMessages(messages) {
  if (!Array.isArray(messages)) {
    return [];
  }

  return messages
    .slice(-300)
    .map((message) => {
      const id = String(message?.id || '').trim();
      const senderUserId = String(message?.senderUserId || '').trim().slice(0, 120);
      const senderUserName = String(message?.senderUserName || '').trim().slice(0, 80);
      const senderRole = normalizeRole(message?.senderRole);
      const targetUserId = String(message?.targetUserId || '').trim().slice(0, 120);
      const text = String(message?.text || '').trim().slice(0, 800);
      const createdAt = String(message?.createdAt || '').trim();

      if (!id || !senderUserName || !targetUserId || !text || !createdAt) {
        return null;
      }

      return {
        id,
        senderUserId: senderUserId || 'unknown',
        senderUserName,
        senderRole,
        targetUserId,
        text,
        createdAt
      };
    })
    .filter(Boolean);
}

async function readChatMessages() {
  try {
    const raw = await fs.readFile(CHAT_MESSAGES_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return normalizeChatMessages(parsed?.messages || parsed);
  } catch {
    return [];
  }
}

async function writeChatMessages(messages) {
  await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  await fs.writeFile(CHAT_MESSAGES_FILE, JSON.stringify({ messages: normalizeChatMessages(messages) }, null, 2));
}

function listChatTargets(currentUserId) {
  return ACCESS_USERS
    .filter((user) => String(user.id) !== String(currentUserId || ''))
    .map((user) => ({
      id: String(user.id),
      name: String(user.name || 'User').slice(0, 80),
      role: normalizeRole(user.role)
    }));
}

function getChatThread(messages, userA, userB) {
  return normalizeChatMessages(messages).filter((message) => {
    const sender = String(message.senderUserId || '');
    const target = String(message.targetUserId || '');
    return (sender === userA && target === userB) || (sender === userB && target === userA);
  });
}

ACCESS_USERS = normalizeAccessUsers(null, AUTH_CODE);

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

    let sourceUsers = config.ACCESS_USERS;
    if (!sourceUsers && process.env.ACCESS_USERS_JSON) {
      try {
        sourceUsers = JSON.parse(process.env.ACCESS_USERS_JSON);
      } catch {
        sourceUsers = null;
      }
    }

    ACCESS_USERS = normalizeAccessUsers(sourceUsers, AUTH_CODE);
    const adminUser = ACCESS_USERS.find((user) => user.role === 'admin');
    if (adminUser?.code) {
      AUTH_CODE = adminUser.code;
    }
  } catch (error) {
    ACCESS_USERS = normalizeAccessUsers(null, AUTH_CODE);
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

function requireRole(requiredRole) {
  return (req, res, next) => {
    if (!req.session?.authenticated) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' });
    }

    if (!hasRole(req.session?.role, requiredRole)) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    return next();
  };
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

  const matchedUser = ACCESS_USERS.find((user) => user.code === code);
  if (!matchedUser) {
    return res.status(401).json({ ok: false, error: 'Invalid code' });
  }

  try {
    await appendLoginActivity(req, matchedUser);
  } catch (error) {
    console.error('Failed to append login activity:', error);
  }

  req.session.authenticated = true;
  req.session.userId = matchedUser.id;
  req.session.name = matchedUser.name;
  req.session.role = matchedUser.role;
  return res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    ok: true,
    user: {
      id: req.session.userId,
      name: req.session.name,
      role: normalizeRole(req.session.role)
    }
  });
});

app.get('/api/access-users', requireRole('admin'), (req, res) => {
  res.json({ ok: true, users: sanitizeAccessUsersForAdmin(ACCESS_USERS) });
});

app.post('/api/access-users', requireRole('admin'), async (req, res) => {
  try {
    const { name, code, role } = req.body || {};
    const normalizedCode = String(code || '').trim();
    const normalizedName = String(name || '').trim();
    const normalizedRole = normalizeRole(role);

    if (!normalizedName) {
      return res.status(400).json({ error: 'Name is required' });
    }

    if (!/^\d{4}$/.test(normalizedCode)) {
      return res.status(400).json({ error: 'Code must be exactly 4 digits' });
    }

    if (ACCESS_USERS.some((user) => user.code === normalizedCode)) {
      return res.status(409).json({ error: 'Code is already in use' });
    }

    ACCESS_USERS.push({
      id: generateUserId(),
      name: normalizedName,
      code: normalizedCode,
      role: normalizedRole
    });

    const adminUser = ACCESS_USERS.find((user) => user.role === 'admin');
    AUTH_CODE = adminUser?.code || AUTH_CODE;

    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH,
      ACCESS_USERS
    });

    return res.json({ ok: true, users: sanitizeAccessUsersForAdmin(ACCESS_USERS) });
  } catch (error) {
    console.error('Error creating access user:', error);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/access-users/:id', requireRole('admin'), async (req, res) => {
  try {
    const targetId = String(req.params.id || '').trim();
    const { name, code, role } = req.body || {};

    const user = ACCESS_USERS.find((entry) => entry.id === targetId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (name !== undefined) {
      const normalizedName = String(name).trim();
      if (!normalizedName) {
        return res.status(400).json({ error: 'Name is required' });
      }
      user.name = normalizedName;
    }

    if (code !== undefined) {
      const normalizedCode = String(code).trim();
      if (!/^\d{4}$/.test(normalizedCode)) {
        return res.status(400).json({ error: 'Code must be exactly 4 digits' });
      }

      if (ACCESS_USERS.some((entry) => entry.id !== targetId && entry.code === normalizedCode)) {
        return res.status(409).json({ error: 'Code is already in use' });
      }

      user.code = normalizedCode;
    }

    if (role !== undefined) {
      const normalizedRole = normalizeRole(role);
      if (user.role === 'admin' && normalizedRole !== 'admin') {
        const adminCount = ACCESS_USERS.filter((entry) => entry.role === 'admin').length;
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'At least one admin is required' });
        }
      }
      user.role = normalizedRole;
    }

    const adminUser = ACCESS_USERS.find((entry) => entry.role === 'admin');
    AUTH_CODE = adminUser?.code || AUTH_CODE;

    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH,
      ACCESS_USERS
    });

    return res.json({ ok: true, users: sanitizeAccessUsersForAdmin(ACCESS_USERS) });
  } catch (error) {
    console.error('Error updating access user:', error);
    return res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/access-users/:id', requireRole('admin'), async (req, res) => {
  try {
    const targetId = String(req.params.id || '').trim();
    const targetIndex = ACCESS_USERS.findIndex((entry) => entry.id === targetId);

    if (targetIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (req.session?.userId === targetId) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    const targetUser = ACCESS_USERS[targetIndex];
    if (targetUser.role === 'admin') {
      const adminCount = ACCESS_USERS.filter((entry) => entry.role === 'admin').length;
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'At least one admin is required' });
      }
    }

    ACCESS_USERS.splice(targetIndex, 1);

    const adminUser = ACCESS_USERS.find((entry) => entry.role === 'admin');
    AUTH_CODE = adminUser?.code || AUTH_CODE;

    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH,
      ACCESS_USERS
    });

    return res.json({ ok: true, users: sanitizeAccessUsersForAdmin(ACCESS_USERS) });
  } catch (error) {
    console.error('Error deleting access user:', error);
    return res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/highlights', async (req, res) => {
  try {
    const items = await readHighlights();
    res.json({ ok: true, items });
  } catch (error) {
    console.error('Error reading highlights:', error);
    res.status(500).json({ ok: false, error: 'Failed to load highlights' });
  }
});

app.post('/api/highlights', requireRole('admin'), async (req, res) => {
  try {
    const items = normalizeHighlights(req.body?.items || []);
    await writeHighlights(items);
    res.json({ ok: true, items });
  } catch (error) {
    console.error('Error saving highlights:', error);
    res.status(500).json({ ok: false, error: 'Failed to save highlights' });
  }
});

app.post('/api/user-activity', requireAuth, async (req, res) => {
  try {
    await appendUserActivity(req, req.body || {});
    return res.json({ ok: true });
  } catch (error) {
    console.error('Error appending user activity:', error);
    return res.status(500).json({ ok: false, error: 'Failed to record activity' });
  }
});

app.get('/api/user-activity', requireRole('admin'), async (req, res) => {
  try {
    const activity = await readUserActivity();
    return res.json({ ok: true, activity });
  } catch (error) {
    console.error('Error reading user activity:', error);
    return res.status(500).json({ ok: false, error: 'Failed to load activity' });
  }
});

app.get('/api/thread-posts', requireAuth, async (req, res) => {
  try {
    const posts = await readThreadPosts();
    return res.json({ ok: true, posts });
  } catch (error) {
    console.error('Error reading thread posts:', error);
    return res.status(500).json({ ok: false, error: 'Failed to load thread posts' });
  }
});

app.post('/api/thread-posts', requireRole('editor'), async (req, res) => {
  try {
    const title = String(req.body?.title || '').trim().slice(0, 160);
    const content = String(req.body?.content || '').trim().slice(0, 4000);

    if (!content) {
      return res.status(400).json({ ok: false, error: 'Post content is required' });
    }

    const posts = await readThreadPosts();
    posts.unshift({
      id: generateUserId(),
      author: String(req.session?.name || 'Unknown user').slice(0, 80),
      role: normalizeRole(req.session?.role),
      title,
      content,
      createdAt: new Date().toISOString()
    });

    const normalized = normalizeThreadPosts(posts);
    await writeThreadPosts(normalized);

    await appendUserActivity(req, {
      action: 'post',
      target: title || 'Thread post',
      details: 'Created a thread/blog post'
    });

    return res.json({ ok: true, posts: normalized });
  } catch (error) {
    console.error('Error creating thread post:', error);
    return res.status(500).json({ ok: false, error: 'Failed to create thread post' });
  }
});

app.get('/api/chat-users', requireAuth, async (req, res) => {
  try {
    const users = listChatTargets(req.session?.userId);
    return res.json({ ok: true, users });
  } catch (error) {
    console.error('Error reading chat users:', error);
    return res.status(500).json({ ok: false, error: 'Failed to load chat users' });
  }
});

app.get('/api/chat-messages', requireAuth, async (req, res) => {
  try {
    const targetUserId = String(req.query?.userId || '').trim();
    if (!targetUserId) {
      return res.status(400).json({ ok: false, error: 'Target user is required' });
    }

    const targetUserExists = ACCESS_USERS.some((user) => String(user.id) === targetUserId);
    if (!targetUserExists) {
      return res.status(404).json({ ok: false, error: 'Target user not found' });
    }

    const messages = await readChatMessages();
    const thread = getChatThread(messages, String(req.session?.userId || ''), targetUserId);
    return res.json({ ok: true, messages: thread });
  } catch (error) {
    console.error('Error reading chat messages:', error);
    return res.status(500).json({ ok: false, error: 'Failed to load chat messages' });
  }
});

app.post('/api/chat-messages', requireAuth, async (req, res) => {
  try {
    const targetUserId = String(req.body?.targetUserId || '').trim();
    const text = String(req.body?.text || '').trim().slice(0, 800);

    if (!targetUserId) {
      return res.status(400).json({ ok: false, error: 'Target user is required' });
    }

    if (targetUserId === String(req.session?.userId || '')) {
      return res.status(400).json({ ok: false, error: 'Cannot message yourself' });
    }

    const targetUser = ACCESS_USERS.find((user) => String(user.id) === targetUserId);
    if (!targetUser) {
      return res.status(404).json({ ok: false, error: 'Target user not found' });
    }

    if (!text) {
      return res.status(400).json({ ok: false, error: 'Message text is required' });
    }

    const messages = await readChatMessages();
    messages.push({
      id: generateUserId(),
      senderUserId: String(req.session?.userId || 'unknown'),
      senderUserName: String(req.session?.name || 'Unknown user').slice(0, 80),
      senderRole: normalizeRole(req.session?.role),
      targetUserId,
      text,
      createdAt: new Date().toISOString()
    });

    const normalized = normalizeChatMessages(messages);
    await writeChatMessages(normalized);
    const thread = getChatThread(normalized, String(req.session?.userId || ''), targetUserId);

    await appendUserActivity(req, {
      action: 'chat',
      target: `Chat with ${String(targetUser.name || 'User').slice(0, 80)}`,
      details: 'Sent a direct message'
    });

    return res.json({ ok: true, messages: thread });
  } catch (error) {
    console.error('Error creating chat message:', error);
    return res.status(500).json({ ok: false, error: 'Failed to send chat message' });
  }
});

app.get('/pages/main.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'main.html'));
});

app.get('/pages/settings.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'settings.html'));
});

app.get('/pages/admin.html', requireRole('admin'), (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'admin.html'));
});

app.get('/pages/highlights.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'highlights.html'));
});

app.get('/pages/thread.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'thread.html'));
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

app.post('/api/data', requireRole('editor'), async (req, res) => {
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
app.post('/api/upload', requireRole('editor'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const requiredRole = normalizeRequiredRole(req.body?.requiredRole);
    await writeUploadMeta(req.file.path, {
      originalName: req.file.originalname,
      contentType: req.file.mimetype,
      requiredRole,
      allowedUserIds: []
    });

    await appendUserActivity(req, {
      action: 'upload',
      target: req.file.originalname,
      details: `Uploaded file (${req.file.size} bytes)`
    });
    
    // Return file information
    const fileInfo = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      url: `/api/files/${req.file.filename}`,
      requiredRole,
      allowedUserIds: []
    };
    
    res.json(fileInfo);
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// Serve uploaded files
app.get('/api/files/:filename', async (req, res) => {
  try {
    const filePath = path.join(__dirname, 'data', 'uploads', req.params.filename);

    const meta = await readUploadMeta(filePath);
    const requiredRole = normalizeRequiredRole(meta.requiredRole);
    const allowedUserIds = normalizeAllowedUserIds(meta.allowedUserIds);

    if (allowedUserIds.length > 0) {
      if (!req.session?.authenticated) {
        return res.status(401).json({ ok: false, error: 'Unauthorized' });
      }

      const currentUserId = String(req.session?.userId || '');
      if (!allowedUserIds.includes(currentUserId)) {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
    }

    if (requiredRole) {
      if (!req.session?.authenticated) {
        return res.status(401).json({ ok: false, error: 'Unauthorized' });
      }

      if (!hasRole(req.session?.role, requiredRole)) {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
    }

    res.sendFile(filePath);
  } catch (error) {
    console.error('Error serving file:', error);
    res.status(404).json({ error: 'File not found' });
  }
});

app.get('/api/file-permissions/:fileId', requireRole('admin'), async (req, res) => {
  try {
    const fileId = decodeURIComponent(String(req.params.fileId || '').trim());
    if (!fileId) {
      return res.status(400).json({ ok: false, error: 'File ID is required' });
    }

    const filePath = path.join(__dirname, 'data', 'uploads', fileId);
    const meta = await readUploadMeta(filePath);
    const requiredRole = normalizeRequiredRole(meta.requiredRole);
    const allowedUserIds = normalizeAllowedUserIds(meta.allowedUserIds);
    const allowedUserId = allowedUserIds.length > 0 ? allowedUserIds[0] : '';
    const accessMode = allowedUserId ? 'user' : (requiredRole ? 'role' : 'public');

    return res.json({
      ok: true,
      accessMode,
      requiredRole: requiredRole || '',
      allowedUserId
    });
  } catch (error) {
    console.error('Error reading file permissions:', error);
    return res.status(500).json({ ok: false, error: 'Failed to load file permissions' });
  }
});

app.put('/api/file-permissions/:fileId', requireRole('admin'), async (req, res) => {
  try {
    const fileId = decodeURIComponent(String(req.params.fileId || '').trim());
    if (!fileId) {
      return res.status(400).json({ ok: false, error: 'File ID is required' });
    }

    const accessMode = String(req.body?.accessMode || 'public').trim().toLowerCase();
    const normalizedRole = normalizeRequiredRole(req.body?.requiredRole);
    const requestedUserId = String(req.body?.allowedUserId || '').trim();
    const validUserIds = new Set(ACCESS_USERS.map((user) => String(user.id)));

    let requiredRole = null;
    let allowedUserIds = [];

    if (accessMode === 'role') {
      if (!normalizedRole) {
        return res.status(400).json({ ok: false, error: 'Valid role is required' });
      }
      requiredRole = normalizedRole;
    } else if (accessMode === 'user') {
      if (!requestedUserId || !validUserIds.has(requestedUserId)) {
        return res.status(400).json({ ok: false, error: 'Valid user is required' });
      }
      allowedUserIds = [requestedUserId];
    } else if (accessMode !== 'public') {
      return res.status(400).json({ ok: false, error: 'Invalid access mode' });
    }

    const filePath = path.join(__dirname, 'data', 'uploads', fileId);
    const currentMeta = await readUploadMeta(filePath);
    const nextMeta = {
      ...currentMeta,
      requiredRole,
      allowedUserIds
    };

    await writeUploadMeta(filePath, nextMeta);

    return res.json({
      ok: true,
      accessMode,
      requiredRole: requiredRole || '',
      allowedUserId: allowedUserIds[0] || ''
    });
  } catch (error) {
    console.error('Error updating file permissions:', error);
    return res.status(500).json({ ok: false, error: 'Failed to update file permissions' });
  }
});

app.get('/api/login-activity', requireRole('admin'), async (req, res) => {
  try {
    const raw = await fs.readFile(LOGIN_ACTIVITY_FILE, 'utf8');
    const activity = JSON.parse(raw);
    res.json({ ok: true, activity: Array.isArray(activity) ? activity : [] });
  } catch {
    res.json({ ok: true, activity: [] });
  }
});

app.post('/api/delete-password', requireRole('admin'), async (req, res) => {
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

      const validCurrentPassword = await verifyPasswordSecure(String(currentPassword), DELETE_PASSWORD_HASH);
      if (!validCurrentPassword) {
        return res.status(401).json({ error: 'Current delete password is incorrect' });
      }
    }

    DELETE_PASSWORD_HASH = await hashPasswordSecure(String(newPassword));
    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH,
      ACCESS_USERS
    });

    return res.json({ ok: true, message: 'Delete password updated successfully' });
  } catch (error) {
    console.error('Error setting delete password:', error);
    return res.status(500).json({ error: 'Failed to update delete password' });
  }
});

app.delete('/api/data-all', requireRole('admin'), async (req, res) => {
  try {
    const { password } = req.body || {};

    if (!DELETE_PASSWORD_HASH) {
      return res.status(400).json({ error: 'Delete password is not set yet' });
    }

    const validDeletePassword = await verifyPasswordSecure(String(password || ''), DELETE_PASSWORD_HASH);
    if (!validDeletePassword) {
      return res.status(401).json({ error: 'Invalid delete password' });
    }

    // Upgrade legacy hash in-place after successful verification
    if (!String(DELETE_PASSWORD_HASH).startsWith('scrypt$')) {
      DELETE_PASSWORD_HASH = await hashPasswordSecure(String(password));
      const config = await readConfig();
      await writeConfig({
        ...config,
        AUTH_CODE,
        DELETE_PASSWORD_HASH,
        ACCESS_USERS
      });
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

    const currentUser = ACCESS_USERS.find((user) => user.id === req.session?.userId);
    if (!currentUser) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (currentCode !== currentUser.code) {
      return res.status(401).json({ error: 'Current code is incorrect' });
    }

    currentUser.code = newCode;
    const adminUser = ACCESS_USERS.find((user) => user.role === 'admin');
    AUTH_CODE = adminUser?.code || AUTH_CODE;

    // Save to config file for persistence across restarts
    const config = await readConfig();
    await writeConfig({
      ...config,
      AUTH_CODE,
      DELETE_PASSWORD_HASH,
      ACCESS_USERS
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
