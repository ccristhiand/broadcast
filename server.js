require('dotenv').config();
const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const { v4: uuidv4 } = require('uuid');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Op }   = require('sequelize');
const {
  Publication, Setting, User, ActivityLog,
  getSetting, setSetting, getAllSettings, log, initDB
} = require('./db');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', methods: ['GET','POST','PUT','DELETE','PATCH'] } });

const JWT_SECRET = process.env.JWT_SECRET || 'broadcastos_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/sortable.min.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules/sortablejs/Sortable.min.js'));
});

// ── Multer ────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isVideo = file.mimetype.startsWith('video/');
    cb(null, path.join(__dirname, 'uploads', isVideo ? 'videos' : 'images'));
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}${path.extname(file.originalname)}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/gif','image/webp','video/mp4','video/webm','video/ogg'];
    cb(null, allowed.includes(file.mimetype));
  }
});

// ── Middleware JWT ────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Token requerido' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// ── AUTH ──────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

    // Buscar por username O por email
    const user = await User.findOne({
      where: { [Op.or]: [{ username }, { email: username }] }
    });
    if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
    if (!user.active) return res.status(403).json({ error: 'Usuario bloqueado. Contacta al administrador.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });

    await user.update({ lastLogin: new Date() });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Log manual (no hay req.user aún)
    await ActivityLog.create({
      userId: user.id, username: user.username,
      action: 'LOGIN', entity: 'auth', entityId: user.id,
      detail: 'Inicio de sesión exitoso',
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    });

    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// ── USERS (solo admin) ────────────────────────────────────────
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id','username','email','role','active','lastLogin','createdAt'],
      order: [['createdAt','ASC']]
    });
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    const exists = await User.findOne({ where: { username } });
    if (exists) return res.status(409).json({ error: 'El nombre de usuario ya existe' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username, email: email || null,
      password: hashed,
      role: role || 'editor',
      active: true,
    });

    await log(req, 'CREATE_USER', 'user', user.id, `Usuario: ${username} | Rol: ${role}`);
    io.emit('users:update');
    res.status(201).json({ id: user.id, username: user.username, role: user.role, active: user.active });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    // No puede editarse a sí mismo el rol
    const { username, email, password, role } = req.body;
    const updates = {};
    if (username)  updates.username = username;
    if (email !== undefined) updates.email = email || null;
    if (role && req.user.id !== user.id) updates.role = role;
    if (password) {
      if (password.length < 6) return res.status(400).json({ error: 'Mínimo 6 caracteres' });
      updates.password = await bcrypt.hash(password, 10);
    }

    await user.update(updates);
    await log(req, 'UPDATE_USER', 'user', user.id, `Editó usuario: ${user.username}`);
    io.emit('users:update');
    res.json({ id: user.id, username: user.username, role: user.role, active: user.active });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id/toggle', authMiddleware, adminOnly, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'No encontrado' });
    if (user.id === req.user.id) return res.status(400).json({ error: 'No puedes bloquearte a ti mismo' });

    await user.update({ active: !user.active });
    await log(req, user.active ? 'UNBLOCK_USER' : 'BLOCK_USER', 'user', user.id, `Usuario: ${user.username}`);
    io.emit('users:update');
    res.json({ id: user.id, active: user.active });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'No encontrado' });
    if (user.id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
    await log(req, 'DELETE_USER', 'user', user.id, `Eliminó usuario: ${user.username}`);
    await user.destroy();
    io.emit('users:update');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ACTIVITY LOGS (solo admin) ────────────────────────────────
app.get('/api/logs', authMiddleware, adminOnly, async (req, res) => {
  try {
    const limit  = parseInt(req.query.limit)  || 100;
    const offset = parseInt(req.query.offset) || 0;
    const userId = req.query.userId || null;
    const where  = userId ? { userId } : {};

    const logs = await ActivityLog.findAndCountAll({
      where,
      order: [['createdAt','DESC']],
      limit,
      offset,
    });
    res.json(logs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PUBLICATIONS ──────────────────────────────────────────────
app.get('/api/publications', authMiddleware, async (req, res) => {
  try {
    const pubs = await Publication.findAll({ order: [['order','ASC'],['createdAt','ASC']] });
    res.json(pubs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/publications/active', async (req, res) => {
  try {
    const now = new Date();
    const pubs = await Publication.findAll({
      where: {
        active: true,
        [Op.or]: [
          { indefinite: true },
          { indefinite: false,
            [Op.and]: [
              { [Op.or]: [{ startDate: null },{ startDate: { [Op.lte]: now } }] },
              { [Op.or]: [{ endDate: null },  { endDate:   { [Op.gte]: now } }] },
            ]
          }
        ]
      },
      order: [['order','ASC'],['createdAt','ASC']]
    });
    res.json(pubs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/publications', authMiddleware, upload.single('media'), async (req, res) => {
  try {
    const body  = req.body;
    const count = await Publication.count();
    const pub   = await Publication.create({
      title:       body.title || 'Sin título',
      subtitle:    body.subtitle || null,
      description: body.description || null,
      type:        body.type || 'image',
      mediaUrl:    req.file ? `/uploads/${req.file.mimetype.startsWith('video/') ? 'videos' : 'images'}/${req.file.filename}` : null,
      mediaType:   req.file ? req.file.mimetype : null,
      embedUrl:    body.embedUrl || null,
      bgColor:     body.bgColor || '#0a0a1a',
      textColor:   body.textColor || '#ffffff',
      indefinite:  body.indefinite === 'true',
      startDate:   body.startDate || null,
      endDate:     body.endDate || null,
      duration:    parseInt(body.duration) || 8,
      timeStart:   body.timeStart || null,
      timeEnd:     body.timeEnd || null,
      active:      true,
      order:       count,
    });
    await log(req, 'CREATE_PUBLICATION', 'publication', pub.id, `Creó: "${pub.title}"`);
    io.emit('publications:update', { action: 'create', publication: pub });
    res.status(201).json(pub);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/publications/:id', authMiddleware, upload.single('media'), async (req, res) => {
  try {
    const pub = await Publication.findByPk(req.params.id);
    if (!pub) return res.status(404).json({ error: 'Not found' });
    const body    = req.body;
    const updates = {};
    if (body.title       !== undefined) updates.title       = body.title;
    if (body.subtitle    !== undefined) updates.subtitle    = body.subtitle;
    if (body.description !== undefined) updates.description = body.description;
    if (body.bgColor     !== undefined) updates.bgColor     = body.bgColor;
    if (body.textColor   !== undefined) updates.textColor   = body.textColor;
    if (body.indefinite  !== undefined) updates.indefinite  = body.indefinite === 'true';
    if (body.startDate   !== undefined) updates.startDate   = body.startDate || null;
    if (body.endDate     !== undefined) updates.endDate     = body.endDate || null;
    if (body.duration    !== undefined) updates.duration    = parseInt(body.duration);
    if (body.active      !== undefined) updates.active      = body.active === 'true';
    if (body.embedUrl    !== undefined) updates.embedUrl    = body.embedUrl || null;
    if (body.timeStart   !== undefined) updates.timeStart   = body.timeStart || null;
    if (body.timeEnd     !== undefined) updates.timeEnd     = body.timeEnd || null;
    if (req.file) {
      if (pub.mediaUrl) { const op = path.join(__dirname, pub.mediaUrl); if (fs.existsSync(op)) fs.unlinkSync(op); }
      updates.mediaUrl  = `/uploads/${req.file.mimetype.startsWith('video/') ? 'videos' : 'images'}/${req.file.filename}`;
      updates.mediaType = req.file.mimetype;
      updates.type      = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
    }
    await pub.update(updates);
    await log(req, 'UPDATE_PUBLICATION', 'publication', pub.id, `Editó: "${pub.title}"`);
    io.emit('publications:update', { action: 'update', publication: pub });
    res.json(pub);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/publications/:id', authMiddleware, async (req, res) => {
  try {
    const pub = await Publication.findByPk(req.params.id);
    if (!pub) return res.status(404).json({ error: 'Not found' });
    if (pub.mediaUrl) { const fp = path.join(__dirname, pub.mediaUrl); if (fs.existsSync(fp)) fs.unlinkSync(fp); }
    await log(req, 'DELETE_PUBLICATION', 'publication', pub.id, `Eliminó: "${pub.title}"`);
    await pub.destroy();
    io.emit('publications:update', { action: 'delete', id: req.params.id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/publications/:id/toggle', authMiddleware, async (req, res) => {
  try {
    const pub = await Publication.findByPk(req.params.id);
    if (!pub) return res.status(404).json({ error: 'Not found' });
    await pub.update({ active: !pub.active });
    await log(req, pub.active ? 'ACTIVATE_PUBLICATION' : 'DEACTIVATE_PUBLICATION', 'publication', pub.id, `"${pub.title}"`);
    io.emit('publications:update', { action: 'update', publication: pub });
    res.json(pub);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/publications/reorder', authMiddleware, async (req, res) => {
  try {
    const { ids } = req.body;
    await Promise.all(ids.map((id, index) => Publication.update({ order: index }, { where: { id } })));
    await log(req, 'REORDER_PUBLICATIONS', 'publication', null, 'Reordenó publicaciones');
    io.emit('publications:update', { action: 'reorder' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SETTINGS ──────────────────────────────────────────────────
app.get('/api/settings', authMiddleware, async (req, res) => {
  try { res.json(await getAllSettings()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/settings', authMiddleware, adminOnly, async (req, res) => {
  try {
    await Promise.all(Object.entries(req.body).map(([k, v]) => setSetting(k, v)));
    const all = await getAllSettings();
    await log(req, 'UPDATE_SETTINGS', 'settings', null, 'Actualizó configuración');
    io.emit('settings:update', all);
    res.json(all);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── WEBSOCKET ─────────────────────────────────────────────────
let lastTvStatus = null;

io.on('connection', (socket) => {
  // Si tenemos estado reciente del TV, enviarlo al admin recién conectado
  if(lastTvStatus) {
    const age = Date.now() - (lastTvStatus.receivedAt || 0);
    if(age < 60000) { // solo si tiene menos de 1 minuto
      socket.emit('tv:status', lastTvStatus);
    }
  }
  socket.on('admin:forceRefresh', () => io.emit('tv:refresh'));
});

// ── BOOT ──────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 BroadcastOS en http://localhost:${PORT}`);
    console.log(`📺 Smart TV:  http://localhost:${PORT}/tv`);
    console.log(`🛠️  Admin:     http://localhost:${PORT}/admin\n`);
  });
}).catch(err => {
  console.error('❌ Error BD:', err.message);
  process.exit(1);
});