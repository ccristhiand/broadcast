require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');

const dialect = process.env.DB_DIALECT || 'mysql';
const dialectOptions = {};
if (dialect === 'mssql') {
  dialectOptions.options = {
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: true,
    enableArithAbort: true,
  };
}

const sequelize = new Sequelize(
  process.env.DB_NAME || 'broadcastos',
  process.env.DB_USER || 'root',
  process.env.DB_PASS || '',
  {
    host:    process.env.DB_HOST || 'localhost',
    port:    parseInt(process.env.DB_PORT) || (dialect === 'mssql' ? 1433 : 3306),
    dialect,
    dialectOptions,
    logging: false,
    pool: { max: 5, min: 0, acquire: 30000, idle: 10000 },
  }
);

// ── Publication ───────────────────────────────────────────────
const Publication = sequelize.define('Publication', {
  id:          { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  title:       { type: DataTypes.STRING(200), allowNull: false },
  subtitle:    { type: DataTypes.STRING(300), allowNull: true },
  description: { type: DataTypes.TEXT, allowNull: true },
  type:        { type: DataTypes.ENUM('image','video','text','embed'), defaultValue: 'image' },
  mediaUrl:    { type: DataTypes.STRING(500), allowNull: true },
  mediaType:   { type: DataTypes.STRING(100), allowNull: true },
  bgColor:     { type: DataTypes.STRING(20), defaultValue: '#0a0a1a' },
  textColor:   { type: DataTypes.STRING(20), defaultValue: '#ffffff' },
  indefinite:  { type: DataTypes.BOOLEAN, defaultValue: true },
  startDate:   { type: DataTypes.DATE, allowNull: true },
  endDate:     { type: DataTypes.DATE, allowNull: true },
  duration:    { type: DataTypes.INTEGER, defaultValue: 8 },
  active:      { type: DataTypes.BOOLEAN, defaultValue: true },
  order:       { type: DataTypes.INTEGER, defaultValue: 0 },
  embedUrl:    { type: DataTypes.STRING(1000), allowNull: true },
  timeStart:   { type: DataTypes.STRING(5), allowNull: true },  // HH:MM
  timeEnd:     { type: DataTypes.STRING(5), allowNull: true },  // HH:MM
}, { tableName: 'publications', timestamps: true });

// ── Setting ───────────────────────────────────────────────────
const Setting = sequelize.define('Setting', {
  key:   { type: DataTypes.STRING(100), primaryKey: true },
  value: { type: DataTypes.TEXT, allowNull: true },
}, { tableName: 'settings', timestamps: false });

// ── User ──────────────────────────────────────────────────────
const User = sequelize.define('User', {
  id:        { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  username:  { type: DataTypes.STRING(80), allowNull: false, unique: true },
  email:     { type: DataTypes.STRING(200), allowNull: true },
  password:  { type: DataTypes.STRING(255), allowNull: false },
  role:      { type: DataTypes.ENUM('admin','editor'), defaultValue: 'editor' },
  active:    { type: DataTypes.BOOLEAN, defaultValue: true },
  lastLogin: { type: DataTypes.DATE, allowNull: true },
}, { tableName: 'users', timestamps: true });

// ── ActivityLog ───────────────────────────────────────────────
const ActivityLog = sequelize.define('ActivityLog', {
  id:       { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  userId:   { type: DataTypes.UUID, allowNull: false },
  username: { type: DataTypes.STRING(80), allowNull: false },
  action:   { type: DataTypes.STRING(100), allowNull: false },
  entity:   { type: DataTypes.STRING(50), allowNull: true },
  entityId: { type: DataTypes.STRING(36), allowNull: true },
  detail:   { type: DataTypes.TEXT, allowNull: true },
  ip:       { type: DataTypes.STRING(45), allowNull: true },
}, { tableName: 'activity_logs', timestamps: true, updatedAt: false });

// ── Settings helpers ──────────────────────────────────────────
async function getSetting(key, defaultVal = null) {
  const row = await Setting.findByPk(key);
  if (!row) return defaultVal;
  try { return JSON.parse(row.value); } catch { return row.value; }
}
async function setSetting(key, val) {
  const value = typeof val === 'object' ? JSON.stringify(val) : String(val);
  await Setting.upsert({ key, value });
}
async function getAllSettings() {
  const rows = await Setting.findAll();
  const obj = {};
  for (const r of rows) {
    try { obj[r.key] = JSON.parse(r.value); } catch { obj[r.key] = r.value; }
  }
  return { defaultDuration: 8, showClock: true, showBar: true, title: 'BroadcastOS', ...obj };
}

// ── Log helper ────────────────────────────────────────────────
async function log(req, action, entity = null, entityId = null, detail = null) {
  try {
    await ActivityLog.create({
      userId:   req.user.id,
      username: req.user.username,
      action,
      entity,
      entityId: entityId ? String(entityId) : null,
      detail,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    });
  } catch(e) { console.error('Log error:', e.message); }
}

// ── Init ──────────────────────────────────────────────────────
// ── Init ──────────────────────────────────────────────────────
// ── BloombergNews ─────────────────────────────────────────────
const BloombergNews = sequelize.define('BloombergNews', {
  id:          { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  headline:    { type: DataTypes.STRING(500), allowNull: false },
  summary:     { type: DataTypes.TEXT, allowNull: true },
  url:         { type: DataTypes.STRING(1000), allowNull: true },
  section:     { type: DataTypes.STRING(50), defaultValue: 'markets' },
  tickers:     { type: DataTypes.STRING(200), allowNull: true },
  publishedAt: { type: DataTypes.DATE, allowNull: false },
  active:      { type: DataTypes.BOOLEAN, defaultValue: true },
}, { tableName: 'bloomberg_news', timestamps: true, updatedAt: false });

// ── BloombergPrice ─────────────────────────────────────────────
const BloombergPrice = sequelize.define('BloombergPrice', {
  symbol:    { type: DataTypes.STRING(50), primaryKey: true },
  name:      { type: DataTypes.STRING(100), allowNull: false },
  category:  { type: DataTypes.ENUM('fx','index','equity','crypto','commodity'), defaultValue: 'fx' },
  lastPrice: { type: DataTypes.DECIMAL(18,4), defaultValue: 0 },
  prevClose: { type: DataTypes.DECIMAL(18,4), allowNull: true },
  changeAmt: { type: DataTypes.DECIMAL(18,4), allowNull: true },
  changePct: { type: DataTypes.DECIMAL(8,4), allowNull: true },
  currency:  { type: DataTypes.STRING(10), defaultValue: 'USD' },
  active:    { type: DataTypes.BOOLEAN, defaultValue: true },
}, { tableName: 'bloomberg_prices', timestamps: true, createdAt: false });

// ── BloombergConfig ────────────────────────────────────────────
const BloombergConfig = sequelize.define('BloombergConfig', {
  key:   { type: DataTypes.STRING(100), primaryKey: true },
  value: { type: DataTypes.TEXT, allowNull: true },
}, { tableName: 'bloomberg_config', timestamps: false });

async function initDB() {
  await sequelize.authenticate();
  console.log(`✅ Base de datos conectada [${dialect.toUpperCase()}]`);
  await sequelize.sync({ alter: true });
  console.log('✅ Tablas sincronizadas');
}

module.exports = {
  sequelize, Publication, Setting, User, ActivityLog,
  getSetting, setSetting, getAllSettings, log, initDB
};