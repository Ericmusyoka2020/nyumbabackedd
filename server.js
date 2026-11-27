
import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createClient } from '@libsql/client';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const PORT = process.env.PORT || 4000;
const PAYMENT_GATEWAY_URL = process.env.PAYMENT_GATEWAY_URL || 'https://parero.vercel.app';
const TURSO_DATABASE_URL = process.env.TURSO_DATABASE_URL || 'file:./nyumba.db';
const TURSO_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN || '';
const JWT_SECRET = process.env.JWT_SECRET || crypto.createHash('sha256').update(String(TURSO_AUTH_TOKEN || 'nyumba-default-secret').slice(0, 64)).digest('hex');
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE || 'admin';

const EMAILJS_SERVICE_ID = (process.env.EMAILJS_SERVICE_ID || '').trim();
const EMAILJS_PUBLIC_KEY = (process.env.EMAILJS_PUBLIC_KEY || '').trim();
const EMAILJS_PRIVATE_KEY = (process.env.EMAILJS_PRIVATE_KEY || '').trim();
const EMAILJS_TEMPLATE_ID = (process.env.EMAILJS_TEMPLATE_ID || '').trim();

const FIVE_HOURS_MS = 5 * 60 * 60 * 1000;
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = 15000;
const PROPERTY_TYPES = [
  'Single Room',
  'Bedsitter',
  'Studio',
  '1 Bedroom',
  '2 Bedroom',
  '3 Bedroom',
  'Apartment',
  'House',
  'Lodging',
  'Cottage',
  'Restaurant',
  'Students Hostel',
];
const DEFAULT_CONTACT_UNLOCK_PRICES = Object.fromEntries(PROPERTY_TYPES.map((type) => [type, 10]));

const db = createClient({
  url: TURSO_DATABASE_URL,
  authToken: TURSO_AUTH_TOKEN || undefined,
});

app.use(helmet());
const allowedOrigins = [
  'https://house.stackcrafts.com',
  'https://rent.stackcrafts.com',
  'https://main.xyz',
];
app.use(cors({
  origin: allowedOrigins,
}));
app.use(express.json({ limit: '4mb' }));

function isRemoteDisconnect(error) {
  for (let current = error; current; current = current.cause) {
    if (current.code === 'UND_ERR_SOCKET') return true;
  }
  return false;
}

async function fetchUpstream(url, options = {}) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch (error) {
    const code = error.cause?.code || error.name || 'UPSTREAM_ERROR';
    console.warn(`Upstream request failed (${code}): ${new URL(url).host}`);
    const wrapped = new Error('A connected service could not be reached. Please try again.');
    wrapped.status = 502;
    wrapped.code = code;
    throw wrapped;
  }
}

async function fetchUpstreamJson(url, options = {}) {
  const response = await fetchUpstream(url, options);
  let data;
  try {
    data = await response.json();
  } catch {
    const error = new Error(`The connected service returned an invalid response (${response.status}).`);
    error.status = 502;
    throw error;
  }
  return { response, data };
}

app.get('/api/health', async (req, res) => {
  await db.execute('SELECT 1');
  return res.json({ success: true, database: 'connected' });
});

app.get('/api', (req, res) => res.json({ success: true, name: 'Lodora Houses and Homes API', health: '/api/health' }));
app.get(['/', '/index.html', '/admin', '/admin.html'], (req, res) => {
  return res.json({ success: true, name: 'Lodora Houses and Homes API', health: '/api/health' });
});

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, originalHex] = storedHash.split(':');
  const derivedBuf = crypto.scryptSync(String(password), salt, 64);
  const originalBuf = Buffer.from(originalHex, 'hex');
  if (derivedBuf.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derivedBuf, originalBuf);
}

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function safeUser(row) {
  if (!row) return null;
  const { password_hash, ...clean } = row;
  return clean;
}

function normalizePhone(raw) {
  const digits = String(raw || '').replace(/\D/g, '');
  if (digits.startsWith('0') && digits.length === 10) return '254' + digits.slice(1);
  if (digits.startsWith('254') && digits.length === 12) return digits;
  if ((digits.startsWith('7') || digits.startsWith('1')) && digits.length === 9) return '254' + digits;
  return digits;
}

async function initDb() {
  await db.batch([
    `PRAGMA foreign_keys = ON`,
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'AGENT' CHECK (role IN ('USER', 'AGENT', 'ADMIN')),
      call_phone TEXT UNIQUE,
      whatsapp_phone TEXT UNIQUE,
      profile_completed INTEGER NOT NULL DEFAULT 0,
      is_suspended INTEGER NOT NULL DEFAULT 0,
      free_post_used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS password_reset_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      sent_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`,
    `INSERT OR IGNORE INTO system_config (key, value) VALUES
      ('free_posts_allowed', '5'),
      ('free_post_duration_days', '14'),
      ('add_photo_price', '30'),
      ('contact_unlock_prices', '${JSON.stringify(DEFAULT_CONTACT_UNLOCK_PRICES)}')`,
    `UPDATE system_config SET value = '5' WHERE key = 'free_posts_allowed' AND value = '1'`,
    `CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'KES',
      posts_allowed INTEGER NOT NULL,
      duration_days INTEGER NOT NULL,
      priority_level INTEGER NOT NULL DEFAULT 1,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `INSERT OR IGNORE INTO plans (id, name, description, price, currency, posts_allowed, duration_days, priority_level, is_active) VALUES
      ('plan-basic', 'Basic', '1 property post for 30 days', 100, 'KES', 1, 30, 1, 1),
      ('plan-standard', 'Standard', '5 property posts for 30 days', 250, 'KES', 5, 30, 3, 1),
      ('plan-premium', 'Premium', '10 property posts for 60 days', 500, 'KES', 10, 60, 5, 1)`,
    `CREATE TABLE IF NOT EXISTS priority_plans (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'KES',
      duration_days INTEGER NOT NULL,
      priority_level INTEGER NOT NULL DEFAULT 10,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `INSERT OR IGNORE INTO priority_plans (id, name, description, price, currency, duration_days, priority_level, is_active) VALUES
      ('prio-featured', 'Featured', 'Boosted placement for 7 days', 100, 'KES', 7, 10, 1),
      ('prio-top', 'Top Priority', 'Top search placement for 14 days', 250, 'KES', 14, 25, 1)`,
    `CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan_id TEXT,
      source_type TEXT NOT NULL CHECK (source_type IN ('FREE_FIRST_POST', 'PAID_PLAN')),
      posts_total INTEGER NOT NULL,
      posts_used INTEGER NOT NULL DEFAULT 0,
      starts_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      source_label TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS properties (
      id TEXT PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      owner_name TEXT NOT NULL DEFAULT 'Property Owner',
      subscription_id TEXT,
      title TEXT NOT NULL,
      property_type TEXT NOT NULL DEFAULT 'Single Room',
      property_types_json TEXT NOT NULL DEFAULT '[]',
      description TEXT NOT NULL DEFAULT '',
      target_tenants_desc TEXT NOT NULL DEFAULT '',
      min_rent REAL NOT NULL DEFAULT 0,
      max_rent REAL NOT NULL DEFAULT 0,
      monthly_rent REAL NOT NULL DEFAULT 0,
      rent_period TEXT NOT NULL DEFAULT 'MONTH' CHECK (rent_period IN ('DAY', 'NIGHT', 'MONTH', 'YEAR')),
      type_pricing_json TEXT NOT NULL DEFAULT '{}',
      deposit REAL NOT NULL DEFAULT 0,
      county TEXT NOT NULL DEFAULT '',
      town TEXT NOT NULL DEFAULT '',
      estate TEXT NOT NULL DEFAULT '',
      pin_lat REAL,
      pin_lng REAL,
      pin_label TEXT NOT NULL DEFAULT '',
      bedrooms INTEGER NOT NULL DEFAULT 0,
      bathrooms INTEGER NOT NULL DEFAULT 1,
      furnished_status TEXT NOT NULL DEFAULT 'UNFURNISHED',
      amenities_json TEXT NOT NULL DEFAULT '[]',
      images_json TEXT NOT NULL DEFAULT '[]',
      contact_phone TEXT NOT NULL DEFAULT '',
      contact_whatsapp TEXT NOT NULL DEFAULT '',
      contact_hidden INTEGER NOT NULL DEFAULT 0,
      approval_status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (approval_status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED')),
      availability_status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (availability_status IN ('AVAILABLE', 'OCCUPIED', 'PAUSED', 'EXPIRED', 'PENDING_APPROVAL')),
      priority_score INTEGER NOT NULL DEFAULT 1,
      priority_label TEXT NOT NULL DEFAULT 'Normal',
      priority_plan_price REAL NOT NULL DEFAULT 0,
      priority_expires_at TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK (purpose IN ('POST_PLAN', 'PRIORITY_PROMOTION', 'ADD_PHOTO', 'CONTACT_UNLOCK')),
      plan_id TEXT,
      priority_plan_id TEXT,
      property_id TEXT,
      pending_photo_data TEXT,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'KES',
      phone_number TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      result_code INTEGER,
      result_desc TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS property_contact_unlocks (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      property_id TEXT NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
      payment_id TEXT NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
      unlocked_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, property_id)
    )`,
    `CREATE TABLE IF NOT EXISTS property_reports (
      id TEXT PRIMARY KEY,
      property_id TEXT NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      details TEXT,
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'REMOVED_POST', 'REJECTED_RETAINED')),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS admin_alerts (
      id TEXT PRIMARY KEY,
      alert_type TEXT NOT NULL DEFAULT 'USER_COMMENT',
      sender_name TEXT,
      sender_email TEXT,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS guest_contact_payments (
      id TEXT PRIMARY KEY,
      property_id TEXT NOT NULL,
      property_title TEXT NOT NULL,
      amount REAL NOT NULL,
      phone_number TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT 'CONTACT_AND_LOCATION_UNLOCK',
      status TEXT NOT NULL DEFAULT 'PENDING',
      result_code INTEGER,
      result_desc TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS property_activity_notifications (
      id TEXT PRIMARY KEY,
      property_id TEXT NOT NULL,
      activity_type TEXT NOT NULL CHECK (activity_type IN ('CALL', 'WHATSAPP', 'LOCATION_PIN', 'CONTACT_UNLOCK')),
      property_title TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      visitor_name TEXT NOT NULL DEFAULT 'Visitor',
      visitor_phone TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ], 'write');

  const usersColumns = (await db.execute('PRAGMA table_info(users)')).rows.map((column) => column.name);
  if (!usersColumns.includes('phone')) {
    await db.execute('ALTER TABLE users ADD COLUMN phone TEXT');
  }
  if (!usersColumns.includes('password_hash')) {
    await db.execute('ALTER TABLE users ADD COLUMN password_hash TEXT');
  }
  const propertyColumns = (await db.execute('PRAGMA table_info(properties)')).rows.map((column) => column.name);
  const subscriptionColumns = (await db.execute('PRAGMA table_info(subscriptions)')).rows.map((column) => column.name);
  if (!subscriptionColumns.includes('source_label')) {
    await db.execute("ALTER TABLE subscriptions ADD COLUMN source_label TEXT NOT NULL DEFAULT ''");
  }
  if (!propertyColumns.includes('rent_period')) {
    await db.execute("ALTER TABLE properties ADD COLUMN rent_period TEXT NOT NULL DEFAULT 'MONTH'");
  }
  if (!propertyColumns.includes('property_types_json')) {
    await db.execute("ALTER TABLE properties ADD COLUMN property_types_json TEXT NOT NULL DEFAULT '[]'");
  }
  if (!propertyColumns.includes('type_pricing_json')) {
    await db.execute("ALTER TABLE properties ADD COLUMN type_pricing_json TEXT NOT NULL DEFAULT '{}'");
  }
  if (!propertyColumns.includes('contact_hidden')) {
    await db.execute('ALTER TABLE properties ADD COLUMN contact_hidden INTEGER NOT NULL DEFAULT 0');
  }
  if (!propertyColumns.includes('priority_plan_price')) {
    await db.execute('ALTER TABLE properties ADD COLUMN priority_plan_price REAL NOT NULL DEFAULT 0');
  }
  const paymentTable = (await db.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'payments'")).rows[0];
  if (paymentTable && !String(paymentTable.sql || '').includes('CONTACT_UNLOCK')) {
    await db.batch([
      `CREATE TABLE payments_new (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose TEXT NOT NULL CHECK (purpose IN ('POST_PLAN', 'PRIORITY_PROMOTION', 'ADD_PHOTO', 'CONTACT_UNLOCK')),
        plan_id TEXT,
        priority_plan_id TEXT,
        property_id TEXT,
        pending_photo_data TEXT,
        amount REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'KES',
        phone_number TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        result_code INTEGER,
        result_desc TEXT,
        expires_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`,
      `INSERT INTO payments_new (
        id, user_id, purpose, plan_id, priority_plan_id, property_id, pending_photo_data,
        amount, currency, phone_number, status, result_code, result_desc, expires_at, created_at
      ) SELECT
        id, user_id, purpose, plan_id, priority_plan_id, property_id, pending_photo_data,
        amount, currency, phone_number, status, result_code, result_desc, expires_at, created_at
      FROM payments`,
      'DROP TABLE payments',
      'ALTER TABLE payments_new RENAME TO payments',
    ], 'write');
  }
  await db.execute(`
    UPDATE properties
    SET property_types_json = json_array(property_type)
    WHERE property_types_json = '[]' AND property_type != ''
  `);
  await db.execute(`
    UPDATE properties
    SET availability_status = 'AVAILABLE'
    WHERE approval_status = 'APPROVED' AND availability_status = 'EXPIRED'
  `);
  await db.execute(`
    UPDATE users
    SET phone = COALESCE(NULLIF(phone, ''), NULLIF(call_phone, ''), whatsapp_phone)
    WHERE phone IS NULL OR phone = ''
  `);
  const config = await getConfig();
  let contactPrices = {};
  try {
    contactPrices = JSON.parse(config.contact_unlock_prices || '{}');
  } catch {
    console.error('Stored contact unlock prices are invalid JSON; preserving them for admin review.');
  }
  if (contactPrices && typeof contactPrices === 'object' && !Array.isArray(contactPrices)) {
    const migratedPrices = Object.fromEntries(PROPERTY_TYPES.map((type) => [
      type,
      Number(contactPrices[type]) > 0 ? Number(contactPrices[type]) : 10,
    ]));
    await db.execute({
      sql: `INSERT INTO system_config (key, value) VALUES ('contact_unlock_prices', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      args: [JSON.stringify(migratedPrices)],
    });
  }
}

function slugify(str) {
  return `${String(str || 'house').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'house'}-${crypto.randomBytes(3).toString('hex')}`;
}

function normalizePropertyTypes(input, fallbackType = '') {
  const requested = Array.isArray(input) ? input : [fallbackType];
  return [...new Set(requested
    .map((type) => String(type || '').trim())
    .filter((type) => PROPERTY_TYPES.includes(type)))];
}

function contactUnlockPrice(property, config) {
  let prices = {};
  let storedTypes = [];
  try {
    prices = JSON.parse(config.contact_unlock_prices || '{}');
  } catch {
    console.error('The configured contact unlock prices are not valid JSON.');
  }
  try {
    storedTypes = JSON.parse(property.property_types_json || '[]');
  } catch {
    console.error(`Listing ${property.id} has invalid property type data.`);
  }
  const type = normalizePropertyTypes(storedTypes, property.property_type)[0] || property.property_type;
  const price = Number(prices[type] ?? DEFAULT_CONTACT_UNLOCK_PRICES[type] ?? 10);
  return Number.isFinite(price) && price >= 1 ? price : 10;
}

function normalizeRentPricing(input, propertyTypes, fallback = {}) {
  if (input !== undefined && (!input || typeof input !== 'object' || Array.isArray(input))) {
    return { error: 'Enter rent details for every selected property type.' };
  }

  const pricing = {};
  const prices = [];
  for (const type of propertyTypes) {
    const entry = input?.[type] || {};
    const price = Number(entry.price ?? entry.rent_amount ?? fallback.price);
    const rentPeriod = entry.rent_period ?? entry.period ?? fallback.rent_period ?? 'MONTH';
    const rentPeriodDays = rentPeriod === 'DAY' ? Number(entry.rent_period_days ?? entry.period_days ?? 1) : 1;
    const availabilityStatus = entry.availability_status ?? fallback.availability_status ?? 'AVAILABLE';
    if (!Number.isFinite(price) || price <= 0) {
      return { error: `Enter a valid price for ${type}.` };
    }
    if (!['DAY', 'NIGHT', 'MONTH', 'YEAR'].includes(rentPeriod)) {
      return { error: `Select a valid rent period for ${type}.` };
    }
    if (!Number.isInteger(rentPeriodDays) || rentPeriodDays < 1 || rentPeriodDays > 365) {
      return { error: `The number of days for ${type} must be between 1 and 365.` };
    }
    if (!['AVAILABLE', 'OCCUPIED'].includes(availabilityStatus)) {
      return { error: `Select whether ${type} is available or occupied.` };
    }
    pricing[type] = { price, rent_period: rentPeriod, rent_period_days: rentPeriodDays, availability_status: availabilityStatus };
    prices.push(price);
  }

  return {
    pricing,
    minRent: Math.min(...prices),
    maxRent: Math.max(...prices),
    first: pricing[propertyTypes[0]],
    availabilityStatus: Object.values(pricing).some((entry) => entry.availability_status === 'AVAILABLE')
      ? 'AVAILABLE'
      : 'OCCUPIED',
  };
}

function addPlanDuration(startAt, durationDays) {
  const expiry = new Date(startAt);
  expiry.setUTCDate(expiry.getUTCDate() + Number(durationDays));
  return expiry.toISOString();
}

async function getConfig() {
  const res = await db.execute('SELECT key, value FROM system_config');
  return Object.fromEntries(res.rows.map((r) => [r.key, r.value]));
}

function issueToken(subject, role) {
  return jwt.sign({ role }, JWT_SECRET, {
    subject,
    expiresIn: '12h',
    issuer: 'nyumba-api',
    audience: 'nyumba-web',
  });
}

function readBearerToken(req) {
  const authorization = String(req.headers.authorization || '');
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : '';
}

async function requireAuth(req, res, next) {
  try {
    const claims = jwt.verify(readBearerToken(req), JWT_SECRET, {
      issuer: 'nyumba-api',
      audience: 'nyumba-web',
    });
    if (typeof claims === 'string' || !claims.sub) {
      return res.status(401).json({ success: false, message: 'Sign in required' });
    }

    const found = await db.execute({
      sql: 'SELECT * FROM users WHERE id = ?',
      args: [claims.sub],
    });
    const user = found.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Invalid account session' });
    if (user.is_suspended) {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        email: user.email,
        message: 'This account is suspended. Submit a review request to the admin.',
      });
    }
    req.user = user;
    return next();
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ success: false, message: 'Your session expired. Please sign in again.' });
    }
    if (isRemoteDisconnect(err)) {
      console.warn('Account authentication could not reach the database.');
      return res.status(503).json({ success: false, message: 'Account data is temporarily unavailable. Please retry.' });
    }
    console.error('Authentication check failed:', err.message);
    return res.status(500).json({ success: false, message: 'Could not verify account session' });
  }
}

async function optionalAuth(req, res, next) {
  const token = readBearerToken(req);
  if (!token) return next();
  try {
    const claims = jwt.verify(token, JWT_SECRET, {
      issuer: 'nyumba-api',
      audience: 'nyumba-web',
    });
    if (typeof claims === 'string' || !claims.sub) return next();
    const user = (await db.execute({
      sql: 'SELECT * FROM users WHERE id = ?',
      args: [claims.sub],
    })).rows[0];
    if (user && !user.is_suspended) req.user = user;
    return next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) return next();
    console.error('Optional account lookup failed:', error.message);
    return res.status(500).json({ success: false, message: 'Could not verify account session.' });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const claims = jwt.verify(readBearerToken(req), JWT_SECRET, {
      issuer: 'nyumba-api',
      audience: 'nyumba-web',
    });
    if (typeof claims === 'string' || claims.role !== 'ADMIN' || !claims.sub) {
      return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    if (claims.sub !== 'admin') {
      const user = (await db.execute({
        sql: 'SELECT id, role, is_suspended FROM users WHERE id = ?',
        args: [claims.sub],
      })).rows[0];
      if (!user || user.role !== 'ADMIN' || user.is_suspended) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
      }
    }
    return next();
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ success: false, message: 'Admin session expired. Enter the passcode again.' });
    }
    if (isRemoteDisconnect(err)) {
      console.warn('Admin authorization could not reach the database.');
      return res.status(503).json({ success: false, message: 'Admin data is temporarily unavailable. Please retry.' });
    }
    console.error('Admin authorization check failed:', err.message);
    return res.status(500).json({ success: false, message: 'Could not verify admin session' });
  }
}

async function sendResetCodeEmail(toEmail, toName, code) {
  const missingConfiguration = [
    ['EMAILJS_SERVICE_ID', EMAILJS_SERVICE_ID],
    ['EMAILJS_PUBLIC_KEY', EMAILJS_PUBLIC_KEY],
    ['EMAILJS_PRIVATE_KEY', EMAILJS_PRIVATE_KEY],
    ['EMAILJS_TEMPLATE_ID', EMAILJS_TEMPLATE_ID],
  ].filter(([, value]) => !value).map(([name]) => name);
  if (missingConfiguration.length) {
    throw new Error(`Password reset email is not configured on this API host. Missing: ${missingConfiguration.join(', ')}.`);
  }
  const resetMessage = `Hello ${toName || 'there'}, your Lodora Houses and Homes password reset verification code is ${code}. Enter this code in the password reset form within 15 minutes. If you did not request this, you can ignore this email.`;
  const resp = await fetchUpstream('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service_id: EMAILJS_SERVICE_ID,
      template_id: EMAILJS_TEMPLATE_ID,
      user_id: EMAILJS_PUBLIC_KEY,
      accessToken: EMAILJS_PRIVATE_KEY,
      template_params: {
        subject: 'Lodora Houses and Homes password reset verification code',
        message: resetMessage,
        content: resetMessage,
        to_email: toEmail,
        to_name: toName,
        user_name: toName,
        email: toEmail,
        name: toName,
        code,
        otp: code,
        passcode: code,
        verification_code: code,
        reset_code: code,
        expires_minutes: '15',
      },
    }),
  });
  if (!resp.ok) {
    const responseText = (await resp.text()).trim();
    const error = new Error(`EmailJS rejected the reset email (${resp.status})${responseText ? `: ${responseText.slice(0, 300)}` : '.'}`);
    error.status = 502;
    throw error;
  }
  const responseText = (await resp.text()).trim();
  if (responseText.toLowerCase() !== 'ok') {
    const error = new Error(`EmailJS returned an unexpected response${responseText ? `: ${responseText.slice(0, 300)}` : '.'}`);
    error.status = 502;
    throw error;
  }
}

// USER SIGN-UP WITH PHONE NUMBER
app.post('/api/auth/register', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const phoneNorm = normalizePhone(req.body.phone || '');
    const cleanName = String(req.body.full_name || '').trim() || (cleanEmail ? cleanEmail.split('@')[0] : 'Member');

    if (!cleanEmail || password.length < 6) {
      return res.status(400).json({ success: false, message: 'Valid email and password (min 6 chars) required' });
    }
    if (phoneNorm.length < 12) {
      return res.status(400).json({ success: false, message: 'Enter a valid phone number when creating an account' });
    }

    const existing = (await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [cleanEmail] })).rows[0];
    if (existing) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists' });
    }

    const id = crypto.randomUUID();
    const passwordHash = hashPassword(password);
    await db.execute({
      sql: `INSERT INTO users (id, full_name, email, phone, call_phone, whatsapp_phone, password_hash, role, profile_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'AGENT', 1)`,
      args: [id, cleanName, cleanEmail, phoneNorm, phoneNorm, phoneNorm, passwordHash],
    });
    const user = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })).rows[0];
    return res.status(201).json({
      success: true,
      message: 'Account created',
      data: { user: safeUser(user), token: issueToken(user.id, user.role) },
    });
  } catch (err) {
    if (String(err.message || '').includes('UNIQUE')) {
      return res.status(409).json({ success: false, message: 'Email or phone number is already registered' });
    }
    return res.status(500).json({ success: false, message: 'Failed to create account' });
  }
});

app.get('/api/auth/session', requireAuth, (req, res) => {
  return res.json({ success: true, data: { user: safeUser(req.user) } });
});

// USER EMAIL & PASSWORD LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    if (!cleanEmail || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = (await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [cleanEmail] })).rows[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
    if (user.is_suspended) {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        message: 'This account is suspended. You can only submit a review request to the admin.',
      });
    }

    return res.json({
      success: true,
      message: 'Logged in',
      data: { user: safeUser(user), token: issueToken(user.id, user.role) },
    });
  } catch {
    return res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.post('/api/auth/suspension-review', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const message = String(req.body?.message || '').trim();
  if (!email || !message || message.length > 2000) {
    return res.status(400).json({ success: false, message: 'Enter the account email and a review message (up to 2000 characters).' });
  }
  const user = (await db.execute({
    sql: 'SELECT id, full_name, is_suspended FROM users WHERE email = ?',
    args: [email],
  })).rows[0];
  if (!user || !user.is_suspended) {
    return res.status(400).json({ success: false, message: 'No suspended account was found for this email.' });
  }
  await db.execute({
    sql: `INSERT INTO admin_alerts (id, alert_type, sender_name, sender_email, message)
          VALUES (?, 'SUSPENSION_REVIEW', ?, ?, ?)`,
    args: [crypto.randomUUID(), user.full_name, email, message],
  });
  return res.status(201).json({ success: true, message: 'Your account review request was sent to the admin.' });
});

// Admin passcode exchange; the passcode itself is never returned to the browser.
app.post('/api/auth/admin-passcode', async (req, res) => {
  const { passcode } = req.body;
  if (String(passcode || '').trim() !== ADMIN_PASSCODE) {
    return res.status(401).json({ success: false, message: 'Invalid admin passcode' });
  }
  return res.json({
    success: true,
    message: 'Admin unlocked',
    data: { token: issueToken('admin', 'ADMIN'), role: 'ADMIN' },
  });
});

// FORGOT PASSWORD: SEND ONE-TIME CODE VIA EMAILJS (COOLDOWN: 5 HOURS AFTER PREVIOUS SEND; EXPIRES IN 15 MINUTES)
app.post('/api/auth/forgot-password/request', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').toLowerCase().trim();
    if (!cleanEmail) {
      return res.status(400).json({ success: false, message: 'Enter your account email' });
    }

    const user = (await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [cleanEmail] })).rows[0];
    if (!user) {
      return res.status(404).json({ success: false, message: 'No account found with that email' });
    }

    const nowMs = Date.now();
    const lastSent = (await db.execute({
      sql: 'SELECT sent_at_ms FROM password_reset_codes WHERE user_id = ? ORDER BY sent_at_ms DESC LIMIT 1',
      args: [user.id],
    })).rows[0];

    if (lastSent && nowMs - Number(lastSent.sent_at_ms) < FIVE_HOURS_MS) {
      const remainingMs = FIVE_HOURS_MS - (nowMs - Number(lastSent.sent_at_ms));
      const minsLeft = Math.ceil(remainingMs / 60000);
      return res.status(429).json({
        success: false,
        message: `Verification code already sent. You can request another code after 5 hours (${minsLeft} min remaining).`,
      });
    }

    const code = String(crypto.randomInt(100000, 999999));
    const codeId = crypto.randomUUID();
    const expiresAtMs = nowMs + FIFTEEN_MINUTES_MS;

    await db.execute({
      sql: `INSERT INTO password_reset_codes (id, user_id, email, code_hash, sent_at_ms, expires_at_ms, used)
            VALUES (?, ?, ?, ?, ?, ?, 0)`,
      args: [codeId, user.id, user.email, hashCode(code), nowMs, expiresAtMs],
    });

    try {
      await sendResetCodeEmail(cleanEmail, user.full_name, code);
    } catch (emailError) {
      try {
        await db.execute({
          sql: 'DELETE FROM password_reset_codes WHERE id = ?',
          args: [codeId],
        });
      } catch (cleanupError) {
        console.error('Could not remove an unsent password-reset code:', cleanupError.message);
      }
      throw emailError;
    }

    return res.json({
      success: true,
      message: 'One-time verification code sent to your email. It expires in 15 minutes.',
    });
  } catch (err) {
    return res.status(err.status || 500).json({ success: false, message: err.message || 'Failed to send verification code' });
  }
});

// FORGOT PASSWORD: VERIFY ONE-TIME CODE (ACCOUNT-BOUND, 15-MIN EXPIRY, SINGLE-USE) AND SET NEW PASSWORD
app.post('/api/auth/forgot-password/reset', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').toLowerCase().trim();
    const code = String(req.body.code || '').trim();
    const newPassword = String(req.body.new_password || '');

    if (!cleanEmail || !code || newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Email, 6-digit code, and new password (min 6 chars) are required' });
    }

    const user = (await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [cleanEmail] })).rows[0];
    if (!user) {
      return res.status(404).json({ success: false, message: 'Account not found' });
    }

    const record = (await db.execute({
      sql: `SELECT * FROM password_reset_codes
            WHERE user_id = ? AND email = ? AND code_hash = ?
            ORDER BY sent_at_ms DESC LIMIT 1`,
      args: [user.id, cleanEmail, hashCode(code)],
    })).rows[0];

    if (!record) {
      return res.status(400).json({ success: false, message: 'Invalid verification code for this account' });
    }
    if (Number(record.used) === 1) {
      return res.status(400).json({ success: false, message: 'This verification code has already been used' });
    }
    if (Date.now() > Number(record.expires_at_ms)) {
      return res.status(400).json({ success: false, message: 'Verification code expired (15-minute limit exceeded)' });
    }

    const newHash = hashPassword(newPassword);
    await db.batch([
      {
        sql: 'UPDATE password_reset_codes SET used = 1 WHERE id = ?',
        args: [record.id],
      },
      {
        sql: 'UPDATE users SET password_hash = ? WHERE id = ?',
        args: [newHash, user.id],
      },
    ], 'write');

    return res.json({ success: true, message: 'Password changed successfully. You can now log in.' });
  } catch {
    return res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

app.post('/api/auth/forgot-password/verify', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').toLowerCase().trim();
    const code = String(req.body.code || '').trim();
    if (!cleanEmail || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ success: false, message: 'Enter the account email and its 6-digit code.' });
    }

    const user = (await db.execute({
      sql: 'SELECT id FROM users WHERE email = ?',
      args: [cleanEmail],
    })).rows[0];
    if (!user) return res.status(400).json({ success: false, message: 'The email or verification code is invalid.' });

    const record = (await db.execute({
      sql: `SELECT id, expires_at_ms, used FROM password_reset_codes
            WHERE user_id = ? AND email = ? AND code_hash = ?
            ORDER BY sent_at_ms DESC LIMIT 1`,
      args: [user.id, cleanEmail, hashCode(code)],
    })).rows[0];
    if (!record || Number(record.used) || Date.now() > Number(record.expires_at_ms)) {
      return res.status(400).json({ success: false, message: 'The verification code is invalid or expired.' });
    }
    return res.json({ success: true, message: 'Code verified. Choose a new password.' });
  } catch (err) {
    console.error('Password reset code verification failed:', err);
    return res.status(500).json({ success: false, message: 'Could not verify the code. Please try again.' });
  }
});

// UNIQUE CALL & WHATSAPP NUMBERS (1 USE PER ACCOUNT)
app.put('/api/user/contact-profile', requireAuth, async (req, res) => {
  try {
    const callPhone = normalizePhone(req.body.call_phone);
    const whatsappPhone = normalizePhone(req.body.whatsapp_phone);
    const fullName = String(req.body.full_name || req.user.full_name).trim();

    if (callPhone.length < 12 || whatsappPhone.length < 12) {
      return res.status(400).json({
        success: false,
        message: 'Enter valid Kenyan Call and WhatsApp numbers (e.g., 0712345678)',
      });
    }

    const conflict = await db.execute({
      sql: `SELECT id FROM users WHERE id != ? AND (call_phone IN (?, ?) OR whatsapp_phone IN (?, ?))`,
      args: [req.user.id, callPhone, whatsappPhone, callPhone, whatsappPhone],
    });
    if (conflict.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Number already used on another account. Each number can only be used once per account.',
      });
    }

    await db.execute({
      sql: `UPDATE users SET full_name = ?, phone = COALESCE(phone, ?), call_phone = ?, whatsapp_phone = ?, profile_completed = 1 WHERE id = ?`,
      args: [fullName, callPhone, callPhone, whatsappPhone, req.user.id],
    });
    await db.execute({
      sql: `UPDATE properties SET contact_phone = ?, contact_whatsapp = ?, owner_name = ? WHERE owner_id = ?`,
      args: [callPhone, whatsappPhone, fullName, req.user.id],
    });

    const updated = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.user.id] })).rows[0];
    return res.json({ success: true, message: 'Unique Call & WhatsApp numbers saved', data: safeUser(updated) });
  } catch {
    return res.status(500).json({ success: false, message: 'Failed to save contact numbers' });
  }
});

// PUBLIC HOUSE LISTINGS
app.get('/api/properties/:id', optionalAuth, async (req, res) => {
  try {
    const now = new Date().toISOString();
    const config = await getConfig();
    const property = (await db.execute({
      sql: `SELECT id, title, property_type, property_types_json, type_pricing_json, owner_name, estate, town, county, min_rent, max_rent,
                   rent_period, availability_status,
                   contact_phone, contact_whatsapp,
                   expires_at, contact_hidden, pin_lat, pin_lng, pin_label, description, target_tenants_desc, images_json
            FROM properties
            WHERE id = ? AND approval_status = 'APPROVED'
              AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
      args: [req.params.id],
    })).rows[0];
    if (!property) return res.status(404).json({ success: false, message: 'This listing is no longer available.' });
    const isLocked = Boolean(property.contact_hidden) || property.expires_at <= now;
    const accountUnlock = req.user ? (await db.execute({
      sql: 'SELECT 1 FROM property_contact_unlocks WHERE user_id = ? AND property_id = ?',
      args: [req.user.id, property.id],
    })).rows[0] : null;
    const guestUnlock = req.query.unlock_token ? (await db.execute({
      sql: `SELECT 1 FROM guest_contact_payments
            WHERE id = ? AND property_id = ? AND status = 'SUCCESSFUL'`,
      args: [String(req.query.unlock_token), property.id],
    })).rows[0] : null;
    const contactUnlocked = !isLocked || Boolean(accountUnlock || guestUnlock);
    return res.json({
      success: true,
      data: {
        ...property,
        contact_phone: contactUnlocked ? property.contact_phone : null,
        contact_whatsapp: contactUnlocked ? property.contact_whatsapp : null,
        pin_lat: contactUnlocked ? property.pin_lat : null,
        pin_lng: contactUnlocked ? property.pin_lng : null,
        contact_locked: isLocked && !contactUnlocked,
        contact_unlock_price: contactUnlockPrice(property, config),
      },
    });
  } catch {
    return res.status(500).json({ success: false, message: 'Failed to load listing details.' });
  }
});

app.get('/api/properties', async (req, res) => {
  try {
    const { county, town, property_type, min_rent, max_rent, owner_name, q, sort = 'priority' } = req.query;
    const now = new Date().toISOString();
    const conds = [`approval_status = 'APPROVED'`, `availability_status IN ('AVAILABLE', 'OCCUPIED')`];
    const args = [];

    if (county) { conds.push('LOWER(county) LIKE LOWER(?)'); args.push(`%${county}%`); }
    if (town) { conds.push('LOWER(town) LIKE LOWER(?)'); args.push(`%${town}%`); }
    if (property_type) {
      conds.push(`(
        LOWER(property_type) = LOWER(?)
        OR EXISTS (
          SELECT 1 FROM json_each(
            CASE WHEN json_valid(property_types_json) THEN property_types_json ELSE '[]' END
          ) AS selected_type
          WHERE LOWER(selected_type.value) = LOWER(?)
        )
      )`);
      args.push(property_type, property_type);
    }
    if (owner_name) { conds.push('LOWER(owner_name) LIKE LOWER(?)'); args.push(`%${owner_name}%`); }
    if (min_rent) { conds.push('max_rent >= ?'); args.push(Number(min_rent)); }
    if (max_rent) { conds.push('min_rent <= ?'); args.push(Number(max_rent)); }
    if (q) {
      conds.push('(LOWER(title) LIKE LOWER(?) OR LOWER(town) LIKE LOWER(?) OR LOWER(estate) LIKE LOWER(?) OR LOWER(county) LIKE LOWER(?) OR LOWER(owner_name) LIKE LOWER(?) OR LOWER(property_types_json) LIKE LOWER(?))');
      args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
    }

    const priorityOrder = `CASE WHEN priority_expires_at > '${now}' THEN 1 ELSE 0 END DESC,
      priority_plan_price DESC,
      CASE WHEN priority_expires_at > '${now}' THEN priority_score ELSE 1 END DESC`;
    const orderBy =
      sort === 'lowest_price' ? `${priorityOrder}, min_rent ASC` :
      sort === 'highest_price' ? `${priorityOrder}, max_rent DESC` :
      sort === 'newest' ? `${priorityOrder}, created_at DESC` :
      `${priorityOrder}, created_at DESC`;

    const rows = await db.execute({
      sql: `SELECT id, title, property_type, property_types_json, type_pricing_json, owner_name, estate, town, county, min_rent, max_rent,
                   rent_period, availability_status,
                   CASE WHEN expires_at > ? AND contact_hidden = 0 THEN contact_phone ELSE NULL END AS contact_phone,
                   CASE WHEN expires_at > ? AND contact_hidden = 0 THEN contact_whatsapp ELSE NULL END AS contact_whatsapp,
                   expires_at, contact_hidden, priority_score, priority_label, priority_expires_at,
                   CASE WHEN expires_at > ? AND contact_hidden = 0 THEN pin_lat ELSE NULL END AS pin_lat,
                   CASE WHEN expires_at > ? AND contact_hidden = 0 THEN pin_lng ELSE NULL END AS pin_lng,
                   pin_label,
                   json_extract(images_json, '$[0]') AS cover_image
            FROM properties WHERE ${conds.join(' AND ')} ORDER BY ${orderBy} LIMIT 80`,
      args: [now, now, now, now, ...args],
    });
    const config = await getConfig();
    return res.json({
      success: true,
      data: rows.rows.map((property) => ({
        ...property,
        contact_locked: Boolean(property.contact_hidden) || property.expires_at <= now,
        contact_unlock_price: contactUnlockPrice(property, config),
      })),
    });
  } catch {
    return res.status(500).json({ success: false, message: 'Failed to load houses' });
  }
});

app.get('/api/properties/:id/contact', optionalAuth, async (req, res) => {
  try {
    const property = (await db.execute({
      sql: `SELECT id, property_type, property_types_json, contact_phone, contact_whatsapp,
                   contact_hidden, expires_at
            FROM properties
            WHERE id = ? AND approval_status = 'APPROVED'
              AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
      args: [req.params.id],
    })).rows[0];
    if (!property) return res.status(404).json({ success: false, message: 'This listing is no longer available.' });

    const unlock = req.user ? (await db.execute({
      sql: 'SELECT 1 FROM property_contact_unlocks WHERE user_id = ? AND property_id = ?',
      args: [req.user.id, property.id],
    })).rows[0] : null;
    const isLocked = Boolean(property.contact_hidden) || property.expires_at <= new Date().toISOString();
    const guestPayment = req.query.unlock_token ? (await db.execute({
      sql: `SELECT 1 FROM guest_contact_payments
            WHERE id = ? AND property_id = ? AND status = 'SUCCESSFUL'`,
      args: [String(req.query.unlock_token), property.id],
    })).rows[0] : null;
    if (isLocked && !unlock && !guestPayment) {
      return res.status(402).json({
        success: false,
        code: 'CONTACT_LOCKED',
        amount: contactUnlockPrice(property, await getConfig()),
        property_type: normalizePropertyTypes(
          JSON.parse(property.property_types_json || '[]'),
          property.property_type,
        )[0] || property.property_type,
        message: 'A small payment is required to unlock the contact and exact location. It goes to the system, not the landlord or house owner.',
      });
    }

    return res.json({
      success: true,
      data: {
        contact_phone: property.contact_phone,
        contact_whatsapp: property.contact_whatsapp,
      },
    });
  } catch (error) {
    console.error('Could not load listing contact:', error.message);
    return res.status(500).json({ success: false, message: 'Could not load listing contact.' });
  }
});

// CREATE PROPERTY
app.post('/api/properties', requireAuth, async (req, res) => {
  let freePostReserved = false;
  try {
    const callPhone = req.user.call_phone || req.user.phone;
    const waPhone = req.user.whatsapp_phone || req.user.phone;
    if (!callPhone || !waPhone) {
      return res.status(400).json({
        success: false,
        message: 'Set your Call and WhatsApp numbers first before posting a house.',
      });
    }

    const b = req.body || {};
    const propertyTypes = normalizePropertyTypes(b.property_types, b.property_type);
    if (!propertyTypes.length) {
      return res.status(400).json({ success: false, message: 'Select at least one valid property type in this building.' });
    }
    const rentPricing = normalizeRentPricing(b.rent_pricing, propertyTypes, {
      price: b.rent_amount ?? b.min_rent ?? b.monthly_rent,
      rent_period: b.rent_period,
      availability_status: b.availability_status,
    });
    if (rentPricing.error) {
      return res.status(400).json({ success: false, message: rentPricing.error });
    }

    const cfg = await getConfig();
    const freePostsAllowed = Number(cfg.free_posts_allowed || 5);
    const freeDays = Number(cfg.free_post_duration_days || 14);
    const requestedImages = Array.isArray(b.images) ? b.images : [];
    if (requestedImages.length > 3) {
      return res.status(400).json({ success: false, message: 'A new listing includes up to 3 free photos. Pay the add-photo fee to add a fourth photo later.' });
    }

    const existingPostCount = Number((await db.execute({
      sql: 'SELECT COUNT(*) AS count FROM properties WHERE owner_id = ?',
      args: [req.user.id],
    })).rows[0].count);
    await db.execute({
      sql: 'UPDATE users SET free_post_used = MAX(free_post_used, ?) WHERE id = ?',
      args: [existingPostCount, req.user.id],
    });
    const reservation = await db.execute({
      sql: 'UPDATE users SET free_post_used = free_post_used + 1 WHERE id = ? AND free_post_used < ?',
      args: [req.user.id, freePostsAllowed],
    });
    if (!reservation.rowsAffected) {
      return res.status(402).json({
        success: false,
        message: `This account has used all ${freePostsAllowed} free listing posts. Contact the administrator if you need more.`,
      });
    }
    freePostReserved = true;

    const propertyType = propertyTypes[0];
    const title = String(b.title || '').trim() || `${propertyTypes.join(', ')} Listing`;
    const minRent = rentPricing.minRent;
    const maxRent = rentPricing.maxRent;
    const rentPeriod = rentPricing.first.rent_period;
    const requestedAvailability = rentPricing.availabilityStatus;
    const images = requestedImages;
    const amenities = Array.isArray(b.amenities) ? b.amenities : [];

    const id = crypto.randomUUID();
    const slug = slugify(`${title}-${b.town || ''}`);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + freeDays * 86400000).toISOString();

    await db.execute({
      sql: `INSERT INTO properties (
        id, slug, owner_id, owner_name, subscription_id, title, property_type,
        property_types_json,
        description, target_tenants_desc, min_rent, max_rent, monthly_rent, rent_period, type_pricing_json, deposit,
        county, town, estate, pin_lat, pin_lng, pin_label,
        bedrooms, bathrooms, furnished_status, amenities_json, images_json,
        contact_phone, contact_whatsapp, approval_status, availability_status, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?)`,
      args: [
        id, slug, req.user.id, req.user.full_name, null, title, propertyType, JSON.stringify(propertyTypes),
        String(b.description || '').trim(),
        String(b.target_tenants_desc || '').trim(),
        minRent, maxRent, minRent, rentPeriod, JSON.stringify(rentPricing.pricing), Number(b.deposit || 0),
        String(b.county || '').trim(), String(b.town || '').trim(), String(b.estate || '').trim(),
        b.pin_lat !== undefined && b.pin_lat !== null && b.pin_lat !== '' ? Number(b.pin_lat) : null,
        b.pin_lng !== undefined && b.pin_lng !== null && b.pin_lng !== '' ? Number(b.pin_lng) : null,
        String(b.pin_label || '').trim(),
        Number(b.bedrooms || 0), Number(b.bathrooms || 1),
        String(b.furnished_status || 'UNFURNISHED'),
        JSON.stringify(amenities), JSON.stringify(images),
        callPhone, waPhone, requestedAvailability, expiresAt,
      ],
    });
    freePostReserved = false;

    return res.status(201).json({
      success: true,
      message: 'Your free listing was submitted. An admin must approve it before it goes live.',
      data: { id, slug, approval_status: 'PENDING_APPROVAL' },
    });
  } catch (err) {
    if (freePostReserved) {
      await db.execute({
        sql: 'UPDATE users SET free_post_used = MAX(0, free_post_used - 1) WHERE id = ?',
        args: [req.user.id],
      }).catch((rollbackError) => console.error('Could not restore a reserved free post:', rollbackError.message));
    }
    return res.status(500).json({ success: false, message: 'Failed to create house post', error: err.message });
  }
});

// EDIT EXISTING HOUSE
app.put('/api/user/properties/:id', requireAuth, async (req, res) => {
  try {
    const existing = (await db.execute({
      sql: 'SELECT * FROM properties WHERE id = ? AND owner_id = ?',
      args: [req.params.id, req.user.id],
    })).rows[0];
    if (!existing) return res.status(404).json({ success: false, message: 'House not found' });

    const b = req.body || {};
    const propertyTypes = b.property_types !== undefined
      ? normalizePropertyTypes(b.property_types, b.property_type)
      : normalizePropertyTypes(JSON.parse(existing.property_types_json || '[]'), existing.property_type);
    if (!propertyTypes.length) {
      return res.status(400).json({ success: false, message: 'Select at least one valid property type in this building.' });
    }
    let existingPricing = {};
    try {
      existingPricing = JSON.parse(existing.type_pricing_json || '{}');
    } catch {
      existingPricing = {};
    }
    let rentPricing;
    if (b.rent_pricing !== undefined) {
      rentPricing = normalizeRentPricing(b.rent_pricing, propertyTypes, {

      });
    } else if (Object.keys(existingPricing).length) {
      rentPricing = normalizeRentPricing(existingPricing, propertyTypes, {
        price: existing.min_rent ?? existing.monthly_rent,
        rent_period: existing.rent_period,
        availability_status: existing.availability_status,
      });
    } else if (b.rent_amount !== undefined || b.min_rent !== undefined) {
      rentPricing = normalizeRentPricing(undefined, propertyTypes, {
        price: b.rent_amount ?? b.min_rent,
        rent_period: b.rent_period ?? existing.rent_period,
      });
    } else if (propertyTypes.join('|') === normalizePropertyTypes(JSON.parse(existing.property_types_json || '[]'), existing.property_type).join('|')) {
      rentPricing = {
        pricing: {},
        minRent: Number(existing.min_rent ?? existing.monthly_rent),
        maxRent: Number(existing.max_rent ?? existing.monthly_rent),
        first: { rent_period: existing.rent_period || 'MONTH' },
        availabilityStatus: existing.availability_status === 'OCCUPIED' ? 'OCCUPIED' : 'AVAILABLE',
      };
    } else {
      rentPricing = normalizeRentPricing(undefined, propertyTypes, {
        price: existing.min_rent ?? existing.monthly_rent,
        rent_period: existing.rent_period,
        availability_status: existing.availability_status,
      });
    }
    if (rentPricing.error) {
      return res.status(400).json({ success: false, message: rentPricing.error });
    }
    const minRent = rentPricing.minRent;
    const maxRent = rentPricing.maxRent;

    const existingImgs = JSON.parse(existing.images_json || '[]');
    const keptImages = Array.isArray(b.kept_images)
      ? b.kept_images.filter((img) => existingImgs.includes(img))
      : existingImgs;
    const newImages = Array.isArray(b.new_images) ? b.new_images : [];
    if (newImages.some((image) => typeof image !== 'string' || !image.trim())
      || (newImages.length && keptImages.length + newImages.length > 3)
      || keptImages.length + newImages.length > 4) {
      return res.status(400).json({ success: false, message: 'Up to 3 photos are included for free. Add free photos up to that limit; the fourth photo requires payment.' });
    }
    const finalImgs = [...keptImages, ...newImages];
    if (finalImgs.length === 0) {
      return res.status(400).json({ success: false, message: 'A listing must keep at least one photo.' });
    }
    if (finalImgs.length > 4) {
      return res.status(400).json({ success: false, message: 'A listing can have no more than 4 photos.' });
    }

    await db.execute({
      sql: `UPDATE properties SET
        title = ?, property_type = ?, property_types_json = ?, description = ?, target_tenants_desc = ?,
        min_rent = ?, max_rent = ?, monthly_rent = ?, rent_period = ?, type_pricing_json = ?, deposit = ?,
        availability_status = CASE
          WHEN availability_status IN ('AVAILABLE', 'OCCUPIED') THEN ?
          ELSE availability_status
        END,
        county = ?, town = ?, estate = ?, pin_lat = ?, pin_lng = ?, pin_label = ?,
        images_json = ?
        WHERE id = ? AND owner_id = ?`,
      args: [
        b.title !== undefined ? String(b.title).trim() : existing.title,
        propertyTypes[0],
        JSON.stringify(propertyTypes),
        b.description !== undefined ? String(b.description).trim() : existing.description,
        b.target_tenants_desc !== undefined ? String(b.target_tenants_desc).trim() : existing.target_tenants_desc,
        minRent, maxRent, minRent, rentPricing.first.rent_period,
        JSON.stringify(Object.keys(rentPricing.pricing).length ? rentPricing.pricing : existingPricing),
        b.deposit !== undefined ? Number(b.deposit) : Number(existing.deposit),
        rentPricing.availabilityStatus,
        b.county !== undefined ? String(b.county).trim() : existing.county,
        b.town !== undefined ? String(b.town).trim() : existing.town,
        b.estate !== undefined ? String(b.estate).trim() : existing.estate,
        b.pin_lat !== undefined && b.pin_lat !== '' ? Number(b.pin_lat) : existing.pin_lat,
        b.pin_lng !== undefined && b.pin_lng !== '' ? Number(b.pin_lng) : existing.pin_lng,
        b.pin_label !== undefined ? String(b.pin_label).trim() : existing.pin_label,
        JSON.stringify(finalImgs),
        req.params.id, req.user.id,
      ],
    });

    return res.json({ success: true, message: 'House details updated' });
  } catch {
    return res.status(500).json({ success: false, message: 'Failed to update house' });
  }
});

app.get('/api/user/dashboard', requireAuth, async (req, res) => {
  const properties = (await db.execute({ sql: 'SELECT * FROM properties WHERE owner_id = ? ORDER BY created_at DESC', args: [req.user.id] })).rows;
  const subscriptions = (await db.execute({
    sql: `SELECT s.*, p.name AS plan_name
          FROM subscriptions s
          LEFT JOIN plans p ON p.id = s.plan_id
          WHERE s.user_id = ?
          ORDER BY s.created_at DESC`,
    args: [req.user.id],
  })).rows;
  const payments = (await db.execute({ sql: 'SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC', args: [req.user.id] })).rows;
  const dashboardUser = safeUser(req.user);
  dashboardUser.free_post_used = Math.max(Number(dashboardUser.free_post_used || 0), properties.length);
  return res.json({ success: true, data: { user: dashboardUser, properties, subscriptions, payments } });
});

app.patch('/api/user/properties/:id/availability', requireAuth, async (req, res) => {
  const { availability_status } = req.body;
  if (!['AVAILABLE', 'OCCUPIED', 'PAUSED'].includes(availability_status)) {
    return res.status(400).json({ success: false, message: 'Invalid status' });
  }
  const prop = (await db.execute({ sql: 'SELECT * FROM properties WHERE id = ? AND owner_id = ?', args: [req.params.id, req.user.id] })).rows[0];
  if (!prop) return res.status(404).json({ success: false, message: 'House not found' });
  if (prop.approval_status !== 'APPROVED' && availability_status === 'AVAILABLE') {
    return res.status(400).json({ success: false, message: 'Admin must approve post before setting AVAILABLE' });
  }
  await db.execute({
    sql: 'UPDATE properties SET availability_status = ? WHERE id = ? AND owner_id = ?',
    args: [availability_status, req.params.id, req.user.id],
  });
  return res.json({ success: true, message: `Status updated to ${availability_status}` });
});

app.post('/api/user/properties/:id/renew', requireAuth, async (req, res) => {
  return res.status(400).json({ success: false, message: 'Select a renewal plan and complete payment to renew this listing.' });
});

app.post('/api/properties/:id/report', async (req, res) => {
  const { reason, details } = req.body;
  if (!reason) return res.status(400).json({ success: false, message: 'Reason is required' });
  await db.execute({
    sql: 'INSERT INTO property_reports (id, property_id, reason, details) VALUES (?, ?, ?, ?)',
    args: [crypto.randomUUID(), req.params.id, reason, details || ''],
  });
  return res.status(201).json({ success: true, message: 'Report sent to admin' });
});

app.post('/api/alerts/comment', async (req, res) => {
  const { sender_name, sender_email, message } = req.body;
  if (!String(message || '').trim()) {
    return res.status(400).json({ success: false, message: 'Please write a comment' });
  }
  await db.execute({
    sql: `INSERT INTO admin_alerts (id, alert_type, sender_name, sender_email, message)
          VALUES (?, 'USER_COMMENT', ?, ?, ?)`,
    args: [crypto.randomUUID(), String(sender_name || 'Visitor').trim(), String(sender_email || '').trim(), String(message).trim()],
  });
  return res.status(201).json({ success: true, message: 'Comment sent to Admin Alert' });
});

app.get('/api/plans', async (req, res) => {
  const priorityPlans = (await db.execute('SELECT * FROM priority_plans WHERE is_active = 1 ORDER BY price ASC')).rows;
  const config = await getConfig();
  return res.json({ success: true, data: { plans: [], priorityPlans, config } });
});

app.post('/api/guest/contact-payments', async (req, res) => {
  let paymentId = null;
  try {
    const propertyId = String(req.body?.property_id || '');
    const phone = normalizePhone(req.body?.phone_number);
    if (!/^(?:254)?[17]\d{8}$/.test(phone)) {
      return res.status(400).json({ success: false, message: 'Enter a valid Kenyan mobile number for the payment prompt.' });
    }
    const property = (await db.execute({
      sql: `SELECT id, title, property_type, property_types_json, contact_hidden, expires_at
            FROM properties WHERE id = ? AND approval_status = 'APPROVED'
              AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
      args: [propertyId],
    })).rows[0];
    if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
    if (!property.contact_hidden && property.expires_at > new Date().toISOString()) {
      return res.status(409).json({ success: false, message: 'This listing contact and location are currently free to view.' });
    }
    const amount = contactUnlockPrice(property, await getConfig());
    paymentId = crypto.randomUUID();
    await db.execute({
      sql: `INSERT INTO guest_contact_payments (id, property_id, property_title, amount, phone_number, reason)
            VALUES (?, ?, ?, ?, ?, 'CONTACT_AND_LOCATION_UNLOCK')`,
      args: [paymentId, property.id, property.title, amount, phone],
    });
    const { response, data } = await fetchUpstreamJson(`${PAYMENT_GATEWAY_URL}/api/stk-push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
      body: JSON.stringify({ amount, phone_number: phone }),
    });
    if (!response.ok || !data.success) {
      await db.execute({
        sql: `UPDATE guest_contact_payments SET status = 'FAILED', result_desc = ? WHERE id = ?`,
        args: [String(data.message || 'The payment provider rejected the payment prompt.').slice(0, 500), paymentId],
      });
      return res.status(502).json({ success: false, message: data.message || 'The payment provider rejected the payment prompt.' });
    }
    return res.json({ success: true, message: 'Payment prompt sent.', data: { payment_id: paymentId, amount } });
  } catch (error) {
    if (paymentId) {
      await db.execute({
        sql: `UPDATE guest_contact_payments SET status = 'FAILED', result_desc = ? WHERE id = ? AND status = 'PENDING'`,
        args: [String(error.message || 'Payment provider unavailable').slice(0, 500), paymentId],
      }).catch((databaseError) => console.error('Could not mark guest payment failed:', databaseError.message));
    }
    return res.status(error.status || 500).json({ success: false, message: error.message || 'Could not start payment.' });
  }
});

app.get('/api/guest/contact-payments/:id/verify', async (req, res) => {
  try {
    const payment = (await db.execute({
      sql: 'SELECT * FROM guest_contact_payments WHERE id = ?',
      args: [req.params.id],
    })).rows[0];
    if (!payment) return res.status(404).json({ success: false, message: 'Payment not found.' });
    if (payment.status === 'SUCCESSFUL') {
      return res.json({ success: true, data: { status: 'SUCCESSFUL', resultCode: 0 } });
    }
    const { data } = await fetchUpstreamJson(`${PAYMENT_GATEWAY_URL}/api/status`, {
      headers: { 'ngrok-skip-browser-warning': 'true' },
    });
    if (data.status !== true || !data.response) {
      return res.json({ success: true, data: { status: 'PENDING' } });
    }
    const resultCode = Number(data.response.ResultCode);
    const resultDesc = String(data.response.ResultDesc || '');
    if (resultCode === 0) {
      await db.execute({
        sql: `UPDATE guest_contact_payments SET status = 'SUCCESSFUL', result_code = ?, result_desc = ? WHERE id = ? AND status = 'PENDING'`,
        args: [resultCode, resultDesc, payment.id],
      });
      return res.json({ success: true, data: { status: 'SUCCESSFUL', resultCode } });
    }
    const status = resultCode === 1032 ? 'CANCELLED' : 'FAILED';
    await db.execute({
      sql: 'UPDATE guest_contact_payments SET status = ?, result_code = ?, result_desc = ? WHERE id = ?',
      args: [status, resultCode, resultDesc, payment.id],
    });
    return res.json({ success: false, message: resultDesc, data: { status, resultCode } });
  } catch (error) {
    return res.status(error.status || 500).json({ success: false, message: error.message || 'Payment verification error.' });
  }
});

app.post('/api/properties/:id/activity', optionalAuth, async (req, res) => {
  const activityType = String(req.body?.activity_type || '').toUpperCase();
  if (!['CALL', 'WHATSAPP', 'LOCATION_PIN', 'CONTACT_UNLOCK'].includes(activityType)) {
    return res.status(400).json({ success: false, message: 'Select a valid listing activity.' });
  }
  const property = (await db.execute({
    sql: `SELECT id, title, owner_name FROM properties
          WHERE id = ? AND approval_status = 'APPROVED'
            AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
    args: [req.params.id],
  })).rows[0];
  if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
  await db.execute({
    sql: `INSERT INTO property_activity_notifications
          (id, property_id, activity_type, property_title, owner_name, visitor_name, visitor_phone)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [
      crypto.randomUUID(), property.id, activityType, property.title, property.owner_name,
      String(req.user?.full_name || 'Visitor').slice(0, 120),
      String(req.user?.call_phone || req.user?.phone || '').slice(0, 32),
    ],
  });
  return res.status(201).json({ success: true });
});

app.post('/api/payments/initiate', requireAuth, async (req, res) => {
  let paymentId = null;
  try {
    const { purpose, plan_id, priority_plan_id, property_id, phone_number, new_photo } = req.body;
    const phone = normalizePhone(phone_number || req.user.call_phone || req.user.phone);
    const cfg = await getConfig();
    let amount = 0;

    if (purpose === 'PRIORITY_PROMOTION') {
      const pp = (await db.execute({ sql: 'SELECT * FROM priority_plans WHERE id = ? AND is_active = 1', args: [priority_plan_id] })).rows[0];
      if (!pp) return res.status(404).json({ success: false, message: 'Priority plan not found' });
      if (property_id) {
        const prop = (await db.execute({
          sql: 'SELECT id FROM properties WHERE id = ? AND owner_id = ?',
          args: [property_id, req.user.id],
        })).rows[0];
        if (!prop) return res.status(404).json({ success: false, message: 'Listing not found' });
      }
      amount = Number(pp.price);
    } else if (purpose === 'ADD_PHOTO') {
      const prop = (await db.execute({ sql: 'SELECT * FROM properties WHERE id = ? AND owner_id = ?', args: [property_id, req.user.id] })).rows[0];
      if (!prop) return res.status(404).json({ success: false, message: 'House not found' });
      const imgs = JSON.parse(prop.images_json || '[]');
      if (imgs.length >= 4) return res.status(400).json({ success: false, message: 'Maximum of 4 photos already reached. Three are included; the fourth is added for the configured fee.' });
      if (imgs.length < 3) return res.status(400).json({ success: false, message: 'Add up to 3 free photos first. The configured fee applies to the fourth photo.' });
      if (!new_photo) return res.status(400).json({ success: false, message: 'Select a photo to add' });
      amount = Number(cfg.add_photo_price || 30);
    } else if (purpose === 'CONTACT_UNLOCK') {
      const property = (await db.execute({
        sql: `SELECT id, property_type, property_types_json, contact_hidden, expires_at
              FROM properties
              WHERE id = ? AND approval_status = 'APPROVED'
                AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
        args: [property_id],
      })).rows[0];
      if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
      const alreadyUnlocked = (await db.execute({
        sql: 'SELECT 1 FROM property_contact_unlocks WHERE user_id = ? AND property_id = ?',
        args: [req.user.id, property.id],
      })).rows[0];
      if (alreadyUnlocked) {
        return res.status(409).json({ success: false, message: 'You have already unlocked this listing contact.' });
      }
      if (!property.contact_hidden && property.expires_at > new Date().toISOString()) {
        return res.status(409).json({ success: false, message: 'This listing contact is currently free to view.' });
      }
      amount = contactUnlockPrice(property, cfg);
    } else {
      return res.status(400).json({
        success: false,
        message: purpose === 'POST_PLAN'
          ? 'House and home listings are free. Post plans are no longer offered.'
          : 'Invalid payment purpose',
      });
    }

    paymentId = crypto.randomUUID();
    await db.execute({
      sql: `INSERT INTO payments (id, user_id, purpose, plan_id, priority_plan_id, property_id, pending_photo_data, amount, phone_number, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
      args: [paymentId, req.user.id, purpose, plan_id || null, priority_plan_id || null, property_id || null, new_photo || null, amount, phone],
    });

    const { response: stkRes, data: stkData } = await fetchUpstreamJson(`${PAYMENT_GATEWAY_URL}/api/stk-push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
      body: JSON.stringify({ amount, phone_number: phone }),
    });
    if (!stkRes.ok || !stkData.success) {
      await db.execute({ sql: `UPDATE payments SET status = 'FAILED' WHERE id = ?`, args: [paymentId] });
      return res.status(502).json({ success: false, message: stkData.message || 'The payment provider rejected the payment prompt.' });
    }

    return res.json({ success: true, message: 'STK Push sent', data: { payment_id: paymentId, amount } });
  } catch (error) {
    if (paymentId) {
      await db.execute({
        sql: `UPDATE payments SET status = 'FAILED', result_desc = ? WHERE id = ? AND status = 'PENDING'`,
        args: [String(error.message || 'Payment provider unavailable').slice(0, 500), paymentId],
      }).catch((databaseError) => console.error('Could not mark failed payment:', databaseError.message));
    }
    return res.status(error.status || 500).json({ success: false, message: error.message || 'Payment initiation error' });
  }
});

app.get('/api/payments/:id/verify', requireAuth, async (req, res) => {
  try {
    const payment = (await db.execute({
      sql: 'SELECT * FROM payments WHERE id = ? AND user_id = ?',
      args: [req.params.id, req.user.id],
    })).rows[0];
    if (!payment) return res.status(404).json({ success: false, message: 'Payment not found' });
    if (payment.status === 'SUCCESSFUL') {
      return res.json({ success: true, data: { status: 'SUCCESSFUL', resultCode: 0 } });
    }

    const { data: statusData } = await fetchUpstreamJson(`${PAYMENT_GATEWAY_URL}/api/status`, {
      headers: { 'ngrok-skip-browser-warning': 'true' },
    });

    if (statusData.status === true && statusData.response) {
      const code = Number(statusData.response.ResultCode);
      const desc = statusData.response.ResultDesc || '';
      if (code === 0) {
        const now = new Date();
        let expiresAt = null;

        const statements = [];
        if (payment.purpose === 'POST_PLAN' && payment.property_id) {
          const plan = (await db.execute({
            sql: 'SELECT * FROM plans WHERE id = ? AND is_active = 1',
            args: [payment.plan_id],
          })).rows[0];
          const prop = (await db.execute({
            sql: 'SELECT * FROM properties WHERE id = ? AND owner_id = ?',
            args: [payment.property_id, payment.user_id],
          })).rows[0];
          if (!plan || !prop) {
            return res.status(409).json({ success: false, message: 'The listing or renewal plan is no longer available.' });
          }
          const base = Math.max(now.getTime(), new Date(prop.expires_at).getTime());
          expiresAt = new Date(base + Number(plan.duration_days) * 86400000).toISOString();
          statements.push({
            sql: `UPDATE properties SET expires_at = ?,
                    availability_status = CASE WHEN approval_status = 'APPROVED' AND availability_status = 'EXPIRED' THEN 'AVAILABLE' ELSE availability_status END
                  WHERE id = ? AND owner_id = ?`,
            args: [expiresAt, payment.property_id, payment.user_id],
          });
        } else if (payment.purpose === 'POST_PLAN') {
          const plan = (await db.execute({ sql: 'SELECT * FROM plans WHERE id = ?', args: [payment.plan_id] })).rows[0];
          if (!plan) return res.status(409).json({ success: false, message: 'The selected plan is no longer available.' });
          expiresAt = new Date(now.getTime() + Number(plan.duration_days) * 86400000).toISOString();
          statements.push({
            sql: `INSERT INTO subscriptions (id, user_id, plan_id, source_type, posts_total, posts_used, starts_at, expires_at, status)
                  VALUES (?, ?, ?, 'PAID_PLAN', ?, 0, ?, ?, 'ACTIVE')`,
            args: [crypto.randomUUID(), payment.user_id, plan.id, Number(plan.posts_allowed), now.toISOString(), expiresAt],
          });
        } else if (payment.purpose === 'PRIORITY_PROMOTION' && payment.property_id) {
          const pPlan = (await db.execute({ sql: 'SELECT * FROM priority_plans WHERE id = ?', args: [payment.priority_plan_id] })).rows[0];
          const prop = (await db.execute({
            sql: 'SELECT id FROM properties WHERE id = ? AND owner_id = ?',
            args: [payment.property_id, payment.user_id],
          })).rows[0];
          if (!pPlan || !prop) {
            return res.status(409).json({ success: false, message: 'The listing or priority plan is no longer available.' });
          }
          expiresAt = new Date(now.getTime() + Number(pPlan.duration_days) * 86400000).toISOString();
          statements.push({
            sql: `UPDATE properties SET priority_score = ?, priority_label = ?, priority_plan_price = ?, priority_expires_at = ? WHERE id = ? AND owner_id = ?`,
            args: [Number(pPlan.priority_level), pPlan.name, Number(pPlan.price), expiresAt, payment.property_id, payment.user_id],
          });
        } else if (payment.purpose === 'ADD_PHOTO' && payment.property_id && payment.pending_photo_data) {
          const prop = (await db.execute({ sql: 'SELECT * FROM properties WHERE id = ? AND owner_id = ?', args: [payment.property_id, payment.user_id] })).rows[0];
          if (!prop) return res.status(409).json({ success: false, message: 'The listing is no longer available.' });
          const imgs = JSON.parse(prop.images_json || '[]');
          if (imgs.length !== 3) return res.status(409).json({ success: false, message: 'The listing photos changed while payment was pending. The paid fourth photo was not added.' });
          imgs.push(payment.pending_photo_data);
          statements.push({
            sql: 'UPDATE properties SET images_json = ? WHERE id = ? AND owner_id = ?',
            args: [JSON.stringify(imgs), prop.id, payment.user_id],
          });
        } else if (payment.purpose === 'CONTACT_UNLOCK' && payment.property_id) {
          const prop = (await db.execute({
            sql: `SELECT id FROM properties
                  WHERE id = ? AND approval_status = 'APPROVED'
                    AND availability_status IN ('AVAILABLE', 'OCCUPIED')`,
            args: [payment.property_id],
          })).rows[0];
          if (!prop) return res.status(409).json({ success: false, message: 'The listing is no longer available.' });
          statements.push({
            sql: `INSERT OR IGNORE INTO property_contact_unlocks (user_id, property_id, payment_id)
                  VALUES (?, ?, ?)`,
            args: [payment.user_id, payment.property_id, payment.id],
          });
        }

        statements.push({
          sql: `UPDATE payments SET status = 'SUCCESSFUL', result_code = ?, result_desc = ?, expires_at = ? WHERE id = ?`,
          args: [code, desc, expiresAt, payment.id],
        });
        await db.batch(statements, 'write');
        return res.json({ success: true, data: { status: 'SUCCESSFUL', resultCode: 0 } });
      }

      const finalStatus = code === 1032 ? 'CANCELLED' : 'FAILED';
      await db.execute({
        sql: `UPDATE payments SET status = ?, result_code = ?, result_desc = ? WHERE id = ?`,
        args: [finalStatus, code, desc, payment.id],
      });
      return res.json({ success: false, message: desc, data: { status: finalStatus, resultCode: code, resultDesc: desc } });
    }

    return res.json({ success: true, data: { status: 'PENDING' } });
  } catch (error) {
    return res.status(error.status || 500).json({ success: false, message: error.message || 'Verification error' });
  }
});

// ADMIN ROUTES
app.get('/api/admin/overview', requireAdmin, async (req, res) => {
  const properties = (await db.execute('SELECT * FROM properties ORDER BY created_at DESC')).rows;
  const plans = (await db.execute('SELECT * FROM plans ORDER BY created_at DESC')).rows;
  const priorityPlans = (await db.execute('SELECT * FROM priority_plans ORDER BY created_at DESC')).rows;
  const users = (await db.execute('SELECT id, full_name, email, phone, role, call_phone, whatsapp_phone, is_suspended, created_at FROM users ORDER BY created_at DESC')).rows;
  const accountPayments = (await db.execute(`
    SELECT p.*, u.full_name AS account_name, p.purpose AS payment_reason,
           property.title AS property_title
    FROM payments p
    LEFT JOIN users u ON u.id = p.user_id
    LEFT JOIN properties property ON property.id = p.property_id
    ORDER BY p.created_at DESC
  `)).rows;
  const guestPayments = (await db.execute(`
    SELECT guest.id, NULL AS user_id, 'CONTACT_UNLOCK' AS purpose, NULL AS plan_id,
           NULL AS priority_plan_id, guest.property_id, NULL AS pending_photo_data,
           guest.amount, 'KES' AS currency, guest.phone_number, guest.status,
           guest.result_code, guest.result_desc, NULL AS expires_at, guest.created_at,
           'Visitor (no account)' AS account_name,
           guest.reason AS payment_reason, guest.property_title
    FROM guest_contact_payments guest
    ORDER BY guest.created_at DESC
  `)).rows;
  const payments = [...accountPayments, ...guestPayments]
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  const reports = (await db.execute(`
    SELECT r.*, p.title AS property_title, p.availability_status AS property_status
    FROM property_reports r
    LEFT JOIN properties p ON p.id = r.property_id
    ORDER BY r.created_at DESC
  `)).rows;
  const alerts = (await db.execute('SELECT * FROM admin_alerts ORDER BY created_at DESC')).rows;
  const activityNotifications = (await db.execute(`
    SELECT * FROM property_activity_notifications ORDER BY created_at DESC LIMIT 1000
  `)).rows;
  const config = await getConfig();

  const stats = {
    totalUsers: users.length,
    totalProperties: properties.length,
    pendingApproval: properties.filter((p) => p.approval_status === 'PENDING_APPROVAL').length,
    liveProperties: properties.filter((p) => p.approval_status === 'APPROVED' && p.availability_status === 'AVAILABLE').length,
    revenue: payments.filter((p) => p.status === 'SUCCESSFUL').reduce((sum, p) => sum + Number(p.amount || 0), 0),
    openReports: reports.filter((r) => r.status === 'OPEN').length,
  };

  return res.json({ success: true, data: { stats, properties, plans, priorityPlans, users, payments, reports, alerts, activityNotifications, config } });
});

app.patch('/api/admin/properties/:id/approve', requireAdmin, async (req, res) => {
  const config = await getConfig();
  const expiresAt = new Date(Date.now() + Number(config.free_post_duration_days || 14) * 86400000).toISOString();
  const result = await db.execute({
    sql: `UPDATE properties
          SET expires_at = CASE WHEN approval_status = 'APPROVED' THEN expires_at ELSE ? END,
              approval_status = 'APPROVED',
              availability_status = CASE WHEN availability_status = 'PENDING_APPROVAL' THEN 'AVAILABLE' ELSE availability_status END
          WHERE id = ?`,
    args: [expiresAt, req.params.id],
  });
  if (!result.rowsAffected) return res.status(404).json({ success: false, message: 'Listing not found.' });
  return res.json({ success: true, message: 'Property approved and live' });
});

app.patch('/api/admin/properties/:id/reject', requireAdmin, async (req, res) => {
  await db.execute({
    sql: `UPDATE properties SET approval_status = 'REJECTED', availability_status = 'PAUSED' WHERE id = ?`,
    args: [req.params.id],
  });
  return res.json({ success: true, message: 'Property rejected' });
});

app.patch('/api/admin/properties/:id/pause', requireAdmin, async (req, res) => {
  await db.execute({
    sql: `UPDATE properties SET availability_status = 'PAUSED' WHERE id = ?`,
    args: [req.params.id],
  });
  return res.json({ success: true, message: 'Property paused' });
});

app.patch('/api/admin/properties/:id/restore', requireAdmin, async (req, res) => {
  const result = await db.execute({
    sql: `UPDATE properties SET availability_status = 'AVAILABLE'
          WHERE id = ? AND approval_status = 'APPROVED' AND availability_status = 'PAUSED'`,
    args: [req.params.id],
  });
  if (!result.rowsAffected) return res.status(400).json({ success: false, message: 'Only paused, approved listings can be restored.' });
  return res.json({ success: true, message: 'Listing restored' });
});

app.put('/api/admin/properties/:id', requireAdmin, async (req, res) => {
  const existing = (await db.execute({
    sql: 'SELECT * FROM properties WHERE id = ?',
    args: [req.params.id],
  })).rows[0];
  if (!existing) return res.status(404).json({ success: false, message: 'Listing not found.' });

  const body = req.body || {};
  const title = String(body.title ?? existing.title).trim();
  if (!title) return res.status(400).json({ success: false, message: 'A listing name is required.' });
  const currentTypes = normalizePropertyTypes(JSON.parse(existing.property_types_json || '[]'), existing.property_type);
  const propertyTypes = body.property_types !== undefined
    ? normalizePropertyTypes(body.property_types, body.property_type)
    : currentTypes;
  if (!propertyTypes.length) {
    return res.status(400).json({ success: false, message: 'Select at least one valid property type.' });
  }
  let existingPricing = {};
  try {
    existingPricing = JSON.parse(existing.type_pricing_json || '{}');
  } catch {
    existingPricing = {};
  }
  const rentPricingInput = body.rent_pricing ?? (Object.keys(existingPricing).length ? existingPricing : undefined);
  const rentPricing = normalizeRentPricing(rentPricingInput, propertyTypes, {
    price: body.rent_amount ?? existing.min_rent ?? existing.monthly_rent,
    rent_period: body.rent_period ?? existing.rent_period,
    availability_status: existing.availability_status,
  });
  if (rentPricing.error) return res.status(400).json({ success: false, message: rentPricing.error });
  const approvalStatus = body.approval_status ?? existing.approval_status;
  if (!['PENDING_APPROVAL', 'APPROVED', 'REJECTED'].includes(approvalStatus)) {
    return res.status(400).json({ success: false, message: 'Select a valid approval status.' });
  }
  const startsFreeContactPeriod = existing.approval_status !== 'APPROVED' && approvalStatus === 'APPROVED';
  const freeContactExpiry = startsFreeContactPeriod
    ? new Date(Date.now() + Number((await getConfig()).free_post_duration_days || 14) * 86400000).toISOString()
    : existing.expires_at;
  const requestedAvailabilityStatus = body.availability_status ?? existing.availability_status;
  const availabilityStatus = ['AVAILABLE', 'OCCUPIED'].includes(requestedAvailabilityStatus)
    ? rentPricing.availabilityStatus
    : requestedAvailabilityStatus;
  if (!['AVAILABLE', 'OCCUPIED', 'PAUSED', 'EXPIRED', 'PENDING_APPROVAL'].includes(availabilityStatus)) {
    return res.status(400).json({ success: false, message: 'Select a valid availability status.' });
  }
  const contactHiddenValue = body.contact_hidden ?? existing.contact_hidden;
  if (typeof contactHiddenValue !== 'boolean' && contactHiddenValue !== 0 && contactHiddenValue !== 1) {
    return res.status(400).json({ success: false, message: 'Select whether listing contacts should be hidden.' });
  }

  const images = body.images !== undefined ? body.images : JSON.parse(existing.images_json || '[]');
  if (!Array.isArray(images) || images.length > 4
    || images.some((image) => typeof image !== 'string' || !image.trim())) {
    return res.status(400).json({ success: false, message: 'A listing can have no more than 4 valid photos.' });
  }
  const amenities = body.amenities !== undefined ? body.amenities : JSON.parse(existing.amenities_json || '[]');
  if (!Array.isArray(amenities) || amenities.some((item) => typeof item !== 'string')) {
    return res.status(400).json({ success: false, message: 'Amenities must be a list of text values.' });
  }

  const numericFields = ['deposit', 'bedrooms', 'bathrooms'];
  const numbers = Object.fromEntries(numericFields.map((field) => [
    field,
    Number(body[field] ?? existing[field]),
  ]));
  if (Object.values(numbers).some((value) => !Number.isFinite(value) || value < 0)) {
    return res.status(400).json({ success: false, message: 'Deposit, bedrooms, and bathrooms must be non-negative numbers.' });
  }
  const pinValue = (field) => {
    const raw = body[field] ?? existing[field];
    if (raw === '' || raw === null || raw === undefined) return null;
    const value = Number(raw);
    return Number.isFinite(value) ? value : NaN;
  };
  const pinLat = pinValue('pin_lat');
  const pinLng = pinValue('pin_lng');
  if (Number.isNaN(pinLat) || Number.isNaN(pinLng)) {
    return res.status(400).json({ success: false, message: 'Location coordinates must be valid numbers.' });
  }

  await db.execute({
    sql: `UPDATE properties SET
      title = ?, owner_name = ?, property_type = ?, property_types_json = ?,
      description = ?, target_tenants_desc = ?, min_rent = ?, max_rent = ?, monthly_rent = ?, rent_period = ?, type_pricing_json = ?,
      deposit = ?, county = ?, town = ?, estate = ?, pin_lat = ?, pin_lng = ?, pin_label = ?,
      bedrooms = ?, bathrooms = ?, furnished_status = ?, amenities_json = ?, images_json = ?,
      contact_phone = ?, contact_whatsapp = ?, contact_hidden = ?, expires_at = ?, approval_status = ?, availability_status = ?
      WHERE id = ?`,
    args: [
      title,
      String(body.owner_name ?? existing.owner_name).trim(),
      propertyTypes[0],
      JSON.stringify(propertyTypes),
      String(body.description ?? existing.description).trim(),
      String(body.target_tenants_desc ?? existing.target_tenants_desc).trim(),
      rentPricing.minRent, rentPricing.maxRent, rentPricing.minRent,
      rentPricing.first.rent_period, JSON.stringify(rentPricing.pricing),
      numbers.deposit,
      String(body.county ?? existing.county).trim(),
      String(body.town ?? existing.town).trim(),
      String(body.estate ?? existing.estate).trim(),
      pinLat,
      pinLng,
      String(body.pin_label ?? existing.pin_label).trim(),
      numbers.bedrooms,
      numbers.bathrooms,
      String(body.furnished_status ?? existing.furnished_status),
      JSON.stringify(amenities),
      JSON.stringify(images),
      String(body.contact_phone ?? existing.contact_phone).trim(),
      String(body.contact_whatsapp ?? existing.contact_whatsapp).trim(),
      contactHiddenValue ? 1 : 0,
      freeContactExpiry,
      approvalStatus,
      availabilityStatus,
      req.params.id,
    ],
  });
  return res.json({ success: true, message: 'Listing updated.' });
});

app.patch('/api/admin/properties/:id/extend', requireAdmin, async (req, res) => {
  const days = Number(req.body?.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ success: false, message: 'Enter a whole number of days between 1 and 3650.' });
  }
  const property = (await db.execute({
    sql: 'SELECT expires_at FROM properties WHERE id = ?',
    args: [req.params.id],
  })).rows[0];
  if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
  const base = Math.max(Date.now(), new Date(property.expires_at).getTime());
  const expiresAt = new Date(base + days * 86400000).toISOString();
  await db.execute({
    sql: `UPDATE properties SET expires_at = ?,
            availability_status = CASE WHEN approval_status = 'APPROVED' AND availability_status = 'EXPIRED' THEN 'AVAILABLE' ELSE availability_status END
          WHERE id = ?`,
    args: [expiresAt, req.params.id],
  });
  return res.json({ success: true, message: `Listing extended by ${days} days.` });
});

app.patch('/api/admin/properties/:id/gift', requireAdmin, async (req, res) => {
  const days = Number(req.body?.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ success: false, message: 'Enter a whole number of gifted days between 1 and 3650.' });
  }
  const property = (await db.execute({
    sql: 'SELECT expires_at FROM properties WHERE id = ?',
    args: [req.params.id],
  })).rows[0];
  if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
  const base = Math.max(Date.now(), new Date(property.expires_at).getTime());
  const expiresAt = new Date(base + days * 86400000).toISOString();
  await db.execute({
    sql: `UPDATE properties SET expires_at = ?,
      availability_status = CASE WHEN approval_status = 'APPROVED' AND availability_status = 'EXPIRED' THEN 'AVAILABLE' ELSE availability_status END
      WHERE id = ?`,
    args: [expiresAt, req.params.id],
  });
  return res.json({ success: true, message: `Gifted ${days} additional listing days. New expiry: ${expiresAt}.` });
});

app.patch('/api/admin/properties/:id/priority', requireAdmin, async (req, res) => {
  const planId = String(req.body?.priority_plan_id || '');
  const plan = planId ? (await db.execute({
    sql: 'SELECT * FROM priority_plans WHERE id = ? AND is_active = 1',
    args: [planId],
  })).rows[0] : null;
  if (planId && !plan) return res.status(404).json({ success: false, message: 'Select an active priority plan.' });
  const days = Number(plan?.duration_days ?? req.body?.days);
  if (!Number.isInteger(days) || days < 1 || days > 36500) {
    return res.status(400).json({ success: false, message: 'Enter a whole number of priority days between 1 and 36500.' });
  }
  const property = (await db.execute({
    sql: 'SELECT priority_expires_at FROM properties WHERE id = ?',
    args: [req.params.id],
  })).rows[0];
  if (!property) return res.status(404).json({ success: false, message: 'Listing not found.' });
  const existingExpiry = property.priority_expires_at ? new Date(property.priority_expires_at).getTime() : 0;
  const expiresAt = new Date(Math.max(Date.now(), existingExpiry) + days * 86400000).toISOString();
  await db.execute({
    sql: `UPDATE properties SET priority_score = ?, priority_label = ?, priority_plan_price = ?, priority_expires_at = ? WHERE id = ?`,
    args: [plan ? Number(plan.priority_level) : 100, plan?.name || 'Admin Priority', Number(plan?.price || 0), expiresAt, req.params.id],
  });
  return res.json({ success: true, message: `${plan?.name || 'Admin priority'} applied for ${days} days, until ${expiresAt}.` });
});

app.delete('/api/admin/properties/:id', requireAdmin, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM properties WHERE id = ?', args: [req.params.id] });
  return res.json({ success: true, message: 'Property removed' });
});

app.post('/api/admin/reports/:reportId/decision', requireAdmin, async (req, res) => {
  const { decision } = req.body;
  const report = (await db.execute({ sql: 'SELECT * FROM property_reports WHERE id = ?', args: [req.params.reportId] })).rows[0];
  if (!report) return res.status(404).json({ success: false, message: 'Report not found' });

  if (decision === 'accept_remove') {
    await db.execute({ sql: 'DELETE FROM properties WHERE id = ?', args: [report.property_id] });
    await db.execute({ sql: `UPDATE property_reports SET status = 'REMOVED_POST' WHERE id = ?`, args: [report.id] });
    return res.json({ success: true, message: 'Report accepted and post removed' });
  }

  if (decision === 'reject_retain') {
    await db.execute({ sql: `UPDATE property_reports SET status = 'REJECTED_RETAINED' WHERE id = ?`, args: [report.id] });
    return res.json({ success: true, message: 'Report rejected; post retained' });
  }

  return res.status(400).json({ success: false, message: 'Invalid decision' });
});

app.post('/api/admin/plans', requireAdmin, async (req, res) => {
  const { name, description, price, currency = 'KES', posts_allowed, duration_days, priority_level = 1 } = req.body;
  const cleanName = String(name || '').trim();
  const numericValues = [Number(price), Number(posts_allowed), Number(duration_days), Number(priority_level)];
  if (!cleanName || numericValues.some((value) => !Number.isFinite(value) || value < 0)
    || !Number.isInteger(Number(posts_allowed)) || !Number.isInteger(Number(duration_days))
    || !Number.isInteger(Number(priority_level)) || Number(posts_allowed) < 1 || Number(duration_days) < 1) {
    return res.status(400).json({ success: false, message: 'Enter a name, valid price, at least one post, and a valid duration.' });
  }
  const id = crypto.randomUUID();
  await db.execute({
    sql: `INSERT INTO plans (id, name, description, price, currency, posts_allowed, duration_days, priority_level, is_active)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
    args: [id, cleanName, description || '', numericValues[0], currency, numericValues[1], numericValues[2], numericValues[3]],
  });
  return res.status(201).json({ success: true, message: 'Post plan created' });
});

app.post('/api/admin/priority-plans', requireAdmin, async (req, res) => {
  const { name, description, price, currency = 'KES', duration_days, priority_level = 10 } = req.body;
  const cleanName = String(name || '').trim();
  const numericValues = [Number(price), Number(duration_days), Number(priority_level)];
  if (!cleanName || numericValues.some((value) => !Number.isFinite(value) || value < 0)
    || !Number.isInteger(Number(duration_days)) || !Number.isInteger(Number(priority_level))
    || Number(duration_days) < 1) {
    return res.status(400).json({ success: false, message: 'Enter a name, valid price, priority score, and duration.' });
  }
  const id = crypto.randomUUID();
  await db.execute({
    sql: `INSERT INTO priority_plans (id, name, description, price, currency, duration_days, priority_level, is_active)
          VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
    args: [id, cleanName, description || '', Number(price), currency, Number(duration_days), Number(priority_level)],
  });
  return res.status(201).json({ success: true, message: 'Priority plan created' });
});

app.put('/api/admin/plans/:id', requireAdmin, async (req, res) => {
  const { name, description = '', price, currency = 'KES', posts_allowed, duration_days, priority_level = 1, is_active = 1 } = req.body;
  const cleanName = String(name || '').trim();
  const numbers = [Number(price), Number(posts_allowed), Number(duration_days), Number(priority_level)];
  if (!cleanName || numbers.some((value) => !Number.isFinite(value) || value < 0)
    || !Number.isInteger(numbers[1]) || numbers[1] < 1
    || !Number.isInteger(numbers[2]) || numbers[2] < 1
    || !Number.isInteger(numbers[3]) || ![0, 1, false, true].includes(is_active)) {
    return res.status(400).json({ success: false, message: 'Enter valid post plan details.' });
  }
  const result = await db.execute({
    sql: `UPDATE plans SET name = ?, description = ?, price = ?, currency = ?, posts_allowed = ?, duration_days = ?, priority_level = ?, is_active = ?
          WHERE id = ?`,
    args: [cleanName, String(description), numbers[0], String(currency), numbers[1], numbers[2], numbers[3], Number(Boolean(is_active)), req.params.id],
  });
  if (!result.rowsAffected) return res.status(404).json({ success: false, message: 'Post plan not found.' });
  return res.json({ success: true, message: 'Post plan updated.' });
});

app.delete('/api/admin/plans/:id', requireAdmin, async (req, res) => {
  const result = await db.execute({ sql: 'UPDATE plans SET is_active = 0 WHERE id = ?', args: [req.params.id] });
  if (!result.rowsAffected) return res.status(404).json({ success: false, message: 'Post plan not found.' });
  return res.json({ success: true, message: 'Post plan deactivated.' });
});

app.put('/api/admin/priority-plans/:id', requireAdmin, async (req, res) => {
  const { name, description = '', price, currency = 'KES', duration_days, priority_level = 10, is_active = 1 } = req.body;
  const cleanName = String(name || '').trim();
  const numbers = [Number(price), Number(duration_days), Number(priority_level)];
  if (!cleanName || numbers.some((value) => !Number.isFinite(value) || value < 0)
    || !Number.isInteger(numbers[1]) || numbers[1] < 1
    || !Number.isInteger(numbers[2]) || ![0, 1, false, true].includes(is_active)) {
    return res.status(400).json({ success: false, message: 'Enter valid priority plan details.' });
  }
  const result = await db.execute({
    sql: `UPDATE priority_plans SET name = ?, description = ?, price = ?, currency = ?, duration_days = ?, priority_level = ?, is_active = ?
          WHERE id = ?`,
    args: [cleanName, String(description), numbers[0], String(currency), numbers[1], numbers[2], Number(Boolean(is_active)), req.params.id],
  });
  if (!result.rowsAffected) return res.status(404).json({ success: false, message: 'Priority plan not found.' });
  return res.json({ success: true, message: 'Priority plan updated.' });
});

app.delete('/api/admin/priority-plans/:id', requireAdmin, async (req, res) => {
  const result = await db.execute({ sql: 'UPDATE priority_plans SET is_active = 0 WHERE id = ?', args: [req.params.id] });
  if (!result.rowsAffected) return res.status(404).json({ success: false, message: 'Priority plan not found.' });
  return res.json({ success: true, message: 'Priority plan deactivated.' });
});

app.put('/api/admin/config', requireAdmin, async (req, res) => {
  const rules = {
    add_photo_price: { min: 1, max: 1000000 },
    free_posts_allowed: { min: 1, max: 100, integer: true },
    free_post_duration_days: { min: 1, max: 3650, integer: true },
  };
  const body = req.body || {};
  const entries = Object.entries(body).filter(([key]) => key !== 'contact_unlock_prices');
  if (!entries.length && body.contact_unlock_prices === undefined) {
    return res.status(400).json({ success: false, message: 'Invalid configuration values.' });
  }
  if (entries.some(([key, value]) => {
    const rule = rules[key];
    const number = Number(value);
    return !rule || !Number.isFinite(number) || number < rule.min || number > rule.max
      || (rule.integer && !Number.isInteger(number));
  })) {
    return res.status(400).json({ success: false, message: 'Invalid configuration values.' });
  }
  let contactPricesEntry = null;
  if (body.contact_unlock_prices !== undefined) {
    const prices = body.contact_unlock_prices;
    if (!prices || typeof prices !== 'object' || Array.isArray(prices)
      || Object.keys(prices).length !== PROPERTY_TYPES.length
      || PROPERTY_TYPES.some((type) => {
        const price = Number(prices[type]);
        return !Object.hasOwn(prices, type) || !Number.isFinite(price) || price < 1 || price > 1000000;
      })) {
      return res.status(400).json({ success: false, message: 'Set a valid contact unlock amount for every listing type.' });
    }
    contactPricesEntry = ['contact_unlock_prices', JSON.stringify(
      Object.fromEntries(PROPERTY_TYPES.map((type) => [type, Number(prices[type])])),
    )];
  }
  const configEntries = contactPricesEntry ? [...entries, contactPricesEntry] : entries;
  await db.batch(configEntries.map(([key, value]) => ({
      sql: `INSERT INTO system_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      args: [key, String(value)],
  })), 'write');
  return res.json({ success: true, message: 'Configuration updated' });
});

app.patch('/api/admin/users/:id/suspend', requireAdmin, async (req, res) => {
  const isSuspended = req.body.is_suspended;
  if (typeof isSuspended !== 'boolean' && isSuspended !== 0 && isSuspended !== 1) {
    return res.status(400).json({ success: false, message: 'A valid suspension status is required.' });
  }
  await db.execute({
    sql: 'UPDATE users SET is_suspended = ? WHERE id = ?',
    args: [isSuspended ? 1 : 0, req.params.id],
  });
  return res.json({ success: true, message: 'User status updated' });
});

app.post('/api/admin/users/:id/gift-post', requireAdmin, async (req, res) => {
  const posts = Number(req.body?.posts);
  const days = Number(req.body?.days);
  if (!Number.isInteger(posts) || posts < 1 || posts > 1000) {
    return res.status(400).json({ success: false, message: 'Enter a whole number of posts between 1 and 1000.' });
  }
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ success: false, message: 'Enter a whole number of gifted post days between 1 and 3650.' });
  }
  const userExists = (await db.execute({
    sql: 'SELECT id FROM users WHERE id = ?',
    args: [req.params.id],
  })).rows[0];
  if (!userExists) return res.status(404).json({ success: false, message: 'User not found.' });

  const startsAt = new Date();
  const expiresAt = new Date(startsAt.getTime() + days * 86400000);
  await db.execute({
    sql: `INSERT INTO subscriptions (id, user_id, plan_id, source_type, posts_total, posts_used, starts_at, expires_at, source_label, status)
          VALUES (?, ?, NULL, 'FREE_FIRST_POST', ?, 0, ?, ?, 'ADMIN_GIFT', 'ACTIVE')`,
    args: [crypto.randomUUID(), req.params.id, posts, startsAt.toISOString(), expiresAt.toISOString()],
  });
  return res.json({ success: true, message: `Gifted ${posts} post${posts === 1 ? '' : 's'} to the user. They can be used until ${expiresAt.toISOString()}.` });
});

app.use((req, res) => {
  return res.status(404).json({ success: false, message: 'API route not found.' });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (isRemoteDisconnect(err)) {
    console.warn(`Request interrupted by a remote connection (${req.method} ${req.path}).`);
    return res.status(503).json({ success: false, message: 'A remote service interrupted this request. Please retry in a moment.' });
  }
  console.error(`Request failed (${req.method} ${req.path}):`, err.message);
  return res.status(err.status || 500).json({
    success: false,
    message: err.status ? err.message : 'The request could not be completed. Please try again.',
  });
});

export { app, initDb };

const isDirectExecution = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectExecution) {
  initDb()
    .then(() => app.listen(PORT, () => console.log(`Lodora Houses and Homes API running on port ${PORT}`)))
    .catch((err) => {
      console.error('Database initialization failed:', err.message);
      process.exit(1);
    });
}
