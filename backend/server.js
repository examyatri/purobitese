'use strict';
// ╔══════════════════════════════════════════════════════╗
// ║  Tiffo — Backend API (server.js)                    ║
// ║  Version : v59.2                                    ║
// ║  Updated : 2026-05-16                               ║
// ║  Changes : Version bump for v63 release             ║
// ╚══════════════════════════════════════════════════════╝

// ─── DEPENDENCIES ────────────────────────────────────────────────────────────
const express     = require('express');
const https       = require('https');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const bcrypt      = require('bcryptjs');
const rateLimit   = require('express-rate-limit');

// ─── SETUP ───────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); // Required for correct IP behind Render's reverse proxy

// ─── RATE LIMITERS ───────────────────────────────────────────────────────────
// Auth limiter: tight limit for login/signup/password actions (brute-force protection)
const _authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ success: false, error: 'Too many requests. Please try again later.' }),
});

// General limiter: permissive limit for all other actions
const _generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ success: false, error: 'Too many requests. Please try again later.' }),
});

// Auth actions that get the tighter limit
const _AUTH_ACTIONS = new Set([
  'login', 'signup', 'adminLogin', 'riderLogin', 'staffLogin',
  'resetUserPassword', 'adminResetUserPassword', 'changePassword',
]);

// ─── CORS ─────────────────────────────────────────────────────────────────────
// ALLOWED_ORIGINS env var: comma-separated list, e.g.:
//   https://tiffo.online,https://www.tiffo.online
// Falls back to '*' only when unset (local dev).
const _allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : [];

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (_allowedOrigins.length === 0) {
    // Dev mode — no restriction
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (_allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  } else {
    // Origin not whitelisted — block preflight, let real request proceed
    // without ACAO header (browser will block it)
    if (req.method === 'OPTIONS') return res.status(403).end();
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(compression()); // gzip all responses — 60–80% smaller payloads
app.use(express.json({ limit: '512kb' })); // guard against oversized payloads

// ─── NO-CACHE HEADER for all /api responses (data must always be fresh) ──────
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY
);

const SECURE_API_KEY = process.env.API_KEY;
if (!SECURE_API_KEY) console.error('[FATAL] API_KEY env var not set');

// ─── SESSION TOKEN (HMAC-SHA256, no external deps) ────────────────────────────
// Format: base64url(header).base64url(payload).base64url(sig)
// Secret is separate from API_KEY so rotating one doesn't break the other.
const SESSION_SECRET = process.env.SESSION_SECRET || SECURE_API_KEY + '_session';
if (!process.env.SESSION_SECRET) console.warn('[WARN] SESSION_SECRET env var not set — falling back to derived secret. Set SESSION_SECRET in production.');
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function _b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function _signToken(payload) {
  const header  = _b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = _b64url(JSON.stringify(payload));
  const sig     = _b64url(require('crypto').createHmac('sha256', SESSION_SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

function _verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const expected = _b64url(require('crypto').createHmac('sha256', SESSION_SECRET).update(`${parts[0]}.${parts[1]}`).digest());
  if (expected !== parts[2]) return null; // signature mismatch
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (Date.now() > payload.exp) return null; // expired
    return payload;
  } catch { return null; }
}

// Actions that require a valid admin session token (role = 'admin' only)
const _ADMIN_ONLY_ACTIONS = new Set([
  // Truly admin-exclusive: account/staff management and nuclear data wipe
  'masterDelete',        // wipe all historical data
  'addStaff', 'createStaff', 'updateStaff', 'deleteStaff', // manage staff accounts
  'resetAdminPassword',  // change admin/staff passwords
]);

// Actions that require any valid staff session token (role = 'admin' OR 'staff')
// Staff can do EVERYTHING except: masterDelete, adminDeleteUser, staff management, resetAdminPassword
const _STAFF_ACTIONS = new Set([
  // ── Read / dashboard ──
  'adminGetOrders', 'adminGetMenu', 'adminGetUsers', 'adminGetSubscribers',
  'adminGetAllKhata', 'adminGetCoupons', 'getStaff',
  'getSubscribersForBulk', 'getRiders', 'getNuCouponPending', 'getNuCouponSent',
  'getAdminSettings', 'getOrderCutoffConfig', 'getWeeklySchedule', 'getDeliveryZone',
  'getDashboard', 'getNotifications', 'markNotificationRead', 'clearNotifications',
  'getCookingSessions', 'adminGetCouponReport', 'getCookingSummary', 'getCookingSessionDetail',
  'getAllKhata', 'getAnalytics', 'getCoupons', 'getKitchenDashboard',
  'getMenuItems', 'getUserByPhone',
  // NOTE: getKhata, getUserOrders, getOrderTransactions, getSettings, validateCoupon, applyCoupon are customer-facing — apiKey only, no session needed
  // ── Orders & operations ──
  'assignRider', 'bulkUpdateOrder', 'rejectOrder', 'updateOrderStatus',
  'lockCookingSession', 'unlockCookingSession', 'startCookingSession',
  'forceUdharOrder', 'bulkGenerateOrders',
  // ── Wallet & khata ──
  'rechargeWallet', 'manualRefund',
  // ── Subscribers & users ──
  'pauseSubscriber', 'resumeSubscriber', 'togglePauseSession', 'updateSubscriber',
  'promoteToSubscriber', 'removeSubscriber',
  'adminCreateUser', 'adminResetUserPassword', 'resetUserPassword',
  // ── Menu ──
  'addMenuItem', 'updateMenuItem', 'deleteMenuItem', 'updateMenuOrder', 'updateMenuStock',
  // ── Coupons ──
  'createCoupon', 'deleteCoupon', 'deleteExpiredCoupons', 'addCoupon', 'updateCoupon',
  // NOTE: validateCoupon, applyCoupon are customer-facing — apiKey only, no session needed
  // ── Riders ──
  'addRider', 'updateRider', 'deleteRider',
  // ── Notifications & cleanup ──
  'deleteNotification', 'deleteNotificationRange', 'deleteOldData', 'previewCleanup',
  // ── Nu-coupon ──
  'addNuCouponPending', 'markNuCouponSent', 'deleteOldNuCouponSent',
  // ── Settings ──
  'setCutoffConfig', 'setOrderCutoff', 'setWeeklySchedule', 'setKhataEnabled', 'setDeliveryZone', 'setAutoTiffinCutoff',
  // ── User management ──
  'adminDeleteUser', 'saveAndSendCoupon',
  // ── Additional admin-panel operational actions ──
  'addKhataEntry', 'addSubscriber', 'autoCleanupStatus', 'createNotification',
  'createRider', 'deleteOldOrders', 'deleteOldTransactions', 'getOrdersByDate',
  'getSubscribers', 'getUsers', 'markNotificationGroupRead',
  'previewDeleteNotifications', 'previewDeleteOrders', 'previewDeleteTransactions',
  'purgeOldNotifications',
]);


// ─── USER-SENSITIVE ACTIONS ───────────────────────────────────────────────────
// These actions operate on user-owned data. They require a valid userToken
// (issued at login) matching the phone in the request. This prevents one user
// from reading/modifying another user's orders, wallet, or subscription.
const _USER_SENSITIVE_ACTIONS = new Set([
  'getUserOrders', 'getKhata', 'updatePauseDelivery',
  'getSubscriberPauseStatus', 'changePassword', 'updateProfile', 'getMyProfile',
  'getSubscriberStatus', 'getSubscriberBalance',
]);

function _verifyUserToken(token, phone) {
  if (!token || !phone) return false;
  const session = _verifyToken(token);
  if (!session) return false;
  if (session.role !== 'user') return false;
  if (session.phone !== phone) return false;
  return true;
}

const SALT_ROUNDS = 10;

// ─── SELF-PING ────────────────────────────────────────────────────────────────
// Pings own /ping every 12 minutes to prevent Render free-tier sleep.
// Only runs if RENDER_EXTERNAL_URL is set (i.e. on Render, not local).
if (process.env.RENDER_EXTERNAL_URL) {
  const PING_URL = process.env.RENDER_EXTERNAL_URL + '/ping';
  setInterval(() => {
    https.get(PING_URL, (res) => {
      console.log(`[self-ping] ${new Date().toISOString()} → ${res.statusCode}`);
    }).on('error', (err) => {
      console.error('[self-ping] error:', err.message);
    });
  }, 12 * 60 * 1000); // every 12 minutes  (comment fix: was incorrectly labelled "10 minutes")
  console.log('[self-ping] active →', PING_URL);
}

// ─── AUTO CLEANUP SCHEDULER ──────────────────────────────────────────────────
// Runs daily at midnight IST to silently purge stale data.
// Retention rules (all dates in IST):
//   orders           → older than 5 days
//   khata_entries    → older than 35 days
//   notifications    → older than 1 day
//   cooking_sessions → older than 5 days  (done sessions have no business value)
//   nu_coupon_sent   → older than 5 days  (sent record no longer needed)
//
// NEVER touches: users, subscribers, riders, staff, menu_items, thalis,
//                thali_items, admin_settings, coupons, khata_summary
//
async function runAutoCleanup() {
  try {
    const ist = getIST();
    const dateCutoff = (days) => {
      const d = new Date(ist.getTime() - days * 86_400_000);
      return istDateStr(d);
    };
    const isoCutoff = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

    const [r1, r2, r3, r4, r5] = await Promise.allSettled([
      supabase.from('orders').delete({ count: 'exact' }).lte('date', dateCutoff(5)),
      supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', dateCutoff(35)),
      supabase.from('notifications').delete({ count: 'exact' }).lt('created_at', isoCutoff(1)),
      supabase.from('cooking_sessions').delete({ count: 'exact' }).lte('session_date', dateCutoff(5)),
      supabase.from('nu_coupon_sent').delete({ count: 'exact' }).lt('sent_at', isoCutoff(5)),
    ]);

    const counts = {
      orders:           r1.status === 'fulfilled' ? (r1.value.count || 0) : 'err',
      khata_entries:    r2.status === 'fulfilled' ? (r2.value.count || 0) : 'err',
      notifications:    r3.status === 'fulfilled' ? (r3.value.count || 0) : 'err',
      cooking_sessions: r4.status === 'fulfilled' ? (r4.value.count || 0) : 'err',
      nu_coupon_sent:   r5.status === 'fulfilled' ? (r5.value.count || 0) : 'err',
    };
    console.log('[auto-cleanup]', new Date().toISOString(), JSON.stringify(counts));
  } catch (err) {
    console.error('[auto-cleanup] fatal:', err.message);
  }
}

// Fires at next midnight IST, then every 24h
function scheduleMidnightCleanup() {
  const now = getIST();
  // Next midnight IST: advance to next UTC day start, subtract IST offset (5h30m)
  const nextMidnightUTC = Date.UTC(
    now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0
  ) - 5.5 * 3_600_000;
  const msUntil = nextMidnightUTC - Date.now();
  console.log(`[auto-cleanup] next run in ${Math.round(msUntil / 60000)} min`);
  setTimeout(() => {
    runAutoCleanup();
    setInterval(runAutoCleanup, 24 * 3_600_000);
  }, msUntil);
}
scheduleMidnightCleanup();


// ─── IN-MEMORY CACHES ────────────────────────────────────────────────────────
// Analytics cache — dashboard numbers (8 parallel queries) cached for 90s
let _analyticsCache   = null;
let _analyticsCacheTs = 0;
const _ANALYTICS_TTL  = 90_000; // 90 seconds

// Settings cache — admin_settings rows cached for 5 minutes
const _settingsCache  = {};
const _SETTINGS_TTL   = 5 * 60_000; // 5 minutes

async function getCachedSetting(key) {
  const entry = _settingsCache[key];
  if (entry && (Date.now() - entry.ts) < _SETTINGS_TTL) return entry.val;
  const { data } = await supabase.from('admin_settings').select('value').eq('key', key).single();
  const val = data?.value ?? null;
  _settingsCache[key] = { val, ts: Date.now() };
  return val;
}

function _invalidateSettingsCache() {
  delete _settingsCache['weekly_schedule'];
  delete _settingsCache['order_cutoff_config'];
  delete _settingsCache['khata_enabled'];
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getIST() {
  return new Date(Date.now() + 5.5 * 3_600_000);
}

function istDateStr(d) {
  const y  = d.getUTCFullYear();
  const m  = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${dd}`;
}

function istTimeStr(d) {
  let h  = d.getUTCHours();
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  return `${String(h).padStart(2, '0')}:${min} ${ampm}`;
}

// Returns true if a pause flag is active for a given IST date string (YYYY-MM-DD).
// pauseFlag   : boolean — the pause_morning / pause_evening field
// pauseFrom   : string|null — the pause_morning_from / pause_evening_from field
// todayStr    : YYYY-MM-DD IST date string for the day being evaluated
// Logic: pause is active when pauseFlag=true AND (pauseFrom is null OR pauseFrom <= todayStr)
// pauseFrom=null means the record pre-dates this feature → treat as active immediately (safe default).
function isPauseActive(pauseFlag, pauseFrom, todayStr) {
  if (!pauseFlag) return false;
  if (!pauseFrom) return true;           // legacy rows without _from → honour existing behaviour
  return pauseFrom <= todayStr;
}

// Computes the EFFECTIVE pause_delivery value for TODAY from granular fields.
// Uses pause_morning/pause_morning_from and pause_evening/pause_evening_from with
// isPauseActive so that a "tomorrow-only" pause (pause_morning_from = tomorrow) is
// NOT treated as active today.  Falls back to legacy pause_delivery when granular
// booleans are both false (pre-feature rows).
// Returns: 'none' | 'lunch' | 'dinner' | 'both'
function computeEffectivePauseDelivery(sub, todayStr) {
  if (!sub) return 'none';
  const legacy = sub.pause_delivery || 'none';
  const pm = sub.pause_morning
    ? isPauseActive(sub.pause_morning, sub.pause_morning_from, todayStr)
    : (legacy === 'lunch' || legacy === 'both');
  const pe = sub.pause_evening
    ? isPauseActive(sub.pause_evening, sub.pause_evening_from, todayStr)
    : (legacy === 'dinner' || legacy === 'both');
  return pm && pe ? 'both' : pm ? 'lunch' : pe ? 'dinner' : 'none';
}

function cleanPhone(p) {
  return String(p).replace(/\D/g, '');
}

function rand5() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 5; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function generateId(prefix, ist) {
  const y   = ist.getUTCFullYear();
  const mo  = String(ist.getUTCMonth() + 1).padStart(2, '0');
  const d   = String(ist.getUTCDate()).padStart(2, '0');
  const h   = String(ist.getUTCHours()).padStart(2, '0');
  const mi  = String(ist.getUTCMinutes()).padStart(2, '0');
  const s   = String(ist.getUTCSeconds()).padStart(2, '0');
  return `${prefix}-${y}${mo}${d}-${h}${mi}${s}-${rand5()}`;
}

function generateOrderId(ist)  { return generateId('ORD', ist); }
function generateTxnId(ist)    { return generateId('TXN', ist); }

async function generateRiderId(ist) {
  const d   = String(ist.getUTCDate()).padStart(2, '0');
  const mo  = String(ist.getUTCMonth() + 1).padStart(2, '0');
  const y   = ist.getUTCFullYear();
  const prefix = `RDR-${d}${mo}${y}-`;
  const { data: rows } = await supabase
    .from('riders')
    .select('rider_id')
    .like('rider_id', `${prefix}%`);
  const n = String(((rows || []).length) + 1).padStart(4, '0');
  return `${prefix}${n}`;
}

function normOrderDate(v) {
  if (!v) return '';
  if (v instanceof Date) return istDateStr(new Date(v.getTime() + 5.5 * 3_600_000));
  const s = String(v);
  // DD/MM/YYYY
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) {
    const [dd, mm, yyyy] = s.split('/');
    return `${yyyy}-${mm}-${dd}`;
  }
  // YYYY-MM-DD (possibly with time suffix)
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  // Excel serial
  const n = Number(s);
  if (!isNaN(n) && n > 40000) {
    const d = new Date((n - 25569) * 86400000);
    return istDateStr(d);
  }
  return s;
}

function normOrderTime(v) {
  if (!v) return '';
  if (v instanceof Date) {
    const ist = new Date(v.getTime() + 5.5 * 3_600_000);
    return istTimeStr(ist);
  }
  const s = String(v).trim();
  if (/AM|PM/i.test(s)) return s.toUpperCase();
  // HH:MM 24h
  if (/^\d{1,2}:\d{2}$/.test(s)) {
    let [h, m] = s.split(':').map(Number);
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')} ${ampm}`;
  }
  return s;
}

function formatOrder(o) {
  return {
    ...o,
    date:  normOrderDate(o.date),
    time:  normOrderTime(o.time),
    items: typeof o.items === 'string' ? JSON.parse(o.items) : (o.items || []),
    source: o.source || 'user'  // consistent with khata_entries.source
  };
}

// Fetch all active riders once and inject rider_name into orders by matching rider_id.
// This is the correct approach since orders table has no rider_name column.
async function resolveRiderNames(orders) {
  if (!orders || orders.length === 0) return orders;
  const { data: riders } = await supabase.from('riders').select('rider_id, name');
  if (!riders || riders.length === 0) return orders;
  const riderMap = {};
  riders.forEach(r => { riderMap[r.rider_id] = r.name; });
  return orders.map(o => ({
    ...o,
    rider_name: o.rider_id ? (riderMap[o.rider_id] || o.rider_name || null) : null
  }));
}

function formatMenuItem(i) {
  return {
    ...i,
    variants: typeof i.variants === 'string' ? JSON.parse(i.variants) : (i.variants || [])
  };
}

// ─── PRIVATE HELPERS ─────────────────────────────────────────────────────────

// Shared user auth — used by both 'login' and 'checkSession' (were 100% identical)
async function _authenticateUser(phone, password) {
  const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
  if (!user) return { success: false, error: 'Session invalid' };
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return { success: false, error: 'Session invalid' };
  const { data: sub }    = await supabase.from('subscribers').select('*').eq('phone', phone).single();
  const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
  const { password_hash, ...safeUser } = user;
  // Issue a signed user token — 30-day TTL so customers never face forced re-login
  const USER_TOKEN_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days
  const userToken = _signToken({ role: 'user', phone, exp: Date.now() + USER_TOKEN_TTL });
  // Override pause_delivery with effective value for TODAY — a "tomorrow-only" pause
  // (set after cutoff) must not block today's orders in the customer frontend.
  const subWithEffectivePause = sub
    ? { ...sub, pause_delivery: computeEffectivePauseDelivery(sub, istDateStr(getIST())) }
    : null;
  return { success: true, user: safeUser, subscriber: subWithEffectivePause, walletBalance: balRow?.balance || 0, userToken };
}

// Shared staff auth — used by both 'adminLogin' and 'staffLogin' (were 100% identical)
async function _authenticateStaff(username, password) {
  const { data: staff } = await supabase.from('staff').select('*').eq('username', username).single();
  if (!staff) return { success: false, error: 'Invalid credentials' };
  const valid = await bcrypt.compare(password, staff.password_hash);
  if (!valid) return { success: false, error: 'Invalid credentials' };
  const { password_hash, ...safeStaff } = staff;
  return { success: true, staff: safeStaff };
}

async function _atomicWalletUpdate(phone, delta) {
  // Preferred path: atomic Postgres RPC (no read-modify-write race).
  // Run migration_v46_atomic_wallet.sql in Supabase once to enable this.
  const { data: rpcResult, error: rpcErr } = await supabase.rpc('increment_balance', {
    p_phone: phone,
    p_delta: delta
  });
  if (!rpcErr && rpcResult !== null && rpcResult !== undefined) {
    return Number(rpcResult); // RPC returned new balance atomically ✓
  }

  // Fallback: safe read-modify-write (single-process Render env — not truly racy in practice)
  const { data: row } = await supabase
    .from('khata_summary')
    .select('balance')
    .eq('phone', phone)
    .single();
  const newBalance = ((row?.balance) ?? 0) + delta;
  await supabase
    .from('khata_summary')
    .upsert({ phone, balance: newBalance, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
  return newBalance;
}

async function _createTxnEntry(phone, orderId, amount, newBalance, type, source, ist) {
  const txnId = generateTxnId(ist);
  await supabase.from('khata_entries').insert({
    id:              txnId,
    phone,
    type,
    amount,
    running_balance: newBalance,
    note:            'Order ' + orderId,
    date:            istDateStr(ist),
    time:            istTimeStr(ist),
    order_id:        orderId,
    order_status:    'pending',
    source:          source,
    created_at:      new Date().toISOString()
  });
  return txnId;
}

async function _createNotification(fields) {
  await supabase.from('notifications').insert({
    id:         generateId('NTF', getIST()),
    type:       fields.type,
    priority:   fields.priority,
    group_id:   fields.group_id,
    title:      fields.title,
    body:       fields.body,
    meta:       JSON.stringify(fields.meta || {}),
    is_read:    false,
    read_at:    null,
    created_at: new Date().toISOString()
  });
}

async function _deductMenuStock(items) {
  if (!items || items.length === 0) return;
  // Batch-fetch all stock values in one query, then update in parallel
  const ids = items.map(i => i.item_id).filter(Boolean);
  if (!ids.length) return;
  const { data: rows } = await supabase
    .from('menu_items')
    .select('item_id, stock_grams')
    .in('item_id', ids);
  const stockMap = {};
  for (const r of (rows || [])) stockMap[r.item_id] = r.stock_grams;
  await Promise.all(items.map(item => {
    const cur = stockMap[item.item_id];
    if (cur == null) return Promise.resolve();
    const newStock = Math.max(0, cur - (item.stock_grams || 100) * item.qty);
    return supabase.from('menu_items').update({ stock_grams: newStock }).eq('item_id', item.item_id);
  }));
}

async function _createSingleOrder({ user, items, deliveryCharge, khataEnabled, ist, coupon, source = 'user', slot = 'morning', paymentMode = null }) {
  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  let discount = 0;
  if (coupon) {
    if (coupon.discount_type === 'percent' || coupon.discount_type === 'percent_cap') {
      discount = Math.round(subtotal * coupon.discount_value / 100);
      const cap = coupon.cap_amount ?? coupon.max_cap ?? null;
      if (cap != null && discount > cap) discount = cap;
    } else if (coupon.discount_type === 'flat') {
      discount = coupon.discount_value;
    }
  }
  // Mark coupon used at order-placement time (not at validate time)
  if (coupon && coupon.code) {
    try {
      const { data: cpnRow } = await supabase.from('coupons').select('used_count,usage_count,used_by,auto_delete,max_usage,total_usage_limit').eq('code', coupon.code).single();
      if (cpnRow) {
        const newUsedCount = (cpnRow.used_count||0) + 1;
        let ub=[]; try{ub=JSON.parse(cpnRow.used_by||'[]');}catch{ub=[];}
        await supabase.from('coupons').update({
          used_count:  newUsedCount,
          usage_count: (cpnRow.usage_count||0)+1,
          used_by:     JSON.stringify([...ub, ...(user.phone ? [user.phone] : [])])
        }).eq('code', coupon.code);
        // Auto-delete: remove from DB if auto_delete=true and usage limit is now reached
        const limit = cpnRow.max_usage ?? cpnRow.total_usage_limit ?? null;
        if (cpnRow.auto_delete === true && limit !== null && newUsedCount >= limit) {
          await supabase.from('coupons').delete().eq('code', coupon.code);
        }
      }
    } catch(_) {}
  }
  const finalAmount = Math.max(0, subtotal + deliveryCharge - discount); // FIX #5: never negative
  const orderId  = generateOrderId(ist);
  const dateStr  = istDateStr(ist);
  const timeStr  = istTimeStr(ist);
  let newBal = null;
  let txnId  = null;

  if (khataEnabled && user.is_subscriber && paymentMode !== 'upi_insuf') {
    newBal = await _atomicWalletUpdate(user.phone, -finalAmount);
    const txnType = newBal < 0 ? 'tiffin_udhar' : 'tiffin_given';
    txnId = await _createTxnEntry(user.phone, orderId, -finalAmount, newBal, txnType, source, ist);
  }

  await _deductMenuStock(items);

  const { error: ordErr } = await supabase.from('orders').insert({
    order_id:        orderId,
    user_id:         user.phone,
    name:            user.name,
    phone:           user.phone,
    address:         user.address,
    items:           JSON.stringify(items),
    total_amount:    subtotal,
    delivery_charge: deliveryCharge,
    final_amount:    finalAmount,
    coupon_code:     coupon?.code || null,
    discount,
    order_status:    'pending',
    payment_status:  'pending',
    payment_mode:    paymentMode || (khataEnabled && user.is_subscriber ? 'wallet' : 'upi'),
    user_type:       user.is_subscriber ? 'subscriber' : 'daily',
    rider_id:        null,
    slot:            slot || 'morning',
    source:          source === 'admin' ? 'admin' : source === 'admin_bulk' ? 'admin_bulk' : 'user',
    date:            dateStr,
    time:            timeStr,
    created_at:      new Date().toISOString()
  });
  if (ordErr) throw new Error('Order save failed: ' + ordErr.message);

  // ── Fire notification for every order type (subscriber + daily + upi_insuf) ──
  try {
    const effectivePayMode = paymentMode || (khataEnabled && user.is_subscriber ? 'wallet' : 'upi');
    await _createNotification({
      type:     'order',
      priority: 'high',
      group_id: orderId,
      title:    'New Order',
      body:     user.name + ' placed order ' + orderId,
      meta:     {
        orderId,
        phone:         user.phone,
        userName:      user.name,
        finalAmount,
        paymentMode:   effectivePayMode,
        txnId:         txnId || null,
        is_subscriber: !!user.is_subscriber
      }
    });
  } catch (_) {}

  return { orderId, finalAmount, walletBalance: newBal };
}

// ─── HEALTH ROUTES ────────────────────────────────────────────────────────────
app.get('/',     (_req, res) => res.json({ app: 'Tiffo API', status: 'running', version: 'v2' }));
app.get('/ping', (_req, res) => res.json({ status: 'alive', time: new Date().toISOString() }));

// ─── CONFIG INJECTION ─────────────────────────────────────────────────────────
// Serves the API key to all frontends without ever hardcoding it in HTML.
// Each HTML file loads: <script src="https://purobitese-api.onrender.com/config.js"></script>
// This sets window.__TIFFO_API_KEY__ which CFG.KEY falls back to.
app.get('/config.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-store'); // always fresh — key may rotate
  res.send(`window.__TIFFO_API_KEY__ = ${JSON.stringify(process.env.API_KEY || '')};`);
});

// ─── IDEMPOTENCY GUARD (in-memory, protects createOrder double-submits) ───────
// Stores SHA-256-like fingerprint of mutation actions for 30s to reject duplicates.
// Cleared automatically — Map never grows unboundedly on free-tier Render.
const _recentMutations = new Map();
const _MUTATION_TTL = 30_000; // 30 seconds
const _MUTATION_ACTIONS = new Set(['createOrder', 'bulkGenerateOrders', 'forceUdharOrder', 'rechargeWallet', 'manualRefund', 'rejectOrder']);

function _mutationKey(action, data) {
  // Key = action + phone + total_amount (enough to catch accidental double-submit)
  // data.orderId is used as fallback identifier for rejectOrder (which has no phone/amount)
  const phone = data.phone || data.phones?.join(',') || data.orderId || '';
  const amt   = data.amount || data.price || (data.items ? data.items.reduce((s,i)=>s+(i.price*i.qty),0) : '');
  return `${action}:${phone}:${amt}`;
}

// ─── MAIN ENDPOINT ────────────────────────────────────────────────────────────
app.post('/api', async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ success: false, error: 'Invalid request body' });
  }
  const { action, data = {}, apiKey } = req.body;

  // Apply rate limiting before any auth or DB work
  const limiter = _AUTH_ACTIONS.has(action) ? _authRateLimit : _generalRateLimit;
  await new Promise((resolve) => limiter(req, res, resolve));
  if (res.headersSent) return; // limiter already sent 429

  if (apiKey !== SECURE_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  // ── SESSION TOKEN CHECK ────────────────────────────────────────────────────
  // Admin-only and staff actions require a valid signed session token issued at login.
  // This is enforced server-side — the API key alone is NOT enough for these actions.
  const { sessionToken } = req.body;
  if (_ADMIN_ONLY_ACTIONS.has(action)) {
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    if (session.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required.' });
    }
  } else if (_STAFF_ACTIONS.has(action)) {
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    if (session.role !== 'admin' && session.role !== 'staff') {
      return res.status(403).json({ success: false, error: 'Staff access required.' });
    }
  }

  // ── USER-SENSITIVE ACTION CHECK ─────────────────────────────────────────────
  // Verify userToken for actions that touch user-owned data.
  // Admin/staff bypass this check (they carry a sessionToken with role=admin/staff).
  if (_USER_SENSITIVE_ACTIONS.has(action)) {
    const phone = cleanPhone(data.phone || '');
    const { userToken } = req.body;
    // Staff/admin acting on behalf of a user: allow if valid staff session
    const staffSession = _verifyToken(req.body.sessionToken);
    const isStaff = staffSession && (staffSession.role === 'admin' || staffSession.role === 'staff');
    if (!isStaff && !_verifyUserToken(userToken, phone)) {
      return res.status(401).json({ success: false, error: 'Auth required. Please log in again.' });
    }
  }

  // Idempotency: reject mutation duplicates within 30s window
  if (_MUTATION_ACTIONS.has(action)) {
    const mKey = _mutationKey(action, data);
    const lastTs = _recentMutations.get(mKey);
    const now = Date.now();
    if (lastTs && (now - lastTs) < _MUTATION_TTL) {
      return res.status(429).json({ success: false, error: 'Duplicate request — please wait a moment' });
    }
    _recentMutations.set(mKey, now);
    // Cleanup stale keys lazily (runs max once per request, O(n) but Map is tiny)
    if (_recentMutations.size > 500) {
      for (const [k, ts] of _recentMutations) {
        if (now - ts > _MUTATION_TTL) _recentMutations.delete(k);
      }
    }
  }

  const ist = getIST();

  try {
    switch (action) {

      // ── AUTH ──────────────────────────────────────────────────────────────

      case 'checkSession':
      case 'login': {
        const result = await _authenticateUser(cleanPhone(data.phone), data.password);
        return res.json(result);
      }

      case 'signup': {
        const phone = cleanPhone(data.phone);
        const { data: existing } = await supabase.from('users').select('phone').eq('phone', phone).single();
        if (existing) return res.json({ success: false, error: 'Phone already registered' });
        const hash = await bcrypt.hash(data.password, SALT_ROUNDS);
        const createdAt = new Date().toISOString();
        const { error: insertErr } = await supabase.from('users').insert({
          user_id:       phone,
          name:          data.name,
          phone,
          email:         data.email || null,
          address:       data.address || null,
          password_hash: hash,
          created_at:    createdAt
        });
        if (insertErr) return res.json({ success: false, error: 'Registration failed. Please try again.' });
        // ── Fire new-user notification so admin can send welcome coupon ──
        try {
          await _createNotification({
            type:     'user',
            priority: 'normal',
            group_id: phone,
            title:    `New user joined: ${data.name}`,
            body:     `${data.name} (${phone}) just registered${data.address ? ' — ' + data.address : ''}`,
            meta:     { phone, name: data.name, address: data.address || '', email: data.email || '' }
          });
        } catch(_) {}
        // ── Initialise wallet row so balance reads 0 immediately (not null) ──
        try {
          await supabase.from('khata_summary')
            .upsert({ phone, balance: 0, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
        } catch(_) {}
        const USER_TOKEN_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days — matches login
        const signupToken = _signToken({ role: 'user', phone, exp: Date.now() + USER_TOKEN_TTL });
        return res.json({
          success: true,
          user: { user_id: phone, name: data.name, phone, email: data.email || null, address: data.address || null, created_at: createdAt },
          subscriber:    null,
          walletBalance: 0,
          userToken:     signupToken
        });
      }

      case 'adminLogin':
      case 'staffLogin': {
        const result = await _authenticateStaff(data.username, data.password);
        if (result.success && result.staff) {
          // Issue a signed session token — role is embedded and server-verified on every sensitive call
          result.sessionToken = _signToken({
            username: result.staff.username,
            role:     result.staff.role,   // 'admin' | 'staff' (from DB)
            exp:      Date.now() + SESSION_TTL_MS,
          });
        }
        return res.json(result);
      }

      case 'updateProfile': {
        const phone = cleanPhone(data.phone);
        // FIX #8: Require password verification — prevent unauthenticated profile updates
        if (!data.password) return res.json({ success: false, error: 'Password required to update profile' });
        const { data: userRow } = await supabase.from('users').select('password_hash').eq('phone', phone).single();
        if (!userRow) return res.json({ success: false, error: 'User not found' });
        const validPw = await bcrypt.compare(data.password, userRow.password_hash);
        if (!validPw) return res.json({ success: false, error: 'Incorrect password' });
        const updates = {};
        if (data.name    !== undefined) updates.name    = data.name;
        if (data.email   !== undefined) updates.email   = data.email;
        if (data.address !== undefined) updates.address = data.address;
        await supabase.from('users').update(updates).eq('phone', phone);
        return res.json({ success: true });
      }

      case 'getMyProfile': {
        const phone = cleanPhone(data.phone);
        const [userRes, subRes] = await Promise.all([
          supabase.from('users').select('*').eq('phone', phone).single(),
          supabase.from('subscribers').select('*').eq('phone', phone).single()
        ]);
        if (!userRes.data) return res.json({ success: false, error: 'User not found' });
        const { password_hash, ...safeUser } = userRes.data;
        // Override pause_delivery with effective value for TODAY so frontend
        // does not treat a tomorrow-only pause as active for today's orders.
        const subData = subRes.data
          ? { ...subRes.data, pause_delivery: computeEffectivePauseDelivery(subRes.data, istDateStr(ist)) }
          : null;
        return res.json({ success: true, user: safeUser, subscriber: subData });
      }

      case 'resetAdminPassword': {
        const { data: staff } = await supabase.from('staff').select('*').eq('username', data.username).single();
        if (!staff) return res.json({ success: false, error: 'User not found' });
        const valid = await bcrypt.compare(data.oldPassword, staff.password_hash);
        if (!valid) return res.json({ success: false, error: 'Wrong current password' });
        const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
        await supabase.from('staff').update({ password_hash: hash }).eq('username', data.username);
        return res.json({ success: true });
      }

      case 'resetUserPassword': {
        const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
        await supabase.from('users').update({ password_hash: hash }).eq('phone', cleanPhone(data.phone));
        return res.json({ success: true });
      }

      // ── MENU ──────────────────────────────────────────────────────────────

      case 'getMenu': {
        const { data: rows } = await supabase.from('menu_items').select('*').eq('is_active', true).order('sort_order', { ascending: true });
        return res.json({ success: true, items: (rows || []).map(formatMenuItem) });
      }

      // ── MERGED: replaces 4 separate calls (getMenu + getWeeklySchedule + getOrderCutoff + getKhataEnabled) ──
      case 'getHomeData': {
        const [menuRes, scheduleVal, cutoffVal, khataVal] = await Promise.all([
          supabase.from('menu_items').select('*').eq('is_active', true).order('sort_order', { ascending: true }),
          getCachedSetting('weekly_schedule'),
          getCachedSetting('order_cutoff_config'),
          getCachedSetting('khata_enabled')
        ]);
        let schedule = null, config = null;
        if (scheduleVal)  { try { schedule = JSON.parse(scheduleVal); } catch { schedule = null; } }
        if (cutoffVal)    { try { config   = JSON.parse(cutoffVal);   } catch { config   = null; } }
        const enabled = JSON.parse(khataVal || 'false') === true;
        return res.json({ success: true, items: (menuRes.data || []).map(formatMenuItem), schedule, config, enabled });
      }

      // ── MERGED: replaces getSubscriberBalance + getSubscriberPauseStatus (same row) ──
      case 'getSubscriberStatus': {
        const phone = cleanPhone(data.phone);
        const [balRes, subRes] = await Promise.all([
          supabase.from('khata_summary').select('balance').eq('phone', phone).single(),
          supabase.from('subscribers').select('pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, plan').eq('phone', phone).single()
        ]);
        const subRow = subRes.data;
        // Compute effective pause for TODAY — respects _from date so a tomorrow-only
        // pause does not falsely block today's orders in the customer frontend.
        const effectivePauseMode = computeEffectivePauseDelivery(subRow, istDateStr(ist));
        return res.json({ success: true, balance: balRes.data?.balance || 0, pauseMode: effectivePauseMode, plan: subRow?.plan || 'morning' });
      }

      case 'adminGetMenu': {
        const { data: rows } = await supabase.from('menu_items').select('*').order('sort_order', { ascending: true });
        return res.json({ success: true, items: (rows || []).map(formatMenuItem) });
      }

      case 'addMenuItem': {
        const { error: miErr } = await supabase.from('menu_items').insert({
          item_id:     data.item_id || generateId('ITEM', ist),
          name:        data.name,
          category:    data.category,
          image_url:   data.image_url || null,
          variants:    JSON.stringify(data.variants || []),
          price:       data.price,
          highlight:   data.highlight || null,
          sort_order:  data.sort_order || 99,
          is_active:   data.is_active !== undefined ? data.is_active : true,
          stock_grams: data.stock_grams ?? null,
          veg_type:    data.veg_type || 'veg',
          sub_items:    data.sub_items || null,
          sub_category: data.sub_category || null,
          meal_session: data.meal_session || 'both',
          created_at:   new Date().toISOString()
        });
        if (miErr) throw new Error(miErr.message || 'Failed to add menu item');
        return res.json({ success: true });
      }

      case 'updateMenuItem': {
        const mid = data.item_id || data.id; // normalize: frontend may send data.id
        const updates = { ...data };
        delete updates.item_id;
        delete updates.id;
        if (Array.isArray(updates.variants)) updates.variants = JSON.stringify(updates.variants);
        await supabase.from('menu_items').update(updates).eq('item_id', mid);
        return res.json({ success: true });
      }

      case 'deleteMenuItem': {
        const mid = data.item_id || data.id;
        await supabase.from('menu_items').delete().eq('item_id', mid);
        return res.json({ success: true });
      }

      case 'updateMenuOrder': {
        await Promise.all((data.order || []).map(entry =>
          supabase.from('menu_items').update({ sort_order: entry.sort_order }).eq('item_id', entry.item_id)
        ));
        return res.json({ success: true });
      }

      case 'updateMenuStock': {
        await supabase.from('menu_items').update({ stock_grams: data.stock_grams }).eq('item_id', data.item_id);
        return res.json({ success: true });
      }

      // ── ORDERS ────────────────────────────────────────────────────────────

      case 'createOrder': {
        const phone = cleanPhone(data.phone);
        // Auth: must be the user's own token (staff bypass allowed for admin-placed orders)
        const _staffSess = _verifyToken(req.body.sessionToken);
        const _isStaff   = _staffSess && (_staffSess.role === 'admin' || _staffSess.role === 'staff');
        if (!_isStaff && !_verifyUserToken(req.body.userToken, phone)) {
          return res.status(401).json({ success: false, error: 'Auth required. Please log in again.' });
        }
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        const address = data.address || user.address;
        if (!address) return res.json({ success: false, error: 'Delivery address required' });
        const khataEnabledRaw = await getCachedSetting('khata_enabled');
        const khataEnabled = JSON.parse(khataEnabledRaw || 'false');
        const { data: subRow } = await supabase.from('subscribers').select('*').eq('phone', phone).single();
        user.is_subscriber = !!subRow;
        user.address = address;
        if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
          return res.json({ success: false, error: 'Order items required' });
        }

        // ── Price verification: fetch DB prices — never blindly trust client values ──
        // Strategy:
        //   1. Item has variants in DB + client sent a matching variantLabel → use that variant price
        //   2. Item has variants in DB + label missing/not matched → use closest variant by price,
        //      or first variant as safe default (never fall back to base item price)
        //   3. Item has NO variants in DB → use base item price
        const clientItemIds = data.items.map(i => i.item_id).filter(Boolean);
        let verifiedItems = data.items;
        if (clientItemIds.length > 0) {
          const { data: dbMenuItems } = await supabase.from('menu_items').select('item_id, price, name, variants').in('item_id', clientItemIds);
          if (dbMenuItems && dbMenuItems.length > 0) {
            const dbItemMap = {};
            for (const m of dbMenuItems) dbItemMap[m.item_id] = m;
            verifiedItems = data.items.map(i => {
              const dbItem = dbItemMap[i.item_id];
              if (!dbItem) return i; // item not in DB — pass through as-is

              // Parse DB variants
              let dbVariants = [];
              try { dbVariants = typeof dbItem.variants === 'string' ? JSON.parse(dbItem.variants) : (Array.isArray(dbItem.variants) ? dbItem.variants : []); } catch(_) {}
              // Filter out any malformed variant entries
              dbVariants = dbVariants.filter(v => v && v.label && v.price != null);

              if (dbVariants.length > 0) {
                // Item has variants — NEVER use base item price
                // Step 1: exact label match (normal happy path)
                if (i.variantLabel) {
                  const exact = dbVariants.find(v => v.label === i.variantLabel);
                  if (exact) return { ...i, price: exact.price };
                  // Step 2: case-insensitive match (handles minor label casing differences)
                  const loose = dbVariants.find(v => v.label.toLowerCase() === i.variantLabel.toLowerCase());
                  if (loose) return { ...i, price: loose.price, variantLabel: loose.label };
                }
                // Step 3: client sent a price — find the closest variant price in DB
                // This prevents price manipulation while gracefully handling label mismatches
                if (i.price != null) {
                  const byPrice = dbVariants.find(v => v.price === i.price);
                  if (byPrice) return { ...i, price: byPrice.price, variantLabel: byPrice.label };
                }
                // Step 4: safe fallback — use first (cheapest or default) variant
                return { ...i, price: dbVariants[0].price, variantLabel: dbVariants[0].label };
              }

              // Item has no variants — use DB base price
              return { ...i, price: dbItem.price != null ? dbItem.price : i.price };
            });
          }
        }

        // ── FIX #4: Re-fetch coupon from DB — never trust client-supplied coupon values ──
        let verifiedCoupon = null;
        if (data.coupon && data.coupon.code) {
          const cpnCode = (data.coupon.code || '').toUpperCase();
          const { data: dbCoupon } = await supabase.from('coupons').select('*').eq('code', cpnCode).single();
          const today = istDateStr(ist);
          if (dbCoupon && dbCoupon.is_active && !(dbCoupon.expiry_date && dbCoupon.expiry_date < today)) {
            const maxUse = dbCoupon.max_usage ?? dbCoupon.total_usage_limit ?? null;
            if (maxUse == null || (dbCoupon.used_count || 0) < maxUse) {
              const capAmt = dbCoupon.cap_amount ?? dbCoupon.max_cap ?? null;
              verifiedCoupon = {
                code:           dbCoupon.code,
                discount_type:  dbCoupon.discount_type,
                discount_value: dbCoupon.discount_value,
                cap_amount:     capAmt
              };
            }
          }
        }

        // ── Auto-detect slot for order ──
        let autoSlot = 'morning';
        try {
          const schVal = await getCachedSetting('weekly_schedule');
          const sch = JSON.parse(schVal || '[]');
          const dayIdx = ist.getUTCDay();
          const d = Array.isArray(sch) && sch.length === 7 ? sch[dayIdx] : null;
          const nowMins = ist.getUTCHours() * 60 + ist.getUTCMinutes();
          if (d && d.open) {
            const dsH = parseInt(d.dinnerStart || '18') || 18;
            const dsM = parseInt(d.dinnerStartMin || '0') || 0;
            if (nowMins >= dsH * 60 + dsM) autoSlot = 'evening';
          } else {
            autoSlot = nowMins >= 17 * 60 ? 'evening' : 'morning';
          }
        } catch { autoSlot = (ist.getUTCHours() * 60 + ist.getUTCMinutes()) >= 17 * 60 ? 'evening' : 'morning'; }

        // NOTE: Multiple orders per slot are now allowed (users may order 2nd/3rd tiffin).
        // The idempotency guard (30s window above) still prevents accidental double-click duplicates.
        // Bulk order eligibility: if user has already ordered this slot today, they are
        // ineligible for admin bulk generation (handled in bulkGenerateOrders, unchanged).

        // ── FIX #3: Compute delivery charge server-side — never trust client value ──
        // upi_insuf: subscriber has insufficient wallet, pays via UPI — delivery is charged (₹20)
        // wallet:    subscriber has sufficient balance — free delivery
        // daily:     non-subscriber — always ₹20 delivery
        const serverDeliveryCharge = (user.is_subscriber && khataEnabled && data.paymentMode !== 'upi_insuf') ? 0 : 20;

        // Skip balance check for upi_insuf orders — subscriber chose to pay via UPI instead
        if (user.is_subscriber && khataEnabled && data.paymentMode !== 'upi_insuf') {
          const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
          const currentBal = balRow?.balance || 0;
          const subtotal   = verifiedItems.reduce((s, i) => s + i.price * i.qty, 0);
          let disc = 0;
          if (verifiedCoupon) {
            if (verifiedCoupon.discount_type === 'percent' || verifiedCoupon.discount_type === 'percent_cap') {
              disc = Math.round(subtotal * verifiedCoupon.discount_value / 100);
              if (verifiedCoupon.cap_amount != null && disc > verifiedCoupon.cap_amount) disc = verifiedCoupon.cap_amount;
            } else {
              disc = verifiedCoupon.discount_value;
            }
          }
          const finalEst = Math.max(0, subtotal + serverDeliveryCharge - disc);
          if (currentBal < finalEst) return res.json({ success: false, error: 'Insufficient wallet balance' });
        }

        const result = await _createSingleOrder({
          user, items: verifiedItems, deliveryCharge: serverDeliveryCharge,
          khataEnabled, ist, coupon: verifiedCoupon, source: 'user',
          paymentMode: data.paymentMode || null, slot: autoSlot
        });
        return res.json({ success: true, orderId: result.orderId, finalAmount: result.finalAmount, walletBalance: result.walletBalance });
      }

      case 'getUserOrders': {
        if (!data.phone) return res.json({ success: false, error: 'Phone required' });
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('user_id', cleanPhone(data.phone))
          .order('created_at', { ascending: false })
          .limit(50); // stability: cap at 50 most recent orders
        return res.json({ success: true, orders: (rows || []).map(formatOrder) });
      }

      case 'adminGetOrders': {
        let query = supabase.from('orders').select('*');
        if (data.date) query = query.eq('date', data.date);
        else if (data.fromDate) query = query.gte('date', data.fromDate);
        query = query.order('created_at', { ascending: false });
        const { data: rows } = await query;
        const formatted = (rows || []).map(formatOrder);
        const resolved = await resolveRiderNames(formatted);
        return res.json({ success: true, orders: resolved });
      }

      case 'getOrdersByDate': {
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('date', data.date)
          .order('created_at', { ascending: false });
        const formatted = (rows || []).map(formatOrder);
        const resolved = await resolveRiderNames(formatted);
        return res.json({ success: true, orders: resolved });
      }

      case 'updateOrderStatus': {
        // Normalize: accept both 'out for delivery' (frontend) and 'out_for_delivery' (db)
        const rawStatus = (data.status || '').toLowerCase().trim();
        const statusMap = {
          'out for delivery': 'out for delivery',
          'out_for_delivery': 'out for delivery',
          'pending':   'pending',
          'confirmed': 'confirmed',
          'preparing': 'preparing',
          'delivered': 'delivered',
          'rejected':  'rejected',
          'cancelled': 'cancelled'
        };
        const normalizedStatus = statusMap[rawStatus];
        if (!normalizedStatus) {
          return res.json({ success: false, error: 'Invalid order status: ' + rawStatus });
        }
        const updates = { order_status: normalizedStatus };
        // rider_id is set ONLY by admin via assignRider — never overwritten here
        await supabase.from('orders').update(updates).eq('order_id', data.orderId);
        if (normalizedStatus === 'delivered') {
          await supabase.from('khata_entries').update({ order_status: 'delivered' }).eq('order_id', data.orderId);
        }
        return res.json({ success: true });
      }

      case 'rejectOrder': {
        const { data: order } = await supabase.from('orders').select('*').eq('order_id', data.orderId).single();
        if (!order) return res.json({ success: false, error: 'Order not found' });

        // FIX #2: Idempotency — reject if already rejected (prevents double-refund on retry)
        if (order.order_status === 'rejected') {
          return res.json({ success: false, error: 'Order is already rejected' });
        }
        // FIX #6: Status guard — only allow rejection on active (non-final) orders
        const rejectableStatuses = ['pending', 'confirmed', 'preparing'];
        if (!rejectableStatuses.includes(order.order_status)) {
          return res.json({ success: false, error: `Cannot reject an order with status: ${order.order_status}` });
        }

        // Check if customer is a subscriber (wallet user)
        const { data: subRow } = await supabase.from('subscribers').select('phone').eq('phone', order.phone).single();
        const isSubscriber = !!subRow;

        const refundType = data.refundType || 'wallet'; // 'wallet' | 'cash' | 'none'

        // If refundType=wallet but not a subscriber → return error so frontend can inform admin
        if (refundType === 'wallet' && !isSubscriber) {
          return res.json({ success: false, error: 'NOT_SUBSCRIBER', message: 'This customer is a normal user and does not have a wallet. Please try a different refund method.' });
        }

        // Mark order rejected
        await supabase.from('orders').update({ order_status: 'rejected', refund_type: refundType }).eq('order_id', data.orderId);

        // Wallet refund — only for subscribers
        let refundNewBal = null;
        if (refundType === 'wallet' && isSubscriber) {
          refundNewBal = await _atomicWalletUpdate(order.phone, +order.final_amount);
          await supabase.from('khata_entries').insert({
            id:              generateTxnId(ist),
            phone:           order.phone,
            type:            'adjustment',
            amount:          +order.final_amount,
            running_balance: refundNewBal,
            note:            'Refund: Order ' + data.orderId + ' rejected',
            date:            istDateStr(ist),
            time:            istTimeStr(ist),
            order_id:        data.orderId,
            order_status:    'rejected',
            source:          'admin',
            created_at:      new Date().toISOString()
          });
          await _createNotification({
            type:     'order',
            priority: 'high',
            group_id: data.orderId,
            title:    'Order Rejected — Wallet Refunded',
            body:     'Order ' + data.orderId + ' rejected. ₹' + order.final_amount + ' refunded to your wallet.',
            meta:     { orderId: data.orderId, phone: order.phone, refundAmount: order.final_amount, is_subscriber: isSubscriber }
          });
        } else if (refundType === 'cash') {
          await _createNotification({
            type:     'order',
            priority: 'high',
            group_id: data.orderId,
            title:    'Order Rejected — Cash Refund',
            body:     'Order ' + data.orderId + ' rejected. Cash refund of ₹' + order.final_amount + ' to be given.',
            meta:     { orderId: data.orderId, phone: order.phone, is_subscriber: isSubscriber }
          });
        } else if (refundType === 'none') {
          await _createNotification({
            type:     'order',
            priority: 'normal',
            group_id: data.orderId,
            title:    'Order Rejected',
            body:     'Order ' + data.orderId + ' rejected. No refund issued.',
            meta:     { orderId: data.orderId, phone: order.phone, is_subscriber: isSubscriber }
          });
        }

        return res.json({ success: true, refundType, isSubscriber, newBalance: refundNewBal });
      }

      case 'getOrderTransactions': {
        // Returns last 30 khata_entries for a given phone
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('name').eq('phone', phone).single();
        const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
        const { data: entries } = await supabase
          .from('khata_entries').select('*')
          .eq('phone', phone)
          .order('created_at', { ascending: false })
          .limit(30);
        return res.json({
          success: true,
          name: user?.name || phone,
          balance: balRow?.balance || 0,
          entries: entries || []
        });
      }

      // ── BULK ORDERS v2 ───────────────────────────────────────────────────

      // Get subscribers list with eligibility info for bulk order preview
      case 'getSubscribersForBulk': {
        const today = istDateStr(ist);
        const slot  = data.slot || 'morning';
        const planFilter = data.planFilter || 'all'; // 'all' | 'active' | 'expiring'
        const orderFor   = data.orderFor || 'subscribers'; // 'subscribers' | 'all'

        // Fetch khata setting to know if balance matters for eligibility
        const khataSettingRawForBulk = await getCachedSetting('khata_enabled');
        const khataEnabledForBulk = JSON.parse(khataSettingRawForBulk || 'false');
        const bulkPrice = parseFloat(data.price) || 0;  // price for balance eligibility check

        // Fetch all subscribers (no expiry — subscriptions are now infinite)
        const { data: subs } = await supabase.from('subscribers').select('*');

        // Fetch today's orders for this slot to detect duplicates
        // slot='both' → check both morning and evening orders
        let todayOrdersQuery = supabase.from('orders')
          .select('phone, order_id')
          .eq('date', today)
          .not('order_status', 'eq', 'cancelled');
        if (slot === 'both') {
          todayOrdersQuery = todayOrdersQuery.in('slot', ['morning', 'evening']);
        } else {
          todayOrdersQuery = todayOrdersQuery.eq('slot', slot);
        }
        const { data: todayOrders } = await todayOrdersQuery;

        const orderedPhones = new Set((todayOrders || []).map(o => o.phone));

        // Batch-fetch users and wallet balances — avoids N+1 DB round trips
        const subPhones = (subs || []).map(s => s.phone);
        const [{ data: allUserRows }, { data: allBalRows }] = await Promise.all([
          supabase.from('users').select('phone, name, address').in('phone', subPhones.length ? subPhones : ['']),
          supabase.from('khata_summary').select('phone, balance').in('phone', subPhones.length ? subPhones : [''])
        ]);
        const userMap = {};
        (allUserRows || []).forEach(u => { userMap[u.phone] = u; });
        const balMap = {};
        (allBalRows || []).forEach(b => { balMap[b.phone] = b.balance; });

        const result = [];
        for (const sub of (subs || [])) {
          const userRow = userMap[sub.phone];
          const balance   = balMap[sub.phone] ?? 0;
          const pause     = sub.pause_delivery || 'none';
          const ordered   = orderedPhones.has(sub.phone);

          // Granular fields (pause_morning/pause_evening) are source of truth when set.
          // Fall back to legacy pause_delivery ONLY when the granular boolean is false
          // (rows pre-dating granular fields). This ensures pause_morning_from date is respected.
          const pm = sub.pause_morning
            ? isPauseActive(sub.pause_morning, sub.pause_morning_from, today)
            : (pause === 'lunch' || pause === 'both');
          const pe = sub.pause_evening
            ? isPauseActive(sub.pause_evening, sub.pause_evening_from, today)
            : (pause === 'dinner' || pause === 'both');
          const deliveryOff = sub.is_delivery_off || false;

          const slotPaused = deliveryOff
            || (slot === 'morning' && pm)
            || (slot === 'evening' && pe);
          // Plan-slot mismatch: morning-only subscriber excluded from evening bulk and vice versa
          const subPlan = sub.plan || 'both';
          const planMismatch = (slot === 'morning' && subPlan === 'evening')
            || (slot === 'evening' && subPlan === 'morning');
          // Eligible for auto-bulk: not paused, not already ordered, plan matches slot, and sufficient balance (if khata enabled)
          const insufficientBalance = khataEnabledForBulk && balance < bulkPrice;
          const eligible = !slotPaused && !planMismatch && !ordered && !insufficientBalance;

          result.push({
            phone:       sub.phone,
            name:        userRow?.name || sub.phone,
            address:     userRow?.address || '',
            balance,
            plan:        sub.plan || 'morning',
            plan_end:    sub.plan_end,
            pause,
            pause_morning:  sub.pause_morning || false,
            pause_evening:  sub.pause_evening || false,
            is_delivery_off: sub.is_delivery_off || false,
            already_ordered: ordered,
            insufficient_balance: insufficientBalance,
            eligible
          });
        }

        // If orderFor === 'all', also include non-subscriber users
        if (orderFor === 'all') {
          const { data: allUsers } = await supabase.from('users').select('phone, name, address');
          const subPhoneSet = new Set(subPhones);
          const extraPhones = (allUsers || []).filter(u => !subPhoneSet.has(u.phone)).map(u => u.phone);
          // Batch-fetch balances for extra users too
          const { data: extraBalRows } = extraPhones.length
            ? await supabase.from('khata_summary').select('phone, balance').in('phone', extraPhones)
            : { data: [] };
          const extraBalMap = {};
          (extraBalRows || []).forEach(b => { extraBalMap[b.phone] = b.balance; });
          for (const u of (allUsers || [])) {
            if (subPhoneSet.has(u.phone)) continue;
            const ordered = orderedPhones.has(u.phone);
            result.push({
              phone: u.phone, name: u.name || u.phone, address: u.address || '',
              balance: extraBalMap[u.phone] ?? 0, plan_end: null,
              pause: 'none', already_ordered: ordered, eligible: !ordered
            });
          }
        }

        return res.json({ success: true, subscribers: result });
      }

      // Generate bulk orders as PENDING for selected phones
      case 'bulkGenerateOrders': {
        const { itemName, description: itemDesc, price, reason, slot, phones, orderFor } = data;
        if (!itemName || !price || !phones || !phones.length) {
          return res.json({ success: false, error: 'Item name, price and recipients required' });
        }
        const today    = istDateStr(ist);
        const created  = [], skipped = [], udhar = [];
        const priceNum = parseFloat(price) || 0;
        const bulkSlot = slot || 'morning';

        // ─── STEP 1: Pre-fetch all data in parallel ──────────────────────────
        const cleanPhones = phones.map(cleanPhone);
        const [
          khataSettingVal,
          { data: existingOrders },
          { data: bulkUserRows },
          { data: bulkSubRows }
        ] = await Promise.all([
          getCachedSetting('khata_enabled'),
          supabase.from('orders').select('phone').eq('date', today).or(`slot.eq.${bulkSlot},slot.is.null`).not('order_status', 'eq', 'cancelled'),
          supabase.from('users').select('*').in('phone', cleanPhones),
          supabase.from('subscribers').select('phone, pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, is_delivery_off, plan').in('phone', cleanPhones)
        ]);

        const bulkKhataEnabled = JSON.parse(khataSettingVal || 'false');
        const alreadyOrderedSet = new Set((existingOrders || []).map(o => o.phone));
        const bulkUserMap = {};
        for (const u of (bulkUserRows || [])) bulkUserMap[u.phone] = u;
        // Build pause map — skip subscribers who have paused the relevant slot
        const bulkSubMap = {};
        for (const s of (bulkSubRows || [])) bulkSubMap[s.phone] = s;

        // ─── STEP 2: Filter eligible users — pure JS, zero DB calls ─────────
        const eligiblePhones = [];
        for (const phone of phones) {
          const cleanPh = cleanPhone(phone);
          if (alreadyOrderedSet.has(cleanPh)) {
            skipped.push({ phone: cleanPh, reason: 'already ordered today' }); continue;
          }
          if (!bulkUserMap[cleanPh]) {
            skipped.push({ phone: cleanPh, reason: 'user not found' }); continue;
          }
          // Pause/delivery-off check — respects both legacy pause_delivery and granular fields.
          // Granular fields (pause_morning/pause_evening) take priority when set; the _from date
          // ensures a pause set after morning cutoff (effective tomorrow) does NOT skip today's bulk.
          // Legacy pause_delivery is the fallback for old rows where granular booleans are false.
          const sub = bulkSubMap[cleanPh];
          if (sub) {
            const pause = sub.pause_delivery || 'none';
            const pm = sub.pause_morning
              ? isPauseActive(sub.pause_morning, sub.pause_morning_from, today)
              : (pause === 'lunch' || pause === 'both');
            const pe = sub.pause_evening
              ? isPauseActive(sub.pause_evening, sub.pause_evening_from, today)
              : (pause === 'dinner' || pause === 'both');
            const deliveryOff = sub.is_delivery_off || false;
            const slotPaused = deliveryOff
              || (bulkSlot === 'morning' && pm)
              || (bulkSlot === 'evening' && pe);
            // Plan-slot mismatch: skip subscriber if their plan doesn't include this slot
            const subPlan = sub.plan || 'both';
            const planMismatch = (bulkSlot === 'morning' && subPlan === 'evening')
              || (bulkSlot === 'evening' && subPlan === 'morning');
            if (slotPaused || planMismatch) {
              skipped.push({ phone: cleanPh, reason: slotPaused ? 'delivery paused for this slot' : 'plan does not include this slot' }); continue;
            }
          }
          eligiblePhones.push(cleanPh);
        }

        if (!eligiblePhones.length) {
          return res.json({ success: true, created: 0, skipped: skipped.length, udhar: 0, details: { created, udhar, skipped } });
        }

        // ─── STEP 3: Batch wallet deduction — ONE DB call for all users ──────
        // bulk_increment_balance() atomically updates all wallets in one SQL statement
        // and returns each user's new balance. Falls back to sequential if RPC missing.
        const balanceMap = {};  // phone → new balance after deduction
        if (bulkKhataEnabled) {
          const { data: balRows, error: balErr } = await supabase.rpc('bulk_increment_balance', {
            p_phones: eligiblePhones,
            p_delta:  -priceNum
          });
          if (balErr) {
            // RPC not yet deployed — sequential fallback (run database.sql migration to fix)
            console.warn('[bulkGenerateOrders] bulk_increment_balance unavailable, using sequential fallback:', balErr.message);
            for (const ph of eligiblePhones) {
              balanceMap[ph] = await _atomicWalletUpdate(ph, -priceNum);
            }
          } else {
            for (const row of (balRows || [])) balanceMap[row.phone] = Number(row.new_balance);
          }
        }

        // ─── STEP 4: Build all rows in JS — zero DB calls ───────────────────
        // IDs use a zero-padded batch index (B0001…B0999) instead of rand5() to
        // guarantee uniqueness within the batch regardless of how fast it runs.

        // Build items array from the multi-item payload sent by admin.
        // New format: data.items = [{ item_id, name, variantLabel, qty, price }]
        // Legacy fallback: single itemName/description (old admin panel, backward compat).
        let bulkItemsArr;
        if (data.items && Array.isArray(data.items) && data.items.length > 0) {
          // New multi-item format — validate and clean each item
          bulkItemsArr = data.items.map(it => {
            const itName = (it.name || '').trim() || itemName;
            const itQty  = Math.max(1, parseInt(it.qty) || 1);
            const itObj  = { name: itName, qty: itQty, price: 0 };
            // Preserve variantLabel for kitchen quantity aggregation
            // e.g. "100 Gram" on Bhindi lets kitchen show 500g for 5 orders
            if (it.variantLabel) itObj.variantLabel = it.variantLabel;
            if (it.item_id)      itObj.item_id      = it.item_id;
            return itObj;
          });
        } else {
          // Legacy single-item fallback — auto-extract variantLabel from itemName
          let bulkVariantLabel = data.variantLabel || null;
          if (!bulkVariantLabel) {
            const vm = String(itemName).match(/^(\d+(?:\.\d+)?)\s+([A-Za-z]+)/);
            if (vm) bulkVariantLabel = `${vm[1]} ${vm[2]}`;
          }
          const legacyItem = { name: itemName, description: itemDesc || '', qty: 1, price: priceNum };
          if (bulkVariantLabel) legacyItem.variantLabel = bulkVariantLabel;
          bulkItemsArr = [legacyItem];
        }
        const itemsJson  = JSON.stringify(bulkItemsArr);
        const nowIso     = new Date().toISOString();
        const timeStr    = istTimeStr(ist);
        const datePart   = `${ist.getUTCFullYear()}${String(ist.getUTCMonth()+1).padStart(2,'0')}${String(ist.getUTCDate()).padStart(2,'0')}`;
        const timePart   = `${String(ist.getUTCHours()).padStart(2,'0')}${String(ist.getUTCMinutes()).padStart(2,'0')}${String(ist.getUTCSeconds()).padStart(2,'0')}`;
        const allOrderRows = [];

        eligiblePhones.forEach((cleanPh, idx) => {
          const user     = bulkUserMap[cleanPh];
          const newBal   = bulkKhataEnabled ? (balanceMap[cleanPh] ?? null) : null;
          const isUdhar  = bulkKhataEnabled && newBal !== null && newBal < 0;
          const seqTag   = `B${String(idx + 1).padStart(4, '0')}`;  // B0001, B0002 …
          const orderId  = `ORD-${datePart}-${timePart}-${seqTag}`;

          allOrderRows.push({
            order_id:        orderId,
            user_id:         cleanPh,       // orders.user_id = phone, same as _createSingleOrder
            name:            user.name,
            phone:           cleanPh,
            address:         user.address || '',
            items:           itemsJson,
            total_amount:    priceNum,
            delivery_charge: 0,
            final_amount:    priceNum,
            discount:        0,
            order_status:    'pending',
            payment_status:  bulkKhataEnabled ? (isUdhar ? 'unpaid' : 'wallet') : 'pending',
            payment_mode:    bulkKhataEnabled ? (isUdhar ? 'unpaid' : 'wallet') : 'upi',
            user_type:       'subscriber',
            rider_id:        null,
            source:          'admin_bulk',
            slot:            bulkSlot,
            date:            today,
            time:            timeStr,
            created_at:      nowIso
          });

          if (isUdhar) udhar.push({ phone: cleanPh, orderId, balance: newBal });
          else created.push({ phone: cleanPh, orderId });
        });

        // ─── STEP 5: Batch orders insert — ONE DB call ───────────────────────
        const { error: ordersErr } = await supabase.from('orders').insert(allOrderRows);
        if (ordersErr) {
          // Insert failed — reverse ALL wallet deductions atomically
          if (bulkKhataEnabled && eligiblePhones.length) {
            await supabase.rpc('bulk_increment_balance', { p_phones: eligiblePhones, p_delta: +priceNum })
              .catch(async () => {
                for (const ph of eligiblePhones) await _atomicWalletUpdate(ph, +priceNum).catch(() => {});
              });
          }
          return res.json({ success: false, error: 'Orders insert failed: ' + ordersErr.message });
        }

        // ─── STEP 6: Batch khata entries insert — ONE DB call ───────────────
        // Non-fatal: orders are already committed — log error and return success.
        if (bulkKhataEnabled) {
          const allKhataRows = allOrderRows.map((ord, idx) => {
            const isUdharRow = ord.payment_status === 'unpaid';
            // Use same type values as _createSingleOrder so wallet ledger displays correctly:
            // 'tiffin_udhar' → red  |  'tiffin_given' → amber  (keyed in admin typeLabel/typeColor)
            const txnType    = isUdharRow ? 'tiffin_udhar' : 'tiffin_given';
            const txnNote    = isUdharRow
              ? (reason ? `[UDHAR] ${reason}` : `[UDHAR] Bulk order: ${itemName}`)
              : (reason  || `Bulk order: ${itemName}`);
            const seqTag     = `B${String(idx + 1).padStart(4, '0')}`;
            return {
              id:              `TXN-${datePart}-${timePart}-${seqTag}`,
              phone:           ord.phone,
              type:            txnType,             // 'tiffin_given' or 'tiffin_udhar'
              amount:          -priceNum,   // negative = deduction, matches _createSingleOrder
              running_balance: balanceMap[ord.phone] ?? null,
              note:            txnNote,
              date:            today,
              time:            timeStr,
              order_id:        ord.order_id,
              order_status:    'pending',
              source:          'admin_bulk',
              created_at:      nowIso
            };
          });
          const { error: khataErr } = await supabase.from('khata_entries').insert(allKhataRows);
          if (khataErr) console.error('[bulkGenerateOrders] khata_entries batch insert failed:', khataErr.message);
        }

        return res.json({
          success: true,
          created: created.length + udhar.length,
          skipped: skipped.length,
          udhar:   udhar.length,
          details: { created, udhar, skipped }
        });
      }


      case 'forceUdharOrder': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        // FIX #12: Check actual subscriber status — don't hardcode is_subscriber = true
        const { data: udharSubRow } = await supabase.from('subscribers').select('phone').eq('phone', phone).single();
        if (!udharSubRow) {
          // Auto-create subscriber row so wallet deduction works correctly
          await supabase.from('subscribers').insert({
            phone,
            plan:            data.plan || 'morning',
            plan_start:      istDateStr(ist),
            notes:           'Auto-created by forceUdharOrder',
            pause_delivery:  'none',
            pause_morning:   false,
            pause_evening:   false,
            pause_morning_from: null,
            pause_evening_from: null,
            is_delivery_off: false,
            created_at:      new Date().toISOString()
          });
          // Ensure wallet row exists
          try {
            await supabase.from('khata_summary')
              .upsert({ phone, balance: 0, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
          } catch(_) {}
        }
        user.is_subscriber = true;
        const result = await _createSingleOrder({
          user, items: data.items, deliveryCharge: data.deliveryCharge || 0,
          khataEnabled: true, ist, source: 'admin', slot: data.slot || 'morning'
        });
        return res.json({ success: true, orderId: result.orderId, walletBalance: result.walletBalance });
      }

      case 'assignRider': {
        const updates = { rider_id: data.riderId };
        await supabase.from('orders').update(updates).eq('order_id', data.orderId);
        return res.json({ success: true });
      }

      case 'bulkUpdateOrder': {
        // Combined update: rider, order_status, payment_status — all optional
        const bulkUpdates = {};

        if (data.riderId) {
          bulkUpdates.rider_id = data.riderId;
          // Note: rider_name column does not exist in orders table.
          // rider_name is resolved at read time via resolveRiderNames().
        }

        if (data.orderStatus) {
          const rawStatus = (data.orderStatus || '').toLowerCase().trim();
          const statusMap = {
            'out for delivery': 'out for delivery',
            'out_for_delivery': 'out for delivery',
            'pending':   'pending',
            'confirmed': 'confirmed',
            'preparing': 'preparing',
            'delivered': 'delivered',
            'rejected':  'rejected',
            'cancelled': 'cancelled'
          };
          const normalizedStatus = statusMap[rawStatus];
          if (normalizedStatus) {
            bulkUpdates.order_status = normalizedStatus;
            if (normalizedStatus === 'delivered') {
              await supabase.from('khata_entries').update({ order_status: 'delivered' }).eq('order_id', data.orderId);
            }
          }
        }

        if (data.paymentStatus) {
          bulkUpdates.payment_status = data.paymentStatus;
        }

        if (Object.keys(bulkUpdates).length === 0) {
          return res.json({ success: false, error: 'Nothing to update' });
        }

        const { error: updateErr } = await supabase.from('orders').update(bulkUpdates).eq('order_id', data.orderId);
        if (updateErr) return res.json({ success: false, error: updateErr.message });
        return res.json({ success: true });
      }

      // ── COUPONS ──────────────────────────────────────────────────────────

      case 'applyCoupon':
      case 'validateCoupon': {
        const cpnCode = (data.code||'').toUpperCase();
        if (!cpnCode) return res.json({ success: false, error: 'Coupon code required' });
        const { data: coupon } = await supabase.from('coupons').select('*').eq('code', cpnCode).single();
        if (!coupon || !coupon.is_active) return res.json({ success: false, error: 'Invalid coupon' });
        const today = istDateStr(ist);
        if (coupon.expiry_date && coupon.expiry_date < today) return res.json({ success: false, error: 'Coupon expired' });
        const maxUse = coupon.max_usage ?? coupon.total_usage_limit ?? null;
        if (maxUse != null && (coupon.used_count||0) >= maxUse) return res.json({ success: false, error: 'Coupon fully used' });
        let usedBy=[]; try{usedBy=JSON.parse(coupon.used_by||'[]');}catch{usedBy=[];}
        const phone = data.phone || null;
        const rtype = coupon.restriction_type || 'unlimited';
        // --- restriction checks ---
        if (rtype === 'specific_phone') {
          let allowed=[]; try{allowed=JSON.parse(coupon.allowed_phones||'[]');}catch{allowed=[];}
          if (!phone || !allowed.includes(phone)) return res.json({ success: false, error: 'This coupon is not valid for your number' });
        }
        if (rtype === 'new_users_only') {
          if (!phone) return res.json({ success: false, error: 'Login required to use this coupon' });
          const { data: usr } = await supabase.from('users').select('created_at').eq('phone', phone).single();
          if (!usr) return res.json({ success: false, error: 'User not found' });
          const regDays = (Date.now() - new Date(usr.created_at).getTime()) / 86400000;
          if (regDays > 30) return res.json({ success: false, error: 'This coupon is only for new users' });
          if (usedBy.includes(phone)) return res.json({ success: false, error: 'Already used this coupon' });
        }
        if (rtype === 'one_time_total') {
          if ((coupon.used_count||0) >= 1) return res.json({ success: false, error: 'Coupon already used' });
        }
        if (rtype === 'one_time_per_user') {
          if (phone && usedBy.filter(p=>p===phone).length >= 1) return res.json({ success: false, error: 'Already used this coupon' });
        }
        if (rtype === 'limited_total') {
          // handled above by maxUse check
        }
        if (rtype === 'per_user_limit') {
          const perLimit = coupon.per_user_limit ?? coupon.max_per_user ?? 1;
          const userCount = phone ? usedBy.filter(p=>p===phone).length : 0;
          if (phone && userCount >= perLimit) return res.json({ success: false, error: `Limit reached: ${perLimit}x per user` });
        }
        // unlimited: no extra check
        const minOrd = coupon.min_order ?? coupon.min_order_amount ?? null;
        if (minOrd && data.orderAmount < minOrd) return res.json({ success: false, error: 'Min order ₹' + minOrd });
        const capAmt = coupon.cap_amount ?? coupon.max_cap ?? null;
        return res.json({ success: true, coupon: { code: coupon.code, discount_type: coupon.discount_type, discount_value: coupon.discount_value, cap_amount: capAmt, min_order: minOrd, restriction_type: rtype } });
      }


      case 'createCoupon': {
        if (!data.code) return res.json({ success: false, error: 'Coupon code required' });
        await supabase.from('coupons').insert({
          code:             data.code.toUpperCase(),
          discount_type:    data.discount_type,
          discount_value:   data.discount_value,
          min_order:        data.min_order ?? null,
          max_usage:        data.max_usage ?? null,
          used_count:       0,
          expiry_date:      data.expiry_date || null,
          is_active:        true,
          used_by:          '[]',
          restriction_type: data.restriction_type || 'unlimited',
          allowed_phones:   JSON.stringify(data.allowed_phones || []),
          per_user_limit:   data.per_user_limit ?? null,
          max_per_user:     data.per_user_limit ?? null,
          cap_amount:       data.cap_amount ?? null,
          max_cap:          data.cap_amount ?? null
        });
        return res.json({ success: true });
      }

      case 'adminGetCoupons': {
        const { data: rows } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
        const coupons = (rows || []).map(c => ({ ...c, used_by: JSON.parse(c.used_by || '[]') }));
        return res.json({ success: true, coupons });
      }

      case 'deleteCoupon': {
        await supabase.from('coupons').delete().eq('id', data.id);
        return res.json({ success: true });
      }

      // Auto-delete all expired coupons (called silently when admin opens coupon tab)
      case 'deleteExpiredCoupons': {
        const today = new Date().toISOString().slice(0, 10);
        const { data: expired, error: fetchErr } = await supabase
          .from('coupons')
          .select('id')
          .not('expiry_date', 'is', null)
          .lt('expiry_date', today);
        if (fetchErr) return res.json({ success: false, error: fetchErr.message });
        const ids = (expired || []).map(r => r.id);
        if (ids.length === 0) return res.json({ success: true, deleted: 0 });
        await supabase.from('coupons').delete().in('id', ids);
        return res.json({ success: true, deleted: ids.length });
      }

      // ── SUBSCRIBERS ──────────────────────────────────────────────────────

      case 'checkSubscriber': {
        const { data: row } = await supabase.from('subscribers').select('*').eq('phone', cleanPhone(data.phone)).single();
        // Override pause_delivery with effective value for TODAY so frontend
        // does not treat a tomorrow-only pause as active for today's orders.
        const subWithEffective = row
          ? { ...row, pause_delivery: computeEffectivePauseDelivery(row, istDateStr(ist)) }
          : null;
        return res.json({ success: true, isSubscriber: !!row, subscriber: subWithEffective });
      }

      case 'getSubscriberPauseStatus': {
        const { data: row } = await supabase.from('subscribers').select('pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, plan').eq('phone', cleanPhone(data.phone)).single();
        // Compute effective pause for TODAY — respects _from date so a tomorrow-only
        // pause does not falsely block today's orders in the customer frontend.
        const effectivePauseMode = computeEffectivePauseDelivery(row, istDateStr(ist));
        return res.json({ success: true, pauseMode: effectivePauseMode, plan: row?.plan || 'morning' });
      }

      case 'getAutoTiffinCutoff': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'auto_tiffin_cutoff').single();
        let cfg = { morning: '11:00', evening: '18:00' };
        if (row?.value) { try { cfg = JSON.parse(row.value); } catch {} }
        return res.json({ success: true, cutoff: cfg });
      }


      case 'adminGetSubscribers': {
        const { data: subs } = await supabase.from('subscribers').select('*');
        const phones = (subs || []).map(s => s.phone);
        const [{ data: userRows }, { data: balRows }] = phones.length
          ? await Promise.all([
              supabase.from('users').select('phone, name, address').in('phone', phones),
              supabase.from('khata_summary').select('phone, balance').in('phone', phones)
            ])
          : [{ data: [] }, { data: [] }];
        const uMap = {}, bMap = {};
        for (const u of (userRows || [])) uMap[u.phone] = u;
        for (const b of (balRows  || [])) bMap[b.phone] = b.balance;
        const enriched = (subs || []).map(s => ({
          ...s,
          name:            uMap[s.phone]?.name    || null,
          address:         uMap[s.phone]?.address || null,
          balance:         bMap[s.phone] ?? 0,
          plan:            s.plan || null,
          pause_morning:   s.pause_morning   || false,
          pause_evening:   s.pause_evening   || false,
          is_delivery_off: s.is_delivery_off || false,
          is_paused:       s.pause_morning || s.pause_evening || (s.pause_delivery && s.pause_delivery !== 'none') || false
        }));
        return res.json({ success: true, subscribers: enriched });
      }

      case 'addSubscriber': {
        await supabase.from('subscribers').insert({
          phone:          cleanPhone(data.phone),
          plan:           data.plan || 'morning',
          plan_start:     data.plan_start,
          notes:          data.notes || '',
          pause_delivery: 'none',
          pause_morning:  false,
          pause_evening:  false,
          pause_morning_from: null,
          pause_evening_from: null,
          is_delivery_off: false,
          created_at:     new Date().toISOString()
        });
        return res.json({ success: true });
      }

      case 'updateSubscriber': {
        const updates = { plan_start: data.plan_start, notes: data.notes };
        if (data.plan)           updates.plan           = data.plan;
        if (data.is_delivery_off !== undefined) updates.is_delivery_off = data.is_delivery_off;
        await supabase.from('subscribers').update(updates).eq('phone', cleanPhone(data.phone));
        return res.json({ success: true });
      }

      case 'removeSubscriber': {
        await supabase.from('subscribers').delete().eq('phone', cleanPhone(data.phone));
        return res.json({ success: true });
      }

      case 'getUserByPhone': {
        const q = (data.phone || data.query || '').trim();
        const checkSlot = data.slot || null;  // optional slot for bulk-add checks
        const checkDate = data.date || istDateStr(ist);
        let user = null;
        // Try exact phone match first
        { const { data: u } = await supabase.from('users').select('*').eq('phone', cleanPhone(q)).single();
          if (u) user = u; }
        // Fallback: search by name (partial, case-insensitive)
        if (!user) {
          const { data: rows } = await supabase.from('users').select('*').ilike('name', `%${q}%`).limit(1);
          if (rows && rows.length) user = rows[0];
        }
        if (!user) return res.json({ success: false, error: 'User not found' });
        const { password_hash, ...safe } = user;
        // Fetch wallet balance
        const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', safe.phone).single();
        safe.balance = balRow?.balance ?? 0;
        const bulkPriceCheck = parseFloat(data.price) || 0;  // 0 = no price check
        safe.insufficient_balance = bulkPriceCheck > 0 && safe.balance < bulkPriceCheck;

        // If slot provided, also check: already ordered this slot today + pause status
        if (checkSlot) {
          const [{ data: existOrd }, { data: subRow }] = await Promise.all([
            supabase.from('orders').select('order_id').eq('phone', safe.phone).eq('date', checkDate).eq('slot', checkSlot).not('order_status', 'eq', 'cancelled').limit(1),
            supabase.from('subscribers').select('pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, is_delivery_off').eq('phone', safe.phone).single()
          ]);
          safe.already_ordered = !!(existOrd && existOrd.length);
          // Compute pause status for this slot — granular fields take priority when set;
          // _from date ensures a "tomorrow" pause does not mark today's preview row as paused.
          const sub = subRow || {};
          const pause = sub.pause_delivery || 'none';
          const pm = sub.pause_morning
            ? isPauseActive(sub.pause_morning, sub.pause_morning_from, checkDate)
            : (pause === 'lunch' || pause === 'both');
          const pe = sub.pause_evening
            ? isPauseActive(sub.pause_evening, sub.pause_evening_from, checkDate)
            : (pause === 'dinner' || pause === 'both');
          const deliveryOff = sub.is_delivery_off || false;
          safe.slot_paused = deliveryOff
            || (checkSlot === 'morning' && pm)
            || (checkSlot === 'evening' && pe);
          safe.is_subscriber = !!subRow;
          safe.pause_delivery = sub.pause_delivery || 'none';
        }
        return res.json({ success: true, user: safe });
      }

      case 'adminCreateUser': {
        const phone = cleanPhone(data.phone);
        const hash  = await bcrypt.hash(data.password, SALT_ROUNDS);
        await supabase.from('users').insert({
          user_id:       phone,
          name:          data.name,
          phone,
          email:         data.email || null,
          address:       data.address || null,
          password_hash: hash,
          created_at:    new Date().toISOString()
        });
        // Initialise wallet row at 0 so balance never shows null (mirrors signup)
        try {
          await supabase.from('khata_summary')
            .upsert({ phone, balance: 0, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
        } catch(_) {}
        if (data.addAsSubscriber) {
          await supabase.from('subscribers').insert({
            phone,
            plan:           data.plan || 'morning',
            plan_start:     data.plan_start || istDateStr(ist),
            notes:          data.notes      || '',
            pause_delivery: 'none',
            pause_morning:  false,
            pause_evening:  false,
            pause_morning_from: null,
            pause_evening_from: null,
            is_delivery_off: false,
            created_at:     new Date().toISOString()
          });
        }
        return res.json({ success: true });
      }

      case 'promoteToSubscriber': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('phone').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        const { data: existing } = await supabase.from('subscribers').select('phone').eq('phone', phone).single();
        if (existing) return res.json({ success: false, error: 'Already a subscriber' });
        await supabase.from('subscribers').insert({
          phone,
          plan:           data.plan || 'morning',
          plan_start:     data.plan_start || istDateStr(getIST()),
          notes:          data.notes || '',
          pause_delivery: 'none',
          pause_morning:  false,
          pause_evening:  false,
          pause_morning_from: null,
          pause_evening_from: null,
          is_delivery_off: false,
          created_at:     new Date().toISOString()
        });
        // Ensure wallet row exists at 0 so balance never shows null
        try {
          await supabase.from('khata_summary')
            .upsert({ phone, balance: 0, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
        } catch(_) {}
        return res.json({ success: true });
      }

      // ── RIDERS ────────────────────────────────────────────────────────────

      case 'addRider':
      case 'createRider': {
        const rider_id = await generateRiderId(ist);
        const hash     = await bcrypt.hash(data.password, SALT_ROUNDS);
        await supabase.from('riders').insert({
          rider_id,
          name:          data.name,
          phone:         cleanPhone(data.phone),
          password_hash: hash,
          vehicle:       data.vehicle || null,
          zone:          data.zone    || null,
          is_active:     true
        });
        return res.json({ success: true, rider_id });
      }

      case 'updateRider': {
        const rid = data.rider_id || data.id; // normalize: frontend sends data.id
        const updates = { ...data };
        delete updates.rider_id;
        delete updates.id;
        delete updates.password_hash; // never allow direct hash overwrite
        if (data.password) {
          updates.password_hash = await bcrypt.hash(data.password, SALT_ROUNDS);
          delete updates.password;
        }
        await supabase.from('riders').update(updates).eq('rider_id', rid);
        return res.json({ success: true });
      }

      case 'deleteRider': {
        const rid = data.rider_id || data.id;
        await supabase.from('riders').update({ is_active: false }).eq('rider_id', rid);
        return res.json({ success: true });
      }

      case 'riderLogin': {
        const { data: rider } = await supabase.from('riders').select('*').eq('rider_id', data.riderId).single();
        if (!rider) return res.json({ success: false, error: 'Invalid credentials' });
        const valid = await bcrypt.compare(data.password, rider.password_hash);
        if (!valid) return res.json({ success: false, error: 'Invalid credentials' });
        const { password_hash, ...safe } = rider;
        // Issue a signed session token so rider can call staff-gated actions (e.g. updateOrderStatus)
        const sessionToken = _signToken({
          role:     'staff',
          username: rider.rider_id,
          exp:      Date.now() + SESSION_TTL_MS,
        });
        return res.json({ success: true, rider: safe, sessionToken });
      }

      case 'getRiderOrders': {
        // Verify the sessionToken belongs to this rider (or is an admin)
        const riderSession = _verifyToken(req.body.sessionToken);
        const isAdmin = riderSession && (riderSession.role === 'admin' || riderSession.role === 'staff');
        const isOwner = riderSession && riderSession.username === data.riderId;
        if (!isAdmin && !isOwner) {
          return res.status(401).json({ success: false, error: 'Rider auth required' });
        }
        const twoDaysAgo = istDateStr(new Date(Date.now() + 5.5 * 3_600_000 - 2 * 86_400_000));
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('rider_id', data.riderId)
          .gte('date', twoDaysAgo)
          .order('created_at', { ascending: false });
        const formatted = (rows || []).map(formatOrder);
        return res.json({ success: true, orders: formatted });
      }

      case 'getRiders': {
        const { data: rows } = await supabase.from('riders').select('*').eq('is_active', true);
        const safe = (rows || []).map(r => { const { password_hash, ...s } = r; return s; });
        return res.json({ success: true, riders: safe });
      }

      // ── STAFF ─────────────────────────────────────────────────────────────

      case 'addStaff':
      case 'createStaff': {
        const hash = await bcrypt.hash(data.password, SALT_ROUNDS);
        await supabase.from('staff').insert({
          id:            generateId('STF', ist),
          username:      data.username,
          name:          data.name,
          password_hash: hash,
          role:          data.role || 'staff',
          created_at:    new Date().toISOString()
        });
        return res.json({ success: true });
      }

      case 'updateStaff': {
        const updates = { ...data };
        delete updates.id;
        delete updates.password_hash; // never allow direct hash overwrite
        if (data.password) {
          updates.password_hash = await bcrypt.hash(data.password, SALT_ROUNDS);
          delete updates.password;
        }
        await supabase.from('staff').update(updates).eq('id', data.id);
        return res.json({ success: true });
      }

      case 'deleteStaff': {
        await supabase.from('staff').delete().eq('id', data.id);
        return res.json({ success: true });
      }

      case 'getStaff': {
        const { data: rows } = await supabase.from('staff').select('*');
        const safe = (rows || []).map(s => { const { password_hash, ...r } = s; return r; });
        return res.json({ success: true, staff: safe });
      }

      // ── WALLET / KHATA ────────────────────────────────────────────────────

      case 'getKhata': {
        const phone = cleanPhone(data.phone);
        const { data: entries } = await supabase.from('khata_entries').select('*').eq('phone', phone).order('created_at', { ascending: false });
        const { data: sumRow }  = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();

        // ── Enrich entries with order details (items, discount, coupon) ──
        const orderIds = (entries || []).map(e => e.order_id).filter(Boolean);
        let orderMap = {};
        if (orderIds.length) {
          const { data: orders } = await supabase
            .from('orders')
            .select('order_id, items, discount, coupon_code, total_amount, delivery_charge, final_amount')
            .in('order_id', orderIds);
          for (const o of (orders || [])) {
            let parsedItems = o.items;
            if (typeof parsedItems === 'string') {
              try { parsedItems = JSON.parse(parsedItems); } catch { parsedItems = []; }
            }
            orderMap[o.order_id] = {
              items:           parsedItems || [],
              discount:        o.discount        || 0,
              coupon_code:     o.coupon_code      || null,
              total_amount:    o.total_amount     || 0,
              delivery_charge: o.delivery_charge  || 0,
              final_amount:    o.final_amount     || 0
            };
          }
        }

        const enriched = (entries || []).map(e => {
          if (e.order_id && orderMap[e.order_id]) {
            return { ...e, ...orderMap[e.order_id] };
          }
          return e;
        });

        return res.json({ success: true, balance: sumRow?.balance || 0, entries: enriched });
      }

      case 'getSubscriberBalance': {
        const { data: row } = await supabase.from('khata_summary').select('balance').eq('phone', cleanPhone(data.phone)).single();
        return res.json({ success: true, balance: row?.balance || 0 });
      }

      case 'rechargeWallet': {
        const phone  = cleanPhone(data.phone);
        const amount = Number(data.amount);
        const newBal = await _atomicWalletUpdate(phone, amount);
        await supabase.from('khata_entries').insert({
          id:              generateTxnId(ist),
          phone,
          type:            'recharge',
          amount,
          running_balance: newBal,
          note:            data.note || 'Wallet recharge',
          date:            istDateStr(ist),
          time:            istTimeStr(ist),
          order_id:        null,
          order_status:    null,
          source:          'admin',
          created_at:      new Date().toISOString()
        });
        await _createNotification({
          type: 'wallet', priority: 'normal', group_id: phone,
          title: 'Wallet Recharged',
          body:  '₹' + amount + ' added to wallet. New balance: ₹' + newBal,
          meta:  { phone, amount, newBal }
        });
        return res.json({ success: true, newBalance: newBal });
      }

      case 'manualRefund': {
        const phone  = cleanPhone(data.phone);
        const amount = Number(data.amount);
        const newBal = await _atomicWalletUpdate(phone, amount);
        await supabase.from('khata_entries').insert({
          id:              generateTxnId(ist),
          phone,
          type:            'adjustment',
          amount,
          running_balance: newBal,
          note:            data.note || 'Manual adjustment',
          date:            istDateStr(ist),
          time:            istTimeStr(ist),
          order_id:        data.order_id || null,
          order_status:    null,
          source:          'admin',
          created_at:      new Date().toISOString()
        });
        await _createNotification({
          type: 'wallet', priority: 'normal', group_id: phone,
          title: 'Wallet Adjustment',
          body:  '₹' + amount + ' adjusted. New balance: ₹' + newBal,
          meta:  { phone, amount, newBal }
        });
        return res.json({ success: true, newBalance: newBal });
      }

      case 'adminGetAllKhata': {
        const { data: rows } = await supabase.from('khata_summary').select('*');
        const kPhones = (rows || []).map(k => k.phone);
        const { data: kUsers } = kPhones.length
          ? await supabase.from('users').select('phone, name').in('phone', kPhones)
          : { data: [] };
        const kuMap = {};
        for (const u of (kUsers || [])) kuMap[u.phone] = u.name;
        const enriched = (rows || []).map(k => ({ ...k, name: kuMap[k.phone] || null }));
        return res.json({ success: true, khata: enriched });
      }

      case 'addKhataEntry': {
        const phone  = cleanPhone(data.phone);
        const amount = Number(data.amount);
        await supabase.from('khata_entries').insert({
          id:              generateTxnId(ist),
          phone,
          type:            data.type,
          amount,
          running_balance: data.running_balance ?? null,
          note:            data.note || '',
          date:            data.date || istDateStr(ist),
          time:            data.time || istTimeStr(ist),
          order_id:        data.order_id || null,
          order_status:    data.order_status || null,
          source:          data.source || 'admin',
          created_at:      new Date().toISOString()
        });
        await _atomicWalletUpdate(phone, amount);
        return res.json({ success: true });
      }

      // ── SETTINGS ──────────────────────────────────────────────────────────

      case 'getOrderCutoff': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'order_cutoff_config').single();
        let config = null;
        if (row?.value) { try { config = JSON.parse(row.value); } catch { config = null; } }
        return res.json({ success: true, config });
      }

      case 'setOrderCutoff': {
        await supabase.from('admin_settings').upsert({ key: 'order_cutoff_config', value: JSON.stringify(data.config), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null;
        return res.json({ success: true });
      }

      case 'getWeeklySchedule': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'weekly_schedule').single();
        let schedule = null;
        if (row?.value) { try { schedule = JSON.parse(row.value); } catch { schedule = null; } }
        return res.json({ success: true, schedule });
      }

      case 'setWeeklySchedule': {
        await supabase.from('admin_settings').upsert({ key: 'weekly_schedule', value: JSON.stringify(data.schedule), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null;
        return res.json({ success: true });
      }

      case 'setAutoTiffinCutoff': {
        // config = { morning: 'HH:MM', evening: 'HH:MM' }
        const cfg = data.config || {};
        const timeRe = /^\d{2}:\d{2}$/;
        if (!timeRe.test(cfg.morning) || !timeRe.test(cfg.evening))
          return res.json({ success: false, error: 'Invalid time format. Use HH:MM' });
        await supabase.from('admin_settings').upsert({ key: 'auto_tiffin_cutoff', value: JSON.stringify(cfg), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache();
        return res.json({ success: true });
      }

      case 'getKhataEnabled': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'khata_enabled').single();
        return res.json({ success: true, enabled: JSON.parse(row?.value || 'false') === true });
      }

      case 'setKhataEnabled': {
        await supabase.from('admin_settings').upsert({ key: 'khata_enabled', value: JSON.stringify(!!data.enabled), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null;
        return res.json({ success: true });
      }

      case 'getDeliveryZone': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'delivery_zone').single();
        let zone = null;
        if (row?.value) { try { zone = JSON.parse(row.value); } catch { zone = null; } }
        return res.json({ success: true, zone });
      }

      case 'setDeliveryZone': {
        const zone = { lat: parseFloat(data.lat), lng: parseFloat(data.lng), radiusKm: parseFloat(data.radiusKm) };
        if (isNaN(zone.lat) || isNaN(zone.lng) || isNaN(zone.radiusKm) || zone.radiusKm <= 0) {
          return res.json({ success: false, error: 'Invalid zone data' });
        }
        await supabase.from('admin_settings').upsert({ key: 'delivery_zone', value: JSON.stringify(zone), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        return res.json({ success: true });
      }

      // ── ANALYTICS ─────────────────────────────────────────────────────────

      case 'getAnalytics': {
        const now = Date.now();
        if (_analyticsCache && (now - _analyticsCacheTs) < _ANALYTICS_TTL) {
          return res.json(_analyticsCache);
        }
        const today      = istDateStr(ist);
        const monthStart = today.slice(0, 7) + '-01';
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
        const [
          r1, r2, r3, r4, r5, r6, r7, r8, r9
        ] = await Promise.all([
          supabase.from('orders').select('*', { count: 'exact', head: true }).eq('date', today),
          supabase.from('orders').select('final_amount').eq('date', today).neq('order_status', 'rejected').neq('order_status', 'cancelled'),
          supabase.from('orders').select('final_amount').gte('date', monthStart).neq('order_status', 'rejected').neq('order_status', 'cancelled'),
          supabase.from('orders').select('*', { count: 'exact', head: true }),
          supabase.from('users').select('*', { count: 'exact', head: true }),
          supabase.from('subscribers').select('*', { count: 'exact', head: true }),
          supabase.from('khata_summary').select('balance'),
          supabase.from('users').select('*', { count: 'exact', head: true }).gte('created_at', thirtyDaysAgo),
          supabase.from('orders').select('order_id, name, phone, final_amount, order_status, date, time').order('created_at', { ascending: false }).limit(10)
        ]);
        const todayRevenue = (r2.data || []).reduce((s, o) => s + (o.final_amount || 0), 0);
        const monthRevenue = (r3.data || []).reduce((s, o) => s + (o.final_amount || 0), 0);
        const totalWalletBalance = (r7.data || []).reduce((s, k) => s + (k.balance || 0), 0);
        const analyticsResult = {
          success: true,
          todayOrders:         r1.count || 0,
          todayRevenue,
          monthRevenue,
          totalOrders:         r4.count || 0,
          totalUsers:          r5.count || 0,
          subscriberCount:     r6.count || 0,
          totalWalletBalance,
          newUsers30d:         r8.count || 0,
          recentOrders:        r9.data  || []
        };
        _analyticsCache   = analyticsResult;
        _analyticsCacheTs = Date.now();
        return res.json(analyticsResult);
      }

      case 'getUsers': {
        const { data: rows, error: uErr2 } = await supabase.from('users').select('*').order('created_at', { ascending: false });
        if (uErr2) throw new Error('DB error: ' + uErr2.message);
        const safe = (rows || []).map(u => { const { password_hash, ...s } = u; return s; });
        return res.json({ success: true, users: safe });
      }

      // ── NOTIFICATIONS ─────────────────────────────────────────────────────

      case 'getNotifications': {
        const { data: rows } = await supabase.from('notifications').select('*').order('created_at', { ascending: false });
        const list = (rows || []).map(n => {
          if (n.meta && typeof n.meta === 'string') {
            try { n.meta = JSON.parse(n.meta); } catch (_) { n.meta = {}; }
          }
          return n;
        });
        const unreadCount = list.filter(n => !n.is_read).length;
        return res.json({ success: true, notifications: list, unreadCount });
      }

      case 'createNotification': {
        await _createNotification(data);
        return res.json({ success: true });
      }

      case 'markNotificationRead': {
        await supabase.from('notifications').update({ is_read: true, read_at: new Date().toISOString() }).eq('id', data.id);
        return res.json({ success: true });
      }

      case 'markNotificationGroupRead': {
        await supabase.from('notifications').update({ is_read: true, read_at: new Date().toISOString() }).eq('group_id', data.group_id);
        return res.json({ success: true });
      }

      case 'deleteNotification': {
        await supabase.from('notifications').delete().eq('id', data.id);
        return res.json({ success: true });
      }

      case 'purgeOldNotifications': {
        const cutoff = new Date(Date.now() - 24 * 3_600_000).toISOString();
        await supabase.from('notifications').delete().lt('created_at', cutoff);
        return res.json({ success: true });
      }

      // Returns row counts that WOULD be deleted by auto-cleanup (for admin info display)
      case 'autoCleanupStatus': {
        const ist2 = getIST();
        const dc = (days) => istDateStr(new Date(ist2.getTime() - days * 86_400_000));
        const ic = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

        const [c1, c2, c3, c4, c5] = await Promise.all([
          supabase.from('orders').select('order_id', { count: 'exact', head: true }).lte('date', dc(5)),
          supabase.from('khata_entries').select('id', { count: 'exact', head: true }).lte('date', dc(35)),
          supabase.from('notifications').select('id', { count: 'exact', head: true }).lt('created_at', ic(1)),
          supabase.from('cooking_sessions').select('session_id', { count: 'exact', head: true }).lte('session_date', dc(5)),
          supabase.from('nu_coupon_sent').select('phone', { count: 'exact', head: true }).lt('sent_at', ic(5)),
        ]);

        return res.json({
          success: true,
          pending: {
            orders:           c1.count || 0,
            khata_entries:    c2.count || 0,
            notifications:    c3.count || 0,
            cooking_sessions: c4.count || 0,
            nu_coupon_sent:   c5.count || 0,
          },
          retention: { orders: 5, khata_entries: 35, notifications: 1, cooking_sessions: 5, nu_coupon_sent: 5 }
        });
      }

      // ── NEW USER COUPON ───────────────────────────────────────────────────

      case 'getNuCouponPending': {
        // Fetch unread new-user notifications, cross-reference with nu_coupon_sent
        const { data: notifRows } = await supabase
          .from('notifications')
          .select('id, meta, created_at')
          .eq('type', 'user')
          .eq('is_read', false)
          .order('created_at', { ascending: false });
        const { data: sentRows } = await supabase.from('nu_coupon_sent').select('phone');
        const sentPhones = new Set((sentRows || []).map(r => r.phone));
        const pending = (notifRows || [])
          .map(n => {
            let meta = {}; try { meta = typeof n.meta === 'string' ? JSON.parse(n.meta) : (n.meta || {}); } catch(_) {}
            return { phone: meta.phone, name: meta.name, address: meta.address, notif_id: n.id, created_at: n.created_at };
          })
          .filter(u => u.phone && !sentPhones.has(u.phone));
        return res.json({ success: true, records: pending });
      }

      case 'getNuCouponSent': {
        const { data: rows } = await supabase.from('nu_coupon_sent').select('*').order('sent_at', { ascending: false });
        return res.json({ success: true, records: rows || [] });
      }

      case 'addNuCouponPending': {
        // No-op stored handler — pending list is derived from unread notifications.
        // This is a safe stub so admin.html's saveAndSendCoupon() doesn't error.
        return res.json({ success: true });
      }

      case 'markNuCouponSent': {
        await supabase.from('nu_coupon_sent').upsert({
          phone:       cleanPhone(data.phone),
          name:        data.name || null,
          sent_at:     new Date().toISOString(),
          coupon_code: data.coupon_code || null,
          notif_id:    data.notif_id || null
        }, { onConflict: 'phone' });
        return res.json({ success: true });
      }

      case 'deleteOldNuCouponSent': {
        const cutoff = new Date(Date.now() - 90 * 86_400_000).toISOString();
        const { count } = await supabase.from('nu_coupon_sent').delete({ count: 'exact' }).lt('sent_at', cutoff);
        return res.json({ success: true, deleted: count || 0 });
      }

      // ── DATA CLEANUP ──────────────────────────────────────────────────────

      case 'previewDeleteOrders': {
        const { count } = await supabase.from('orders').select('*', { count: 'exact', head: true }).lte('date', data.before_date);
        return res.json({ success: true, count: count || 0 });
      }

      case 'previewDeleteTransactions': {
        const { count } = await supabase.from('khata_entries').select('*', { count: 'exact', head: true }).lte('date', data.before_date);
        return res.json({ success: true, count: count || 0 });
      }

      case 'previewDeleteNotifications': {
        const { count } = await supabase.from('notifications').select('*', { count: 'exact', head: true }).lte('created_at', data.before_date);
        return res.json({ success: true, count: count || 0 });
      }

      case 'deleteOldOrders': {
        const { count } = await supabase.from('orders').delete({ count: 'exact' }).lte('date', data.before_date);
        return res.json({ success: true, deleted: count || 0 });
      }

      case 'deleteOldTransactions': {
        const { count } = await supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', data.before_date);
        return res.json({ success: true, deleted: count || 0 });
      }

      case 'deleteOldData': {
        const type       = (data.type || '').toLowerCase();
        const reqDate    = data.before;   // YYYY-MM-DD from client
        if (!reqDate) return res.json({ success: false, error: 'Missing date' });

        // Minimum retention rules (days): data newer than this is never deleted
        const MIN_DAYS = { orders: 5, transactions: 35, notifications: 1 };
        const minDays  = MIN_DAYS[type];
        if (minDays === undefined) return res.json({ success: false, error: 'Unknown type: ' + type });

        // Compute the safest allowed cutoff date (today − minDays) in IST, not UTC
        const safeCutoffIST = getIST();
        safeCutoffIST.setUTCDate(safeCutoffIST.getUTCDate() - minDays);
        const safeCutoffStr = istDateStr(safeCutoffIST);

        // Honour whichever is earlier: what admin requested vs. the safety cutoff
        const cutoffDate = reqDate < safeCutoffStr ? reqDate : safeCutoffStr;

        if (type === 'orders') {
          const { count, error } = await supabase.from('orders').delete({ count: 'exact' }).lte('date', cutoffDate);
          if (error) throw new Error(error.message);
          return res.json({ success: true, deleted: count || 0, cutoffUsed: cutoffDate });
        } else if (type === 'transactions') {
          const { count, error } = await supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', cutoffDate);
          if (error) throw new Error(error.message);
          return res.json({ success: true, deleted: count || 0, cutoffUsed: cutoffDate });
        } else if (type === 'notifications') {
          const { count, error } = await supabase.from('notifications').delete({ count: 'exact' }).lte('created_at', cutoffDate + 'T23:59:59Z');
          if (error) throw new Error(error.message);
          return res.json({ success: true, deleted: count || 0, cutoffUsed: cutoffDate });
        }
        return res.json({ success: false, error: 'Unhandled type' });
      }

      case 'masterDelete': {
        if (data.confirm !== 'DELETE_ALL_TIFFO_DATA') {
          return res.json({ success: false, error: 'Confirmation string mismatch' });
        }

        // Minimum retention: delete only data OLDER than these cutoffs (in IST, not UTC)
        const dateCutoff = (daysAgo) => {
          const d = getIST();
          d.setUTCDate(d.getUTCDate() - daysAgo);
          return istDateStr(d);
        };

        const ordersCutoff  = dateCutoff(5);   // orders  older than 5 days
        const txnsCutoff    = dateCutoff(35);  // transactions older than 35 days
        const notifsCutoff  = dateCutoff(1);   // notifications older than 1 day

        const sessionsCutoff = dateCutoff(5);  // cooking_sessions older than 5 days
        const nuCouponCutoff  = new Date(Date.now() - 5 * 86_400_000).toISOString(); // nu_coupon_sent older than 5 days

        const [r1, r2, r3, r4, r5] = await Promise.all([
          supabase.from('orders').delete({ count: 'exact' }).lte('date', ordersCutoff),
          supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', txnsCutoff),
          supabase.from('notifications').delete({ count: 'exact' }).lte('created_at', notifsCutoff + 'T23:59:59Z'),
          supabase.from('cooking_sessions').delete({ count: 'exact' }).lte('session_date', sessionsCutoff),
          supabase.from('nu_coupon_sent').delete({ count: 'exact' }).lt('sent_at', nuCouponCutoff),
        ]);

        return res.json({
          success: true,
          message: 'Master delete completed (retention rules applied)',
          ordersDeleted:          r1.count || 0,
          txnsDeleted:            r2.count || 0,
          notifsDeleted:          r3.count || 0,
          cookingSessionsDeleted: r4.count || 0,
          nuCouponSentDeleted:    r5.count || 0,
          cutoffs: { orders: ordersCutoff, transactions: txnsCutoff, notifications: notifsCutoff, cookingSessions: sessionsCutoff }
        });
      }

      // ── INDEX (CUSTOMER) ALIASES ──────────────────────────────────────────
      case 'updatePauseDelivery':
        { if (!data.phone) return res.json({ success: false, error: 'Phone required' });
          const allowed = ['none', 'lunch', 'dinner', 'both'];
          const mode = data.pauseMode || data.mode;
          if (!allowed.includes(mode)) return res.json({ success: false, error: 'Invalid mode' });
          // FIX #14: Sync granular pause fields to match legacy pause_delivery
          const pm = (mode === 'lunch' || mode === 'both');
          const pe = (mode === 'dinner' || mode === 'both');
          // morningForToday/eveningForToday: sent by frontend based on cutoff check.
          // true  = cutoff not yet passed → pause is active TODAY
          // false = cutoff already passed → pause should only activate TOMORROW
          // When resuming (mode='none'), clear both _from dates.
          const todayStr    = istDateStr(ist);
          const tomorrowIST = new Date(ist.getTime() + 86_400_000);
          const tomorrowStr = istDateStr(tomorrowIST);
          const pmFrom = pm ? (data.morningForToday !== false ? todayStr : tomorrowStr) : null;
          const peFrom = pe ? (data.eveningForToday !== false ? todayStr : tomorrowStr) : null;
          await supabase.from('subscribers').update({
            pause_delivery:     mode,
            pause_morning:      pm,
            pause_evening:      pe,
            pause_morning_from: pmFrom,
            pause_evening_from: peFrom
          }).eq('phone', cleanPhone(data.phone));
          return res.json({ success: true, pauseMode: mode }); }

      case 'changePassword':
        { const phone = cleanPhone(data.phone);
          const { data: user } = await supabase.from('users').select('password_hash').eq('phone', phone).single();
          if (!user) return res.json({ success: false, error: 'User not found' });
          const valid = await bcrypt.compare(data.currentPassword, user.password_hash);
          if (!valid) return res.json({ success: false, error: 'Current password incorrect' });
          const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
          await supabase.from('users').update({ password_hash: hash }).eq('phone', phone);
          return res.json({ success: true }); }

      // ── ADMIN PANEL ALIASES (fixes action name mismatches) ────────────────
      case 'adminGetUsers':
        { const { data: rows, error: uErr } = await supabase.from('users').select('*').order('created_at', { ascending: false });
          if (uErr) throw new Error('DB error: ' + uErr.message);
          const { data: subs } = await supabase.from('subscribers').select('phone, plan, plan_end');
          const subMap = {};
          for (const s of (subs || [])) subMap[s.phone] = s;
          const { data: orderAgg } = await supabase.from('orders').select('phone, date').order('date', { ascending: false });
          const orderMap = {};
          for (const o of (orderAgg || [])) {
            if (!orderMap[o.phone]) orderMap[o.phone] = { count: 0, last: o.date };
            orderMap[o.phone].count++;
          }
          const safe = (rows || []).map(u => {
            const { password_hash, ...s } = u;
            const sub = subMap[u.phone];
            const ord = orderMap[u.phone] || { count: 0, last: null };
            return { ...s, is_subscriber: !!sub, subscriber_plan: sub?.plan || null, subscriber_plan_end: sub?.plan_end || null, total_orders: ord.count, last_order_date: ord.last };
          });
          return res.json({ success: true, users: safe }); }

      case 'getMenuItems':
        { const { data: items } = await supabase.from('menu_items').select('*').order('sort_order', { ascending: true });
          return res.json({ success: true, items: (items || []).map(formatMenuItem) }); }

      case 'getCoupons':
        { const { data: rows, error: cErr } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
          if (cErr) throw new Error('DB error: ' + cErr.message);
          const coupons = (rows || []).map(c => ({ ...c, used_by: (() => { try { return JSON.parse(c.used_by || '[]'); } catch { return []; } })() }));
          return res.json({ success: true, coupons }); }

      case 'addCoupon':
        { if (!data.code) return res.json({ success: false, error: 'Coupon code required' });
          // usage_limit: explicit field, or fall back to max_usage; for new-user coupons this will be 1
          const usageLimit = data.usage_limit ?? data.max_usage ?? null;
          // auto_delete: delete coupon from DB once usage_limit is reached (used for new-user welcome coupons)
          const autoDelete = data.auto_delete === true ? true : false;
          await supabase.from('coupons').insert({
            code:              (data.code || '').toUpperCase(),
            discount_type:     data.discount_type,
            discount_value:    data.discount_value,
            expiry_date:       data.expiry_date || null,
            is_active:         true,
            min_order:         data.min_order ?? null,
            min_order_amount:  data.min_order ?? null,
            max_usage:         usageLimit,
            total_usage_limit: usageLimit,
            per_user_limit:    data.per_user_limit ?? null,
            max_per_user:      data.per_user_limit ?? null,
            cap_amount:        data.cap_amount ?? null,
            max_cap:           data.cap_amount ?? null,
            restriction_type:  data.restriction_type || 'unlimited',
            allowed_phones:    JSON.stringify(data.allowed_phones || []),
            auto_delete:       autoDelete,
            used_count:        0,
            usage_count:       0,
            used_by:           '[]',
            created_at:        new Date().toISOString()
          });
          return res.json({ success: true }); }

      case 'updateCoupon': {
        const COUPON_EDITABLE = ['code','discount_type','discount_value','cap_amount','max_cap',
          'min_order','min_order_amount','max_usage','total_usage_limit','per_user_limit',
          'max_per_user','expiry_date','is_active','restriction_type','allowed_phones','auto_delete'];
        const updates = {};
        for (const k of COUPON_EDITABLE) { if (data[k] !== undefined) updates[k] = data[k]; }
        if (!Object.keys(updates).length) return res.json({ success: false, error: 'Nothing to update' });
        await supabase.from('coupons').update(updates).eq('id', data.id);
        return res.json({ success: true }); }

      case 'getSubscribers':
        { const { data: subs } = await supabase.from('subscribers').select('*').order('plan_start', { ascending: false });
          const gsPhones = (subs || []).map(s => s.phone);
          const { data: gsUsers } = gsPhones.length
            ? await supabase.from('users').select('phone, name, address').in('phone', gsPhones)
            : { data: [] };
          const gsMap = {};
          for (const u of (gsUsers || [])) gsMap[u.phone] = u;
          const result = (subs || []).map(s => ({ ...s, name: gsMap[s.phone]?.name || '', address: gsMap[s.phone]?.address || '', plan: s.plan || null }));
          return res.json({ success: true, subscribers: result }); }

      case 'getAllKhata': {
        const { data: rows } = await supabase.from('khata_summary').select('*');
        const akPhones = (rows || []).map(r => r.phone);
        const [{ data: akUsers }, { data: akTxns }] = akPhones.length
          ? await Promise.all([
              supabase.from('users').select('phone, name').in('phone', akPhones),
              supabase.from('khata_entries').select('phone, id, type, created_at').in('phone', akPhones).order('created_at', { ascending: false })
            ])
          : [{ data: [] }, { data: [] }];
        const akUMap = {}, akTMap = {};
        for (const u of (akUsers || [])) akUMap[u.phone] = u.name;
        for (const t of (akTxns  || [])) {
          if (!akTMap[t.phone]) akTMap[t.phone] = { count: 0, lastRecharge: null };
          akTMap[t.phone].count++;
          if (!akTMap[t.phone].lastRecharge && t.type === 'recharge') akTMap[t.phone].lastRecharge = t.created_at;
        }
        const enriched = (rows || []).map(r => ({
          phone:            r.phone,
          balance:          r.balance,
          updated_at:       r.updated_at,
          name:             akUMap[r.phone] || null,
          txn_count:        akTMap[r.phone]?.count || 0,
          last_recharge_at: akTMap[r.phone]?.lastRecharge || null
        }));
        return res.json({ success: true, khata: enriched });
      }

      case 'getSettings':
        { const { data: rows } = await supabase.from('admin_settings').select('*');
          const map = {};
          for (const r of (rows || [])) { try { map[r.key] = JSON.parse(r.value); } catch { map[r.key] = r.value; } }
          return res.json({ success: true, settings: {
            cutoff:           map['order_cutoff_config']   || {},
            weeklySchedule:   map['weekly_schedule']       || [],
            khataEnabled:     map['khata_enabled']         === true,
            deliveryZone:     map['delivery_zone']         || null,
            autoTiffinCutoff: map['auto_tiffin_cutoff']   || { morning: '11:00', evening: '18:00' }
          }}); }

      case 'adminResetUserPassword':
        { const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
          await supabase.from('users').update({ password_hash: hash }).eq('phone', cleanPhone(data.phone));
          return res.json({ success: true }); }

      case 'deleteNotificationRange': {
        // Respects read_only flag — only deletes read notifications, never unread
        // ALWAYS excludes today's notifications regardless of read status
        // Use IST midnight (not UTC midnight) so the "today" guard is correct
        // getIST() shifts clock by +5:30 and stores IST time in UTC fields
        const todayStart = getIST();
        todayStart.setUTCHours(0, 0, 0, 0); // zero IST midnight via UTC accessors
        const safeEnd = data.to + 'T23:59:59.999Z';
        // Ensure the range end never reaches today
        let rangeEnd;
        if (new Date(safeEnd) >= todayStart) {
          const dayBefore = new Date(todayStart.getTime() - 1);
          rangeEnd = dayBefore.toISOString();
        } else {
          rangeEnd = safeEnd;
        }
        let query = supabase.from('notifications').delete()
          .gte('created_at', data.from)
          .lte('created_at', rangeEnd);
        if (data.read_only !== false) query = query.eq('is_read', true);
        const { count } = await query;
        return res.json({ success: true, deleted: count || 0 });
      }

      case 'previewCleanup': {
        const type     = (data.type || '').toLowerCase();
        const reqDate  = data.before;
        if (!reqDate) return res.json({ success: false, error: 'Missing date' });

        const MIN_DAYS = { orders: 5, transactions: 35, notifications: 1 };
        const minDays  = MIN_DAYS[type];
        if (minDays === undefined) return res.json({ success: false, error: 'Unknown type: ' + type });

        const safeCutoffIST2 = getIST();
        safeCutoffIST2.setUTCDate(safeCutoffIST2.getUTCDate() - minDays);
        const safeCutoffStr = istDateStr(safeCutoffIST2);
        const cutoffDate    = reqDate < safeCutoffStr ? reqDate : safeCutoffStr;

        if (type === 'orders') {
          const { count } = await supabase.from('orders').select('*', { count: 'exact', head: true }).lte('date', cutoffDate);
          return res.json({ success: true, count: count || 0, cutoffUsed: cutoffDate });
        } else if (type === 'transactions') {
          const { count } = await supabase.from('khata_entries').select('*', { count: 'exact', head: true }).lte('date', cutoffDate);
          return res.json({ success: true, count: count || 0, cutoffUsed: cutoffDate });
        } else if (type === 'notifications') {
          const { count } = await supabase.from('notifications').select('*', { count: 'exact', head: true }).lte('created_at', cutoffDate + 'T23:59:59Z');
          return res.json({ success: true, count: count || 0, cutoffUsed: cutoffDate });
        }
        return res.json({ success: false, error: 'Unhandled type' });
      }

      // ─────────────────────────────────────────────────────────────────────
      // Toggle granular pause for a subscriber session (admin action)
      case 'toggleSubPause': {
        const phone   = cleanPhone(data.phone);
        const session = data.session; // 'morning' | 'evening'
        const action  = data.action;  // 'pause' | 'resume'
        if (!['morning','evening'].includes(session)) return res.json({ success: false, error: 'Invalid session' });
        if (!['pause','resume'].includes(action))     return res.json({ success: false, error: 'Invalid action' });
        const field   = session === 'morning' ? 'pause_morning' : 'pause_evening';
        const val     = action === 'pause';
        const { data: sub } = await supabase.from('subscribers').select('pause_morning, pause_evening').eq('phone', phone).single();
        if (!sub) return res.json({ success: false, error: 'Subscriber not found' });
        const updates = { [field]: val };
        // Keep legacy pause_delivery in sync for index.html compatibility
        const pm = field === 'pause_morning' ? val : (sub.pause_morning || false);
        const pe = field === 'pause_evening' ? val : (sub.pause_evening || false);
        updates.pause_delivery = pm && pe ? 'both' : pm ? 'lunch' : pe ? 'dinner' : 'none';
        // Admin action always takes effect today. When resuming, clear the _from date.
        const todayStr = istDateStr(ist);
        if (field === 'pause_morning') updates.pause_morning_from = val ? todayStr : null;
        if (field === 'pause_evening') updates.pause_evening_from = val ? todayStr : null;
        await supabase.from('subscribers').update(updates).eq('phone', phone);
        return res.json({ success: true, pause_morning: pm, pause_evening: pe });
      }

      // Delete user account completely (admin action)
      case 'adminDeleteUser': {
        const phone = cleanPhone(data.phone);
        // FIX #16: Also delete the user's orders to prevent orphaned records
        await supabase.from('orders').delete().eq('phone', phone);
        // Remove subscriber record, wallet, ledger entries, then user
        await supabase.from('subscribers').delete().eq('phone', phone);
        await supabase.from('khata_summary').delete().eq('phone', phone);
        await supabase.from('khata_entries').delete().eq('phone', phone);
        await supabase.from('nu_coupon_sent').delete().eq('phone', phone);
        await supabase.from('users').delete().eq('phone', phone);
        return res.json({ success: true });
      }

      // ─── KITCHEN / COOKING SUMMARY ───────────────────────────────────────
      // getCookingSummary: aggregate item quantities from orders in a time range,
      // excluding orders already locked in a cooking session.
      case 'getCookingSummary': {
        // data.slot = 'morning' | 'evening' | 'all'
        // data.fromDate, data.toDate  (YYYY-MM-DD)
        const fromDate = data.fromDate || new Date().toISOString().slice(0, 10);
        const toDate   = data.toDate   || fromDate;
        const slot     = (data.slot || 'all').toLowerCase();

        // 1. Fetch all locked order_ids from cooking_sessions that OVERLAP this date range
        //    A session overlaps if its from_date <= toDate AND its to_date >= fromDate
        const { data: sessions } = await supabase
          .from('cooking_sessions')
          .select('locked_order_ids')
          .lte('from_date', toDate)
          .gte('to_date', fromDate);

        const lockedIds = new Set();
        (sessions || []).forEach(s => {
          (s.locked_order_ids || []).forEach(id => lockedIds.add(id));
        });

        // 2. Fetch orders in date range (non-cancelled)
        let q = supabase.from('orders').select('order_id,items,slot,order_status')
          .gte('date', fromDate)
          .lte('date', toDate)
          .not('order_status', 'eq', 'cancelled');

        if (slot === 'morning') q = q.eq('slot', 'morning');
        else if (slot === 'evening') q = q.eq('slot', 'evening');

        const { data: orders } = await q;

        // 3. Aggregate quantities, skip locked orders
        //
        // variantLabel parsing: extract numeric quantity and unit text from labels like:
        //   "100 Gram"        → numQty=100, unit="Gram"
        //   "50 Gram"         → numQty=50,  unit="Gram"
        //   "6 Roti ₹30"     → numQty=6,   unit="Roti"
        //   "4 Roti ₹22"     → numQty=4,   unit="Roti"
        //   "2 piece ₹60"    → numQty=2,   unit="piece"
        //   "1 piece ₹40"    → numQty=1,   unit="piece"
        // If no variant label or no leading number, fall back to item.qty (cart quantity).
        function _parseVariantQtyUnit(variantLabel) {
          if (!variantLabel) return null;
          // Match leading number (int or decimal) followed by a word unit, optionally followed by price/extra text
          // e.g. "100 Gram ₹100" → ["100", "Gram"]
          //      "6 Roti ₹30"   → ["6",   "Roti"]
          //      "4 piece ₹22"  → ["4",   "piece"]
          const m = String(variantLabel).match(/^(\d+(?:\.\d+)?)\s+([A-Za-z]+)/);
          if (!m) return null;
          return { numQty: parseFloat(m[1]), unit: m[2] };
        }

        const summary = {};
        let includedOrderIds = [];
        (orders || []).forEach(ord => {
          if (lockedIds.has(ord.order_id)) return;
          includedOrderIds.push(ord.order_id);
          // items is stored as JSON string in DB — parse it first
          let rawItems = ord.items;
          if (typeof rawItems === 'string') {
            try { rawItems = JSON.parse(rawItems); } catch { rawItems = []; }
          }
          const items = Array.isArray(rawItems) ? rawItems : [];
          items.forEach(item => {
            const key      = (item.name || item.item_name || 'Unknown').trim();
            // Cart quantity (how many of this variant the user added to cart, usually 1)
            const cartQty  = parseFloat(item.quantity || item.qty || 1);
            // Try to parse real numeric quantity from variantLabel first
            const parsed   = _parseVariantQtyUnit(item.variantLabel || item.variant_label || '');
            // realQty = variant numeric amount × cart qty (e.g. "100 Gram" × 1 = 100)
            const realQty  = parsed ? parsed.numQty * cartQty : cartQty;
            // Unit from variant label (e.g. "Gram", "Roti", "piece"); fall back to stored unit field
            const unit     = parsed ? parsed.unit : (item.unit || item.variant || '').trim();

            if (!summary[key]) summary[key] = { name: key, totalQty: 0, unit, orders: 0 };
            summary[key].totalQty += realQty;
            summary[key].orders   += 1;
            // Ensure unit is set (first variant's unit wins; subsequent same-unit items won't overwrite)
            if (!summary[key].unit && unit) summary[key].unit = unit;
          });
        });

        const summaryArr = Object.values(summary).sort((a, b) => a.name.localeCompare(b.name));
        return res.json({
          success: true,
          summary: summaryArr,
          orderCount: includedOrderIds.length,
          includedOrderIds,
          fromDate, toDate, slot
        });
      }

      // startCookingSession: lock the current includedOrderIds so they won't be
      // counted again in future getCookingSummary calls.
      case 'startCookingSession': {
        const sessionDate = data.sessionDate || new Date().toISOString().slice(0, 10);
        const slot        = (data.slot || 'all').toLowerCase();
        const orderIds    = data.orderIds || [];
        const label       = data.label || '';
        const fromDate    = data.fromDate || sessionDate;
        const toDate      = data.toDate   || sessionDate;

        if (!orderIds.length) {
          return res.json({ success: false, error: 'No orders to lock' });
        }

        const sessionId = 'cs_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
        const { error } = await supabase.from('cooking_sessions').insert({
          session_id:       sessionId,
          session_date:     sessionDate,
          slot,
          from_date:        fromDate,
          to_date:          toDate,
          label,
          locked_order_ids: orderIds,
          created_at:       new Date().toISOString()
        });

        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true, sessionId });
      }

      // getCookingSessions: return past cooking sessions for audit/history
      case 'getCookingSessions': {
        const fromDate = data.fromDate || new Date().toISOString().slice(0, 10);
        const toDate   = data.toDate   || fromDate;
        const { data: sessions, error } = await supabase
          .from('cooking_sessions')
          .select('*')
          .lte('from_date', toDate)
          .gte('to_date', fromDate)
          .order('created_at', { ascending: false });
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true, sessions: sessions || [] });
      }

      // getCookingSessionDetail: fetch orders for a specific cooking session
      // so admin can see what items / quantities were locked.
      case 'getCookingSessionDetail': {
        const orderIds = data.orderIds || [];
        if (!orderIds.length) return res.json({ success: true, orders: [], summary: [] });

        const { data: rows, error } = await supabase
          .from('orders')
          .select('order_id,name,phone,address,items,slot,order_status,payment_mode,final_amount,date')
          .in('order_id', orderIds);

        if (error) return res.json({ success: false, error: error.message });

        const orders = (rows || []).map(o => ({
          ...o,
          items: typeof o.items === 'string' ? JSON.parse(o.items) : (o.items || [])
        }));

        // Build item summary — mirrors _parseVariantQtyUnit logic from getCookingSummary.
        // Items are stored with 'variantLabel' (e.g. "100 Gram"), NOT 'variant'.
        // Using i.variant was always '' → qty was always raw cart qty (1), not real qty.
        function _parseVQL(variantLabel) {
          if (!variantLabel) return null;
          const m = String(variantLabel).match(/^(\d+(?:\.\d+)?)\s+([A-Za-z]+)/);
          if (!m) return null;
          return { numQty: parseFloat(m[1]), unit: m[2] };
        }
        const itemMap = {};
        orders.forEach(o => {
          // Track which item keys appear in this order so we count orders once per item per order
          const seenKeysInOrder = new Set();
          (o.items || []).forEach(i => {
            const key = (i.name || i.item_id || 'Unknown').trim();
            // Robustly read cart quantity — check all common field names used across app versions
            const rawQty = i.qty ?? i.quantity ?? i.count ?? i.amount ?? null;
            const cartQty = rawQty !== null && rawQty !== undefined ? parseFloat(rawQty) || 1 : 1;
            const parsed  = _parseVQL(i.variantLabel || i.variant_label || '');
            const realQty = parsed ? parsed.numQty * cartQty : cartQty;
            const unit    = parsed ? parsed.unit : (i.unit || '').trim();
            if (!itemMap[key]) itemMap[key] = { name: key, variantLabel: i.variantLabel || '', unit, qty: 0, orders: 0 };
            itemMap[key].qty += realQty;
            // Count this order only once per item key (not once per item-line)
            if (!seenKeysInOrder.has(key)) {
              itemMap[key].orders += 1;
              seenKeysInOrder.add(key);
            }
            if (!itemMap[key].unit && unit) itemMap[key].unit = unit;
          });
        });
        const summary = Object.values(itemMap).sort((a, b) => b.qty - a.qty);

        return res.json({ success: true, orders, summary });
      }

      // getKitchenDashboard: single call replacing getCookingSummary + getCookingSessions.
      // Runs both DB queries in parallel (Promise.all) — one HTTP round trip, less server load.
      // getCookingSummary and getCookingSessions remain untouched for backwards compatibility.
      case 'getKitchenDashboard': {
        const fromDate = data.fromDate || new Date().toISOString().slice(0, 10);
        const toDate   = data.toDate   || fromDate;
        const slot     = (data.slot || 'all').toLowerCase();

        // ── Run both queries in parallel ──────────────────────────────────
        let summaryQuery = supabase.from('orders').select('order_id,items,slot,order_status')
          .gte('date', fromDate)
          .lte('date', toDate)
          .not('order_status', 'eq', 'cancelled');
        if (slot === 'morning') summaryQuery = summaryQuery.eq('slot', 'morning');
        else if (slot === 'evening') summaryQuery = summaryQuery.eq('slot', 'evening');

        const [
          { data: lockSessions },
          { data: orders },
          { data: allSessions, error: sesErr }
        ] = await Promise.all([
          supabase.from('cooking_sessions').select('locked_order_ids').lte('from_date', toDate).gte('to_date', fromDate),
          summaryQuery,
          supabase.from('cooking_sessions').select('*').lte('from_date', toDate).gte('to_date', fromDate).order('created_at', { ascending: false })
        ]);

        // ── Build locked set ──────────────────────────────────────────────
        const lockedIds = new Set();
        (lockSessions || []).forEach(s => {
          (s.locked_order_ids || []).forEach(id => lockedIds.add(id));
        });

        // ── Aggregate quantities (same logic as getCookingSummary) ─────────
        function _parseVQU(variantLabel) {
          if (!variantLabel) return null;
          const m = String(variantLabel).match(/^(\d+(?:\.\d+)?)\s+([A-Za-z]+)/);
          if (!m) return null;
          return { numQty: parseFloat(m[1]), unit: m[2] };
        }

        const summary = {};
        const includedOrderIds = [];
        (orders || []).forEach(ord => {
          if (lockedIds.has(ord.order_id)) return;
          includedOrderIds.push(ord.order_id);
          let rawItems = ord.items;
          if (typeof rawItems === 'string') {
            try { rawItems = JSON.parse(rawItems); } catch { rawItems = []; }
          }
          const items = Array.isArray(rawItems) ? rawItems : [];
          // Track seen item keys per order to count orders once per item per order
          const seenKeysInOrder = new Set();
          items.forEach(item => {
            const key     = (item.name || item.item_name || 'Unknown').trim();
            // Robustly read cart quantity — check all common field names used across app versions
            const rawQty  = item.qty != null ? item.qty : (item.quantity != null ? item.quantity : (item.count != null ? item.count : null));
            const cartQty = rawQty !== null ? parseFloat(rawQty) || 1 : 1;
            const parsed  = _parseVQU(item.variantLabel || item.variant_label || '');
            const realQty = parsed ? parsed.numQty * cartQty : cartQty;
            const unit    = parsed ? parsed.unit : (item.unit || item.variant || '').trim();
            if (!summary[key]) summary[key] = { name: key, totalQty: 0, unit, orders: 0 };
            summary[key].totalQty += realQty;
            // Count this order only once per item key (not once per item-line)
            if (!seenKeysInOrder.has(key)) {
              summary[key].orders += 1;
              seenKeysInOrder.add(key);
            }
            if (!summary[key].unit && unit) summary[key].unit = unit;
          });
        });

        const summaryArr = Object.values(summary).sort((a, b) => a.name.localeCompare(b.name));

        return res.json({
          success:          true,
          // summary fields (matches getCookingSummary response exactly)
          summary:          summaryArr,
          orderCount:       includedOrderIds.length,
          includedOrderIds,
          fromDate, toDate, slot,
          // sessions field (matches getCookingSessions response exactly)
          sessions:         allSessions || []
        });
      }

      // ─────────────────────────────────────────────────────────────────────
      default:
        return res.status(400).json({ success: false, error: 'Unknown action: ' + action });
    }
  } catch (err) {
    console.error(`[${action}] ERROR:`, err.message);
    return res.json({ success: false, error: err.message });
  }
});

// ─── LISTEN ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[Tiffo API] running on port ${PORT}`));
