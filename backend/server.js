'use strict';
// ╔══════════════════════════════════════════════════════╗
// ║  Tiffo — Backend API (server.js)                    ║
// ║  Version : v164                                      ║
// ║  Updated : 2026-06-26                               ║
// ║  v164    : Audit fix — explicit startup warning if    ║
// ║            SUPABASE_SERVICE_KEY is missing. RLS is    ║
// ║            enabled on every table with zero policies  ║
// ║            (deny-all by default); only the service    ║
// ║            key bypasses it. Previously a missing/     ║
// ║            typo'd key silently fell back to the anon  ║
// ║            key — app stayed up but every query was    ║
// ║            blocked, with no error surfaced anywhere.  ║
// ║            No behavior change — log only.             ║
// ║  v163    : Rating fix — orders.select('id') →        ║
// ║            select('order_id') in all 3 rating funcs  ║
// ║            (_recomputeAndSyncRating, adminGet-        ║
// ║            UserRating, getUserRating). Order          ║
// ║            Consistency was always 0. Added            ║
// ║            adminRecomputeAllRatings with backfill.   ║
// ║  v161    : Bug fixes — updateOrderStatus rejected    ║
// ║            guard, checkSession brute-force counter   ║
// ║            fix, manualRefund negative wallet guard   ║
// ║  v158    : Opt-in auto-tiffin default fix —          ║
// ║            addAsSubscriber and promoteToSubscriber   ║
// ║            both created new subscriber rows with     ║
// ║            pause_delivery:'none' (auto-tiffin ON by  ║
// ║            default), contradicting the opt-in policy ║
// ║            shipped elsewhere. Both now correctly      ║
// ║            default to pause_delivery:'both' (paused), ║
// ║            requiring explicit opt-in.                 ║
// ║  v157    : SECURITY FIX — wallet race condition in   ║
// ║            createOrder. Old flow read balance once   ║
// ║            (createOrder handler), then deducted it   ║
// ║            separately (_atomicWalletUpdate, a blind   ║
// ║            increment) inside _createSingleOrder.     ║
// ║            Concurrent requests with different carts  ║
// ║            could each read the SAME pre-deduction    ║
// ║            balance and each pass the check before    ║
// ║            any of them had deducted — draining the   ║
// ║            wallet past ₹0. Fixed by a new Postgres   ║
// ║            RPC, decrement_if_sufficient() (see        ║
// ║            database.sql), which checks balance >=    ║
// ║            amount AND deducts in ONE atomic           ║
// ║            statement. Wired in via the new            ║
// ║            _atomicWalletDeductIfSufficient() helper,  ║
// ║            called inside _createSingleOrder BEFORE    ║
// ║            the coupon is marked used or stock is      ║
// ║            touched, so a failed/insufficient order    ║
// ║            now has zero side effects. The old         ║
// ║            duplicate pre-check in the createOrder     ║
// ║            handler was removed entirely.              ║
// ║  v151    : SECURITY FIX — getRiderOrders ownership   ║
// ║            check. riderLogin issues role:'staff' to ║
// ║            every rider, so the old isAdmin check     ║
// ║            (role==='admin'||'staff') let ANY rider   ║
// ║            fetch ANY other rider's order list (PII:  ║
// ║            customer name/phone/address) by passing a ║
// ║            different riderId. Now only role==='admin'║
// ║            bypasses; riders must match their own     ║
// ║            rider_id (isOwner check).                 ║
// ║  v145    : Version sync — no backend logic change.  ║
// ║            Frontend fix: Android WebView freeze     ║
// ║            guard (long background → reload via SW). ║
// ║  v131    : Added riderUpdateUserAddress action —    ║
// ║            rider can edit Room No, Delivery Area,   ║
// ║            and GPS coords for any customer.         ║
// ║  Note    : Version alignment release — header was   ║
// ║            stale at v114; code already included     ║
// ║            v117/v118/v122/v130 features (ratings,   ║
// ║            referrals, atomic coupons, zone backfill).║
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

// ─── PHONE-BASED BRUTE FORCE PROTECTION ──────────────────────────────────────
// express-rate-limit is IP-based — useless when 100,000 BHU students share one IP.
// This tracks failed login attempts per phone number instead.
// Logic: 5 failed attempts → 15 min lockout for that phone only.
// Successful login resets the counter so legitimate users are never locked out.
// In-memory Map is fine: at Tiffo's scale (few hundred users) it stays tiny,
// and a server restart clears it (acceptable — lockout is temporary by design).
const _loginAttempts = new Map(); // phone → { count, lockedUntil }
const _LOGIN_MAX_ATTEMPTS = 5;
const _LOGIN_LOCKOUT_MS   = 15 * 60 * 1000; // 15 minutes

function _checkLoginAttempt(phone) {
  // Returns null if allowed, or error string if locked out
  const now = Date.now();
  const entry = _loginAttempts.get(phone);
  if (!entry) return null;
  if (entry.lockedUntil && now < entry.lockedUntil) {
    const minsLeft = Math.ceil((entry.lockedUntil - now) / 60000);
    return `Too many failed attempts. Try again in ${minsLeft} minute${minsLeft > 1 ? 's' : ''}.`;
  }
  // Lockout expired — reset
  if (entry.lockedUntil && now >= entry.lockedUntil) {
    _loginAttempts.delete(phone);
  }
  return null;
}

function _recordLoginFailure(phone) {
  const now = Date.now();
  const entry = _loginAttempts.get(phone) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= _LOGIN_MAX_ATTEMPTS) {
    entry.lockedUntil = now + _LOGIN_LOCKOUT_MS;
  }
  _loginAttempts.set(phone, entry);
  // Lazy cleanup: remove expired entries when map grows large
  if (_loginAttempts.size > 1000) {
    for (const [p, e] of _loginAttempts) {
      if (!e.lockedUntil || now >= e.lockedUntil) _loginAttempts.delete(p);
    }
  }
}

function _resetLoginAttempts(phone) {
  _loginAttempts.delete(phone);
}

// Auth actions that get the tighter limit
const _AUTH_ACTIONS = new Set([
  'login',
  'signup',
  'adminLogin',
  'riderLogin',
  'adminResetUserPassword',
  'changePassword'
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

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
// Applied to every response. These are cheap, standard browser protections.
// X-Content-Type-Options : prevents MIME-sniffing attacks (browser treats response
//                          as declared content-type only, not executable script).
// X-Frame-Options        : blocks clickjacking — nobody can embed tiffo in an iframe.
// Referrer-Policy        : hides full URL from third-party requests (privacy + leak prevention).
// Content-Security-Policy: whitelists exactly which origins can load scripts, styles, fonts,
//                          images and make API connections — blocks injected malicious scripts.
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    // 'unsafe-inline' needed because all JS/CSS is inline in single-file HTML panels
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://purobitese-api.onrender.com https://www.googletagmanager.com https://www.google-analytics.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    // data: for QR code canvas export; blob: for PDF generation; https: for map tiles
    "img-src 'self' data: blob: https:",
    // API calls + Supabase realtime + map geocoding + GA
    "connect-src 'self' https://purobitese-api.onrender.com https://*.supabase.co wss://*.supabase.co https://nominatim.openstreetmap.org https://www.google-analytics.com",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
  ].join('; '));
  next();
});

// ─── NO-CACHE HEADER for all /api responses (data must always be fresh) ──────
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY
);

// FATAL CHECK — SUPABASE_SERVICE_KEY specifically (not just any key present).
// Every table has RLS enabled with ZERO policies defined (see database.sql) —
// by Postgres default this means "deny all" to any non-service-role connection.
// The service key bypasses RLS entirely; the anon key does NOT. So if this var
// is ever missing/typo'd, the app does NOT crash — it silently falls back to
// the anon key, RLS blocks every query, and every endpoint starts returning
// empty/null data with no visible error. This log is the only signal you'd get.
if (!process.env.SUPABASE_SERVICE_KEY) {
  console.error('[FATAL] SUPABASE_SERVICE_KEY env var not set — falling back to ANON key. ' +
    'RLS is enabled with no policies, so ALL Supabase queries will silently fail/return empty. Fix immediately.');
}

const SECURE_API_KEY = process.env.API_KEY;
if (!SECURE_API_KEY) console.error('[FATAL] API_KEY env var not set');

// ─── SESSION TOKEN (HMAC-SHA256, no external deps) ────────────────────────────
// Format: base64url(header).base64url(payload).base64url(sig)
// Secret is separate from API_KEY so rotating one doesn't break the other.
const SESSION_SECRET = process.env.SESSION_SECRET || SECURE_API_KEY + '_session';
if (!process.env.SESSION_SECRET) console.warn('[WARN] SESSION_SECRET env var not set — falling back to derived secret. Set SESSION_SECRET in production.');
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

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
  'masterDelete',
  'createStaff',
  'updateStaff',
  'deleteStaff',
  'resetAdminPassword',
  'adminDeleteUser',  // permanently deletes a user + all their data — admin-only
  'getEarningReport',  // detailed payment-mode breakdown — admin-only financial report
  'getWalletRechargeReport' // wallet recharges (real cash-in) — admin-only
]);

// ─── RIDER ROLE (separate from staff) ──────────────────────────────────────────
// SECURITY FIX: riderLogin used to issue role:'staff', which is the SAME role
// used by real human staff/admin-panel users. Since _STAFF_ACTIONS accepts any
// role==='staff'||'admin' token, every rider's session token was accepted for
// ALL 60+ _STAFF_ACTIONS — including rechargeWallet, manualRefund, deleteRider,
// adminResetUserPassword, updateCoupon, getAllKhata, etc. The rider frontend
// never called these, but nothing stopped a rider from calling them directly
// (e.g. via dev tools) using their own legitimately-issued token.
// Fix: riderLogin now issues role:'rider' (see riderLogin handler), and riders
// are restricted to ONLY the 3 actions the rider panel actually uses — listed
// here explicitly. Anything not in this list is rejected for role==='rider',
// even if it's in _STAFF_ACTIONS.
const _RIDER_ACTIONS = new Set([
  'getRiderOrders',
  'updateOrderStatus',
  'riderUpdateUserAddress',
]);

// Actions that require any valid staff session token (role = 'admin' OR 'staff')
// Staff can do EVERYTHING except: masterDelete, adminDeleteUser, staff management, resetAdminPassword
const _STAFF_ACTIONS = new Set([
  'adminGetOrders',
  'adminGetUsers',
  'getUserAnalytics',
  'adminAllowOrder',
  'adminBlockOrder',
  'adminSetUserCoords',
  'adminGetSubscribers',
  'getStaff',
  'getSubscribersForBulk',
  'getRiders',
  'getNotifications',
  'markNotificationRead',
  'getCookingSessionDetail',
  'getAllKhata',
  'getAnalytics',
  'getCoupons',
  'getKitchenDashboard',
  'getMenuItems',
  'getUserByPhone',
  'assignRider',
  'bulkUpdateOrder',
  'rejectOrder',
  'updateOrderStatus',
  'startCookingSession',
  'bulkGenerateOrders',
  'rechargeWallet',
  'manualRefund',
  'updateSubscriber',
  'promoteToSubscriber',
  'removeSubscriber',
  'adminCreateUser',
  'adminResetUserPassword',
  'addMenuItem',
  'updateMenuItem',
  'deleteMenuItem',
  'deleteCoupon',
  'deleteExpiredCoupons',
  'addCoupon',
  'updateCoupon',
  'updateRider',
  'deleteRider',
  'deleteNotification',
  'deleteNotificationRange',
  'deleteOldData',
  'previewCleanup',
  'getNuCouponPending',
  'getNuCouponSent',
  'addNuCouponPending',
  'markNuCouponSent',
  'setOrderCutoff',
  'setWeeklySchedule',
  'setKhataEnabled',
  'setDeliveryZone',
  'setAutoTiffinCutoff',
  'setDeliveryAreas',
  'adminSetUserAddress',
  'adminSetUserRating',
  'adminRecomputeAllRatings',
  'adminGetUserRating',
  'createRider',
  'addHelpVideo',
  'updateHelpVideo',
  'deleteHelpVideo',
  'reorderHelpVideos',
  'addHelpCategory',
  'deleteHelpCategory',
  // ── Read-only admin data — still require a valid staff session ──
  'getSettings',           // returns full admin_settings (cutoff, zone, schedule, etc.)
  'getOrderTransactions',  // returns user's khata_entries — sensitive financial data
  'getAdminNotifVersion',  // lightweight version check — admin frontend polls every 60s
  'generateReferralCoupons',
  'setReferralSettings',
  // ── Free First Tiffin Campaign System (v169) ──
  'getFreeTiffinUsers',
  'createFreeTiffinBatch',
  'markFreeTiffinWaSent',
  'markFreeTiffinRedeemed',
  'blockFreeTiffinUser',
  'unblockFreeTiffinUser',
]);


// ─── USER-SENSITIVE ACTIONS ───────────────────────────────────────────────────
// These actions operate on user-owned data. They require a valid userToken
// (issued at login) matching the phone in the request. This prevents one user
// from reading/modifying another user's orders, wallet, or subscription.
const _USER_SENSITIVE_ACTIONS = new Set([
  'getUserOrders', 'getKhata', 'updatePauseDelivery',
  'getSubscriberPauseStatus', 'changePassword', 'updateProfile', 'getMyProfile',
  'getSubscriberStatus', 'getSubscriberBalance',
  'checkSubscriber',  // contains full subscriber row including pause/plan — self or staff only
  'getUserRating',
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

// ════════════════════════════════════════════════════════════════════════════
// PROCESS-LEVEL CRASH GUARDS
// ════════════════════════════════════════════════════════════════════════════
// Any uncaught exception or unhandled promise rejection anywhere in the
// process would kill the server and force a Render restart (cold-start penalty).
// These handlers keep the process alive and log the error for diagnosis.
//
// NOTE: We log and continue — not exit(1). On a food-delivery platform,
// a crashed background job (cleanup, ping) should never take down the API.
// Request handlers already have their own try/catch — these are the last line
// of defence for anything that slips through (e.g. third-party lib bugs).

process.on('uncaughtException', (err) => {
  console.error('[FATAL] uncaughtException — process kept alive:', err.message, err.stack);
});

process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  console.error('[FATAL] unhandledRejection — process kept alive:', msg);
});

// ════════════════════════════════════════════════════════════════════════════
// SELF-PING & SUPABASE WARM
// ════════════════════════════════════════════════════════════════════════════
// Two independent intervals — intentionally decoupled:
//   • Render ping   : 12 min  — prevents free-tier sleep (Render sleeps at 15 min idle)
//   • Supabase warm : 4 min   — prevents PostgREST idle timeout (~5 min)
//
// Design principles (production-grade):
//   1. Interval callbacks are ALWAYS synchronous — async work runs inside an
//      async IIFE so errors are fully contained and never reach the event loop
//      as unhandled rejections.
//   2. Supabase JS v2 query builders are thenable (PromiseLike) but NOT native
//      Promises — they have no .catch() method. Must always `await` them inside
//      try/catch. Never chain .catch() directly on the builder.
//   3. https.get response bodies must be drained (res.resume()) or the socket
//      stays open and leaks memory over hundreds of pings.
//   4. Supabase warm logging is suppressed on success — 360 identical log
//      lines per day add noise without value. Only warnings/errors are logged.
//
// Only runs when RENDER_EXTERNAL_URL is set (i.e. deployed, not local dev).

if (process.env.RENDER_EXTERNAL_URL) {
  const PING_URL = process.env.RENDER_EXTERNAL_URL + '/ping';

  // ── 1. Render keep-alive ────────────────────────────────────────────────
  setInterval(() => {
    https.get(PING_URL, (res) => {
      res.resume(); // drain body so socket closes cleanly — prevents memory leak
      if (res.statusCode !== 200) {
        console.warn(`[render-ping] unexpected status ${res.statusCode}`);
      }
    }).on('error', (err) => {
      console.error('[render-ping] error:', err.message);
    });
  }, 12 * 60 * 1000);

  // ── 2. Supabase PostgREST keep-warm ─────────────────────────────────────
  // HEAD query — PostgREST processes it but returns no rows (zero bandwidth).
  // Async IIFE keeps the interval callback synchronous.
  // Success is silent — only problems are logged.
  setInterval(() => {
    (async () => {
      try {
        const { error } = await supabase
          .from('menu_items')
          .select('item_id', { count: 'exact', head: true })
          .eq('is_active', true);
        if (error) console.warn('[supabase-warm] PostgREST warning:', error.message);
        // Success: intentionally silent — fires 360 times/day, logs would be useless noise
      } catch (err) {
        console.error('[supabase-warm] unexpected error:', err.message);
      }
    })();
  }, 4 * 60 * 1000);

  console.log('[self-ping] render=12min supabase-warm=4min →', PING_URL);
}

// ════════════════════════════════════════════════════════════════════════════
// AUTO CLEANUP SCHEDULER
// ════════════════════════════════════════════════════════════════════════════
// Runs daily at midnight IST to silently purge stale data.
//
// Retention policy:
//   orders           → older than 35 days  (full earning history window)
//   khata_entries    → older than 35 days  (one billing cycle of history)
//   notifications    → older than 1 day    (acted-on or dismissed)
//   cooking_sessions → older than 5 days   (kitchen lock reference only)
//   nu_coupon_sent   → older than 7 days   (coupon dedup record only)
//
// NEVER touches: users, subscribers, riders, staff, menu_items, thalis,
//                thali_items, admin_settings, coupons, khata_summary
//
// Design: self-correcting scheduler (no setInterval drift).
// setInterval(24h) drifts by the server restart time — if Render restarts at
// 01:00 IST, cleanup runs at 01:00 every day instead of midnight. Over weeks
// this becomes significant. Self-correcting pattern: after each run, calculate
// exact ms until next midnight IST and schedule a fresh setTimeout. This
// guarantees cleanup always fires within seconds of midnight IST regardless
// of when the server was last restarted.

async function runAutoCleanup() {
  const start = Date.now();
  try {
    const ist = getIST();
    const dateCutoff = (days) => istDateStr(new Date(ist.getTime() - days * 86_400_000));
    const isoCutoff  = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

    const [r1, r2, r3, r4, r5, r6] = await Promise.allSettled([
      supabase.from('orders')          .delete({ count: 'exact' }).lte('date',         dateCutoff(35)),
      supabase.from('khata_entries')   .delete({ count: 'exact' }).lte('date',         dateCutoff(35)),
      supabase.from('notifications')   .delete({ count: 'exact' }).lt('created_at',    isoCutoff(1)),
      supabase.from('cooking_sessions').delete({ count: 'exact' }).lte('session_date', dateCutoff(5)),
      supabase.from('nu_coupon_sent')  .delete({ count: 'exact' }).lt('sent_at',       isoCutoff(7)),
      // Delete used auto_delete coupons (is_active=false) older than 7 days.
      // referral_key is preserved even after is_active=false, so idempotency is intact.
      supabase.from('coupons').delete({ count: 'exact' })
        .eq('auto_delete', true)
        .eq('is_active', false)
        .lt('created_at', isoCutoff(7)),
    ]);

    const fmt = (r) => r.status === 'fulfilled' ? (r.value.count ?? 0) : `err(${r.reason?.message || '?'})`;
    console.log('[auto-cleanup] done in', Date.now() - start, 'ms — deleted:', JSON.stringify({
      orders: fmt(r1), khata_entries: fmt(r2), notifications: fmt(r3),
      cooking_sessions: fmt(r4), nu_coupon_sent: fmt(r5), used_coupons: fmt(r6),
    }));
  } catch (err) {
    // Should never reach here (Promise.allSettled never rejects) but belt-and-suspenders
    console.error('[auto-cleanup] unexpected error:', err.message);
  } finally {
    // Self-correcting: always schedule next run regardless of success/failure.
    // Calculates exact ms to next midnight IST — no drift, no accumulation error.
    _scheduleNextCleanup();
  }
}

function _scheduleNextCleanup() {
  // Next midnight IST = next 00:00 UTC+5:30
  // In UTC terms: next 18:30 UTC (= 00:00 IST next day)
  const nowUtc    = Date.now();
  const istOffset = 5.5 * 3_600_000;
  const istNow    = new Date(nowUtc + istOffset);

  // Build next midnight IST as a UTC timestamp
  const nextMidnightIST = Date.UTC(
    istNow.getUTCFullYear(),
    istNow.getUTCMonth(),
    istNow.getUTCDate() + 1, // tomorrow in IST terms
    0, 0, 0
  ) - istOffset; // convert back from IST to UTC

  const msUntil = nextMidnightIST - nowUtc;
  // Safety: if calculation produces <=0 (e.g. called exactly at midnight),
  // schedule for next midnight + 1 full day to avoid immediate double-fire.
  const safeMsUntil = msUntil > 0 ? msUntil : msUntil + 86_400_000;

  console.log(`[auto-cleanup] next run in ${Math.round(safeMsUntil / 60_000)} min`);
  setTimeout(runAutoCleanup, safeMsUntil);
}

// Kick off the first scheduled run
_scheduleNextCleanup();


// ─── IN-MEMORY CACHES ────────────────────────────────────────────────────────
// Analytics cache — dashboard numbers (8 parallel queries) cached for 90s
let _analyticsCache   = null;
let _analyticsCacheTs = 0;
const _ANALYTICS_TTL  = 90_000; // 90 seconds

// Settings cache — admin_settings rows cached for 5 minutes
const _settingsCache  = {};
const _SETTINGS_TTL   = 5 * 60_000; // 5 minutes

// Menu cache — menu_items rows cached for 60 seconds
// Avoids a Supabase round-trip on every getHomeData call.
// Invalidated immediately by addMenuItem / updateMenuItem / deleteMenuItem.
let _menuItemsCache   = null;
let _menuItemsCacheTs = 0;
const _MENU_ITEMS_TTL = 60_000; // 60 seconds

async function getCachedSetting(key) {
  const entry = _settingsCache[key];
  if (entry && (Date.now() - entry.ts) < _SETTINGS_TTL) return entry.val;
  const { data } = await supabase.from('admin_settings').select('value').eq('key', key).single();
  const val = data?.value ?? null;
  _settingsCache[key] = { val, ts: Date.now() };
  return val;
}

// ── Menu content version ──────────────────────────────────────────────────────
// Lightweight monotonic counter. Bumped every time admin changes menu items OR
// any setting visible on the user homepage (schedule, cutoff, khata toggle).
// Clients poll getMenuVersion (tiny ~100 byte response) every 60 s and only
// call getHomeData when the version they have differs — eliminates unnecessary
// full-payload round-trips and Render cold-start penalties.
let _menuContentVersion = Date.now(); // seed with epoch so each deploy is unique

function _bumpMenuVersion() {
  _menuContentVersion = Date.now();
}

// ── Admin notification version ────────────────────────────────────────────────
// Separate lightweight monotonic counter bumped every time a new notification
// is created (new order, new user, etc.). Admin frontend polls getAdminNotifVersion
// every 60 s — if version changed, it triggers beep + full notification refresh.
// This replaces the old dumb 60s loadNotifications() timer with a near-zero-cost
// version check (~80 bytes) that only triggers a full DB fetch when truly needed.
let _adminNotifVersion = Date.now(); // seed with epoch so each deploy is unique

function _bumpAdminNotifVersion() {
  _adminNotifVersion = Date.now();
}

function _invalidateSettingsCache() {
  delete _settingsCache['weekly_schedule'];
  delete _settingsCache['order_cutoff_config'];
  delete _settingsCache['khata_enabled'];
  delete _settingsCache['auto_tiffin_cutoff'];
  delete _settingsCache['delivery_zone'];
  delete _settingsCache['delivery_areas'];
  // Also wipe menu cache — admin may have changed items alongside settings
  _menuItemsCache   = null;
  _menuItemsCacheTs = 0;
  // Bump version — clients will detect the change on next version poll
  _bumpMenuVersion();
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

// Format a TIME string (HH:MM or HH:MM:SS) to 12hr display e.g. "08:00" → "8:00 AM"
function fmtFlashTime(t) {
  if (!t) return '';
  const [hh, mm] = t.split(':');
  let h = parseInt(hh, 10);
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  return `${h}:${mm} ${ampm}`;
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
    items: typeof o.items === 'string' ? _safeJsonParse(o.items, []) : (o.items || []),
    source: o.source || 'user'  // consistent with khata_entries.source
  };
}

// Fetch all active riders and inject rider_name into orders by matching rider_id.
// Cached for 5 min — riders table rarely changes, no need to hit DB on every poll.
let _ridersCache   = null;
let _ridersCacheTs = 0;
const _RIDERS_TTL  = 5 * 60_000;

async function resolveRiderNames(orders) {
  if (!orders || orders.length === 0) return orders;
  const now = Date.now();
  if (!_ridersCache || (now - _ridersCacheTs) > _RIDERS_TTL) {
    const { data: riders } = await supabase.from('riders').select('rider_id, name');
    _ridersCache   = riders || [];
    _ridersCacheTs = now;
  }
  if (_ridersCache.length === 0) return orders;
  const riderMap = {};
  _ridersCache.forEach(r => { riderMap[r.rider_id] = r.name; });
  return orders.map(o => ({
    ...o,
    rider_name: o.rider_id ? (riderMap[o.rider_id] || o.rider_name || null) : null
  }));
}

function formatMenuItem(i) {
  return {
    ...i,
    variants: typeof i.variants === 'string' ? _safeJsonParse(i.variants, []) : (i.variants || [])
  };
}

// ─── STOCK UNIT HELPERS ───────────────────────────────────────────────────────
// Single source of truth for unit display — used by kitchen dashboard,
// cooking session detail, and stock deduction logic.
// stock_unit: 'gram' | 'kg' | 'piece' | 'litre' | 'custom'
// stock_unit_label: only used when stock_unit === 'custom'
function _unitLabel(stockUnit, stockUnitLabel) {
  switch ((stockUnit || 'gram').toLowerCase()) {
    case 'gram':   return 'g';
    case 'kg':     return 'kg';
    case 'piece':  return 'pcs';
    case 'litre':  return 'L';
    case 'custom': return stockUnitLabel || 'unit';
    default:       return stockUnit || 'g';
  }
}

// Build a name→{unit,label} map from menu_items rows for kitchen enrichment.
// Keyed by lowercase item name for case-insensitive matching.
function _buildMenuUnitMap(menuRows) {
  const map = {};
  (menuRows || []).forEach(mi => {
    const key = (mi.name || '').trim().toLowerCase();
    map[key] = {
      unit:  mi.stock_unit       || 'gram',
      label: mi.stock_unit_label || null
    };
  });
  return map;
}

// Resolve the display unit for a kitchen summary item.
// Priority:
//   1. Variant label parse (e.g. "50 Gram" → "Gram") — legacy variant-based items
//   2. menu_items stock_unit (e.g. piece, kg, litre, custom)
//   3. item.stock_unit carried in cart JSON
//   4. item.unit / item.variant fields
//   5. Empty string (show raw qty with no unit)
function _resolveKitchenUnit(parsedUnit, itemName, menuUnitMap, cartItem) {
  if (parsedUnit) return parsedUnit;
  const menuEntry = menuUnitMap[(itemName || '').trim().toLowerCase()];
  if (menuEntry) return _unitLabel(menuEntry.unit, menuEntry.label);
  if (cartItem.stock_unit) return _unitLabel(cartItem.stock_unit, cartItem.stock_unit_label);
  return (cartItem.unit || cartItem.variant || '').trim();
}

// ─── PRIVATE HELPERS ─────────────────────────────────────────────────────────

// ── Password length guard (bcrypt DoS prevention) ────────────────────────────
// bcrypt is intentionally slow. Sending a 1MB password forces ~seconds of CPU per request,
// allowing a single attacker to saturate the server. Capping at 72 chars is safe because
// bcrypt silently truncates beyond 72 bytes anyway — longer passwords add zero security.
// Safe JSON parse — never throws. Returns fallback on any parse error.
// Used wherever DB values are parsed (corrupted DB value won't crash the server).
function _safeJsonParse(str, fallback) {
  try { return JSON.parse(str); } catch (_) { return fallback; }
}

function _validatePassword(pw) {
  if (!pw || String(pw).length < 6) return 'Password must be at least 6 characters';
  if (String(pw).length > 72)       return 'Password too long (max 72 characters)';
  return null; // valid
}

// Shared user auth — used by both 'login' and 'checkSession' (were 100% identical)
async function _authenticateUser(phone, password) {
  // bcrypt.compare is also slow on very long input — guard before ANY bcrypt call
  if (!password || String(password).length > 72) return { success: false, error: 'Session invalid' };
  const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
  if (!user) return { success: false, error: 'Session invalid' };
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return { success: false, error: 'Session invalid' };
  // Parallel fetch — subscriber + balance in one round trip instead of two sequential calls
  const [{ data: sub }, { data: balRow }] = await Promise.all([
    supabase.from('subscribers').select('*').eq('phone', phone).single(),
    supabase.from('khata_summary').select('balance').eq('phone', phone).single()
  ]);
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
  if (!password || String(password).length > 72) return { success: false, error: 'Invalid credentials' };
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

// ─── SECURITY FIX v157: atomic "check balance AND deduct" wallet debit ───────
// Closes a race condition in order placement. The old flow was:
//   1. SELECT balance, compare to order total (in the createOrder handler)
//   2. _atomicWalletUpdate(-amount) — a blind increment, no balance gate
// Steps 1 and 2 were two separate round-trips. Several concurrent createOrder
// requests (different carts, so they don't collide on the idempotency key)
// could all execute step 1 against the SAME pre-deduction balance, all pass
// the check, then all execute step 2 — draining the wallet well past ₹0 and
// letting a customer get tiffins beyond what they actually paid for.
// decrement_if_sufficient() (see database.sql) does the check AND the
// deduction in ONE atomic Postgres statement (`UPDATE ... WHERE balance >=
// amount`), so only as many concurrent orders as the balance truly supports
// can ever succeed. Returns the new balance on success, or null if the
// balance was insufficient (or the phone has no wallet row) — callers MUST
// treat null as a hard failure and not create the order.
async function _atomicWalletDeductIfSufficient(phone, amount) {
  const { data: rpcResult, error: rpcErr } = await supabase.rpc('decrement_if_sufficient', {
    p_phone:  phone,
    p_amount: amount
  });
  if (rpcErr) {
    console.error('[_atomicWalletDeductIfSufficient] RPC error:', rpcErr.message);
    return null; // fail closed — never let an order through if we can't verify balance
  }
  return (rpcResult === null || rpcResult === undefined) ? null : Number(rpcResult);
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
  // Bump version so admin frontend detects new notification on next version poll
  _bumpAdminNotifVersion();
}

async function _deductMenuStock(items) {
  if (!items || items.length === 0) return;
  // Batch-fetch stock fields including stock_unit for unit-aware deduction
  const ids = items.map(i => i.item_id).filter(Boolean);
  if (!ids.length) return;
  const { data: rows } = await supabase
    .from('menu_items')
    .select('item_id, stock_grams, portion_grams, stock_unit')
    .in('item_id', ids);
  const stockMap = {};
  for (const r of (rows || [])) stockMap[r.item_id] = r;

  let anyHitZero = false;
  const updateOps = [];

  items.forEach(item => {
    const row = stockMap[item.item_id];
    if (!row || row.stock_grams == null) return; // null = unlimited, skip

    // Variant-aware deduction — mirrors kitchen aggregation logic exactly.
    //
    // Priority order for per-unit deduction amount:
    //   1. variantLabel parse  → "100 Gram" → 100, "4 Piece" → 4
    //      Same regex used by kitchen getCookingSummary so stock & kitchen always match.
    //   2. portion_grams       → admin-set fallback (e.g. for non-variant items like Roti=1)
    //   3. default 1           → safe fallback when neither is set
    //
    // item.qty is the cart quantity (how many times user ordered that variant).
    // perUnit is the stock amount consumed by ONE unit of that cart item.
    let perUnit;
    const vLabel = item.variantLabel || item.variant_label || '';
    if (vLabel) {
      const m = String(vLabel).match(/^(\d+(?:\.\d+)?)\s+[A-Za-z]/);
      if (m) {
        // Variant label carries explicit quantity (e.g. "250 Gram" → 250).
        // portion_grams is intentionally ignored here — the label is the ground truth.
        perUnit = parseFloat(m[1]);
      }
    }
    if (perUnit == null) {
      // No variant label or unparseable label — fall back to admin-set portion_grams.
      perUnit = row.portion_grams != null ? row.portion_grams : 1;
    }

    // stock_grams stores remaining stock in the item's native unit (gram/kg/piece/litre/custom).
    // perUnit is in the same native unit — no conversion needed.
    const newStock = Math.max(0, row.stock_grams - perUnit * item.qty);
    if (newStock <= 0) anyHitZero = true;
    updateOps.push({ item_id: item.item_id, newStock });
  });

  // Execute all stock updates in parallel
  await Promise.all(updateOps.map(({ item_id, newStock }) =>
    supabase.from('menu_items').update({ stock_grams: newStock }).eq('item_id', item_id)
  ));

  // If any item just sold out, invalidate menu cache + bump version so
  // version-polling customers see OOS within their next poll cycle (<=60s)
  if (anyHitZero) {
    _menuItemsCache = null; _menuItemsCacheTs = 0; _bumpMenuVersion();
  }
}

/* ─── TIFFO DELIVERY ZONES (server-side mirror of client zone table) ─────────
   Used in _extractArea as a last resort for orders that have GPS coords in the
   address string but no "Area:" tag (placed before v81 customer app update).
   Keep in sync with _TIFFO_ZONES in index.html. ─── */
const _SERVER_ZONES = [
  ['BHU Campus',       25.2580, 82.9860, 25.2750, 83.0040],
  ['Lanka',            25.2620, 82.9820, 25.2720, 82.9910],
  ['Sunderpur',        25.2750, 82.9860, 25.2860, 83.0000],
  ['Hyderabad Colony', 25.2480, 82.9900, 25.2620, 83.0050],
  ['Durgakund',        25.2900, 82.9980, 25.3020, 83.0100],
  ['Ravindrapuri',     25.2860, 83.0000, 25.2970, 83.0180],
  ['Assi Ghat',        25.2810, 83.0080, 25.2960, 83.0200],
  ['Trauma Centre',    25.2550, 82.9990, 25.2680, 83.0100],
  ['Nagwa',            25.2700, 83.0050, 25.2840, 83.0200],
  ['Shivpur',          25.2960, 82.9780, 25.3100, 82.9960],
];

function _zoneFromCoords(lat, lng) {
  for (const [name, s, w, n, e] of _SERVER_ZONES) {
    if (lat >= s && lat <= n && lng >= w && lng <= e) return name;
  }
  return '';
}

/* ─── AREA EXTRACTION ────────────────────────────────────────────────────────
   Extract the delivery area from a structured address string.
   Priority:
     1. Explicit "Area: X" tag  (written by customer app v79+ with GPS)
     2. Last comma-token of line 1 (road+area line from _buildAddress)
     3. Line 0 if it is a single short token with no digits (bare area like "Lanka")
     4. GPS coords in address → zone lookup (for pre-v81 orders without Area tag)
   Returns a title-cased area string, or '' if none found.
   Server-side: zero external calls, always reliable, works for all address formats. */
function _extractArea(address) {
  if (!address) return '';
  const lines = address.split('\n').map(l => l.trim()).filter(Boolean);

  // Priority 1: explicit "Area: Lanka" tag
  for (const line of lines) {
    const m = line.match(/^Area:\s*(.+)$/i);
    if (m) return _titleCase(m[1].trim());
  }

  const _isMeta = l => /^(coordinates:|plus code:|area:|near\b)/i.test(l)
                    || /\d{5,6}/.test(l)
                    || /india$/i.test(l);

  const _areaToken = l => {
    const parts = l.split(',').map(p => p.trim()).filter(Boolean);
    const c = parts[parts.length - 1] || '';
    return (c.length > 1 && c.length < 30 && !/\d{3,}/.test(c)
            && !/\bno\.?\s*\d+\s*$/i.test(c)) ? c : null;
  };

  // Priority 2: last comma-token of line[1] (road+area line)
  if (lines.length >= 2 && !_isMeta(lines[1])) {
    const a = _areaToken(lines[1]);
    if (a) return _titleCase(a);
  }

  // Priority 3: line[0] is a single short non-numeric token
  if (lines.length >= 1 && !_isMeta(lines[0]) && !lines[0].includes(',')) {
    const l0 = lines[0].trim();
    if (l0.length > 1 && l0.length < 25 && !/\d{3,}/.test(l0)
        && !/\bno\.?\s*\d+\s*$/i.test(l0)) return _titleCase(l0);
  }

  // Priority 4: GPS coords in address → zone lookup (pre-v81 orders)
  const coordMatch = address.match(/Coordinates\s*:\s*([+-]?\d+\.?\d*)\s*,\s*([+-]?\d+\.?\d*)/i);
  if (coordMatch) {
    const zone = _zoneFromCoords(parseFloat(coordMatch[1]), parseFloat(coordMatch[2]));
    if (zone) return zone;
  }

  return '';
}

function _titleCase(str) {
  return (str || '').replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
}

/* ── Server-side geocode safety net ─────────────────────────────────────────
   Called after signup when client Nominatim failed (needs_geocode=true).
   Builds a richer query using room + area + campus context that OSM knows.
   Patches the user's address field with discovered coordinates in v84 format.
   Fire-and-forget — never called awaited, never blocks the signup response.

   Nominatim rate limit: 1 req/s. At Tiffo's scale (handful of signups/day)
   this is never an issue. User-Agent is required by Nominatim policy.         */
async function _geocodeAndPatchAsync(phone, address, area) {
  try {
    // Parse structured fields from v84 address
    const lines = (address || '').split('\n').map(l => l.trim()).filter(Boolean);
    const room  = (lines.find(l => /^Room No:/i.test(l))  || '').replace(/^Room No:\s*/i,  '').trim();
    const areaTag = (lines.find(l => /^Area:/i.test(l))   || '').replace(/^Area:\s*/i,      '').trim();
    const resolvedArea = areaTag || area || '';

    // Already has coordinates — nothing to do (e.g. GPS resolved after initial save)
    if (/Coordinates\s*:/i.test(address)) return;

    // Build enriched query: room + area + BHU campus anchor + city
    // BHU anchor dramatically improves OSM hit rate for campus hostels
    const queryParts = [];
    if (room)          queryParts.push(room);
    if (resolvedArea)  queryParts.push(resolvedArea);
    queryParts.push('BHU', 'Varanasi', 'Uttar Pradesh', 'India');
    const query = queryParts.join(', ');

    const resp = await fetch(
      `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}&limit=1&countrycodes=in`,
      {
        headers: {
          'User-Agent': 'Tiffo-Server/1.0 (tiffo.online)',
          'Accept-Language': 'en'
        }
      }
    );
    if (!resp.ok) return;
    const results = await resp.json();
    if (!results?.length) return;

    const lat = parseFloat(results[0].lat);
    const lng = parseFloat(results[0].lon);
    if (isNaN(lat) || isNaN(lng)) return;

    // Sanity check: must be within reasonable distance of Varanasi centre
    // (25.3176, 82.9739) — reject wild geocode guesses
    const dlat = lat - 25.3176, dlng = lng - 82.9739;
    if (Math.sqrt(dlat*dlat + dlng*dlng) > 0.5) return; // >~55km off → reject

    // ── Re-check-before-write (v148) ────────────────────────────────────────
    // This function now runs fully fire-and-forget (no response delay), so by
    // the time Nominatim replies, the user/rider/admin may have ALREADY set
    // coordinates manually (e.g. they placed an order in the meantime and a
    // rider pinned their location). Re-fetch the current row right before
    // writing — if coordinates are already present, silently no-op. This
    // guarantees coordinates are written AT MOST ONCE and are NEVER
    // overwritten by this background safety net.
    const { data: currentRow } = await supabase.from('users')
      .select('address, coord_lat, coord_lng, order_allowed').eq('phone', phone).single();
    if (!currentRow) return; // user deleted in the meantime
    if (currentRow.coord_lat != null && currentRow.coord_lng != null) return; // already set — never overwrite
    const currentAddress = currentRow.address || address;
    if (/Coordinates\s*:/i.test(currentAddress)) return; // already patched by another path

    // If the address TEXT itself changed since signup (user edited it in
    // Settings, or rider/admin updated it) before Nominatim responded, the
    // coordinates we just geocoded correspond to the OLD text — do not tag
    // the new address with them. Let the user's own edit stand untouched;
    // their next save (or a future signup-like flow) will geocode correctly.
    if (currentAddress.trim() !== address.trim()) return;

    // Patch address: append Coordinates line in v84 format
    const newAddress = currentAddress.trimEnd() + `\nCoordinates: ${lat.toFixed(6)}, ${lng.toFixed(6)}`;

    // Also determine zone_status by checking delivery zone radius
    let patchZoneStatus = 'unknown'; // zone config not yet read — will be set below
    let patchOrderAllowed = false;
    try {
      const { data: zRow } = await supabase.from('admin_settings').select('value').eq('key', 'delivery_zone').single();
      if (zRow?.value) {
        const zone = JSON.parse(zRow.value);
        if (zone?.lat && zone?.lng && zone?.radiusKm) {
          const R = 6371;
          const dLat = (lat - zone.lat) * Math.PI / 180;
          const dLng = (lng - zone.lng) * Math.PI / 180;
          const a = Math.sin(dLat/2)**2 + Math.cos(zone.lat*Math.PI/180)*Math.cos(lat*Math.PI/180)*Math.sin(dLng/2)**2;
          const dist = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
          patchZoneStatus = dist <= zone.radiusKm ? 'inside' : 'outside';
          patchOrderAllowed = patchZoneStatus === 'inside';
        }
      }
    } catch(_) {}

    // Same area-based exemption as signup: a recognised delivery area (not
    // "Other") already grants order access at signup time. This async
    // safety-net patch must NOT silently revoke that — only ever upgrade
    // order_allowed, never downgrade it, for users who picked a valid area.
    const hasValidArea = !!resolvedArea && resolvedArea !== 'Other';
    if (hasValidArea && !patchOrderAllowed) patchOrderAllowed = true;
    if (patchZoneStatus === 'unknown' && hasValidArea) patchZoneStatus = 'manual_only';

    // Never downgrade order_allowed — if admin/rider already granted access
    // (e.g. manual exception for an edge-case address) before this
    // fire-and-forget patch landed, preserve that decision.
    if (currentRow.order_allowed === true) patchOrderAllowed = true;

    // Update address, coords, zone_status, and order_allowed atomically
    await supabase.from('users').update({
      address:       newAddress,
      coord_lat:     lat,
      coord_lng:     lng,
      zone_status:   patchZoneStatus,
      order_allowed: patchOrderAllowed,
    }).eq('phone', phone);
  } catch(e) {
    // Silent fail — user already has their account, coords just won't be in DB
  }
}

// ─── USER RATING UPSERT HELPER ───────────────────────────────────────────────
// Called at every order creation/rejection to keep lifetime_spend + last_order_date
// permanently up-to-date in user_ratings. These values MUST survive the 35-day
// orders auto-delete — storing them here means they are never lost.
//
// spend_delta : +amount on order create, -amount on rejectOrder rollback
// order_date  : YYYY-MM-DD string on create | null on rollback (never downgrade date)
// Non-fatal: rating upsert failure never blocks the order flow.
async function _upsertUserRating(phone, spend_delta, order_date) {
  try {
    const { data: existing } = await supabase
      .from('user_ratings')
      .select('lifetime_spend, last_order_date')
      .eq('phone', phone)
      .single();

    const newSpend = Math.max(0, ((existing?.lifetime_spend) || 0) + spend_delta);
    // Only advance last_order_date — never go backwards (reject shouldn't wipe last date)
    let newLastDate = existing?.last_order_date || null;
    if (order_date && (!newLastDate || order_date >= newLastDate)) {
      newLastDate = order_date;
    }

    await supabase.from('user_ratings').upsert(
      { phone, lifetime_spend: newSpend, last_order_date: newLastDate, updated_at: new Date().toISOString() },
      { onConflict: 'phone' }
    );

    // Non-fatal: recompute full Tiffo Score and sync to users.rating
    _recomputeAndSyncRating(phone).catch(() => {});
  } catch (_) { /* non-fatal */ }
}

// Recomputes all 5 rating parameters and writes the total to users.rating.
// Called after every order create/reject and after manual admin score changes.
async function _recomputeAndSyncRating(phone) {
  const today30ago = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const [
    { data: walRow },
    { data: subRow },
    { data: recentOrders, error: ordErr },
    { data: ratingRow }
  ] = await Promise.all([
    supabase.from('khata_summary').select('balance').eq('phone', phone).single(),
    supabase.from('subscribers').select('created_at').eq('phone', phone).single(),
    supabase.from('orders').select('order_id')
      .eq('phone', phone)
      .neq('order_status', 'cancelled')
      .neq('order_status', 'rejected')
      .gte('date', today30ago),
    supabase.from('user_ratings').select('lifetime_spend, manual_score').eq('phone', phone).single()
  ]);

  const walletBal = parseFloat(walRow?.balance) || 0;
  const recent30  = ordErr ? 0 : (recentOrders || []).length;
  const spend     = parseFloat(ratingRow?.lifetime_spend) || 0;

  const p1 = Math.round(Math.min(walletBal / 500, 1) * 20);
  const p2 = Math.round(Math.min(spend / 10000, 1) * 30);
  const p3 = Math.round(Math.min(recent30 / 30, 1) * 25);
  let p4 = 0;
  if (subRow?.created_at) {
    const subDays = Math.floor((Date.now() - new Date(subRow.created_at)) / 86400000);
    if (subDays >= 90)      p4 = 15;
    else if (subDays >= 30) p4 = 12;
    else                    p4 = 8;
  }
  const p5    = Math.max(0, Math.min(10, ratingRow?.manual_score || 0));
  const total = Math.min(p1 + p2 + p3 + p4 + p5, 100);

  await supabase.from('users').update({ rating: total }).eq('phone', phone);
  return total;
}

async function _createSingleOrder(
{ user, items, deliveryCharge, khataEnabled, ist, coupon, _rawCouponRow = null, source = 'user', slot = 'morning', paymentMode = null }) {
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
  const finalAmount = Math.max(0, subtotal + deliveryCharge - discount); // FIX #5: never negative
  const orderId  = generateOrderId(ist);
  const dateStr  = istDateStr(ist);
  const timeStr  = istTimeStr(ist);
  let newBal = null;
  let txnId  = null;

  // ── SECURITY FIX v157: atomic check-and-deduct, moved BEFORE coupon-use ──
  // Runs first (before the coupon is marked used and before stock is
  // touched) so an order that fails for insufficient balance has caused
  // ZERO side effects — no coupon burned, no stock deducted, nothing to
  // roll back. decrement_if_sufficient() checks balance >= finalAmount AND
  // deducts in one atomic Postgres statement, closing the race condition
  // where concurrent requests could previously all pass a separate,
  // stale balance check before any of them had actually deducted.
  if (khataEnabled && user.is_subscriber && paymentMode !== 'upi_insuf') {
    newBal = await _atomicWalletDeductIfSufficient(user.phone, finalAmount);
    if (newBal === null) {
      const insufErr = new Error('Insufficient wallet balance');
      insufErr.code = 'INSUFFICIENT_BALANCE';
      throw insufErr;
    }
    // newBal is always >= 0 now (decrement_if_sufficient guarantees this),
    // so this is always a normal debit, never an 'udhar' (credit/negative) entry.
    txnId = await _createTxnEntry(user.phone, orderId, -finalAmount, newBal, 'tiffin_given', source, ist);
  }

  // Mark coupon used — atomic RPC prevents double-use in simultaneous orders (v122 fix)
  if (coupon && coupon.code) {
    try {
      const cpnRow = _rawCouponRow ||
        (await supabase.from('coupons').select('auto_delete,max_usage,total_usage_limit,used_count').eq('code', coupon.code).single()).data;
      const maxUsage = cpnRow ? (cpnRow.max_usage ?? cpnRow.total_usage_limit ?? null) : null;
      const { data: rpcResult } = await supabase.rpc('use_coupon_atomic', {
        p_code:      coupon.code,
        p_phone:     user.phone || '',
        p_max_usage: maxUsage
      });
      // Auto-delete: mark inactive instead of deleting — preserves referral_key for idempotency
      // (deleting row would allow admin to re-issue a second coupon for same referral pair)
      if (rpcResult === 'ok' && cpnRow?.auto_delete === true && maxUsage !== null) {
        if ((cpnRow.used_count || 0) + 1 >= maxUsage) {
          await supabase.from('coupons').update({ is_active: false }).eq('code', coupon.code);
        }
      }
    } catch(_) {}
  }

  // ── Free Tiffin Redemption Hook (v171) ───────────────────────────────────
  // Fire-and-forget: if a free_tiffin coupon was used, mark user as redeemed.
  // Never blocks or delays the order response — errors are swallowed silently.
  // Runs AFTER use_coupon_atomic so we know the burn succeeded.
  // v171: uses coupon.coupon_type === 'free_tiffin' instead of TIFFO prefix —
  //   admin can name FT codes anything now.
  // .neq('redeemed') ensures both null→redeemed and wa_sent→redeemed advance
  //   correctly; admin manual overrides are not overwritten.
  if (coupon?.coupon_type === 'free_tiffin' && user.phone) {
    (async () => {
      try {
        await supabase.from('users').update({
          free_tiffin_status:   'redeemed',
          free_tiffin_given_at: new Date().toISOString(),
          free_tiffin_coupon:   coupon.code
        }).eq('phone', user.phone).neq('free_tiffin_status', 'redeemed');
      } catch (_) {}
    })();
  }
  // ── End Free Tiffin Hook ──────────────────────────────────────────────────

  // Stock deduction: ONLY for normal user orders.
  // Admin-placed orders (source='admin') and bulk-generated orders (source='admin_bulk')
  // must NOT affect stock — admin can always order even when OOS.
  if (source === 'user') await _deductMenuStock(items);

  const { error: ordErr } = await supabase.from('orders').insert({
    order_id:        orderId,
    user_id:         user.phone,
    name:            user.name,
    phone:           user.phone,
    address:         user.address,
    area:            _extractArea(user.address),
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
  if (ordErr) {
    // ── ROLLBACK: reverse wallet deduction and txn entry if order insert failed ──
    // Sequence was: wallet deducted → txn recorded → stock deducted → order INSERT (failed here)
    // Without rollback, subscriber's wallet is debited but no order exists — money lost silently.
    if (newBal !== null) {
      // Reverse the wallet deduction atomically
      try {
        await _atomicWalletUpdate(user.phone, +finalAmount);
      } catch (rollbackErr) {
        // Rollback failed — log so admin can manually fix via khata adjustment
        console.error(`[_createSingleOrder] CRITICAL: wallet rollback failed for ${user.phone}, amount=${finalAmount}. Manual adjustment needed.`, rollbackErr.message);
      }
      // Remove the txn entry that was just inserted (delete by txnId)
      if (txnId) {
        try {
          await supabase.from('khata_entries').delete().eq('id', txnId);
        } catch (_) { /* non-fatal — orphaned txn visible in khata but won't affect balance */ }
      }
    }
    // Restore stock that was already deducted (source='user' only — admin orders never deduct)
    if (source === 'user') {
      try {
        const ids = items.map(i => i.item_id).filter(Boolean);
        if (ids.length) {
          const { data: stockRows } = await supabase.from('menu_items').select('item_id, stock_grams, portion_grams').in('item_id', ids);
          const stockMap = {};
          for (const r of (stockRows || [])) stockMap[r.item_id] = r;
          const restoreOps = [];
          items.forEach(item => {
            const row = stockMap[item.item_id];
            if (!row || row.stock_grams == null) return;
            let perUnit;
            const vLabel = item.variantLabel || item.variant_label || '';
            if (vLabel) { const m = String(vLabel).match(/^(\d+(?:\.\d+)?)\s+[A-Za-z]/); if (m) perUnit = parseFloat(m[1]); }
            if (perUnit == null) perUnit = row.portion_grams != null ? row.portion_grams : 1;
            restoreOps.push({ item_id: item.item_id, newStock: row.stock_grams + perUnit * (item.qty || 1) });
          });
          await Promise.all(restoreOps.map(({ item_id, newStock }) =>
            supabase.from('menu_items').update({ stock_grams: newStock }).eq('item_id', item_id)
          ));
        }
      } catch (_) { /* non-fatal stock restore on insert failure */ }
    }
    throw new Error('Order save failed: ' + ordErr.message);
  }

  // ── Update permanent rating stats (non-fatal, fire-and-forget) ──
  // lifetime_spend and last_order_date are stored permanently in user_ratings
  // so they survive the 35-day orders auto-delete.
  _upsertUserRating(user.phone, finalAmount, dateStr).catch(() => {});

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
app.get('/',     (_req, res) => res.json({ app: 'Tiffo API', status: 'running', version: 'v172' }));
app.get('/ping', (_req, res) => res.json({ status: 'alive', time: new Date().toISOString() }));

// ─── CONFIG INJECTION ─────────────────────────────────────────────────────────
// Serves the API key to all frontends without ever hardcoding it in HTML.
// Each HTML file loads: <script src="https://purobitese-api.onrender.com/config.js"></script>
// This sets window.__TIFFO_API_KEY__ which CFG.KEY falls back to.
app.get('/config.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  // Cache for 1 hour — key never rotates in normal operation.
  // If key is rotated intentionally, the existing 401 → _refreshApiKey()
  // auto-recovery in all three panels will fetch fresh immediately.
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(`window.__TIFFO_API_KEY__ = ${JSON.stringify(process.env.API_KEY || '')};`);
});

// ─── IDEMPOTENCY GUARD (in-memory, protects createOrder double-submits) ───────
// Stores SHA-256-like fingerprint of mutation actions for 30s to reject duplicates.
// Cleared automatically — Map never grows unboundedly on free-tier Render.
const _recentMutations = new Map();
const _MUTATION_TTL = 30_000; // 30 seconds
const _MUTATION_ACTIONS = new Set(['createOrder', 'bulkGenerateOrders', 'rechargeWallet', 'manualRefund', 'rejectOrder']);

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
  // Admin-only, rider, and staff actions require a valid signed session token
  // issued at login. The API key alone is NOT enough for these actions.
  //
  // IMPORTANT: these three checks are independent (not else-if branches).
  // Some actions (e.g. updateOrderStatus) are legitimately callable by BOTH
  // a rider (their own assigned orders, enforced inside the handler) AND
  // real staff/admin (any order, e.g. manual override from the admin panel).
  // An earlier mutually-exclusive if/else-if chain caused updateOrderStatus
  // — which is in both _RIDER_ACTIONS and _STAFF_ACTIONS — to silently fall
  // into the rider-only branch for everyone, incorrectly 403-ing real
  // staff-role admin-panel users. Each set is now checked on its own, and a
  // request only needs to pass the check(s) for the set(s) its action is in.
  const { sessionToken } = req.body;

  if (_ADMIN_ONLY_ACTIONS.has(action)) {
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    if (session.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required.' });
    }
  }

  if (_RIDER_ACTIONS.has(action) && _STAFF_ACTIONS.has(action)) {
    // Action is shared by riders AND staff/admin — accept any of the three roles.
    // Per-order/per-rider ownership (if any) is enforced inside the handler itself.
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    if (session.role !== 'admin' && session.role !== 'rider' && session.role !== 'staff') {
      return res.status(403).json({ success: false, error: 'Staff or rider access required.' });
    }
  } else if (_RIDER_ACTIONS.has(action)) {
    // Rider-only action (not shared with staff). Riders get their own narrow
    // allowlist (see _RIDER_ACTIONS above) — a rider token must never reach
    // the broader staff permission set for actions outside this list.
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    if (session.role !== 'admin' && session.role !== 'rider') {
      return res.status(403).json({ success: false, error: 'Rider access required.' });
    }
  } else if (_STAFF_ACTIONS.has(action)) {
    const session = _verifyToken(sessionToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
    }
    // role==='rider' is intentionally excluded here — riders only reach this
    // branch for actions NOT in _RIDER_ACTIONS, which they must never call.
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
        const loginPhone = cleanPhone(data.phone);
        // Phone-based brute force check — IP-independent (BHU 100k students share one IP)
        const lockErr = _checkLoginAttempt(loginPhone);
        if (lockErr) return res.json({ success: false, error: lockErr });
        const result = await _authenticateUser(loginPhone, data.password);
        if (result.success) {
          _resetLoginAttempts(loginPhone); // successful login — clear counter
        } else if (action === 'login') {
          // Only count brute-force failures for explicit login attempts.
          // checkSession is called silently on every app-open (bootApp, 48h background verify).
          // If stale creds are stored (e.g. admin reset user's password), every app-open
          // would increment the counter — 5 opens = 15-min lockout of their own account.
          _recordLoginFailure(loginPhone);
        }
        return res.json(result);
      }

      case 'signup': {
        const phone = cleanPhone(data.phone);
        // Server-side validation
        if (!data.name || String(data.name).trim().length < 2)
          return res.json({ success: false, error: 'Name is required' });
        if (String(data.name).trim().length > 100)
          return res.json({ success: false, error: 'Name too long (max 100 characters)' });
        if (!data.password || String(data.password).length < 6)
          return res.json({ success: false, error: 'Password must be at least 6 characters' });
        if (String(data.password).length > 72)
          return res.json({ success: false, error: 'Password too long (max 72 characters)' });
        if (!phone || phone.length !== 10 || !/^[6-9]/.test(phone))
          return res.json({ success: false, error: 'Invalid phone number' });
        if (data.email && String(data.email).length > 254)
          return res.json({ success: false, error: 'Email too long' });
        if (data.address && String(data.address).length > 1000)
          return res.json({ success: false, error: 'Address too long (max 1000 characters)' });
        const { data: existing } = await supabase.from('users').select('phone').eq('phone', phone).single();
        if (existing) return res.json({ success: false, error: 'Phone already registered' });
        const hash = await bcrypt.hash(data.password, SALT_ROUNDS);
        const createdAt = new Date().toISOString();

        // Parse coords and zone info sent by client
        const signupLat = parseFloat(data.coord_lat) || null;
        const signupLng = parseFloat(data.coord_lng) || null;
        const signupZoneStatus  = data.zone_status || 'unknown';
        const signupArea        = (data.area || '').trim();
        // manual_only (no GPS coords, address typed manually) is allowed to order
        // immediately IF the user picked a recognised delivery area — only the
        // generic "Other" selection (or no area at all) needs admin permission.
        const signupOrderAllowed =
          signupZoneStatus === 'inside' ||
          (signupZoneStatus === 'manual_only' && signupArea && signupArea !== 'Other');

        const { error: insertErr } = await supabase.from('users').insert({
          user_id:       phone,
          name:          data.name,
          phone,
          email:         data.email || null,
          address:       data.address || null,
          area:          data.area || _extractArea(data.address || ''),
          password_hash: hash,
          created_at:    createdAt,
          coord_lat:     signupLat,
          coord_lng:     signupLng,
          zone_status:   signupZoneStatus,
          order_allowed: signupOrderAllowed,
        });
        if (insertErr) return res.json({ success: false, error: 'Registration failed. Please try again.' });
        // ── Server-side geocode safety net ─────────────────────────────────────
        // Fires when client Nominatim failed (e.g. BHU hostel names not in OSM).
        // Uses a richer query with city/campus context.
        // v148: TRUE fire-and-forget — does NOT delay the signup response at all.
        // "Create Account" must feel instant regardless of Nominatim speed/outage.
        // _geocodeAndPatchAsync re-checks the user's row at write-time (not the
        // stale `address` captured here) — if coordinates were already set by
        // then (geocode succeeded fast, or rider/admin/user set them manually
        // in the meantime), it silently no-ops. Coordinates are written AT MOST
        // ONCE per user and are never overwritten afterwards.
        if (data.needs_geocode && data.address) {
          _geocodeAndPatchAsync(phone, data.address, data.area || '').catch(() => {});
        }

        // ── ft_loc_suspect: flag if another user exists within 30 m ──────────
        // Fire-and-forget — never delays signup response.
        // Uses the get_nearby_ft_users() SQL function (Haversine, PART 4 of v169 migration).
        // If any neighbour found → mark THIS new user suspect + mark all neighbours suspect too.
        // Neighbours are only marked if they don't already have ft_loc_suspect = TRUE
        // (avoids unnecessary DB writes on existing flagged users).
        if (signupLat && signupLng) {
          (async () => {
            try {
              const { data: nearby } = await supabase.rpc('get_nearby_ft_users', {
                p_lat:           signupLat,
                p_lng:           signupLng,
                p_radius_m:      30,
                p_exclude_phone: phone
              });
              if (nearby && nearby.length > 0) {
                // v171: mark new user + unflagged neighbours in parallel
                const unflaggedNeighbours = nearby.filter(n => !n.ft_loc_suspect).map(n => n.phone);
                await Promise.all([
                  supabase.from('users').update({ ft_loc_suspect: true }).eq('phone', phone),
                  unflaggedNeighbours.length
                    ? supabase.from('users').update({ ft_loc_suspect: true }).in('phone', unflaggedNeighbours)
                    : Promise.resolve()
                ]);
              }
            } catch (_) { /* non-fatal — never blocks signup */ }
          })();
        }

        // ── Fire new-user notification so admin can send welcome coupon ──
        try {
          // Build a compact 1-line address summary for notification body (v84 multiline → readable)
          const _addrSummary = (() => {
            const a = data.address || '';
            if (!a) return '';
            const lines = a.split('\n').map(l => l.trim()).filter(Boolean);
            const room = (lines.find(l => /^Room No:/i.test(l)) || '').replace(/^Room No:\s*/i,'').trim();
            const pc   = (lines.find(l => /^Plus Code:/i.test(l)) || '').replace(/^Plus Code:\s*/i,'').trim();
            const area = (lines.find(l => /^Area:/i.test(l)) || '').replace(/^Area:\s*/i,'').trim();
            const parts = [room, pc, area].filter(Boolean);
            return parts.length ? parts.join(' · ') : a.split('\n')[0];
          })();
          await _createNotification({
            type:     'user',
            priority: 'normal',
            group_id: phone,
            title:    `New user joined: ${data.name}`,
            body:     `${data.name} (${phone}) just registered${_addrSummary ? ' — ' + _addrSummary : ''}`,
            meta:     { phone, name: data.name, address: data.address || '', email: data.email || '' }
          });
        } catch(_) {}
        // ── Initialise wallet row so balance reads 0 immediately (not null) ──
        try {
          await supabase.from('khata_summary')
            .upsert({ phone, balance: 0, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
        } catch(_) {}

        // ── Referral tracking: save referred_by + create notification for admin ──
        const referredBy = typeof data.referred_by === 'string'
          ? data.referred_by.replace(/\D/g, '').slice(-10)
          : null;
        if (referredBy && referredBy !== phone && referredBy.length === 10) {
          try {
            // Verify referrer actually exists
            const { data: referrer } = await supabase
              .from('users').select('phone').eq('phone', referredBy).single();
            if (referrer) {
              // Save referred_by on new user's row
              await supabase.from('users')
                .update({ referred_by: referredBy })
                .eq('phone', phone);
              // Create referral notification for admin to review and send coupons
              await _createNotification({
                type:     'referral',
                priority: 'high',
                group_id: referredBy + '_' + phone,
                title:    'New Referral! ' + data.name + ' joined',
                body:     data.name + ' (' + phone + ') joined via referral from ' + referredBy,
                meta:     {
                  referrer_phone: referredBy,
                  new_phone:      phone,
                  new_name:       data.name,
                  new_address:    data.address || ''
                }
              });
            }
          } catch (_) { /* non-fatal — referral failure never blocks signup */ }
        }

        const USER_TOKEN_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days — matches login
        const signupToken = _signToken({ role: 'user', phone, exp: Date.now() + USER_TOKEN_TTL });
        return res.json({
          success: true,
          user: { user_id: phone, name: data.name, phone, email: data.email || null, address: data.address || null, area: data.area || null, zone_status: signupZoneStatus, created_at: createdAt },
          subscriber:    null,
          walletBalance: 0,
          userToken:     signupToken,
          zone_status:   signupZoneStatus,
          order_allowed: signupOrderAllowed,
        });
      }

      case 'adminLogin': {
        const adminKey = 'admin:' + (data.username || '');
        const adminLockErr = _checkLoginAttempt(adminKey);
        if (adminLockErr) return res.json({ success: false, error: adminLockErr });
        const result = await _authenticateStaff(data.username, data.password);
        if (result.success) {
          _resetLoginAttempts(adminKey);
          const sessionToken = _signToken({
            role:     result.staff.role,
            username: result.staff.username,
            exp:      Date.now() + SESSION_TTL_MS,
          });
          return res.json({ success: true, staff: result.staff, sessionToken });
        } else {
          _recordLoginFailure(adminKey);
          return res.json(result);
        }
      }

      case 'updateProfile': {
        const phone = cleanPhone(data.phone);
        // FIX #8: Require password verification — prevent unauthenticated profile updates
        if (!data.password) return res.json({ success: false, error: 'Password required to update profile' });
        if (String(data.password).length > 72) return res.json({ success: false, error: 'Password too long (max 72 characters)' });
        const { data: userRow } = await supabase.from('users').select('password_hash').eq('phone', phone).single();
        if (!userRow) return res.json({ success: false, error: 'User not found' });
        const validPw = await bcrypt.compare(data.password, userRow.password_hash);
        if (!validPw) return res.json({ success: false, error: 'Incorrect password' });
        const updates = {};
        if (data.name !== undefined) {
          if (String(data.name).trim().length > 100) return res.json({ success: false, error: 'Name too long (max 100 characters)' });
          updates.name = data.name;
        }
        if (data.email !== undefined) {
          if (data.email && String(data.email).length > 254) return res.json({ success: false, error: 'Email too long' });
          updates.email = data.email;
        }
        if (data.address !== undefined) {
          if (data.address && String(data.address).length > 1000) return res.json({ success: false, error: 'Address too long (max 1000 characters)' });
          updates.address = data.address;
          updates.area    = data.area || _extractArea(data.address || '');
          // If new address contains GPS coordinates, update coord_lat/coord_lng + re-check zone
          const coordMatch = (data.address || '').match(/Coordinates:\s*([+-]?\d+\.?\d*)\s*,\s*([+-]?\d+\.?\d*)/i);
          if (coordMatch) {
            const upLat = parseFloat(coordMatch[1]);
            const upLng = parseFloat(coordMatch[2]);
            if (!isNaN(upLat) && !isNaN(upLng)) {
              updates.coord_lat = upLat;
              updates.coord_lng = upLng;
              // Zone check
              let upZoneStatus = 'unknown';
              let upOrderAllowed = false;
              try {
                const { data: zRow2 } = await supabase.from('admin_settings').select('value').eq('key', 'delivery_zone').single();
                if (zRow2?.value) {
                  const zone2 = JSON.parse(zRow2.value);
                  if (zone2?.lat && zone2?.lng && zone2?.radiusKm) {
                    const R = 6371;
                    const dLat2 = (upLat - zone2.lat) * Math.PI / 180;
                    const dLng2 = (upLng - zone2.lng) * Math.PI / 180;
                    const a2 = Math.sin(dLat2/2)**2 + Math.cos(zone2.lat*Math.PI/180)*Math.cos(upLat*Math.PI/180)*Math.sin(dLng2/2)**2;
                    const dist2 = R * 2 * Math.atan2(Math.sqrt(a2), Math.sqrt(1-a2));
                    upZoneStatus = dist2 <= zone2.radiusKm ? 'inside' : 'outside';
                    upOrderAllowed = upZoneStatus === 'inside';
                  }
                }
              } catch(_) {}
              updates.zone_status   = upZoneStatus;
              updates.order_allowed = upOrderAllowed;
            }
          }
        }
        if (data.room_no !== undefined) {} // v84: room_no stored inside address field, not separate column
        await supabase.from('users').update(updates).eq('phone', phone);
        // Return zone_status + order_allowed so client can sync session
        return res.json({ success: true, zone_status: updates.zone_status, order_allowed: updates.order_allowed });
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
        // bcrypt DoS prevention — cap both passwords before any bcrypt call
        if (String(data.oldPassword || '').length > 72)
          return res.json({ success: false, error: 'Password too long (max 72 characters)' });
        const pwErr2 = _validatePassword(data.newPassword);
        if (pwErr2) return res.json({ success: false, error: pwErr2 });
        const { data: staff } = await supabase.from('staff').select('*').eq('username', data.username).single();
        if (!staff) return res.json({ success: false, error: 'User not found' });
        const valid = await bcrypt.compare(data.oldPassword, staff.password_hash);
        if (!valid) return res.json({ success: false, error: 'Wrong current password' });
        const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
        await supabase.from('staff').update({ password_hash: hash }).eq('username', data.username);
        return res.json({ success: true });
      }
      // ── MENU VERSION CHECK (lightweight — no DB hit) ──────────────────────
      // Returns the current content version as a monotonic integer.
      // Clients call this every 60 s; only fetch getHomeData when version differs.
      // Response is ~80 bytes — virtually no cost on Render free tier.
      case 'getMenuVersion': {
        return res.json({ success: true, version: _menuContentVersion });
      }

      // ── ADMIN NOTIFICATION VERSION CHECK (lightweight — no DB hit) ────────
      // Monotonic counter bumped every time _createNotification() is called.
      // Admin frontend polls this every 60 s; only fetches getNotifications when
      // version changes — eliminates constant full-payload DB queries.
      case 'getAdminNotifVersion': {
        return res.json({ success: true, version: _adminNotifVersion });
      }

      case 'getHomeData': {
        // Serve menu from in-memory cache when fresh (60s TTL).
        // Settings use their own getCachedSetting cache (5min TTL).
        // Cache is wiped instantly by addMenuItem / updateMenuItem / deleteMenuItem.
        const _now = Date.now();
        let menuItems;
        if (_menuItemsCache && (_now - _menuItemsCacheTs) < _MENU_ITEMS_TTL) {
          menuItems = _menuItemsCache; // ~0ms — no Supabase round-trip
        } else {
          const menuRes = await supabase.from('menu_items').select('*').eq('is_active', true).order('sort_order', { ascending: true });
          menuItems = (menuRes.data || []).map(formatMenuItem);
          _menuItemsCache   = menuItems;
          _menuItemsCacheTs = _now;
        }

        // Determine if we need to fetch order_allowed for this user
        const cleanedPhone = data.phone ? cleanPhone(data.phone) : null;
        const needsUserCheck = !!(cleanedPhone && _verifyUserToken(req.body.userToken, cleanedPhone));

        // Settings + optional order_allowed all in one round-trip (was sequential after settings)
        const [scheduleVal, cutoffVal, khataVal, uRow] = await Promise.all([
          getCachedSetting('weekly_schedule'),
          getCachedSetting('order_cutoff_config'),
          getCachedSetting('khata_enabled'),
          needsUserCheck
            ? supabase.from('users').select('order_allowed').eq('phone', cleanedPhone).single()
            : Promise.resolve({ data: null })
        ]);
        let schedule = null, config = null;
        if (scheduleVal)  { try { schedule = JSON.parse(scheduleVal); } catch { schedule = null; } }
        if (cutoffVal)    { try { config   = JSON.parse(cutoffVal);   } catch { config   = null; } }
        const enabled = JSON.parse(khataVal || 'false') === true;
        // order_allowed: default true for guests; use DB value for verified logged-in users
        let orderAllowed = true;
        if (needsUserCheck && uRow?.data) orderAllowed = uRow.data.order_allowed !== false;
        return res.json({ success: true, items: menuItems, schedule, config, enabled, version: _menuContentVersion, order_allowed: orderAllowed });
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
        // Compute pendingTomorrow so frontend can show "Morning Off (Tomorrow)" on toggle
        const tomorrowStrSt = istDateStr(new Date(ist.getTime() + 86_400_000));
        const pmTmrw = subRow?.pause_morning && subRow?.pause_morning_from === tomorrowStrSt;
        const peTmrw = subRow?.pause_evening && subRow?.pause_evening_from === tomorrowStrSt;
        const pendingTomorrowSt = (pmTmrw && peTmrw) ? 'both' : pmTmrw ? 'lunch' : peTmrw ? 'dinner' : null;
        return res.json({ success: true, isSubscriber: !!subRow, balance: balRes.data?.balance || 0, pauseMode: effectivePauseMode, pendingTomorrow: pendingTomorrowSt, plan: subRow?.plan || 'morning' });
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
          stock_grams:      data.stock_grams ?? null,
          portion_grams:    data.portion_grams ?? null,
          stock_unit:       data.stock_unit || 'gram',
          stock_unit_label: data.stock_unit_label || null,
          is_available:     data.is_available !== undefined ? data.is_available : true,
          veg_type:         data.veg_type || 'veg',
          sub_items:        data.sub_items || null,
          sub_category:     data.sub_category || null,
          meal_session:     data.meal_session || 'both',
          created_at:       new Date().toISOString()
        });
        if (miErr) throw new Error(miErr.message || 'Failed to add menu item');
        _menuItemsCache = null; _menuItemsCacheTs = 0; _bumpMenuVersion(); // invalidate + version bump
        return res.json({ success: true });
      }

      case 'updateMenuItem': {
        const mid = data.item_id || data.id; // normalize: frontend may send data.id
        const updates = { ...data };
        delete updates.item_id;
        delete updates.id;
        if (Array.isArray(updates.variants)) updates.variants = JSON.stringify(updates.variants);
        await supabase.from('menu_items').update(updates).eq('item_id', mid);
        _menuItemsCache = null; _menuItemsCacheTs = 0; _bumpMenuVersion(); // invalidate + version bump
        return res.json({ success: true });
      }

      case 'deleteMenuItem': {
        const mid = data.item_id || data.id;
        await supabase.from('menu_items').delete().eq('item_id', mid);
        _menuItemsCache = null; _menuItemsCacheTs = 0; _bumpMenuVersion(); // invalidate + version bump
        return res.json({ success: true });
      }

      case 'createOrder': {
        const phone = cleanPhone(data.phone);
        // Auth: must be the user's own token (staff bypass allowed for admin-placed orders)
        const _staffSess = _verifyToken(req.body.sessionToken);
        const _isStaff   = _staffSess && (_staffSess.role === 'admin' || _staffSess.role === 'staff');
        if (!_isStaff && !_verifyUserToken(req.body.userToken, phone)) {
          return res.status(401).json({ success: false, error: 'Auth required. Please log in again.' });
        }
        // FT fields fetched here so the FT gate below reuses this row — no second DB round-trip.
        const { data: user } = await supabase.from('users').select('phone, name, address, order_allowed, free_tiffin_status, free_tiffin_blocked, free_tiffin_given_at').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        const address = data.address || user.address;
        if (!address) return res.json({ success: false, error: 'Delivery address required' });
        // Outside-zone enforcement — order_allowed=false means admin has not enabled delivery
        if (!_isStaff && user.order_allowed === false) {
          return res.json({ success: false, error: 'OUTSIDE_ZONE', message: 'Ordering is not available for your location yet. Please contact us via WhatsApp to request delivery.' });
        }
        if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
          return res.json({ success: false, error: 'Order items required' });
        }

        // ── OPT: Parallel fetch — subscribers + menu price verify + coupon + slot setting ──
        // All four are independent of each other; only user.phone is needed (already known).
        // Menu items: use in-memory cache if warm (60s TTL, invalidated on any menu change)
        //   → zero Supabase round-trip on cache hit. Falls back to DB if cache is cold.
        const clientItemIds = data.items.map(i => i.item_id).filter(Boolean);
        const cpnCode = data.coupon?.code ? (data.coupon.code || '').toUpperCase() : null;
        const _cacheNow = Date.now();
        const _menuCacheHit = _menuItemsCache && (_cacheNow - _menuItemsCacheTs) < _MENU_ITEMS_TTL;

        const [
          khataEnabledRaw,
          subResult,
          menuResult,
          couponResult,
          schVal
        ] = await Promise.all([
          getCachedSetting('khata_enabled'),
          supabase.from('subscribers').select('phone').eq('phone', phone).single(),
          // Use in-memory menu cache if warm; otherwise hit DB
          _menuCacheHit
            ? Promise.resolve({ data: _menuItemsCache.filter(m => clientItemIds.includes(m.item_id)) })
            : (clientItemIds.length > 0
                ? supabase.from('menu_items').select('item_id, price, name, variants').in('item_id', clientItemIds)
                : Promise.resolve({ data: [] })),
          cpnCode
            ? supabase.from('coupons').select('*').eq('code', cpnCode).single()
            : Promise.resolve({ data: null }),
          getCachedSetting('weekly_schedule')
        ]);

        const khataEnabled = _safeJsonParse(khataEnabledRaw || 'false', false);
        const { data: subRow } = subResult;
        user.is_subscriber = !!subRow;
        user.address = address;

        // ── Price verification: use parallel-fetched menu items ──
        // Strategy:
        //   1. Item has variants in DB + client sent a matching variantLabel → use that variant price
        //   2. Item has variants in DB + label missing/not matched → use closest variant by price,
        //      or first variant as safe default (never fall back to base item price)
        //   3. Item has NO variants in DB → use base item price
        let verifiedItems = data.items;
        const dbMenuItems = menuResult.data || [];
        const dbItemMap = {};
        for (const m of dbMenuItems) dbItemMap[m.item_id] = m;
        // FIX: reject items not in DB — prevents phantom items with attacker-set prices.
        // IMPORTANT: this check runs UNCONDITIONALLY for every order (it used to be
        // nested inside `if (dbMenuItems.length > 0)`. If an attacker sent ONLY
        // fake/unknown item_ids, the Supabase `.in()` query matched nothing and
        // returned an EMPTY array — dbMenuItems.length was 0, so the whole
        // verification block was skipped and the raw client-supplied prices were
        // used as-is. That was the exact price-injection bug this fix was meant to
        // close, just reachable via "all items fake" instead of "some items fake".
        const unknownItems = data.items.filter(i => !dbItemMap[i.item_id]);
        if (unknownItems.length > 0) {
          return res.json({ success: false, error: 'One or more items are no longer available. Please refresh and try again.' });
        }
        verifiedItems = data.items.map(i => {
          const dbItem = dbItemMap[i.item_id];
          if (!dbItem) return i; // unreachable after above guard, kept for safety
          // SECURITY: always use the server's name for this item, never the client's.
          // Previously only `price` was overridden here — `name` passed through
          // from the client untouched, so a forged cart item (valid item_id, but
          // a malicious `name` string) would flow into the order record and later
          // render unescaped in admin/rider order views. Item name must never be
          // attacker-controlled.
          const safeName = dbItem.name;

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
              if (exact) return { ...i, name: safeName, price: exact.price };
              // Step 2: case-insensitive match (handles minor label casing differences)
              const loose = dbVariants.find(v => v.label.toLowerCase() === i.variantLabel.toLowerCase());
              if (loose) return { ...i, name: safeName, price: loose.price, variantLabel: loose.label };
            }
            // Step 3: client sent a price — find the closest variant price in DB
            // This prevents price manipulation while gracefully handling label mismatches
            if (i.price != null) {
              const byPrice = dbVariants.find(v => v.price === i.price);
              if (byPrice) return { ...i, name: safeName, price: byPrice.price, variantLabel: byPrice.label };
            }
            // Step 4: safe fallback — use first (cheapest or default) variant
            return { ...i, name: safeName, price: dbVariants[0].price, variantLabel: dbVariants[0].label };
          }

          // Item has no variants — use DB base price
          return { ...i, name: safeName, price: dbItem.price != null ? dbItem.price : i.price };
        });

        // ── FIX #4: Coupon already fetched in parallel above — verify from that result ──
        let verifiedCoupon = null;
        let _rawCouponRow  = null; // passed to _createSingleOrder to skip a second DB fetch
        if (cpnCode) {
          const dbCoupon = couponResult.data;
          const today = istDateStr(ist);
          if (dbCoupon && dbCoupon.is_active && !(dbCoupon.expiry_date && dbCoupon.expiry_date < today)) {
            // Flash window check at order time
            let flashOk = true;
            if (dbCoupon.restriction_type === 'flash_window') {
              const nowTime2 = String(ist.getUTCHours()).padStart(2,'0') + ':' + String(ist.getUTCMinutes()).padStart(2,'0');
              if (!dbCoupon.flash_date || dbCoupon.flash_date !== today) flashOk = false;
              else if (dbCoupon.flash_start && nowTime2 < dbCoupon.flash_start.slice(0,5)) flashOk = false;
              else if (dbCoupon.flash_end   && nowTime2 >= dbCoupon.flash_end.slice(0,5))  flashOk = false;
            }
            const maxUse = dbCoupon.max_usage ?? dbCoupon.total_usage_limit ?? null;
            // ── FIX #10: Mirror all restriction checks from validateCoupon ─────────────
            // validateCoupon checks these but createOrder previously skipped them,
            // meaning a user could bypass validateCoupon and POST createOrder directly
            // with a locked coupon code (e.g. a referral/welcome coupon for another phone).
            let restrictionOk = true;
            if (flashOk && (maxUse == null || (dbCoupon.used_count || 0) < maxUse)) {
              const rtype = dbCoupon.restriction_type || 'unlimited';
              let usedBy = []; try { usedBy = JSON.parse(dbCoupon.used_by || '[]'); } catch(_) {}
              if (rtype === 'specific_phone') {
                let allowed = []; try { allowed = JSON.parse(dbCoupon.allowed_phones || '[]'); } catch(_) {}
                if (!allowed.includes(phone)) restrictionOk = false;
              } else if (rtype === 'one_time_per_user') {
                if (usedBy.filter(p => p === phone).length >= 1) restrictionOk = false;
              } else if (rtype === 'per_user_limit') {
                const perLimit = dbCoupon.per_user_limit ?? dbCoupon.max_per_user ?? 1;
                if (usedBy.filter(p => p === phone).length >= perLimit) restrictionOk = false;
              }
              // new_users_only: validateCoupon enforces this; skip DB lookup here for perf
              // (the worst outcome of skipping is a slightly-too-old new user gets a discount;
              // the atomic RPC still caps total usage, so financial risk is bounded)
            } else {
              restrictionOk = false; // flashOk failed or maxUse exceeded
            }

            // ── Free Tiffin gate inside createOrder (v171) ───────────────────────────
            // validateCoupon enforces this too, but a client could bypass validateCoupon
            // and POST createOrder directly. Gate enforced server-side regardless.
            // v171: uses coupon_type='free_tiffin' (DB column) instead of TIFFO prefix.
            // v171: reuses the user row already fetched above — zero extra DB round-trip.
            if (restrictionOk && dbCoupon.coupon_type === 'free_tiffin' && phone) {
              if (user.free_tiffin_blocked === true) {
                return res.json({ success: false, error: 'Free tiffin access has been disabled for this account' });
              }
              if (user.free_tiffin_status === 'redeemed') {
                let redeemedOn = '';
                if (user.free_tiffin_given_at) {
                  const _d = new Date(user.free_tiffin_given_at);
                  const _dd = String(_d.getDate()).padStart(2,'0');
                  const _mm = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][_d.getMonth()];
                  redeemedOn = ` on ${_dd} ${_mm}`;
                }
                return res.json({ success: false, error: `You already received your free first tiffin${redeemedOn}. We hope you enjoyed it!` });
              }
            }
            // ── End Free Tiffin gate ─────────────────────────────────────────────────

            if (restrictionOk) {
              const capAmt = dbCoupon.cap_amount ?? dbCoupon.max_cap ?? null;
              verifiedCoupon = {
                code:           dbCoupon.code,
                discount_type:  dbCoupon.discount_type,
                discount_value: dbCoupon.discount_value,
                cap_amount:     capAmt,
                coupon_type:    dbCoupon.coupon_type || 'regular'  // v171: needed by FT redemption hook
              };
              _rawCouponRow = dbCoupon; // full row — _createSingleOrder uses this, skips re-fetch
            }
          }
        }

        // ── Auto-detect slot AND validate store is open — same weekly_schedule fetch ──
        // Strategy: parse full day config, check if current IST time falls within a
        // lunch or dinner window. If outside ALL windows → reject with clear reason.
        // Staff-placed orders (source='admin') bypass the open/closed check.
        let autoSlot = 'morning';
        let _storeOpen = true;
        let _storeClosedReason = '';
        try {
          const sch = JSON.parse(schVal || '[]');
          const dayIdx = ist.getUTCDay();
          const d = Array.isArray(sch) && sch.length === 7 ? sch[dayIdx] : null;
          const nowMins = ist.getUTCHours() * 60 + ist.getUTCMinutes();
          if (d && d.open) {
            // Parse all four window edges from schedule
            // Times are stored as combined "HH:MM" strings — split, don't look for *Min fields
            const parseHM = (s, defH, defM) => {
              const m = /^(\d{1,2}):(\d{2})$/.exec(String(s || ''));
              return m ? (parseInt(m[1], 10) * 60 + parseInt(m[2], 10)) : (defH * 60 + defM);
            };
            const lsTotal = parseHM(d.lunchStart,  10, 0);
            const leTotal = parseHM(d.lunchEnd,    13, 0);
            const dsTotal = parseHM(d.dinnerStart, 18, 0);
            const deTotal = parseHM(d.dinnerEnd,   21, 0);
            const lsH = Math.floor(lsTotal / 60), lsM = lsTotal % 60;
            const dsH = Math.floor(dsTotal / 60), dsM = dsTotal % 60;
            if (nowMins >= lsTotal && nowMins <= leTotal) {
              autoSlot = 'morning'; _storeOpen = true;
            } else if (nowMins >= dsTotal && nowMins <= deTotal) {
              autoSlot = 'evening'; _storeOpen = true;
            } else if (nowMins < lsTotal) {
              _storeOpen = false;
              const h12 = lsH % 12 || 12, ap = lsH >= 12 ? 'PM' : 'AM';
              _storeClosedReason = `Store opens for morning orders at ${h12}:${String(lsM).padStart(2,'0')} ${ap}`;
            } else if (nowMins > leTotal && nowMins < dsTotal) {
              _storeOpen = false;
              const h12 = dsH % 12 || 12, ap = dsH >= 12 ? 'PM' : 'AM';
              _storeClosedReason = `Morning orders closed. Evening orders open at ${h12}:${String(dsM).padStart(2,'0')} ${ap}`;
            } else {
              _storeOpen = false;
              _storeClosedReason = 'Store is closed for today. See you tomorrow!';
            }
          } else if (d && !d.open) {
            // Day explicitly marked closed in schedule
            _storeOpen = false;
            _storeClosedReason = 'Store is closed today';
          } else {
            // No schedule data — fall back to simple 17:00 heuristic (always allow)
            autoSlot = nowMins >= 17 * 60 ? 'evening' : 'morning';
            _storeOpen = true;
          }
        } catch {
          autoSlot = (ist.getUTCHours() * 60 + ist.getUTCMinutes()) >= 17 * 60 ? 'evening' : 'morning';
          _storeOpen = true;
        }

        // Staff/admin bypass: they can always place orders regardless of time
        if (!_storeOpen && !_isStaff) {
          return res.json({ success: false, error: _storeClosedReason, errorCode: 'STORE_CLOSED' });
        }

        // NOTE: Multiple orders per slot are now allowed (users may order 2nd/3rd tiffin).
        // The idempotency guard (30s window above) still prevents accidental double-click duplicates.
        // Bulk order eligibility: if user has already ordered this slot today, they are
        // ineligible for admin bulk generation (handled in bulkGenerateOrders, unchanged).

        // ── FIX #3: Compute delivery charge server-side — never trust client value ──
        // upi_insuf: subscriber has insufficient wallet, pays via UPI — delivery is charged (₹20)
        // wallet:    subscriber has sufficient balance — free delivery
        // daily:     non-subscriber — always ₹20 delivery
        const serverDeliveryCharge = (user.is_subscriber && khataEnabled && data.paymentMode !== 'upi_insuf') ? 0 : 20;

        // ── SECURITY FIX v157 (race condition) ──────────────────────────────
        // REMOVED: the old separate SELECT-then-compare balance check that
        // used to live here. It read khata_summary.balance, compared it to
        // an estimated total, and returned early if insufficient — but that
        // read happened BEFORE _createSingleOrder's (also separate) wallet
        // deduction. Two or more concurrent createOrder requests could each
        // read the SAME pre-deduction balance, each pass this check, and
        // each then deduct — draining the wallet past ₹0 (free tiffin via
        // concurrent requests). It was also duplicate logic: this block
        // recomputed its own discount/finalEst independently of the real
        // discount/finalAmount computed inside _createSingleOrder, which is
        // a maintenance hazard (the two calculations could silently drift).
        // The balance check is now done ONCE, atomically, inside
        // _createSingleOrder via decrement_if_sufficient() — see there.
        let result;
        try {
          result = await _createSingleOrder({
            user, items: verifiedItems, deliveryCharge: serverDeliveryCharge,
            khataEnabled, ist, coupon: verifiedCoupon, _rawCouponRow, source: 'user',
            paymentMode: data.paymentMode || null, slot: autoSlot
          });
        } catch (e) {
          if (e.code === 'INSUFFICIENT_BALANCE') {
            return res.json({ success: false, error: 'Insufficient wallet balance' });
          }
          throw e; // anything else (e.g. order insert failure) — let the outer catch-all handle it
        }
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
        // Safety cap: ONLY applies when neither date nor fromDate is given —
        // i.e. only the dashboard's "Total Orders" (lifetime) stat-detail
        // click. "Today's Orders" always passes data.date and the main
        // Orders tab always passes data.fromDate, so both show every
        // matching order with NO limit, no matter how many there are.
        if (!data.date && !data.fromDate) query = query.limit(500);
        const { data: rows } = await query;
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
        // SAFETY: 'rejected' must go through rejectOrder which handles wallet refund,
        // khata entry, idempotency, and notifications. updateOrderStatus has none of that.
        if (normalizedStatus === 'rejected') {
          return res.json({ success: false, error: "Use the 'rejectOrder' action to reject an order — it handles wallet refund and notifications." });
        }

        // ── OWNERSHIP CHECK (same pattern as getRiderOrders) ──────────────────
        // The outer gate only proves "a valid rider/staff/admin is logged
        // in" — it does NOT prove a RIDER owns this specific order. Without
        // this check, any rider could mark/reject ANY order in the system,
        // not just the ones assigned to them.
        // role==='admin' and role==='staff' both bypass — staff/admin manage
        // orders system-wide via the admin panel and are not scoped to a
        // single rider's deliveries. Only role==='rider' is restricted to
        // orders.rider_id matching their own session username.
        const orderSession = _verifyToken(req.body.sessionToken);
        const isOrderStaffOrAdmin = orderSession && (orderSession.role === 'admin' || orderSession.role === 'staff');
        if (!isOrderStaffOrAdmin) {
          const { data: ownerCheck, error: ownerErr } = await supabase
            .from('orders').select('rider_id').eq('order_id', data.orderId).single();
          if (ownerErr || !ownerCheck) {
            return res.json({ success: false, error: 'Order not found' });
          }
          // Orders with no rider_id yet haven't been assigned (assignRider
          // sets this) — only admin should be able to touch those here.
          const isOrderOwner = orderSession && ownerCheck.rider_id && orderSession.username === ownerCheck.rider_id;
          if (!isOrderOwner) {
            return res.status(403).json({ success: false, error: 'You are not assigned to this order' });
          }
        }

        const updates = { order_status: normalizedStatus };
        // rider_id is set ONLY by admin via assignRider — never overwritten here
        await supabase.from('orders').update(updates).eq('order_id', data.orderId);
        if (normalizedStatus === 'delivered') {
          await supabase.from('khata_entries').update({ order_status: 'delivered' }).eq('order_id', data.orderId);
        }
        _bumpMenuVersion();
        return res.json({ success: true });
      }

      // ── Rider updates a customer's full address (room, area, coordinates) ──
      // Triggered from rider panel "✏️ Edit Address" / "📍 Set Location" on
      // any stop. Rebuilds the address string preserving Plus Code, patches
      // users.address/area/coord_lat/coord_lng/zone_status/order_allowed,
      // AND the current order's address snapshot for immediate display.
      case 'riderUpdateUserAddress': {
        const riderSession = _verifyToken(req.body.sessionToken);
        // role==='rider' is the rider's own role (see riderLogin). 'staff' is
        // kept here too for genuine human staff/ops accounts using the admin
        // panel's equivalent flow, if any — but riders themselves now carry
        // 'rider', not 'staff'.
        if (!riderSession || !(riderSession.role === 'admin' || riderSession.role === 'staff' || riderSession.role === 'rider')) {
          return res.status(401).json({ success: false, error: 'Rider auth required' });
        }
        const phone = cleanPhone(data.phone);
        if (!phone) return res.json({ success: false, error: 'Phone required' });

        const { data: userRow } = await supabase.from('users').select('address, coord_lat, coord_lng, order_allowed, area').eq('phone', phone).single();
        if (!userRow) return res.json({ success: false, error: 'User not found' });

        // ── Parse existing address into lines, preserve Plus Code as-is ──
        const existingLines = (userRow.address || '').split('\n').map(l => l.trim()).filter(Boolean);
        const plusLine = existingLines.find(l => /^Plus Code\s*:/i.test(l)) || '';

        // ── Coordinates: use provided lat/lng if valid, else keep existing ──
        let lat = parseFloat(data.lat);
        let lng = parseFloat(data.lng);
        let hasNewCoords = !isNaN(lat) && !isNaN(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
        if (!hasNewCoords) {
          lat = userRow.coord_lat;
          lng = userRow.coord_lng;
        }
        const hasAnyCoords = (lat != null && lng != null && !isNaN(lat) && !isNaN(lng));

        // ── Room No (optional, blank clears it) ──
        const room = (data.room || '').trim();

        // ── Area: use provided value, else keep existing ──
        const area = (data.area || '').trim() || (userRow.area || '').trim();

        // ── Rebuild address: Room No / Coordinates / Plus Code / Area ──
        const parts = [];
        if (room) parts.push(`Room No: ${room}`);
        if (hasAnyCoords) {
          parts.push(`Coordinates: ${parseFloat(lat).toFixed(6)}, ${parseFloat(lng).toFixed(6)}`);
          if (plusLine) parts.push(plusLine);
        }
        if (area) parts.push(`Area: ${area}`);
        const newAddress = parts.join('\n');
        if (!newAddress) return res.json({ success: false, error: 'Address cannot be empty' });

        const updates = { address: newAddress, area };

        // ── Rider-set coordinates are trusted (rider is physically present
        //    at the location) — treat like a normal verified user: inside
        //    zone, ordering allowed. No distance/zone math needed. ──
        let zoneStatus = null, orderAllowed = null;
        if (hasNewCoords) {
          zoneStatus   = 'inside';
          orderAllowed = true;
          updates.coord_lat     = lat;
          updates.coord_lng     = lng;
          updates.zone_status   = zoneStatus;
          updates.order_allowed = orderAllowed;
        } else if (area && !userRow.coord_lat && area !== 'Other') {
          // No coords at all, but a valid area is set/confirmed — allow ordering
          // (mirrors signup/area-exemption logic; never downgrades).
          if (!userRow.order_allowed) updates.order_allowed = true;
        }

        await supabase.from('users').update(updates).eq('phone', phone);

        // Also patch the current order's address snapshot (if orderId given)
        // so the rider panel shows correct info for THIS delivery immediately.
        if (data.orderId) {
          await supabase.from('orders').update({ address: newAddress }).eq('order_id', data.orderId);
        }

        return res.json({
          success: true,
          address: newAddress,
          lat: hasAnyCoords ? lat : null,
          lng: hasAnyCoords ? lng : null,
          area,
          zone_status:   zoneStatus,
          order_allowed: updates.order_allowed ?? userRow.order_allowed,
        });
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

        // ── FIX #9: Wallet refund BEFORE order status update ─────────────────
        // Bug: old code updated order status to 'rejected' first, then did wallet refund.
        // If _atomicWalletUpdate threw (Supabase timeout), the order was permanently
        // marked rejected but customer's wallet was never credited — money lost.
        // Retry was blocked by idempotency guard: "Order is already rejected".
        //
        // New sequence: wallet refund → khata entry → notification → status update
        // If status update fails after refund: order stays 'pending' — admin can retry.
        //
        // Double-refund guard: before crediting, check if a refund khata_entry already
        // exists for this orderId. Handles the edge case where refund succeeded but the
        // subsequent status update failed, causing admin to retry — without this guard,
        // the wallet would be credited a second time on retry.

        // Wallet refund — only for subscribers (done BEFORE status update)
        let refundNewBal = null;
        if (refundType === 'wallet' && isSubscriber) {
          // Double-refund guard: check if refund entry already exists for this order
          const { data: existingRefund } = await supabase
            .from('khata_entries')
            .select('id, running_balance')
            .eq('order_id', data.orderId)
            .eq('type', 'adjustment')
            .eq('source', 'admin')
            .maybeSingle();

          if (existingRefund) {
            // Refund was already credited in a previous attempt — don't credit again.
            // Use the balance from the existing entry so the response is consistent.
            refundNewBal = existingRefund.running_balance;
          } else {
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
          } // end else (new refund path)
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

        // ── Mark order rejected (AFTER wallet refund) ──────────────────────────
        // Now that refund succeeded (or refundType != wallet), safe to update status.
        // If this update fails, wallet was already credited — admin sees order still
        // in 'pending' state and can see the orphan credit in khata. Rare but recoverable.
        await supabase.from('orders').update({ order_status: 'rejected', refund_type: refundType }).eq('order_id', data.orderId);

        // ── Restore stock for user-placed orders (non-fatal) ──────────────────
        // Stock was deducted when the order was placed (source='user' only).
        // Admin/bulk orders never deducted stock — nothing to restore.
        if ((order.source || 'user') === 'user') {
          try {
            let rejItems = order.items;
            if (typeof rejItems === 'string') { try { rejItems = JSON.parse(rejItems); } catch(_) { rejItems = []; } }
            if (Array.isArray(rejItems) && rejItems.length) {
              const ids = rejItems.map(i => i.item_id).filter(Boolean);
              if (ids.length) {
                const { data: stockRows } = await supabase
                  .from('menu_items').select('item_id, stock_grams, portion_grams').in('item_id', ids);
                const stockMap = {};
                for (const r of (stockRows || [])) stockMap[r.item_id] = r;
                const restoreOps = [];
                rejItems.forEach(item => {
                  const row = stockMap[item.item_id];
                  if (!row || row.stock_grams == null) return;
                  let perUnit;
                  const vLabel = item.variantLabel || item.variant_label || '';
                  if (vLabel) {
                    const m = String(vLabel).match(/^(\d+(?:\.\d+)?)\s+[A-Za-z]/);
                    if (m) perUnit = parseFloat(m[1]);
                  }
                  if (perUnit == null) perUnit = row.portion_grams != null ? row.portion_grams : 1;
                  const cartQty = item.qty ?? item.quantity ?? 1;
                  restoreOps.push({ item_id: item.item_id, newStock: row.stock_grams + perUnit * cartQty });
                });
                await Promise.all(restoreOps.map(({ item_id, newStock }) =>
                  supabase.from('menu_items').update({ stock_grams: newStock, is_available: true }).eq('item_id', item_id)
                ));
                _menuItemsCache = null; _menuItemsCacheTs = 0; _bumpMenuVersion();
              }
            }
          } catch(_) { /* non-fatal — stock restore failure never blocks reject */ }
        }

        // ── Rollback lifetime_spend in user_ratings (non-fatal) ──
        _upsertUserRating(order.phone, -(order.final_amount || 0), null).catch(() => {});
        _bumpMenuVersion();
        return res.json({ success: true, refundType, isSubscriber, newBalance: refundNewBal });
      }

      case 'getOrderTransactions': {
        // Returns last 30 khata_entries for a given phone
        // All 3 reads are independent — run in parallel (was 3 sequential round-trips)
        const phone = cleanPhone(data.phone);
        const [
          { data: user },
          { data: balRow },
          { data: entries }
        ] = await Promise.all([
          supabase.from('users').select('name').eq('phone', phone).single(),
          supabase.from('khata_summary').select('balance').eq('phone', phone).single(),
          supabase.from('khata_entries').select('*')
            .eq('phone', phone)
            .order('created_at', { ascending: false })
            .limit(30)
        ]);
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
        // slot must be 'morning' or 'evening' — 'both' not supported (admin always picks one slot)
        const slot  = data.slot === 'evening' ? 'evening' : 'morning';

        // Fetch khata setting to know if balance matters for eligibility
        const khataSettingRawForBulk = await getCachedSetting('khata_enabled');
        const khataEnabledForBulk = _safeJsonParse(khataSettingRawForBulk || 'false', false);
        const bulkPrice = parseFloat(data.price) || 0;  // price for balance eligibility check

        // Fetch all subscribers (no expiry — subscriptions are now infinite)
        const { data: subs } = await supabase.from('subscribers').select('*');

        // Fetch today's orders for this slot to detect duplicates
        const { data: todayOrders } = await supabase.from('orders')
          .select('phone, order_id')
          .eq('date', today)
          .eq('slot', slot)
          .not('order_status', 'eq', 'cancelled');

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
          supabase.from('users').select('phone, name, address, order_allowed').in('phone', cleanPhones),
          supabase.from('subscribers').select('phone, pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, is_delivery_off, plan').in('phone', cleanPhones)
        ]);

        const bulkKhataEnabled = _safeJsonParse(khataSettingVal || 'false', false);
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
          if (bulkUserMap[cleanPh].order_allowed === false) {
            skipped.push({ phone: cleanPh, reason: 'ordering not enabled for location' }); continue;
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
            if (it.variantLabel)       itObj.variantLabel       = it.variantLabel;
            if (it.item_id)            itObj.item_id            = it.item_id;
            // Carry stock_unit so kitchen unit display is correct even for bulk orders
            if (it.stock_unit)         itObj.stock_unit         = it.stock_unit;
            if (it.stock_unit_label)   itObj.stock_unit_label   = it.stock_unit_label;
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
            area:            _extractArea(user.address || ''),
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
            // Supabase builder is thenable but NOT a native Promise — .catch()
            // does not exist on it. Must await first, then handle error separately.
            try {
              const { error: rollbackErr } = await supabase.rpc('bulk_increment_balance', {
                p_phones: eligiblePhones, p_delta: +priceNum
              });
              if (rollbackErr) throw rollbackErr;
            } catch (_rpcErr) {
              // RPC rollback failed — fall back to sequential individual updates
              for (const ph of eligiblePhones) {
                try { await _atomicWalletUpdate(ph, +priceNum); } catch (_) {}
              }
            }
          }
          return res.json({ success: false, error: 'Orders insert failed: ' + ordersErr.message });
        }

        // ── Update permanent rating stats for all eligible phones (non-fatal) ──
        // Fire-and-forget: don't await — bulk insert already committed, don't delay response
        Promise.allSettled(
          eligiblePhones.map(ph => _upsertUserRating(ph, priceNum, today))
        ).catch(() => {});

        // ─── STEP 6: Admin summary notification — one entry for the whole bulk run ──
        // Mirrors what _createSingleOrder does per order, but bulk collapses to one notification
        // so the admin panel isn't flooded. Non-fatal: orders already committed.
        try {
          const totalCreated = created.length + udhar.length;
          const slotLabel    = bulkSlot === 'morning' ? 'Morning' : bulkSlot === 'evening' ? 'Evening' : 'Today';
          const udharNote    = udhar.length ? ` (${udhar.length} udhar)` : '';
          await _createNotification({
            type:     'order',
            priority: 'high',
            group_id: 'bulk-' + generateId('BLK', ist),
            title:    'Bulk Orders Generated',
            body:     `${totalCreated} orders placed — ${slotLabel} slot${udharNote}. ${skipped.length} skipped.`,
            meta:     {
              source:        'admin_bulk',
              slot:          bulkSlot,
              totalCreated,
              udharCount:    udhar.length,
              skippedCount:  skipped.length,
              itemName
            }
          });
        } catch (_) {}

        // ─── STEP 7: Batch khata entries insert — ONE DB call ───────────────
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

          // ── SAFETY NET: 'rejected' must go through rejectOrder, never here ──
          // bulkUpdateOrder is a plain field-setter with no refund logic. The
          // admin panel's bulk-update UI never offers "rejected" as an option
          // (only pending/preparing/out for delivery/delivered), so this path
          // isn't reachable through normal product use — but a direct API
          // call with orderStatus:'rejected' would silently mark a
          // subscriber's order rejected WITHOUT crediting their wallet,
          // since the refund logic only lives in the 'rejectOrder' handler.
          // Blocked explicitly (rather than silently dropped) so any caller
          // gets a clear, actionable error instead of a confusing no-op.
          if (rawStatus === 'rejected') {
            return res.json({
              success: false,
              error: "Use the 'rejectOrder' action to reject an order — it handles the wallet refund. bulkUpdateOrder does not."
            });
          }

          const statusMap = {
            'out for delivery': 'out for delivery',
            'out_for_delivery': 'out for delivery',
            'pending':   'pending',
            'confirmed': 'confirmed',
            'preparing': 'preparing',
            'delivered': 'delivered',
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
      case 'validateCoupon': {
        const cpnCode = (data.code||'').toUpperCase();
        if (!cpnCode) return res.json({ success: false, error: 'Coupon code required' });
        const { data: coupon } = await supabase.from('coupons').select('*').eq('code', cpnCode).single();
        if (!coupon || !coupon.is_active) return res.json({ success: false, error: 'Invalid coupon' });
        const today = istDateStr(ist);
        if (coupon.expiry_date && coupon.expiry_date < today) return res.json({ success: false, error: 'Coupon expired' });
        // ── Flash window restriction check ───────────────────────────────
        if (coupon.restriction_type === 'flash_window') {
          if (!coupon.flash_date || coupon.flash_date !== today)
            return res.json({ success: false, error: 'Flash sale not active today' });
          const nowTime = String(ist.getUTCHours()).padStart(2,'0') + ':' + String(ist.getUTCMinutes()).padStart(2,'0');
          if (coupon.flash_start && nowTime < coupon.flash_start.slice(0,5))
            return res.json({ success: false, error: `Flash sale starts at ${fmtFlashTime(coupon.flash_start)}` });
          if (coupon.flash_end && nowTime >= coupon.flash_end.slice(0,5))
            return res.json({ success: false, error: 'Flash sale window has ended' });
        }
        const maxUse = coupon.max_usage ?? coupon.total_usage_limit ?? null;
        if (maxUse != null && (coupon.used_count||0) >= maxUse) {
          // v171: use coupon_type for FCFS FT detection instead of prefix
          const isTiffoFcfs = coupon.coupon_type === 'free_tiffin' && coupon.restriction_type === 'one_time_per_user';
          const fullMsg = isTiffoFcfs
            ? `Today's free tiffin slots are full (${maxUse}/${maxUse} claimed). Ask admin for a new coupon for the next batch.`
            : 'Coupon fully used';
          return res.json({ success: false, error: fullMsg });
        }
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

        // ── Free Tiffin Gate (v171) ──────────────────────────────────────────
        // v171: use coupon_type='free_tiffin' DB column — prefix-agnostic.
        // Admin can name FT codes anything; the type tag in DB drives logic.
        const isFreeTiffinCoupon = coupon.coupon_type === 'free_tiffin';
        if (isFreeTiffinCoupon && phone) {
          const { data: ftUser } = await supabase
            .from('users')
            .select('free_tiffin_status, free_tiffin_blocked, free_tiffin_given_at')
            .eq('phone', phone)
            .single();
          if (ftUser) {
            if (ftUser.free_tiffin_blocked === true) {
              return res.json({ success: false, error: 'Free tiffin access has been disabled for this account' });
            }
            if (ftUser.free_tiffin_status === 'redeemed') {
              let redeemedOn = '';
              if (ftUser.free_tiffin_given_at) {
                const d = new Date(ftUser.free_tiffin_given_at);
                const dd = String(d.getDate()).padStart(2,'0');
                const mm = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()];
                redeemedOn = ` on ${dd} ${mm}`;
              }
              return res.json({ success: false, error: `You already received your free first tiffin${redeemedOn}. We hope you enjoyed it!` });
            }
          }
        }
        // ── End Free Tiffin Gate ──────────────────────────────────────────────

        return res.json({ success: true, coupon: { code: coupon.code, discount_type: coupon.discount_type, discount_value: coupon.discount_value, cap_amount: capAmt, min_order: minOrd, restriction_type: rtype } });
      }

      case 'deleteCoupon': {
        await supabase.from('coupons').delete().eq('id', data.id);
        _bumpMenuVersion();
        return res.json({ success: true });
      }

      // Auto-delete all expired coupons (called silently when admin opens coupon tab)
      case 'deleteExpiredCoupons': {
        const today = istDateStr(ist);
        // 1. Standard date-expired coupons
        const { data: expired, error: fetchErr } = await supabase
          .from('coupons')
          .select('id')
          .not('expiry_date', 'is', null)
          .lt('expiry_date', today);
        if (fetchErr) return res.json({ success: false, error: fetchErr.message });
        // 2. Flash coupons from a previous day
        const { data: flashOldDay } = await supabase
          .from('coupons')
          .select('id')
          .eq('restriction_type', 'flash_window')
          .not('flash_date', 'is', null)
          .lt('flash_date', today);
        // 3. Flash coupons for today whose end time has passed
        const hh3 = String(ist.getUTCHours()).padStart(2,'0');
        const mm3 = String(ist.getUTCMinutes()).padStart(2,'0');
        const nowTimeStr = `${hh3}:${mm3}:00`;
        const { data: flashTodayEnded } = await supabase
          .from('coupons')
          .select('id')
          .eq('restriction_type', 'flash_window')
          .eq('flash_date', today)
          .not('flash_end', 'is', null)
          .lte('flash_end', nowTimeStr);
        const allIds = [
          ...(expired       || []).map(r => r.id),
          ...(flashOldDay   || []).map(r => r.id),
          ...(flashTodayEnded || []).map(r => r.id)
        ];
        const uniqueIds = [...new Set(allIds)];
        if (uniqueIds.length === 0) return res.json({ success: true, deleted: 0 });
        await supabase.from('coupons').delete().in('id', uniqueIds);
        return res.json({ success: true, deleted: uniqueIds.length });
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
        const todayStr2    = istDateStr(ist);
        const tomorrowIST2 = new Date(ist.getTime() + 86_400_000);
        const tomorrowStr2 = istDateStr(tomorrowIST2);
        const effectivePauseMode = computeEffectivePauseDelivery(row, todayStr2);
        // Compute pending-tomorrow: a pause that is set but not active today (starts tomorrow)
        const pmTomorrow = row?.pause_morning && row?.pause_morning_from === tomorrowStr2;
        const peTomorrow = row?.pause_evening && row?.pause_evening_from === tomorrowStr2;
        let pendingTomorrow = null;
        if (pmTomorrow && peTomorrow) pendingTomorrow = 'both';
        else if (pmTomorrow) pendingTomorrow = 'lunch';
        else if (peTomorrow) pendingTomorrow = 'dinner';
        return res.json({ success: true, pauseMode: effectivePauseMode, plan: row?.plan || 'morning', pendingTomorrow });
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

      case 'updateSubscriber': {
        const updates = { plan_start: data.plan_start, notes: data.notes };
        if (data.plan)           updates.plan           = data.plan;
        if (data.is_delivery_off !== undefined) updates.is_delivery_off = data.is_delivery_off;
        // plan_end: allow setting or clearing (null = infinite subscription)
        if (data.plan_end !== undefined) updates.plan_end = data.plan_end || null;
        await supabase.from('subscribers').update(updates).eq('phone', cleanPhone(data.phone));
        _bumpMenuVersion(); // subscriber status changed — clients detect via version poll
        return res.json({ success: true });
      }

      case 'removeSubscriber': {
        await supabase.from('subscribers').delete().eq('phone', cleanPhone(data.phone));
        _bumpMenuVersion(); // subscriber removed — clients detect via version poll
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
        const bulkPriceCheck = parseFloat(data.price) || 0;  // 0 = no price check

        // If slot provided: balance + orders + subscriber all parallel (3 → 1 round-trip)
        // If no slot: balance standalone (was already a single call, kept same)
        if (checkSlot) {
          const [{ data: balRow }, { data: existOrd }, { data: subRow }] = await Promise.all([
            supabase.from('khata_summary').select('balance').eq('phone', safe.phone).single(),
            supabase.from('orders').select('order_id').eq('phone', safe.phone).eq('date', checkDate).eq('slot', checkSlot).not('order_status', 'eq', 'cancelled').limit(1),
            supabase.from('subscribers').select('pause_delivery, pause_morning, pause_morning_from, pause_evening, pause_evening_from, is_delivery_off').eq('phone', safe.phone).single()
          ]);
          safe.balance = balRow?.balance ?? 0;
          safe.insufficient_balance = bulkPriceCheck > 0 && safe.balance < bulkPriceCheck;
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
        } else {
          // No slot check — just need balance (single call, was already correct)
          const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', safe.phone).single();
          safe.balance = balRow?.balance ?? 0;
          safe.insufficient_balance = bulkPriceCheck > 0 && safe.balance < bulkPriceCheck;
        }
        return res.json({ success: true, user: safe });
      }

      case 'adminCreateUser': {
        const phone = cleanPhone(data.phone);
        const pwErrACU = _validatePassword(data.password);
        if (pwErrACU) return res.json({ success: false, error: pwErrACU });
        const hash  = await bcrypt.hash(data.password, SALT_ROUNDS);
        await supabase.from('users').insert({
          user_id:       phone,
          name:          data.name,
          phone,
          email:         data.email || null,
          address:       data.address || null,
          area:          _extractArea(data.address || ''),
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
            // Opt-in auto-tiffin: new subscribers start PAUSED ('both') and must
            // explicitly opt in. (Previously defaulted to 'none' = opt-out, i.e.
            // auto-tiffin ON by default — contradicted the opt-in policy.)
            pause_delivery: 'both',
            pause_morning:  true,
            pause_evening:  true,
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
        // Validate user exists + not already subscriber in parallel (was 2 sequential selects)
        const [{ data: user }, { data: existing }] = await Promise.all([
          supabase.from('users').select('phone').eq('phone', phone).single(),
          supabase.from('subscribers').select('phone').eq('phone', phone).single()
        ]);
        if (!user) return res.json({ success: false, error: 'User not found' });
        if (existing) return res.json({ success: false, error: 'Already a subscriber' });
        await supabase.from('subscribers').insert({
          phone,
          plan:           data.plan || 'morning',
          plan_start:     data.plan_start || istDateStr(getIST()),
          notes:          data.notes || '',
          // Opt-in auto-tiffin: see matching note in addAsSubscriber above.
          pause_delivery: 'both',
          pause_morning:  true,
          pause_evening:  true,
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
        _bumpMenuVersion(); // subscriber added — clients detect via version poll
        return res.json({ success: true });
      }
      case 'createRider': {
        const rider_id = await generateRiderId(ist);
        const pwErrCR = _validatePassword(data.password);
        if (pwErrCR) return res.json({ success: false, error: pwErrCR });
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
        _ridersCache = null; // invalidate cache — new rider added
        return res.json({ success: true, rider_id });
      }

      case 'updateRider': {
        const rid = data.rider_id || data.id; // normalize: frontend sends data.id
        const updates = { ...data };
        delete updates.rider_id;
        delete updates.id;
        delete updates.password_hash; // never allow direct hash overwrite
        if (data.password) {
          const pwErrUR = _validatePassword(data.password);
          if (pwErrUR) return res.json({ success: false, error: pwErrUR });
          updates.password_hash = await bcrypt.hash(data.password, SALT_ROUNDS);
          delete updates.password;
        }
        await supabase.from('riders').update(updates).eq('rider_id', rid);
        _ridersCache = null; // invalidate cache — rider updated
        return res.json({ success: true });
      }

      case 'deleteRider': {
        const rid = data.rider_id || data.id;
        await supabase.from('riders').update({ is_active: false }).eq('rider_id', rid);
        _ridersCache = null; // invalidate cache — rider deactivated
        return res.json({ success: true });
      }

      case 'riderLogin': {
        if (!data.password || String(data.password).length > 72)
          return res.json({ success: false, error: 'Invalid credentials' });
        const riderKey = 'rider:' + (data.riderId || '');
        const riderLockErr = _checkLoginAttempt(riderKey);
        if (riderLockErr) return res.json({ success: false, error: riderLockErr });
        const { data: rider } = await supabase.from('riders').select('*').eq('rider_id', data.riderId).single();
        if (!rider) { _recordLoginFailure(riderKey); return res.json({ success: false, error: 'Invalid credentials' }); }
        const valid = await bcrypt.compare(data.password, rider.password_hash);
        if (!valid) { _recordLoginFailure(riderKey); return res.json({ success: false, error: 'Invalid credentials' }); }
        _resetLoginAttempts(riderKey);
        const { password_hash, ...safe } = rider;
        // SECURITY FIX: role is 'rider', NOT 'staff'. Riders previously got
        // role:'staff', the same role real human staff/admin-panel accounts
        // use — which let a rider's token pass every _STAFF_ACTIONS check
        // (rechargeWallet, manualRefund, deleteRider, etc.), not just the
        // 3 rider-panel actions. 'rider' tokens are now restricted to
        // _RIDER_ACTIONS only — see the main /api gate above.
        const sessionToken = _signToken({
          role:     'rider',
          username: rider.rider_id,
          exp:      Date.now() + SESSION_TTL_MS,
        });
        return res.json({ success: true, rider: safe, sessionToken });
      }

      case 'getRiderOrders': {
        // Verify the sessionToken belongs to this rider (or is a true admin).
        // HISTORICAL FIX (v151): riderLogin used to issue role:'staff' to
        // every rider, so checking role==='staff' here let ANY rider fetch
        // ANY other rider's order list (PII: customer names/phones/
        // addresses) by passing a different riderId. riderLogin now issues
        // role:'rider' (its own distinct role — see riderLogin handler), and
        // only role==='admin' bypasses the ownership check below — riders
        // must always match their own rider_id via the username field.
        const riderSession = _verifyToken(req.body.sessionToken);
        const isAdmin = riderSession && riderSession.role === 'admin';
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
      case 'createStaff': {
        const pwErrCS = _validatePassword(data.password);
        if (pwErrCS) return res.json({ success: false, error: pwErrCS });
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
          const pwErrUS = _validatePassword(data.password);
          if (pwErrUS) return res.json({ success: false, error: pwErrUS });
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
        // ── Parallel fetch: entries + balance are independent — one round-trip instead of two ──
        // Capped at 100 most recent entries — the modal renders into a 260px
        // scrollbox (see openKhataDetail), so unbounded history has no UX
        // benefit while growing server cost forever for long-tenured users.
        const [{ data: entries }, { data: sumRow }] = await Promise.all([
          supabase.from('khata_entries').select('*').eq('phone', phone).order('created_at', { ascending: false }).limit(100),
          supabase.from('khata_summary').select('balance').eq('phone', phone).single()
        ]);

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
        if (!phone) return res.json({ success: false, error: 'Phone required' });
        if (!amount || isNaN(amount) || !isFinite(amount) || amount <= 0) {
          return res.json({ success: false, error: 'Invalid amount' });
        }
        if (amount > 50000) return res.json({ success: false, error: 'Amount too large (max ₹50,000 per recharge)' });
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
        _bumpMenuVersion(); // wallet changed — client detects via version poll → refreshes balance
        return res.json({ success: true, newBalance: newBal });
      }

      case 'manualRefund': {
        const phone  = cleanPhone(data.phone);
        const amount = Number(data.amount);
        if (!phone) return res.json({ success: false, error: 'Phone required' });
        if (!amount || isNaN(amount) || !isFinite(amount)) {
          return res.json({ success: false, error: 'Invalid amount' });
        }
        if (Math.abs(amount) > 50000) return res.json({ success: false, error: 'Amount too large (max ±₹50,000)' });
        // Guard: if deduction would push wallet negative, block it server-side.
        // increment_balance has no floor — a typo like -5000 on a ₹100 wallet silently goes to -₹4900.
        if (amount < 0) {
          const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
          const currentBal = Number(balRow?.balance ?? 0);
          if (currentBal + amount < 0) {
            return res.json({ success: false, error: `Deduction of ₹${Math.abs(amount)} would push wallet to ₹${(currentBal + amount).toFixed(2)}. Current balance: ₹${currentBal.toFixed(2)}. Reduce the amount.` });
          }
        }
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
        _bumpMenuVersion(); // wallet changed — client detects via version poll → refreshes balance
        return res.json({ success: true, newBalance: newBal });
      }

      case 'setOrderCutoff': {
        await supabase.from('admin_settings').upsert({ key: 'order_cutoff_config', value: JSON.stringify(data.config), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null; _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'setWeeklySchedule': {
        await supabase.from('admin_settings').upsert({ key: 'weekly_schedule', value: JSON.stringify(data.schedule), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null; _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'setAutoTiffinCutoff': {
        // config = { morning: 'HH:MM', evening: 'HH:MM' }
        const cfg = data.config || {};
        const timeRe = /^\d{2}:\d{2}$/;
        if (!timeRe.test(cfg.morning) || !timeRe.test(cfg.evening))
          return res.json({ success: false, error: 'Invalid time format. Use HH:MM' });
        await supabase.from('admin_settings').upsert({ key: 'auto_tiffin_cutoff', value: JSON.stringify(cfg), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'setKhataEnabled': {
        await supabase.from('admin_settings').upsert({ key: 'khata_enabled', value: JSON.stringify(!!data.enabled), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _analyticsCache = null; _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'setDeliveryZone': {
        const zone = { lat: parseFloat(data.lat), lng: parseFloat(data.lng), radiusKm: parseFloat(data.radiusKm) };
        if (isNaN(zone.lat) || isNaN(zone.lng) || isNaN(zone.radiusKm) || zone.radiusKm <= 0) {
          return res.json({ success: false, error: 'Invalid zone data' });
        }
        await supabase.from('admin_settings').upsert({ key: 'delivery_zone', value: JSON.stringify(zone), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _bumpMenuVersion();
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

      case 'getNotifications': {
        const { data: rows } = await supabase.from('notifications').select('*').order('created_at', { ascending: false }).limit(500); // cap: daily auto-delete keeps table small; 500 covers full day comfortably
        const list = (rows || []).map(n => {
          if (n.meta && typeof n.meta === 'string') {
            try { n.meta = JSON.parse(n.meta); } catch (_) { n.meta = {}; }
          }
          return n;
        });
        const unreadCount = list.filter(n => !n.is_read).length;
        return res.json({ success: true, notifications: list, unreadCount });
      }

      case 'markNotificationRead': {
        await supabase.from('notifications').update({ is_read: true, read_at: new Date().toISOString() }).eq('id', data.id);
        return res.json({ success: true });
      }

      case 'deleteNotification': {
        await supabase.from('notifications').delete().eq('id', data.id);
        return res.json({ success: true });
      }

      case 'getNuCouponPending': {
        // Pending = unread new-user notifications not yet in nu_coupon_sent
        const { data: notifs } = await supabase
          .from('notifications')
          .select('id, meta, created_at')
          .eq('type', 'user')
          .eq('is_read', false)
          .order('created_at', { ascending: false });
        const { data: sentRows } = await supabase
          .from('nu_coupon_sent')
          .select('phone');
        const sentPhones = new Set((sentRows || []).map(r => r.phone));
        const records = (notifs || [])
          .map(n => { try { return { ...JSON.parse(n.meta || '{}'), notif_id: n.id, created_at: n.created_at }; } catch(_) { return null; } })
          .filter(r => r && r.phone && !sentPhones.has(r.phone));
        return res.json({ success: true, records });
      }

      case 'getNuCouponSent': {
        // Sent = rows from nu_coupon_sent, newest first
        const { data: rows } = await supabase
          .from('nu_coupon_sent')
          .select('phone, name, sent_at, coupon_code')
          .order('sent_at', { ascending: false });
        return res.json({ success: true, records: rows || [] });
      }

      case 'addNuCouponPending': {
        // No-op stored handler — pending list is derived from unread notifications.
        // This is a safe stub so admin.html's saveAndSendCoupon() doesn't error.
        return res.json({ success: true });
      }

      case 'markNuCouponSent': {
        // Welcome coupon and Free First Tiffin are two separate systems.
        // This action only records that a welcome/discount coupon was sent to a new user.
        // It has NO effect on free_tiffin_status — that is managed exclusively
        // by the FT Campaign tab (createFreeTiffinBatch / markFreeTiffinWaSent).
        const nuPhone = cleanPhone(data.phone);
        await supabase.from('nu_coupon_sent').upsert({
          phone:       nuPhone,
          name:        data.name || null,
          sent_at:     new Date().toISOString(),
          coupon_code: data.coupon_code || null,
          notif_id:    data.notif_id || null
        }, { onConflict: 'phone' });
        return res.json({ success: true });
      }

      case 'deleteOldData': {
        const type       = (data.type || '').toLowerCase();
        const reqDate    = data.before;   // YYYY-MM-DD from client
        if (!reqDate) return res.json({ success: false, error: 'Missing date' });

        // Minimum retention rules (days): data newer than this is never deleted
        const MIN_DAYS = { orders: 35, transactions: 35, notifications: 1 };
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

        const ordersCutoff  = dateCutoff(35);  // orders  older than 35 days
        const txnsCutoff    = dateCutoff(35);  // transactions older than 35 days
        // FIX: use ISO timestamp (same as auto-cleanup) not date+'T23:59:59Z'
        // The old form 'YYYY-MM-DDT23:59:59Z' = yesterday 23:59 UTC = today 05:29 IST,
        // which would silently delete today's early-morning notifications.
        const notifsCutoff  = new Date(Date.now() - 86_400_000).toISOString(); // 24h ago

        const sessionsCutoff = dateCutoff(5);  // cooking_sessions older than 5 days
        const nuCouponCutoff  = new Date(Date.now() - 7 * 86_400_000).toISOString(); // nu_coupon_sent older than 7 days

        const refCouponCutoff = new Date(Date.now() - 7 * 86_400_000).toISOString(); // used/expired referral coupons older than 7 days

        const [r1, r2, r3, r4, r5, r6] = await Promise.all([
          supabase.from('orders').delete({ count: 'exact' }).lte('date', ordersCutoff),
          supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', txnsCutoff),
          supabase.from('notifications').delete({ count: 'exact' }).lt('created_at', notifsCutoff),
          supabase.from('cooking_sessions').delete({ count: 'exact' }).lte('session_date', sessionsCutoff),
          supabase.from('nu_coupon_sent').delete({ count: 'exact' }).lt('sent_at', nuCouponCutoff),
          // Delete used referral coupons (is_active=false, auto_delete=true) older than 7 days
          supabase.from('coupons').delete({ count: 'exact' })
            .eq('auto_delete', true)
            .eq('is_active', false)
            .lt('created_at', refCouponCutoff),
        ]);

        return res.json({
          success: true,
          message: 'Master delete completed (retention rules applied)',
          ordersDeleted:          r1.count || 0,
          txnsDeleted:            r2.count || 0,
          notifsDeleted:          r3.count || 0,
          cookingSessionsDeleted: r4.count || 0,
          nuCouponSentDeleted:    r5.count || 0,
          usedCouponsDeleted:     r6.count || 0,
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
          _bumpMenuVersion();
          return res.json({ success: true, pauseMode: mode }); }

      case 'changePassword':
        { const phone = cleanPhone(data.phone);
          // Guard both passwords — bcrypt DoS prevention
          if (String(data.currentPassword || '').length > 72)
            return res.json({ success: false, error: 'Password too long (max 72 characters)' });
          const pwErr = _validatePassword(data.newPassword);
          if (pwErr) return res.json({ success: false, error: pwErr });
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

          // ── Parallel fetch: 4 independent tables — single round trip ─────
          const today30ago = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
          const [
            { data: subs },
            { data: balRows },
            { data: recentOrders },
            { data: ratingRows }
          ] = await Promise.all([
            supabase.from('subscribers').select('phone, plan, plan_end, created_at'),
            supabase.from('khata_summary').select('phone, balance'),
            supabase.from('orders')
              .select('phone, date')
              .neq('order_status', 'cancelled')
              .neq('order_status', 'rejected')
              .gte('date', today30ago),
            supabase.from('user_ratings').select('phone, manual_score')
          ]);

          // Build lookup maps in JS — O(n), zero extra DB calls
          const subMap = {};
          for (const s of (subs || [])) subMap[s.phone] = s;

          const balMap = {};
          for (const b of (balRows || [])) balMap[b.phone] = parseFloat(b.balance) || 0;

          const recent30Map = {};
          for (const o of (recentOrders || [])) {
            recent30Map[o.phone] = (recent30Map[o.phone] || 0) + 1;
          }

          const manualScoreMap = {};
          for (const r of (ratingRows || [])) manualScoreMap[r.phone] = r.manual_score ?? 5;

          const safe = (rows || []).map(u => {
            const { password_hash, ...s } = u;
            const sub    = subMap[u.phone];
            const walBal = balMap[u.phone] || 0;
            const recent30 = recent30Map[u.phone] || 0;
            return {
              ...s,
              is_subscriber:       !!sub,
              subscriber_plan:     sub?.plan || null,
              subscriber_plan_end: sub?.plan_end || null,
              total_orders:        recent30,
              wallet_balance:      walBal,
              // rating comes directly from users.rating (NUMERIC) — kept in sync by _recomputeAndSyncRating
              rating:              parseFloat(u.rating) || 0,
              // manual_score from user_ratings — needed for the rating modal slider
              manual_score:        manualScoreMap[u.phone] ?? 5,
              // zone / order fields
              zone_status:         u.zone_status  || 'unknown',
              order_allowed:       u.order_allowed !== false, // default true
              coord_lat:           u.coord_lat  || null,
              coord_lng:           u.coord_lng  || null,
            };
          });
          return res.json({ success: true, users: safe }); }

      // ── USER ANALYTICS (for Analytics modal in All Users tab) ──────────────
      // Returns per-phone order stats for last 90 days + lifetime spend + last_order_date.
      // Two DB calls only — heavy segmentation logic runs on the frontend.
      case 'getUserAnalytics': {
        const parsedDays = parseInt(data.days);
        const days = (Number.isFinite(parsedDays) && parsedDays > 0)
          ? Math.min(parsedDays, 180)
          : 90; // default + guard against 0, negative, NaN, or garbage input
        const fromDate = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
        const [ordersRes, ratingsRes] = await Promise.all([
          supabase.from('orders')
            .select('phone, date, final_amount, order_status, slot')
            .gte('date', fromDate)
            .neq('order_status', 'cancelled')
            .neq('order_status', 'rejected'),
          supabase.from('user_ratings')
            .select('phone, lifetime_spend, last_order_date, manual_score')
        ]);
        if (ordersRes.error) return res.json({ success: false, error: ordersRes.error.message || 'Failed to load orders' });
        if (ratingsRes.error) return res.json({ success: false, error: ratingsRes.error.message || 'Failed to load ratings' });
        // Aggregate per phone
        const statsMap = {};
        for (const o of (ordersRes.data || [])) {
          const p = o.phone;
          if (!statsMap[p]) statsMap[p] = { orderCount: 0, totalSpend: 0, dates: [], morningCount: 0, eveningCount: 0 };
          statsMap[p].orderCount++;
          statsMap[p].totalSpend += (o.final_amount || 0);
          statsMap[p].dates.push(o.date);
          if (o.slot === 'morning') statsMap[p].morningCount++;
          if (o.slot === 'evening') statsMap[p].eveningCount++;
        }
        // Merge ratings
        const ratingsMap = {};
        for (const r of (ratingsRes.data || [])) ratingsMap[r.phone] = r;
        // Build final array
        const result = Object.entries(statsMap).map(([phone, s]) => {
          const r = ratingsMap[phone] || {};
          const sortedDates = [...s.dates].sort();
          return {
            phone,
            orderCount:     s.orderCount,
            totalSpend:     Math.round(s.totalSpend),
            morningCount:   s.morningCount,
            eveningCount:   s.eveningCount,
            firstOrderDate: sortedDates[0] || null,
            lastOrderDate:  sortedDates[sortedDates.length - 1] || null,
            lifetimeSpend:  Math.round(parseFloat(r.lifetime_spend) || 0),
            ratingLastDate: r.last_order_date || null,
            manualScore:    r.manual_score || 5,
          };
        });
        return res.json({ success: true, stats: result, fromDate, days });
      }

      case 'adminAllowOrder': {
        // Admin enables order placement for outside-zone or manual_only users
        const { phone: aoPhone } = data;
        if (!aoPhone) return res.json({ success: false, error: 'Phone required' });
        // Fetch current zone_status so we set the right allowed value
        const { data: aoUser } = await supabase.from('users').select('zone_status').eq('phone', cleanPhone(aoPhone)).single();
        const aoCurrentZs = aoUser?.zone_status || 'outside';
        // manual_only → admin_approved (location unverified but manually enabled)
        // outside → outside_allowed (GPS confirmed outside but admin approved)
        // unknown → admin_approved (no data, manually approved)
        const aoNewZs = aoCurrentZs === 'outside' ? 'outside_allowed' : 'admin_approved';
        const { error: aoErr } = await supabase.from('users')
          .update({ order_allowed: true, zone_status: aoNewZs })
          .eq('phone', cleanPhone(aoPhone));
        if (aoErr) return res.json({ success: false, error: aoErr.message });
        return res.json({ success: true });
      }

      case 'adminBlockOrder': {
        // Admin disables order placement for this user (reverse of adminAllowOrder)
        const { phone: boPhone } = data;
        if (!boPhone) return res.json({ success: false, error: 'Phone required' });
        const { error: boErr } = await supabase.from('users')
          .update({ order_allowed: false })
          .eq('phone', cleanPhone(boPhone));
        if (boErr) return res.json({ success: false, error: boErr.message });
        return res.json({ success: true });
      }

      case 'adminSetUserCoords': {
        // Admin manually sets lat/lng for a user (via edit address modal)
        const { phone: scPhone, lat: scLat, lng: scLng } = data;
        if (!scPhone) return res.json({ success: false, error: 'Phone required' });
        const lat = parseFloat(scLat), lng = parseFloat(scLng);
        if (isNaN(lat) || isNaN(lng)) return res.json({ success: false, error: 'Invalid coordinates' });
        // Do zone check to set zone_status
        let zoneStatus = 'unknown';
        try {
          const { data: zRow } = await supabase.from('admin_settings').select('value').eq('key', 'delivery_zone').single();
          if (zRow?.value) {
            const zone = JSON.parse(zRow.value);
            if (zone?.lat && zone?.lng && zone?.radiusKm) {
              const R = 6371;
              const dLat = (lat - zone.lat) * Math.PI / 180;
              const dLng = (lng - zone.lng) * Math.PI / 180;
              const a = Math.sin(dLat/2)**2 + Math.cos(zone.lat*Math.PI/180)*Math.cos(lat*Math.PI/180)*Math.sin(dLng/2)**2;
              const dist = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
              zoneStatus = dist <= zone.radiusKm ? 'inside' : 'outside';
            }
          }
        } catch(_) {}
        const { error: scErr } = await supabase.from('users')
          .update({ coord_lat: lat, coord_lng: lng, zone_status: zoneStatus,
                    order_allowed: zoneStatus === 'inside' })
          .eq('phone', cleanPhone(scPhone));
        if (scErr) return res.json({ success: false, error: scErr.message });
        return res.json({ success: true, zone_status: zoneStatus });
      }

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
            flash_date:        data.restriction_type === 'flash_window' ? istDateStr(ist) : null,
            flash_start:       data.flash_start || null,
            flash_end:         data.flash_end   || null,
            used_count:        0,
            usage_count:       0,
            used_by:           '[]',
            created_at:        new Date().toISOString()
          });
          _bumpMenuVersion();
          return res.json({ success: true }); }

      case 'updateCoupon': {
        const COUPON_EDITABLE = ['code','discount_type','discount_value','cap_amount','max_cap',
          'min_order','min_order_amount','max_usage','total_usage_limit','per_user_limit',
          'max_per_user','expiry_date','is_active','restriction_type','allowed_phones','auto_delete',
          'flash_date','flash_start','flash_end'];
        const updates = {};
        for (const k of COUPON_EDITABLE) { if (data[k] !== undefined) updates[k] = data[k]; }
        if (!Object.keys(updates).length) return res.json({ success: false, error: 'Nothing to update' });
        await supabase.from('coupons').update(updates).eq('id', data.id);
        _bumpMenuVersion();
        return res.json({ success: true }); }

      case 'getAllKhata': {
        const { data: rows } = await supabase.from('khata_summary').select('*');
        const akPhones = (rows || []).map(r => r.phone);
        const [{ data: akUsers }, { data: akTxns }, { data: akSubs }] = akPhones.length
          ? await Promise.all([
              supabase.from('users').select('phone, name').in('phone', akPhones),
              supabase.from('khata_entries').select('phone, id, type, created_at').in('phone', akPhones).order('created_at', { ascending: false }),
              supabase.from('subscribers').select('phone').in('phone', akPhones)
            ])
          : [{ data: [] }, { data: [] }, { data: [] }];
        const akUMap = {}, akTMap = {};
        const akSubSet = new Set((akSubs || []).map(s => s.phone));
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
          last_recharge_at: akTMap[r.phone]?.lastRecharge || null,
          is_subscriber:    akSubSet.has(r.phone)
        }));
        return res.json({ success: true, khata: enriched });
      }

      case 'getSettings':
        { const { data: rows } = await supabase.from('admin_settings').select('*');
          const map = {};
          for (const r of (rows || [])) { try { map[r.key] = JSON.parse(r.value); } catch { map[r.key] = r.value; } }
          return res.json({ success: true, settings: {
            cutoff:              map['order_cutoff_config']   || {},
            weeklySchedule:      map['weekly_schedule']       || [],
            khataEnabled:        map['khata_enabled']         === true,
            deliveryZone:        map['delivery_zone']         || null,
            autoTiffinCutoff:    map['auto_tiffin_cutoff']   || { morning: '11:00', evening: '18:00' },
            deliveryAreas:       map['delivery_areas']        || [],
            referralReferrerPct: parseInt(map['referral_referrer_pct'] || '10'),
            referralNewUserPct:  parseInt(map['referral_new_user_pct'] || '15')
          }}); }

      case 'getDeliveryAreas': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key','delivery_areas').single();
        if (!row?.value) return res.json({ success: false, error: 'No delivery areas configured' });
        let areas = [];
        try { areas = JSON.parse(row.value); } catch(_) {}
        if (!areas.length) return res.json({ success: false, error: 'No delivery areas configured' });
        return res.json({ success: true, areas });
      }

      // ── PUBLIC — no auth required ──────────────────────────────────────────
      // Returns only the three fields the customer portal needs.
      // Intentionally excludes sensitive admin data: cutoff config, weekly schedule,
      // khata toggle, and any future staff-only keys added to getSettings.
      case 'getPublicSettings': {
        const [zoneRaw, cutoffRaw, areasRaw, referrerPctRaw, newUserPctRaw] = await Promise.all([
          getCachedSetting('delivery_zone'),
          getCachedSetting('auto_tiffin_cutoff'),
          getCachedSetting('delivery_areas'),
          getCachedSetting('referral_referrer_pct'),
          getCachedSetting('referral_new_user_pct'),
        ]);
        let deliveryZone     = null;
        let autoTiffinCutoff = { morning: '11:00', evening: '18:00' };
        let deliveryAreas    = [];
        try { if (zoneRaw)   deliveryZone     = JSON.parse(zoneRaw);   } catch (_) {}
        try { if (cutoffRaw) autoTiffinCutoff = JSON.parse(cutoffRaw); } catch (_) {}
        try { if (areasRaw)  deliveryAreas    = JSON.parse(areasRaw);  } catch (_) {}
        const referralReferrerPct = parseInt(referrerPctRaw || '10');
        const referralNewUserPct  = parseInt(newUserPctRaw  || '15');
        return res.json({ success: true, settings: { deliveryZone, autoTiffinCutoff, deliveryAreas, referralReferrerPct, referralNewUserPct } });
      }

      case 'setDeliveryAreas': {
        const areas = data.areas;
        if (!Array.isArray(areas) || areas.length === 0) return res.json({ success: false, error: 'At least one area required' });
        const cleaned = areas.map(a => String(a).trim()).filter(Boolean);
        await supabase.from('admin_settings').upsert({ key: 'delivery_areas', value: JSON.stringify(cleaned), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        _invalidateSettingsCache(); _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'adminResetUserPassword':
        { const pwErr3 = _validatePassword(data.newPassword);
          if (pwErr3) return res.json({ success: false, error: pwErr3 });
          const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
          await supabase.from('users').update({ password_hash: hash }).eq('phone', cleanPhone(data.phone));
          return res.json({ success: true }); }

      // ── Help Videos (TiffoTube) ──────────────────────────────────────────

      // Merged endpoint for help.html — 1 HTTP request, 2 parallel Supabase queries.
      // Admin panel still uses getHelpCategories / getHelpVideos separately (unchanged).
      case 'getHelpData': {
        const [catsResult, videosResult] = await Promise.all([
          supabase.from('help_video_categories')
            .select('slug,label,color,bg_color,sort_order')
            .order('sort_order', { ascending: true }),
          supabase.from('help_videos')
            .select('id,title,youtube_url,category,description,order_index')
            .order('order_index', { ascending: true })
        ]);
        if (catsResult.error)   return res.json({ success: false, error: catsResult.error.message });
        if (videosResult.error) return res.json({ success: false, error: videosResult.error.message });
        return res.json({ success: true, categories: catsResult.data || [], videos: videosResult.data || [] });
      }

      case 'getHelpCategories': {
        const { data: rows, error } = await supabase
          .from('help_video_categories')
          .select('slug,label,color,bg_color,sort_order')
          .order('sort_order', { ascending: true });
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true, categories: rows || [] });
      }

      case 'addHelpCategory': {
        const { label, color, bg_color } = data;
        if (!label || !label.trim()) return res.json({ success: false, error: 'label required' });
        // Generate slug from label: lowercase, alphanumeric+underscore only
        const slug = label.trim().toLowerCase()
          .replace(/[^a-z0-9]+/g, '_')
          .replace(/^_+|_+$/g, '')
          .slice(0, 40);
        if (!slug) return res.json({ success: false, error: 'Invalid label — use letters/numbers' });
        // Check duplicate slug + get max sort_order in parallel (was 2 sequential reads)
        const [{ data: existing }, { data: maxRow }] = await Promise.all([
          supabase.from('help_video_categories').select('id').eq('slug', slug).maybeSingle(),
          supabase.from('help_video_categories').select('sort_order')
            .order('sort_order', { ascending: false }).limit(1).maybeSingle()
        ]);
        if (existing) return res.json({ success: false, error: `Category "${slug}" already exists` });
        const nextOrder = (maxRow?.sort_order ?? -1) + 1;
        const { error } = await supabase.from('help_video_categories').insert({
          slug,
          label:     label.trim(),
          color:     color     || '#475569',
          bg_color:  bg_color  || '#f1f5f9',
          sort_order: nextOrder
        });
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true, slug });
      }

      case 'deleteHelpCategory': {
        const { slug } = data;
        if (!slug) return res.json({ success: false, error: 'slug required' });
        // Safety: prevent deleting 'general' (fallback category)
        if (slug === 'general') return res.json({ success: false, error: 'Cannot delete the "general" category' });
        // Reassign videos in this category to 'general' before deleting
        await supabase.from('help_videos').update({ category: 'general' }).eq('category', slug);
        const { error } = await supabase.from('help_video_categories').delete().eq('slug', slug);
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true });
      }

      case 'getHelpVideos': {
        const { data: rows, error } = await supabase
          .from('help_videos')
          .select('id,title,youtube_url,category,description,order_index')
          .order('order_index', { ascending: true });
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true, videos: rows || [] });
      }

      case 'addHelpVideo': {
        const { title, youtube_url, category, description } = data;
        if (!title || !youtube_url) return res.json({ success: false, error: 'title and youtube_url required' });
        // Dynamic category validation from DB
        const { data: catRow } = await supabase
          .from('help_video_categories').select('slug').eq('slug', category || 'general').maybeSingle();
        const safeCategory = catRow ? catRow.slug : 'general';
        // Use maybeSingle() — returns null (not an error) when table is empty
        const { data: maxRow } = await supabase
          .from('help_videos').select('order_index')
          .order('order_index', { ascending: false }).limit(1).maybeSingle();
        const nextOrder = (maxRow?.order_index ?? -1) + 1;
        const { error } = await supabase.from('help_videos').insert({
          title:       title.trim(),
          youtube_url: youtube_url.trim(),
          category:    safeCategory,
          description: (description || '').trim(),
          order_index: nextOrder
        });
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true });
      }

      case 'updateHelpVideo': {
        const { id, title, youtube_url, category, description } = data;
        if (!id) return res.json({ success: false, error: 'id required' });
        const updates = {};
        if (title)       updates.title       = title.trim();
        if (youtube_url) updates.youtube_url = youtube_url.trim();
        if (category) {
          // Dynamic category validation from DB
          const { data: catRow } = await supabase
            .from('help_video_categories').select('slug').eq('slug', category).maybeSingle();
          if (catRow) updates.category = catRow.slug;
        }
        if (description !== undefined) updates.description = description.trim();
        if (!Object.keys(updates).length) return res.json({ success: false, error: 'No fields to update' });
        const { error } = await supabase.from('help_videos').update(updates).eq('id', id);
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true });
      }

      case 'deleteHelpVideo': {
        const { id } = data;
        if (!id) return res.json({ success: false, error: 'id required' });
        const { error } = await supabase.from('help_videos').delete().eq('id', id);
        if (error) return res.json({ success: false, error: error.message });
        return res.json({ success: true });
      }

      case 'reorderHelpVideos': {
        const { ordered_ids } = data;
        if (!Array.isArray(ordered_ids) || !ordered_ids.length)
          return res.json({ success: false, error: 'ordered_ids must be a non-empty array' });
        // Validate all IDs are safe integers before touching DB
        const safeIds = ordered_ids.map(id => parseInt(id, 10)).filter(id => Number.isFinite(id) && id > 0);
        if (safeIds.length !== ordered_ids.length)
          return res.json({ success: false, error: 'Invalid id in ordered_ids' });
        const results = await Promise.all(
          safeIds.map((id, idx) =>
            supabase.from('help_videos').update({ order_index: idx }).eq('id', id)
          )
        );
        const failed = results.find(r => r.error);
        if (failed) return res.json({ success: false, error: failed.error.message });
        return res.json({ success: true });
      }
      // ── End Help Videos ──────────────────────────────────────────────────

      case 'adminSetUserAddress': {
        const phone = cleanPhone(data.phone);
        if (!phone) return res.json({ success: false, error: 'Phone required' });
        const addr = (data.address || '').trim();
        const area = (data.area || _extractArea(addr)).trim();
        if (!addr) return res.json({ success: false, error: 'Address cannot be empty' });
        await supabase.from('users').update({ address: addr, area }).eq('phone', phone);
        return res.json({ success: true });
      }

      case 'adminSetUserRating': {
        const phone = cleanPhone(data.phone);
        if (!phone) return res.json({ success: false, error: 'Phone required' });
        const score = Math.max(0, Math.min(10, parseInt(data.manual_score ?? 5)));
        // Only update manual_score + updated_at — never overwrite lifetime_spend or last_order_date
        // which are maintained automatically by order create/reject triggers.
        const { data: existing } = await supabase
          .from('user_ratings').select('lifetime_spend, last_order_date').eq('phone', phone).single();
        const { error: rErr } = await supabase.from('user_ratings').upsert(
          {
            phone,
            manual_score:    score,
            lifetime_spend:  existing?.lifetime_spend  || 0,
            last_order_date: existing?.last_order_date || null,
            updated_at:      new Date().toISOString()
          },
          { onConflict: 'phone' }
        );
        if (rErr) throw new Error('DB error: ' + rErr.message);

        // Recompute full Tiffo Score and sync to users.rating (non-fatal)
        let newTotal = 0;
        try { newTotal = await _recomputeAndSyncRating(phone); } catch (_) {}

        return res.json({ success: true, rating: newTotal });
      }

      case 'adminRecomputeAllRatings': {
        // Efficient bulk recompute — 6 DB round-trips total regardless of user count.
        // Triggered by admin sorting All Users by Top/Low Rating (max once per 6h via client throttle).
        //
        // Strategy: fetch all data in parallel, compute scores in JS, write back in bulk.
        // No per-user DB calls — O(1) DB round-trips instead of O(n).
        const today30ago = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
        const now = new Date().toISOString();

        // ── Round-trip 1: fetch all source data in parallel ──────────────────
        const [
          { data: allUsers },
          { data: allRatings },
          { data: allWallets },
          { data: allSubs },
          { data: recentOrders30 }
        ] = await Promise.all([
          supabase.from('users').select('phone'),
          supabase.from('user_ratings').select('phone, lifetime_spend, last_order_date, manual_score'),
          supabase.from('khata_summary').select('phone, balance'),
          supabase.from('subscribers').select('phone, created_at'),
          supabase.from('orders')
            .select('phone, final_amount, date')
            .neq('order_status', 'cancelled')
            .neq('order_status', 'rejected')
            .gte('date', today30ago)
        ]);

        if (!allUsers || allUsers.length === 0) return res.json({ success: true, updated: 0 });

        // ── Build lookup maps ─────────────────────────────────────────────────
        const ratingMap  = {};
        for (const r of (allRatings  || [])) ratingMap[r.phone]  = r;
        const walletMap  = {};
        for (const w of (allWallets  || [])) walletMap[w.phone]  = parseFloat(w.balance) || 0;
        const subMap     = {};
        for (const s of (allSubs     || [])) subMap[s.phone]     = s;
        const order30Map = {};
        for (const o of (recentOrders30 || [])) {
          order30Map[o.phone] = (order30Map[o.phone] || 0) + 1;
        }

        // ── Step 1: backfill user_ratings rows for users who have none ────────
        const ratedPhones   = new Set(Object.keys(ratingMap));
        const missingPhones = allUsers.map(u => u.phone).filter(p => !ratedPhones.has(p));
        let backfilled = 0;

        if (missingPhones.length > 0) {
          // Need lifetime spend for missing phones — fetch ALL their orders (not just 30d)
          const { data: lifetimeOrders } = await supabase
            .from('orders')
            .select('phone, final_amount, date')
            .in('phone', missingPhones)
            .neq('order_status', 'cancelled')
            .neq('order_status', 'rejected');

          const spendMap = {};
          for (const o of (lifetimeOrders || [])) {
            if (!spendMap[o.phone]) spendMap[o.phone] = { spend: 0, lastDate: null };
            spendMap[o.phone].spend += (o.final_amount || 0);
            if (!spendMap[o.phone].lastDate || o.date > spendMap[o.phone].lastDate)
              spendMap[o.phone].lastDate = o.date;
          }

          const upsertRows = missingPhones.map(p => ({
            phone:           p,
            lifetime_spend:  spendMap[p]?.spend || 0,
            last_order_date: spendMap[p]?.lastDate || null,
            manual_score:    5,
            updated_at:      now
          }));
          // Patch ratingMap so the score computation below picks up the new rows
          for (const row of upsertRows) ratingMap[row.phone] = row;

          // Batch upsert in chunks of 100
          for (let i = 0; i < upsertRows.length; i += 100) {
            await supabase.from('user_ratings').upsert(upsertRows.slice(i, i + 100), { onConflict: 'phone' });
          }
          backfilled = missingPhones.length;
        }

        // ── Step 2: compute scores for all users in JS (zero extra DB calls) ──
        const userUpdates = []; // { phone, rating }
        for (const u of allUsers) {
          const p       = u.phone;
          const rRow    = ratingMap[p]  || {};
          const walBal  = walletMap[p]  || 0;
          const recent30 = order30Map[p] || 0;
          const sub     = subMap[p];
          const spend   = parseFloat(rRow.lifetime_spend) || 0;

          const p1 = Math.round(Math.min(walBal  / 500,   1) * 20);
          const p2 = Math.round(Math.min(spend   / 10000, 1) * 30);
          const p3 = Math.round(Math.min(recent30 / 30,   1) * 25);
          let p4 = 0;
          if (sub?.created_at) {
            const days = Math.floor((Date.now() - new Date(sub.created_at)) / 86400000);
            p4 = days >= 90 ? 15 : days >= 30 ? 12 : 8;
          }
          const p5    = Math.max(0, Math.min(10, rRow.manual_score ?? 5));
          const total = Math.min(p1 + p2 + p3 + p4 + p5, 100);
          userUpdates.push({ phone: p, rating: total });
        }

        // ── Single RPC call: bulk-write all users.rating in one SQL statement ──
        // bulk_update_ratings() uses unnest() — O(1) round-trips regardless of N.
        const p_phones  = userUpdates.map(u => u.phone);
        const p_ratings = userUpdates.map(u => u.rating);
        const { data: rpcUpdated, error: rpcErr } = await supabase.rpc('bulk_update_ratings', {
          p_phones,
          p_ratings
        });

        // Graceful fallback: if RPC not yet deployed, fall back to parallel chunks
        if (rpcErr) {
          console.warn('[adminRecomputeAllRatings] bulk_update_ratings RPC unavailable, using fallback:', rpcErr.message);
          for (let i = 0; i < userUpdates.length; i += 100) {
            const chunk = userUpdates.slice(i, i + 100);
            await Promise.all(
              chunk.map(u => supabase.from('users').update({ rating: u.rating }).eq('phone', u.phone))
            );
          }
        }

        return res.json({ success: true, updated: rpcErr ? userUpdates.length : (rpcUpdated || userUpdates.length), backfilled, total: allUsers.length });
      }

      case 'adminGetUserRating': {
        // Admin panel calls this to get a full live breakdown for any user.
        // Requires staff session token.
        const phone = cleanPhone(data.phone);
        if (!phone) return res.json({ success: false, error: 'Phone required' });

        const today30ago = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
        const [
          { data: ratingRow },
          { data: walRow },
          { data: subRow },
          { data: recentOrders, error: ordErr }
        ] = await Promise.all([
          supabase.from('user_ratings').select('lifetime_spend, last_order_date, manual_score').eq('phone', phone).single(),
          supabase.from('khata_summary').select('balance').eq('phone', phone).single(),
          supabase.from('subscribers').select('created_at').eq('phone', phone).single(),
          supabase.from('orders')
            .select('order_id')
            .eq('phone', phone)
            .neq('order_status', 'cancelled')
            .neq('order_status', 'rejected')
            .gte('date', today30ago)
        ]);

        const walletBal = parseFloat(walRow?.balance) || 0;
        const recent30  = ordErr ? 0 : (recentOrders || []).length;

        const p1 = Math.round(Math.min(walletBal / 500, 1) * 20);
        const spend = parseFloat(ratingRow?.lifetime_spend) || 0;
        const p2 = Math.round(Math.min(spend / 10000, 1) * 30);
        const p3 = Math.round(Math.min(recent30 / 30, 1) * 25);
        let p4 = 0;
        if (subRow?.created_at) {
          const subDays = Math.floor((Date.now() - new Date(subRow.created_at)) / 86400000);
          if (subDays >= 90)      p4 = 15;
          else if (subDays >= 30) p4 = 12;
          else                    p4 = 8;
        }
        const p5    = Math.max(0, Math.min(10, ratingRow?.manual_score || 0));
        const total = Math.min(p1 + p2 + p3 + p4 + p5, 100);

        let badge = 'Inactive';
        if (total >= 80)      badge = 'Champion';
        else if (total >= 60) badge = 'Loyal';
        else if (total >= 40) badge = 'Developing';
        else if (total >= 20) badge = 'At Risk';

        // Also sync users.rating with the freshly computed value (non-fatal)
        supabase.from('users').update({ rating: total }).eq('phone', phone).then(() => {}).catch(() => {});

        return res.json({
          success:   true,
          rating:    total,
          breakdown: {
            wallet:       { score: p1, max: 20,  value: Math.round(walletBal) },
            spend:        { score: p2, max: 30,  value: Math.round(spend) },
            consistency:  { score: p3, max: 25,  value: recent30 },
            subscription: { score: p4, max: 15 },
            manual:       { score: p5, max: 10 }
          },
          badge
        });
      }

      case 'deleteNotificationRange': {
        // Server-side guard: validate from/to before touching DB
        if (!data.from || !data.to) return res.json({ success: false, error: 'from and to dates required' });
        const _dateRe = /^\d{4}-\d{2}-\d{2}$/;
        if (!_dateRe.test(data.from) || !_dateRe.test(data.to)) {
          return res.json({ success: false, error: 'Invalid date format. Use YYYY-MM-DD' });
        }
        if (data.from > data.to) return res.json({ success: false, error: 'from must be before to' });
        // Respects read_only flag — only deletes read notifications, never unread
        // ALWAYS excludes today's notifications regardless of read status
        // IST midnight = today's IST date at 00:00 IST = (IST date string + 'T00:00:00+05:30')
        // Correct: parse ISO string with explicit IST offset so JS gives the right UTC epoch.
        const todayISTDateStr = istDateStr(ist); // e.g. "2024-01-15"
        const todayStart = new Date(todayISTDateStr + 'T00:00:00+05:30'); // IST midnight as UTC
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

        const MIN_DAYS = { orders: 35, transactions: 35, notifications: 1 };
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
      case 'adminDeleteUser': {
        const phone = cleanPhone(data.phone);
        // Delete all user-owned data in parallel before removing the user row.
        // user_ratings and referral notifications are also cleaned to avoid orphaned data.
        await Promise.all([
          supabase.from('orders').delete().eq('phone', phone),
          supabase.from('subscribers').delete().eq('phone', phone),
          supabase.from('khata_summary').delete().eq('phone', phone),
          supabase.from('khata_entries').delete().eq('phone', phone),
          supabase.from('nu_coupon_sent').delete().eq('phone', phone),
          supabase.from('user_ratings').delete().eq('phone', phone),
          // Referral notifications: group_id = referrerPhone_newPhone — clean both roles
          supabase.from('notifications').delete().like('group_id', phone + '_%'),
          supabase.from('notifications').delete().like('group_id', '%_' + phone),
        ]);
        await supabase.from('users').delete().eq('phone', phone);
        return res.json({ success: true });
      }

      // ─── KITCHEN / COOKING SUMMARY ───────────────────────────────────────
      // getCookingSummary: aggregate item quantities from orders in a time range,
      // excluding orders already locked in a cooking session.
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
      case 'getCookingSessionDetail': {
        const orderIds = data.orderIds || [];
        if (!orderIds.length) return res.json({ success: true, orders: [], summary: [] });

        // Parallel: orders + menu_items for unit enrichment.
        // menu_items uses server-side cache if warm — no extra DB hit on hot cache.
        const _sdNow = Date.now();
        const _sdMenuCacheHit = _menuItemsCache && (_sdNow - _menuItemsCacheTs) < _MENU_ITEMS_TTL;

        const [
          { data: rows, error },
          menuUnitRowsSDRaw
        ] = await Promise.all([
          supabase.from('orders')
            .select('order_id,name,phone,address,items,slot,order_status,payment_mode,final_amount,date')
            .in('order_id', orderIds),
          _sdMenuCacheHit
            ? Promise.resolve(_menuItemsCache)
            : supabase.from('menu_items').select('item_id, name, stock_unit, stock_unit_label').then(r => r.data)
        ]);

        if (error) return res.json({ success: false, error: error.message });

        const menuUnitRowsSD = Array.isArray(menuUnitRowsSDRaw) ? menuUnitRowsSDRaw : (menuUnitRowsSDRaw || []);
        const menuUnitMapSD = _buildMenuUnitMap(menuUnitRowsSD);

        const orders = (rows || []).map(o => ({
          ...o,
          items: typeof o.items === 'string' ? _safeJsonParse(o.items, []) : (o.items || [])
        }));

        // Aggregate item quantities using shared unit helpers.
        // Correctly handles: variant-label items ("50 Gram"), stock_unit items (piece/kg/litre/custom),
        // cart items carrying stock_unit, and legacy bare-qty items.
        function _parseVQL(variantLabel) {
          if (!variantLabel) return null;
          const m = String(variantLabel).match(/^(\d+(?:\.\d+)?)\s+([A-Za-z]+)/);
          if (!m) return null;
          return { numQty: parseFloat(m[1]), unit: m[2] };
        }
        const itemMap = {};
        orders.forEach(o => {
          const seenKeysInOrder = new Set();
          (o.items || []).forEach(i => {
            const key     = (i.name || i.item_id || 'Unknown').trim();
            const rawQty  = i.qty ?? i.quantity ?? i.count ?? i.amount ?? null;
            const cartQty = rawQty !== null && rawQty !== undefined ? parseFloat(rawQty) || 1 : 1;
            const parsed  = _parseVQL(i.variantLabel || i.variant_label || '');
            const realQty = parsed ? parsed.numQty * cartQty : cartQty;
            const unit    = _resolveKitchenUnit(parsed?.unit || null, key, menuUnitMapSD, i);
            if (!itemMap[key]) itemMap[key] = { name: key, variantLabel: i.variantLabel || '', unit, qty: 0, orders: 0 };
            itemMap[key].qty += realQty;
            if (!seenKeysInOrder.has(key)) { itemMap[key].orders += 1; seenKeysInOrder.add(key); }
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

        // Lock exclusion: fetch ALL sessions for the date range regardless of slot.
        // A locked order_id must be excluded from ANY slot view — the session's slot tag
        // reflects the admin UI filter at lock-time, NOT the orders' actual slot values.
        // Slot separation is handled entirely by summaryQuery filtering orders by slot field.
        const lockQuery = supabase.from('cooking_sessions').select('locked_order_ids')
          .lte('from_date', toDate).gte('to_date', fromDate);

        // Session list query: for the Cooking Sessions history panel.
        // 'all' filter → show every session. 'morning'/'evening' → exact match only.
        // Do NOT include slot='all' sessions in morning/evening views — session.slot
        // is the admin's UI choice at lock-time, not derived from order content,
        // so mixing 'all' sessions into slot-specific panels causes false bleed-through.
        let sesListQuery = supabase.from('cooking_sessions').select('*')
          .lte('from_date', toDate).gte('to_date', fromDate).order('created_at', { ascending: false });
        if (slot === 'morning') sesListQuery = sesListQuery.eq('slot', 'morning');
        else if (slot === 'evening') sesListQuery = sesListQuery.eq('slot', 'evening');

        // menu_items for unit enrichment — use server-side cache if warm (avoids extra DB hit).
        // Cache is invalidated on any menu change, so unit data is always consistent.
        const _kdNow = Date.now();
        const _kdMenuCacheHit = _menuItemsCache && (_kdNow - _menuItemsCacheTs) < _MENU_ITEMS_TTL;

        const [
          { data: lockSessions },
          { data: orders },
          { data: allSessions, error: sesErr },
          menuUnitRowsRaw
        ] = await Promise.all([
          lockQuery,
          summaryQuery,
          sesListQuery,
          _kdMenuCacheHit
            ? Promise.resolve(_menuItemsCache)
            : supabase.from('menu_items').select('item_id, name, stock_unit, stock_unit_label').then(r => r.data)
        ]);

        const menuUnitRows = Array.isArray(menuUnitRowsRaw) ? menuUnitRowsRaw : (menuUnitRowsRaw?.data || menuUnitRowsRaw || []);
        // Build unit map using shared helper (name → {unit, label})
        const menuUnitMapKD = _buildMenuUnitMap(menuUnitRows);

        // ── Build locked set ──────────────────────────────────────────────
        const lockedIds = new Set();
        (lockSessions || []).forEach(s => {
          (s.locked_order_ids || []).forEach(id => lockedIds.add(id));
        });

        // ── Aggregate quantities ──────────────────────────────────────────
        // Unit resolution (via _resolveKitchenUnit):
        //   1. variantLabel parse ("50 Gram" → "Gram") — legacy variant items
        //   2. stock_unit from menu_items  ("piece" → "pcs", "kg" → "kg", etc.)
        //   3. stock_unit carried in cart item JSON
        //   4. item.unit / item.variant fields (legacy fallback)
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
          const seenKeysInOrder = new Set();
          items.forEach(item => {
            const key     = (item.name || item.item_name || 'Unknown').trim();
            const rawQty  = item.qty != null ? item.qty : (item.quantity != null ? item.quantity : (item.count != null ? item.count : null));
            const cartQty = rawQty !== null ? parseFloat(rawQty) || 1 : 1;
            const parsed  = _parseVQU(item.variantLabel || item.variant_label || '');
            const realQty = parsed ? parsed.numQty * cartQty : cartQty;
            const unit    = _resolveKitchenUnit(parsed?.unit || null, key, menuUnitMapKD, item);
            if (!summary[key]) summary[key] = { name: key, totalQty: 0, unit, orders: 0 };
            summary[key].totalQty += realQty;
            if (!seenKeysInOrder.has(key)) { summary[key].orders += 1; seenKeysInOrder.add(key); }
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

      // ─── EARNING REPORT (admin-only) ─────────────────────────────────────
      // Returns orders grouped by date → slot → payment_mode for a date range.
      // Excludes cancelled and rejected orders — only revenue-generating orders.
      // payment_mode values: 'wallet' | 'upi' | 'upi_insuf' | 'unpaid'
      case 'getEarningReport': {
        const fromDate = data.fromDate || istDateStr(ist);
        const toDate   = data.toDate   || fromDate;
        // Validate date format YYYY-MM-DD
        const dateRe = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRe.test(fromDate) || !dateRe.test(toDate)) {
          return res.json({ success: false, error: 'Invalid date format. Use YYYY-MM-DD' });
        }
        if (fromDate > toDate) {
          return res.json({ success: false, error: 'fromDate must be <= toDate' });
        }

        const { data: rows, error: rErr } = await supabase
          .from('orders')
          .select('order_id, name, phone, slot, payment_mode, payment_status, final_amount, order_status, date, time, items, source')
          .gte('date', fromDate)
          .lte('date', toDate)
          .neq('order_status', 'cancelled')
          .neq('order_status', 'rejected')
          .order('date', { ascending: false })
          .order('created_at', { ascending: false });

        if (rErr) throw new Error('DB error: ' + rErr.message);

        // ── Fetch wallet recharges for the same date range ───────────────────
        // Recharges = real cash physically received on that day.
        // We attach dayRechargeCash to each day so the frontend can show:
        //   True Day Cash = recharges_that_day + upi + upi_insuf + unpaid
        // (wallet orders are excluded from day cash — cash was collected at recharge time)
        const { data: rechargeRows } = await supabase
          .from('khata_entries')
          .select('date, amount')
          .eq('type', 'recharge')
          .gte('date', fromDate)
          .lte('date', toDate);
        // Build a date → total recharge map
        const rechargeDateMap = {};
        for (const r of (rechargeRows || [])) {
          const d = String(r.date).slice(0, 10);
          rechargeDateMap[d] = (rechargeDateMap[d] || 0) + (Number(r.amount) || 0);
        }

        // ── Group in JS: date → slot → payment_mode → orders[] ──────────────
        // payment_mode normalisation:
        //   'wallet'    → subscriber paid via wallet
        //   'upi'       → paid via UPI (daily user OR subscriber with upi_insuf)
        //   'upi_insuf' → subscriber chose UPI due to insufficient wallet
        //   'unpaid'    → bulk udhar (subscription debt)
        //   null/other  → treat as 'upi'
        const dateMap = {};  // { 'YYYY-MM-DD': { morning: { wallet:[], upi:[], upi_insuf:[], unpaid:[] }, evening: {…} } }

        for (const o of (rows || [])) {
          const d    = o.date ? String(o.date).slice(0, 10) : 'unknown';
          const slot = (o.slot === 'evening') ? 'evening' : 'morning';
          const mode = ['wallet', 'upi', 'upi_insuf', 'unpaid'].includes(o.payment_mode)
            ? o.payment_mode : 'upi';

          if (!dateMap[d]) dateMap[d] = {};
          if (!dateMap[d][slot]) dateMap[d][slot] = { wallet: [], upi: [], upi_insuf: [], unpaid: [] };

          dateMap[d][slot][mode].push({
            order_id:       o.order_id,
            name:           o.name || '',
            phone:          o.phone || '',
            final_amount:   Number(o.final_amount) || 0,
            payment_mode:   mode,
            payment_status: o.payment_status || '',
            order_status:   o.order_status || '',
            slot:           o.slot || 'morning',
            time:           o.time || '',
            source:         o.source || 'user',
            items:          typeof o.items === 'string' ? _safeJsonParse(o.items, []) : (o.items || [])
          });
        }

        // ── Build structured response with subtotals at every layer ──────────
        const report = [];
        // Include ALL dates that have either orders OR recharges (don't drop recharge-only days)
        const allDatesSet = new Set([...Object.keys(dateMap), ...Object.keys(rechargeDateMap)]);
        const allDates = [...allDatesSet].sort().reverse(); // newest first

        for (const date of allDates) {
          const dayEntry = { date, slots: [], dayTotal: 0, dayCounts: {} };

          for (const slot of ['morning', 'evening']) {
            if (!dateMap[date]?.[slot]) continue;
            const slotData = dateMap[date][slot];
            const slotEntry = { slot, modes: {}, slotTotal: 0, slotCounts: {}, slotTrueCash: 0 };

            for (const mode of ['wallet', 'upi', 'upi_insuf', 'unpaid']) {
              const orders = slotData[mode];
              if (!orders.length) continue;
              const modeTotal = orders.reduce((s, o) => s + o.final_amount, 0);
              // paidTotal: only orders where admin marked payment_status = 'paid'
              // wallet: all recharges count (collected by admin via any method)
              const paidTotal = mode === 'wallet'
                ? modeTotal
                : orders.reduce((s, o) => s + (o.payment_status === 'paid' ? o.final_amount : 0), 0);
              const paidCount = mode === 'wallet'
                ? orders.length
                : orders.filter(o => o.payment_status === 'paid').length;
              slotEntry.modes[mode] = { orders, total: modeTotal, count: orders.length, paidTotal, paidCount };
              slotEntry.slotTotal  += modeTotal;
              slotEntry.slotCounts[mode] = orders.length;
              // slotTrueCash: wallet excluded (cash collected at recharge), others only if admin marked paid
              if (mode !== 'wallet') slotEntry.slotTrueCash += paidTotal;
            }

            // Combined UPI (upi + upi_insuf) for easy bank reconciliation
            const upiOrders    = slotData['upi']       || [];
            const upiInsufOrds = slotData['upi_insuf'] || [];
            slotEntry.upiCombinedTotal = upiOrders.reduce((s,o)=>s+o.final_amount,0)
                                       + upiInsufOrds.reduce((s,o)=>s+o.final_amount,0);
            slotEntry.upiCombinedCount = upiOrders.length + upiInsufOrds.length;

            dayEntry.slots.push(slotEntry);
            dayEntry.dayTotal += slotEntry.slotTotal;
            for (const [mode, cnt] of Object.entries(slotEntry.slotCounts)) {
              dayEntry.dayCounts[mode] = (dayEntry.dayCounts[mode] || 0) + cnt;
            }
          }

          // Day-level combined UPI
          dayEntry.dayUpiCombinedTotal = dayEntry.slots.reduce((s, sl) => s + sl.upiCombinedTotal, 0);
          dayEntry.dayUpiCombinedCount = dayEntry.slots.reduce((s, sl) => s + sl.upiCombinedCount, 0);

          // ── True Cash / Earnings for the day ────────────────────────────
          // NEW LOGIC (v79): Only orders where admin explicitly marked payment_status='paid'
          // are counted in earnings. This gives a real-money-in-hand picture.
          //
          // dayTrueCash = recharges collected that day          ← all recharges (admin credits wallet)
          //             + UPI orders   (payment_status='paid')  ← admin confirmed payment received
          //             + UPI_insuf    (payment_status='paid')  ← admin confirmed payment received
          //             + Udhar/unpaid (payment_status='paid')  ← admin confirmed cash collected
          // wallet orders EXCLUDED — cash was already counted when subscriber recharged
          const dayUpiPaid    = dayEntry.slots.reduce((s, sl) => s + (sl.modes['upi']?.paidTotal       || 0), 0);
          const dayInsufPaid  = dayEntry.slots.reduce((s, sl) => s + (sl.modes['upi_insuf']?.paidTotal  || 0), 0);
          const dayUdharPaid  = dayEntry.slots.reduce((s, sl) => s + (sl.modes['unpaid']?.paidTotal     || 0), 0);
          // Keep old totals for display reference (all orders, not just paid)
          const dayUpiTotal   = dayEntry.slots.reduce((s, sl) => s + (sl.modes['upi']?.total       || 0), 0);
          const dayInsufTotal = dayEntry.slots.reduce((s, sl) => s + (sl.modes['upi_insuf']?.total  || 0), 0);
          const dayUdharTotal = dayEntry.slots.reduce((s, sl) => s + (sl.modes['unpaid']?.total     || 0), 0);
          dayEntry.dayRechargeCash = rechargeDateMap[date] || 0;
          dayEntry.dayUpiPaid      = dayUpiPaid;
          dayEntry.dayInsufPaid    = dayInsufPaid;
          dayEntry.dayUdharPaid    = dayUdharPaid;
          dayEntry.dayTrueCash     = dayEntry.dayRechargeCash + dayUpiPaid + dayInsufPaid + dayUdharPaid;

          report.push(dayEntry);
        }

        // ── Grand totals across the entire range ─────────────────────────────
        const grandTotal    = report.reduce((s, d) => s + d.dayTotal, 0);
        const grandCounts   = {};
        for (const d of report) {
          for (const [mode, cnt] of Object.entries(d.dayCounts)) {
            grandCounts[mode] = (grandCounts[mode] || 0) + cnt;
          }
        }
        const grandUpiCombinedTotal  = report.reduce((s, d) => s + d.dayUpiCombinedTotal, 0);
        const grandUpiCombinedCount  = report.reduce((s, d) => s + d.dayUpiCombinedCount, 0);
        // grandRechargeCash = ALL recharges in range (including recharge-only days, now included)
        const grandRechargeCash = report.reduce((s, d) => s + d.dayRechargeCash, 0);
        const grandTrueCash     = report.reduce((s, d) => s + d.dayTrueCash,     0);
        // Paid-only breakdowns (admin-confirmed payments only)
        const grandUpiPaid    = report.reduce((s, d) => s + d.dayUpiPaid,    0);
        const grandInsufPaid  = report.reduce((s, d) => s + d.dayInsufPaid,  0);
        const grandUdharPaid  = report.reduce((s, d) => s + d.dayUdharPaid,  0);

        return res.json({
          success: true,
          fromDate, toDate,
          report,
          grandTotal,
          grandCounts,
          grandUpiCombinedTotal,
          grandUpiCombinedCount,
          grandRechargeCash,
          grandTrueCash,
          grandUpiPaid,
          grandInsufPaid,
          grandUdharPaid,
          totalOrders: (rows || []).length
        });
      }

      // ─────────────────────────────────────────────────────────────────────
      case 'getWalletRechargeReport': {
        // Real bank income = wallet recharges only (type='recharge' in khata_entries).
        // Rejected order refunds are internal wallet adjustments — cash was already
        // collected at recharge time, so they do NOT reduce bank earnings. Ignored here.
        const fromDate = data.fromDate || istDateStr(ist);
        const toDate   = data.toDate   || fromDate;
        const dateRe   = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRe.test(fromDate) || !dateRe.test(toDate))
          return res.json({ success: false, error: 'Invalid date format. Use YYYY-MM-DD' });
        if (fromDate > toDate)
          return res.json({ success: false, error: 'fromDate must be <= toDate' });

        // Fetch only recharge entries (real cash-in events)
        const { data: rechargeRows, error: rErr } = await supabase
          .from('khata_entries')
          .select('id, phone, type, amount, note, date, time, order_id, source, created_at')
          .eq('type', 'recharge')
          .gte('date', fromDate)
          .lte('date', toDate)
          .order('date', { ascending: false })
          .order('created_at', { ascending: false });
        if (rErr) throw new Error('DB error: ' + rErr.message);

        // Lookup customer names
        const phones = [...new Set((rechargeRows||[]).map(r => r.phone))];
        let nameMap = {};
        if (phones.length > 0) {
          const { data: users } = await supabase
            .from('users').select('phone, name').in('phone', phones);
          for (const u of (users||[])) nameMap[u.phone] = u.name || u.phone;
        }

        // Group by date (newest first)
        const byDate = {};
        let grandTotal = 0, grandCount = 0;
        for (const r of (rechargeRows||[])) {
          const d = String(r.date).slice(0, 10);
          if (!byDate[d]) byDate[d] = [];
          const amt = Number(r.amount) || 0;
          byDate[d].push({
            id:       r.id,
            phone:    r.phone,
            name:     nameMap[r.phone] || r.phone,
            amount:   amt,
            note:     r.note || '',
            time:     r.time || '',
            source:   r.source || 'admin'
          });
          grandTotal += amt;
          grandCount += 1;
        }

        const report = Object.keys(byDate).sort().reverse().map(date => {
          const entries = byDate[date];
          return {
            date,
            entries,
            dayTotal: entries.reduce((s, e) => s + e.amount, 0),
            dayCount: entries.length
          };
        });

        return res.json({
          success: true,
          fromDate, toDate,
          report,
          grandTotal,
          grandCount
        });
      }

      case 'generateReferralCoupons': {
        // Admin clicks "Send to Referrer" OR "Send to New User" on a referral notification.
        // target: 'old' = referrer, 'new' = new user. Only ONE coupon is created per call.
        // Notification is NOT marked read here — client does that after both buttons are clicked.
        const referrerPhone = cleanPhone(data.referrer_phone);
        const newUserPhone  = cleanPhone(data.new_user_phone);
        const target        = data.target === 'new' ? 'new' : 'old'; // default to 'old' if missing
        if (!referrerPhone || !newUserPhone) {
          return res.json({ success: false, error: 'Both referrer_phone and new_user_phone are required' });
        }

        // Idempotency key: unique per referrer+newUser+target pair
        // Prevents double coupon if admin clicks same button twice (page refresh etc.)
        const refKey = referrerPhone + '_' + newUserPhone + '_' + target;

        // Check if coupon already issued for this exact pair+target
        const { data: existingCpn } = await supabase
          .from('coupons')
          .select('code, discount_value, expiry_date, is_active')
          .eq('referral_key', refKey)
          .maybeSingle();
        if (existingCpn) {
          if (!existingCpn.is_active) {
            // Coupon was already used — block re-issue
            return res.json({ success: false, error: 'Coupon already used by this user — no re-issue allowed' });
          }
          // Already issued but not yet used — return existing code (admin can re-send WhatsApp)
          const isOldExisting = target === 'old';
          return res.json({
            success:       true,
            referrer_code: isOldExisting ? existingCpn.code : null,
            new_user_code: isOldExisting ? null : existingCpn.code,
            referrer_pct:  existingCpn.discount_value,
            new_user_pct:  existingCpn.discount_value,
            expiry:        existingCpn.expiry_date,
            already_issued: true
          });
        }

        const [referrerPctRaw, newUserPctRaw] = await Promise.all([
          getCachedSetting('referral_referrer_pct'),
          getCachedSetting('referral_new_user_pct'),
        ]);
        const referrerPct = Math.max(1, Math.min(50, parseInt(referrerPctRaw || '10')));
        const newUserPct  = Math.max(1, Math.min(50, parseInt(newUserPctRaw  || '15')));

        // Expiry: 7 days from today in IST (YYYY-MM-DD)
        const expiryDate = new Date(Date.now() + 7 * 86400000)
          .toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }); // en-CA gives YYYY-MM-DD

        const rand = () => Math.random().toString(36).slice(2, 5).toUpperCase();

        // Generate only the requested coupon
        const isOld         = target === 'old';
        const targetPhone   = isOld ? referrerPhone : newUserPhone;
        const targetPct     = isOld ? referrerPct   : newUserPct;
        const couponCode    = 'REF' + targetPhone.slice(-4) + rand();

        const now = new Date().toISOString();
        const { error: cErr } = await supabase.from('coupons').insert([
          {
            code:             couponCode,
            discount_type:    'percent',
            discount_value:   targetPct,
            restriction_type: 'specific_phone',
            allowed_phones:   JSON.stringify([targetPhone]),
            expiry_date:      expiryDate,
            auto_delete:      true,
            is_active:        true,
            max_usage:        1,
            used_count:       0,
            referral_key:     refKey,
            created_at:       now
          }
        ]);
        if (cErr) throw new Error('Coupon insert failed: ' + cErr.message);

        // Notification read-marking is handled entirely by the client
        // after admin has clicked both "Send to Referrer" and "Send to New User".

        return res.json({
          success:      true,
          referrer_code: isOld ? couponCode : null,
          new_user_code: isOld ? null        : couponCode,
          referrer_pct:  referrerPct,
          new_user_pct:  newUserPct,
          expiry:        expiryDate
        });
      }

      case 'setReferralSettings': {
        const referrerPct = parseInt(data.referrer_pct);
        const newUserPct  = parseInt(data.new_user_pct);
        if (isNaN(referrerPct) || referrerPct < 1 || referrerPct > 50) {
          return res.json({ success: false, error: 'referrer_pct must be between 1 and 50' });
        }
        if (isNaN(newUserPct) || newUserPct < 1 || newUserPct > 50) {
          return res.json({ success: false, error: 'new_user_pct must be between 1 and 50' });
        }
        const now = new Date().toISOString();
        await supabase.from('admin_settings').upsert([
          { key: 'referral_referrer_pct', value: String(referrerPct), updated_at: now },
          { key: 'referral_new_user_pct', value: String(newUserPct),  updated_at: now }
        ], { onConflict: 'key' });
        // Clear cached values so next read picks up new values
        delete _settingsCache['referral_referrer_pct'];
        delete _settingsCache['referral_new_user_pct'];
        _bumpMenuVersion();
        return res.json({ success: true });
      }

      case 'getUserRating': {
        // Customer panel calls this to show the user their own score and breakdown.
        // Requires user token (getUserRating is in _USER_SENSITIVE_ACTIONS).
        const phone = cleanPhone(data.phone);
        if (!phone) return res.json({ success: false, error: 'Phone required' });

        const today30ago = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
        const [
          { data: ratingRow },
          { data: walRow },
          { data: subRow },
          { data: recentOrders, error: ordErr }
        ] = await Promise.all([
          supabase.from('user_ratings').select('lifetime_spend, last_order_date, manual_score').eq('phone', phone).single(),
          supabase.from('khata_summary').select('balance').eq('phone', phone).single(),
          supabase.from('subscribers').select('created_at').eq('phone', phone).single(),
          supabase.from('orders')
            .select('order_id')
            .eq('phone', phone)
            .neq('order_status', 'cancelled')
            .neq('order_status', 'rejected')
            .gte('date', today30ago)
        ]);

        const walletBal = parseFloat(walRow?.balance) || 0;
        const recent30  = ordErr ? 0 : (recentOrders || []).length;

        // P1: Wallet Balance (₹0=0 → ₹500+=20)
        const p1 = Math.round(Math.min(walletBal / 500, 1) * 20);

        // P2: Lifetime Spend (₹0=0 → ₹10000+=30)
        const spend = parseFloat(ratingRow?.lifetime_spend) || 0;
        const p2 = Math.round(Math.min(spend / 10000, 1) * 30);

        // P3: Order Consistency last 30 days (0=0 → 30=25)
        const p3 = Math.round(Math.min(recent30 / 30, 1) * 25);

        // P4: Subscription tenure
        let p4 = 0;
        if (subRow?.created_at) {
          const subDays = Math.floor((Date.now() - new Date(subRow.created_at)) / 86400000);
          if (subDays >= 90)      p4 = 15;
          else if (subDays >= 30) p4 = 12;
          else                    p4 = 8;
        }

        // P5: Manual admin score (0–10)
        const p5 = Math.max(0, Math.min(10, ratingRow?.manual_score || 0));

        const total = Math.min(p1 + p2 + p3 + p4 + p5, 100);

        let badge = 'Inactive';
        if (total >= 80)      badge = 'Champion';
        else if (total >= 60) badge = 'Loyal';
        else if (total >= 40) badge = 'Developing';
        else if (total >= 20) badge = 'At Risk';

        return res.json({
          success:   true,
          rating:    total,
          breakdown: { wallet: p1, spend: p2, consistency: p3, subscription: p4, manual: p5 },
          badge
        });
      }

      // ── FREE FIRST TIFFIN CAMPAIGN SYSTEM (v169) ─────────────────────────

      // Returns all users enriched with free_tiffin_* columns for admin dashboard.
      // Also does a parallel count of paid orders after redemption for conversion tracking.
      case 'getFreeTiffinUsers': {
        const { data: ftUsers, error: ftErr } = await supabase
          .from('users')
          .select('phone, name, address, area, coord_lat, coord_lng, created_at, free_tiffin_status, free_tiffin_blocked, free_tiffin_wa_sent_at, free_tiffin_given_at, free_tiffin_coupon, order_allowed, ft_loc_suspect')
          .order('created_at', { ascending: false });
        if (ftErr) return res.json({ success: false, error: ftErr.message });

        // Post-redemption analytics: for each redeemed user, compute rich behaviour data.
        // toISTDateStr: convert UTC ISO → IST date string (YYYY-MM-DD)
        const toISTDateStr = isoStr => {
          const d = new Date(isoStr);
          const ist = new Date(d.getTime() + (5 * 60 + 30) * 60 * 1000);
          return `${ist.getUTCFullYear()}-${String(ist.getUTCMonth()+1).padStart(2,'0')}-${String(ist.getUTCDate()).padStart(2,'0')}`;
        };
        const addDays = (dateStr, n) => {
          const d = new Date(dateStr + 'T00:00:00Z');
          d.setUTCDate(d.getUTCDate() + n);
          return d.toISOString().slice(0, 10);
        };

        const redeemedUsers = (ftUsers || []).filter(u => u.free_tiffin_status === 'redeemed' && u.free_tiffin_given_at);
        const conversionMap = {};
        if (redeemedUsers.length) {
          const redeemedPhones = redeemedUsers.map(u => u.phone);
          // Fetch orders with final_amount + date for full analytics
          const { data: paidOrders } = await supabase
            .from('orders')
            .select('phone, created_at, coupon_code, final_amount, date, slot')
            .in('phone', redeemedPhones)
            .neq('order_status', 'rejected');
          for (const u of redeemedUsers) {
            const redeemTime    = new Date(u.free_tiffin_given_at).getTime();
            const redeemDateIST = toISTDateStr(u.free_tiffin_given_at);
            const day1Date      = addDays(redeemDateIST, 1);
            const day2Date      = addDays(redeemDateIST, 2);
            const day3Date      = addDays(redeemDateIST, 3);
            const ordersAfter   = (paidOrders || []).filter(o =>
              o.phone === u.phone &&
              new Date(o.created_at).getTime() > redeemTime &&
              o.coupon_code !== u.free_tiffin_coupon
            );
            const sortedDates = ordersAfter.map(o => o.date).filter(Boolean).sort();
            conversionMap[u.phone] = {
              count:        ordersAfter.length,
              revenue:      Math.round(ordersAfter.reduce((s,o) => s + (o.final_amount || 0), 0)),
              next_day:     ordersAfter.some(o => o.date === day1Date),
              day2:         ordersAfter.some(o => o.date === day2Date),
              day3:         ordersAfter.some(o => o.date === day3Date),
              first_date:   sortedDates[0] || null,
              last_date:    sortedDates[sortedDates.length - 1] || null,
              redeem_date:  redeemDateIST,
            };
          }
        }

        // v171: subscribers fetch + all suspect Haversine RPCs in parallel
        const suspectUsers = (ftUsers || []).filter(u => u.ft_loc_suspect && u.coord_lat && u.coord_lng);
        const [subResult2, ...suspectResults] = await Promise.all([
          supabase.from('subscribers').select('phone'),
          ...suspectUsers.map(u =>
            supabase.rpc('get_nearby_ft_users', {
              p_lat: u.coord_lat, p_lng: u.coord_lng, p_radius_m: 30, p_exclude_phone: u.phone
            }).then(r => ({ phone: u.phone, data: r.data })).catch(() => ({ phone: u.phone, data: null }))
          )
        ]);
        const subSet = new Set((subResult2.data || []).map(r => r.phone));
        const nearbyMap = {};
        for (const { phone, data: nb } of suspectResults) {
          if (nb && nb.length > 0) {
            nearbyMap[phone] = nb.map(n => ({
              phone: n.phone, name: n.name, distance_m: n.distance_m,
              free_tiffin_status: n.free_tiffin_status, free_tiffin_blocked: n.free_tiffin_blocked
            }));
          }
        }

        const nowMs = Date.now();
        const enriched = (ftUsers || []).map(u => {
          const regMs   = u.created_at ? new Date(u.created_at).getTime() : 0;
          const reg_days = regMs ? Math.floor((nowMs - regMs) / 86400000) : null;
          return {
            ...u,
            reg_days,                                              // days since registration (for eligibility filter)
            paid_orders_after: conversionMap[u.phone]?.count ?? 0,
            conversion:        conversionMap[u.phone] || null,
            is_subscriber:     subSet.has(u.phone),
            nearby_suspects:   nearbyMap[u.phone] || []
          };
        });
        return res.json({ success: true, users: enriched });
      }

      // Creates a batch of free-tiffin coupons.
      // mode='personal' → one unique code per phone (specific_phone restriction)
      // mode='fcfs'     → one shared code with max_usage=capacity (one_time_per_user restriction)
      // mode='random'   → server picks <count> random eligible users (specific_phone restriction)
      //
      // v172: eligibility = "has not redeemed free tiffin yet" ONLY (free_tiffin_status !== 'redeemed'
      // AND free_tiffin_blocked === false). Subscriber status no longer matters — any user, subscriber
      // or not, who hasn't already gotten their free first tiffin is eligible. 'random' mode accepts an
      // optional sub_filter ('all' default | 'non_sub' | 'sub') purely for admin targeting convenience.
      case 'createFreeTiffinBatch': {
        const {
          mode,           // 'personal' | 'fcfs' | 'random'
          phones = [],    // required for personal mode
          capacity,       // required for fcfs mode
          discount_type,  // 'percent' | 'percent_cap' | 'flat'
          discount_value,
          cap_amount,
          min_order,
          flash_start,    // e.g. '07:00:00'
          flash_end,      // e.g. '10:00:00'
          flash_date,     // e.g. '2026-07-10' — defaults to today
        } = data;

        if (!discount_type || discount_value == null) {
          return res.json({ success: false, error: 'discount_type and discount_value are required' });
        }

        // Collision-safe unique code generator
        // Format: TIFFO + 6 random UPPERCASE alphanumeric chars
        const _genCode = () => {
          const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
          let s = 'TIFFO';
          for (let i = 0; i < 6; i++) s += chars[Math.floor(Math.random() * chars.length)];
          return s;
        };
        const _uniqueCode = async () => {
          for (let attempt = 0; attempt < 5; attempt++) {
            const candidate = _genCode();
            const { data: existing } = await supabase.from('coupons').select('code').eq('code', candidate).single();
            if (!existing) return candidate;
          }
          throw new Error('Could not generate unique coupon code after 5 attempts');
        };

        const todayStr = flash_date || istDateStr(ist);
        const baseFields = {
          coupon_type:       'free_tiffin',   // v171: DB type tag replaces TIFFO prefix detection
          discount_type,
          discount_value,
          cap_amount:        cap_amount ?? null,
          max_cap:           cap_amount ?? null,
          min_order:         min_order  ?? null,
          min_order_amount:  min_order  ?? null,
          flash_date:        todayStr,
          flash_start:       flash_start || null,
          flash_end:         flash_end   || null,
          restriction_type:  'flash_window',  // will be overridden per mode
          auto_delete:       true,
          is_active:         true,
          used_count:        0,
          usage_count:       0,
          used_by:           '[]',
          created_at:        new Date().toISOString()
        };

        if (mode === 'personal') {
          if (!phones.length) return res.json({ success: false, error: 'phones array required for personal mode' });
          // v171: generate all unique codes in parallel instead of sequential await loop
          const personalCodes = await Promise.all(phones.map(() => _uniqueCode()));
          const rows = [];
          const codeMap = {}; // phone → code
          phones.forEach((ph, i) => {
            codeMap[ph] = personalCodes[i];
            rows.push({
              ...baseFields,
              code:              personalCodes[i],
              restriction_type:  'specific_phone',
              allowed_phones:    JSON.stringify([ph]),
              max_usage:         1,
              total_usage_limit: 1,
              per_user_limit:    1,
              max_per_user:      1,
            });
          });
          const { error: insErr } = await supabase.from('coupons').insert(rows);
          if (insErr) return res.json({ success: false, error: insErr.message });
          _bumpMenuVersion();
          // v171: return new coupon rows inline so admin can patch local cache without getCoupons round-trip
          return res.json({ success: true, mode: 'personal', codeMap, newCoupons: rows });

        } else if (mode === 'fcfs') {
          const cap = parseInt(capacity);
          if (!cap || cap < 1) return res.json({ success: false, error: 'capacity required for fcfs mode' });
          const code = await _uniqueCode();
          const fcfsRow = {
            ...baseFields,
            code,
            restriction_type:  'one_time_per_user',
            allowed_phones:    '[]',
            max_usage:         cap,
            total_usage_limit: cap,
            per_user_limit:    1,
            max_per_user:      1,
          };
          const { error: insErr } = await supabase.from('coupons').insert(fcfsRow);
          if (insErr) return res.json({ success: false, error: insErr.message });
          _bumpMenuVersion();
          // v171: return new coupon row inline so admin can patch local cache without getCoupons round-trip
          return res.json({ success: true, mode: 'fcfs', code, capacity: cap, newCoupons: [fcfsRow] });

        } else if (mode === 'random') {
          // Random mode (v171): admin specifies count; server picks randomly from eligible users
          // and creates personal unique codes for each — same as personal mode but server-picked.
          // v172: eligibility is purely free_tiffin_status/blocked-based — subscriber status is
          // NO LONGER auto-excluded. Any user (subscriber or not) who hasn't redeemed FT yet is
          // eligible. Admin can optionally narrow the pool via sub_filter ('all'|'non_sub'|'sub').
          const count = parseInt(data.count);
          if (!count || count < 1) return res.json({ success: false, error: 'count required for random mode' });
          const subFilter = data.sub_filter || 'all'; // 'all' | 'non_sub' | 'sub'

          // v171 FIX: parallel fetch of subscribers + eligible users (was sequential)
          // v171 FIX: removed duplicate .is('free_tiffin_blocked', false) — .eq() is sufficient
          const [subResultR, eligResult] = await Promise.all([
            supabase.from('subscribers').select('phone'),
            supabase.from('users').select('phone, name')
              .neq('free_tiffin_status', 'redeemed')
              .eq('free_tiffin_blocked', false)
          ]);
          if (eligResult.error) return res.json({ success: false, error: eligResult.error.message });
          const subSetR = new Set((subResultR.data || []).map(r => r.phone));

          // v172: subscribers are eligible by default now (neq above already handles redeemed).
          // Only filtered out if admin explicitly asked for non-subscribers only / subscribers only.
          let pool = eligResult.data || [];
          if (subFilter === 'non_sub') pool = pool.filter(u => !subSetR.has(u.phone));
          else if (subFilter === 'sub') pool = pool.filter(u => subSetR.has(u.phone));
          if (!pool.length) return res.json({ success: false, error: 'No eligible users available for random pick' });

          // Fisher-Yates shuffle, take first <count>
          for (let i = pool.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [pool[i], pool[j]] = [pool[j], pool[i]];
          }
          const picked = pool.slice(0, count).map(u => ({ ...u, is_subscriber: subSetR.has(u.phone) }));

          // v171: generate all unique codes in parallel (was sequential per-user await loop)
          const generatedCodes = await Promise.all(picked.map(() => _uniqueCode()));
          const rows = [];
          const codeMap = {};
          picked.forEach((u, i) => {
            codeMap[u.phone] = generatedCodes[i];
            rows.push({
              ...baseFields,
              code:              generatedCodes[i],
              restriction_type:  'specific_phone',
              allowed_phones:    JSON.stringify([u.phone]),
              max_usage:         1,
              total_usage_limit: 1,
              per_user_limit:    1,
              max_per_user:      1,
            });
          });
          const { error: insErrR } = await supabase.from('coupons').insert(rows);
          if (insErrR) return res.json({ success: false, error: insErrR.message });
          _bumpMenuVersion();
          // v171: return new coupon rows inline so admin can patch local cache without getCoupons round-trip
          return res.json({
            success: true,
            mode: 'random',
            codeMap,
            phones: picked.map(u => u.phone),
            picked: picked,   // includes name + phone for admin UI preview
            newCoupons: rows
          });

        } else {
          return res.json({ success: false, error: "mode must be 'personal', 'fcfs', or 'random'" });
        }
      }

      // Admin clicked WhatsApp send button — mark user's status as 'wa_sent'.
      // Only runs if current status is NULL — never overwrites 'redeemed'.
      case 'markFreeTiffinWaSent': {
        // BUG #4b FIX (v170): previously .is('free_tiffin_status', null) meant that
        // if admin re-sends a WA (resend flow), the wa_sent_at timestamp was never
        // updated because the status was already 'wa_sent'. Now: always update
        // wa_sent_at for wa_sent users too (so resend is tracked), but never
        // overwrite 'redeemed' (that is a terminal state).
        const ph = cleanPhone(data.phone);
        if (!ph) return res.json({ success: false, error: 'Phone required' });
        const { error: e } = await supabase.from('users')
          .update({ free_tiffin_status: 'wa_sent', free_tiffin_wa_sent_at: new Date().toISOString() })
          .eq('phone', ph)
          .neq('free_tiffin_status', 'redeemed');  // allow null→wa_sent AND wa_sent→wa_sent (timestamp refresh)
        if (e) return res.json({ success: false, error: e.message });
        return res.json({ success: true });
      }

      // Manual override: admin marks a user as redeemed (e.g. phone order, outside app).
      // Also called automatically from _createSingleOrder hook (fire-and-forget).
      case 'markFreeTiffinRedeemed': {
        const ph = cleanPhone(data.phone);
        if (!ph) return res.json({ success: false, error: 'Phone required' });
        const updates = {
          free_tiffin_status:   'redeemed',
          free_tiffin_given_at: new Date().toISOString(),
        };
        if (data.coupon_code) updates.free_tiffin_coupon = data.coupon_code;
        const { error: e } = await supabase.from('users').update(updates).eq('phone', ph);
        if (e) return res.json({ success: false, error: e.message });
        return res.json({ success: true });
      }

      // Block a user from using any free-tiffin coupon in future.
      // Does NOT affect normal ordering (order_allowed is separate).
      case 'blockFreeTiffinUser': {
        const ph = cleanPhone(data.phone);
        if (!ph) return res.json({ success: false, error: 'Phone required' });
        const { error: e } = await supabase.from('users')
          .update({ free_tiffin_blocked: true })
          .eq('phone', ph);
        if (e) return res.json({ success: false, error: e.message });
        return res.json({ success: true });
      }

      // Reverse a free-tiffin block.
      case 'unblockFreeTiffinUser': {
        const ph = cleanPhone(data.phone);
        if (!ph) return res.json({ success: false, error: 'Phone required' });
        const { error: e } = await supabase.from('users')
          .update({ free_tiffin_blocked: false })
          .eq('phone', ph);
        if (e) return res.json({ success: false, error: e.message });
        return res.json({ success: true });
      }

      // ── END FREE TIFFIN ACTIONS ───────────────────────────────────────────

      // ─────────────────────────────────────────────────────────────────────
      default:
        return res.status(400).json({ success: false, error: 'Unknown action: ' + action });
    }
  } catch (err) {
    console.error(`[${action}] ERROR:`, err.message);
    // Never expose raw internal error details to client — Supabase messages can
    // contain table names, column names, or query fragments useful to attackers.
    const safeMsg = (err.message || '').includes('duplicate') ? 'Already exists' : 'Something went wrong. Please try again.';
    return res.json({ success: false, error: safeMsg });
  }
});

// ─── LISTEN ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`[Tiffo API] running on port ${PORT}`));

// ─── GRACEFUL SHUTDOWN (Render sends SIGTERM before killing the process) ──────
// Without this, Render kills the process abruptly mid-request.
// server.close() stops accepting new connections, lets in-flight requests finish,
// then exits cleanly — no dropped orders, no corrupted DB writes.
process.on('SIGTERM', () => {
  console.log('[Tiffo API] SIGTERM received — shutting down gracefully');
  server.close(() => {
    console.log('[Tiffo API] Server closed');
    process.exit(0);
  });
  // Force exit after 10s if requests don't finish (safety net)
  setTimeout(() => {
    console.error('[Tiffo API] Forced exit after 10s timeout');
    process.exit(1);
  }, 10000);
});
