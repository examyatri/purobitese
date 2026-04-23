-- ============================================================
--  PURO BITE / TIFFO — COMPLETE DATABASE (MERGED)
--  Generated: 2026-04-23
--  Files merged (in order):
--    1. database.sql          — Full schema reset & base tables
--    2. RUN_THIS_IN_SUPABASE.sql   — v27 migration
--    3. migration_address_latlong.sql  — Address/lat-long columns
--    4. migration_v18_notif_rebuild.sql  — Notification table rebuild
--    5. migration_v46_atomic_wallet.sql  — Atomic wallet RPC
--
--  HOW TO USE:
--    Run in Supabase SQL Editor.
--    database.sql will reset all tables; migrations apply on top.
-- ============================================================


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  FILE 1: database.sql                                        ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ============================================================
--  PURO BITE — DATABASE RESET SCRIPT
--  ✅ Deletes all old data
--  ✅ Recreates all tables with correct columns
--  ✅ PRESERVES admin/staff login details
-- ============================================================

-- ── STEP 1: BACKUP STAFF (ADMIN LOGINS) ─────────────────────
-- We save the staff table into a temp table before wiping

CREATE TEMP TABLE _staff_backup AS
SELECT * FROM staff;


-- ── STEP 2: DROP ALL TABLES (cascade to remove FK deps) ──────

DROP TABLE IF EXISTS nu_coupon_sent    CASCADE;
DROP TABLE IF EXISTS notifications     CASCADE;
DROP TABLE IF EXISTS khata_entries     CASCADE;
DROP TABLE IF EXISTS khata_summary     CASCADE;
DROP TABLE IF EXISTS thali_items       CASCADE;
DROP TABLE IF EXISTS thalis            CASCADE;
DROP TABLE IF EXISTS menu_items        CASCADE;
DROP TABLE IF EXISTS coupons           CASCADE;
DROP TABLE IF EXISTS orders            CASCADE;
DROP TABLE IF EXISTS subscribers       CASCADE;
DROP TABLE IF EXISTS riders            CASCADE;
DROP TABLE IF EXISTS users             CASCADE;
DROP TABLE IF EXISTS admin_settings    CASCADE;
DROP TABLE IF EXISTS staff             CASCADE;


-- ── STEP 3: RECREATE ALL TABLES ──────────────────────────────

-- 3.1  staff  (admin logins — restored after create)
CREATE TABLE staff (
  id            TEXT        PRIMARY KEY,
  username      TEXT        NOT NULL UNIQUE,
  name          TEXT,
  password_hash TEXT        NOT NULL,
  role          TEXT        NOT NULL DEFAULT 'staff',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.2  users  (customers)
CREATE TABLE users (
  user_id       TEXT        PRIMARY KEY,
  name          TEXT        NOT NULL,
  phone         TEXT        NOT NULL UNIQUE,
  email         TEXT,
  address       TEXT,
  password_hash TEXT        NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.3  subscribers  (tiffin plan holders)
-- plan_end is NULL = subscription runs indefinitely (no expiry)
CREATE TABLE subscribers (
  phone           TEXT        PRIMARY KEY,
  plan            TEXT        NOT NULL DEFAULT 'morning', -- morning | evening | both
  plan_start      DATE        NOT NULL,
  plan_end        DATE,                                    -- NULL = infinite subscription
  notes           TEXT        DEFAULT '',
  pause_delivery  TEXT        NOT NULL DEFAULT 'none',    -- legacy: none|lunch|dinner|both
  pause_morning   BOOLEAN     NOT NULL DEFAULT false,
  pause_evening   BOOLEAN     NOT NULL DEFAULT false,
  is_delivery_off BOOLEAN     NOT NULL DEFAULT false,
  auto_tiffin     BOOLEAN     NOT NULL DEFAULT true,      -- kept for legacy; eligibility derived from pause_delivery
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.4  riders
CREATE TABLE riders (
  rider_id      TEXT        PRIMARY KEY,
  name          TEXT        NOT NULL,
  phone         TEXT        NOT NULL UNIQUE,
  password_hash TEXT        NOT NULL,
  vehicle       TEXT,
  zone          TEXT,
  is_active     BOOLEAN     NOT NULL DEFAULT true
);

-- 3.5  menu_items
CREATE TABLE menu_items (
  item_id     TEXT        PRIMARY KEY,
  name        TEXT        NOT NULL,
  category    TEXT        NOT NULL,
  image_url   TEXT,
  variants    JSONB       NOT NULL DEFAULT '[]',
  price       NUMERIC     NOT NULL DEFAULT 0,
  highlight   TEXT,
  sort_order  INTEGER     NOT NULL DEFAULT 99,
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  stock_grams NUMERIC,
  veg_type    TEXT        NOT NULL DEFAULT 'veg',
  sub_items     TEXT,
  sub_category  TEXT,
  meal_session  TEXT        NOT NULL DEFAULT 'both',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.6  thalis  (combo meals)
CREATE TABLE thalis (
  thali_id    TEXT        PRIMARY KEY,
  name        TEXT        NOT NULL,
  description TEXT,
  image_url   TEXT,
  price       NUMERIC     NOT NULL DEFAULT 0,
  stock_qty   INTEGER,
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.7  thali_items  (junction: thali ↔ menu_items)
CREATE TABLE thali_items (
  id             BIGSERIAL   PRIMARY KEY,
  thali_id       TEXT        NOT NULL REFERENCES thalis(thali_id) ON DELETE CASCADE,
  menu_item_id   TEXT        NOT NULL REFERENCES menu_items(item_id) ON DELETE CASCADE,
  variant_label  TEXT,
  menu_item_name TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.8  orders
CREATE TABLE orders (
  order_id        TEXT        PRIMARY KEY,
  user_id         TEXT        NOT NULL,
  name            TEXT,
  phone           TEXT,
  address         TEXT,
  items           JSONB       NOT NULL DEFAULT '[]',
  total_amount    NUMERIC     NOT NULL DEFAULT 0,
  delivery_charge NUMERIC     NOT NULL DEFAULT 0,
  final_amount    NUMERIC     NOT NULL DEFAULT 0,
  coupon_code     TEXT,
  discount        NUMERIC     NOT NULL DEFAULT 0,
  order_status    TEXT        NOT NULL DEFAULT 'pending',
  payment_status  TEXT        NOT NULL DEFAULT 'pending',
  payment_mode    TEXT        DEFAULT NULL,
  user_type       TEXT        NOT NULL DEFAULT 'daily',
  rider_id        TEXT,
  slot            TEXT        DEFAULT NULL,
  refund_type     TEXT        DEFAULT NULL,
  source          TEXT        NOT NULL DEFAULT 'user',  -- 'user' | 'admin' | 'admin_bulk'
  date            DATE,
  time            TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.9  coupons
CREATE TABLE coupons (
  id                 BIGSERIAL   PRIMARY KEY,
  code               TEXT        NOT NULL UNIQUE,
  discount_type      TEXT        NOT NULL,
  discount_value     NUMERIC     NOT NULL DEFAULT 0,
  min_order          NUMERIC,
  min_order_amount   NUMERIC,
  max_usage          INTEGER,
  total_usage_limit  INTEGER,
  per_user_limit     INTEGER,
  max_per_user       INTEGER,
  used_count         INTEGER     NOT NULL DEFAULT 0,
  usage_count        INTEGER     NOT NULL DEFAULT 0,
  expiry_date        DATE,
  is_active          BOOLEAN     NOT NULL DEFAULT true,
  cap_amount         NUMERIC,
  max_cap            NUMERIC,
  restriction_type   TEXT        NOT NULL DEFAULT 'unlimited',
  allowed_phones     JSONB       NOT NULL DEFAULT '[]',
  used_by            JSONB       NOT NULL DEFAULT '[]',
  auto_delete        BOOLEAN     NOT NULL DEFAULT false,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Migration note: run these if upgrading an existing database:
-- ALTER TABLE coupons ADD COLUMN IF NOT EXISTS auto_delete BOOLEAN NOT NULL DEFAULT false;
-- ALTER TABLE coupons ADD COLUMN IF NOT EXISTS restriction_type TEXT NOT NULL DEFAULT 'unlimited';
-- ALTER TABLE coupons ADD COLUMN IF NOT EXISTS allowed_phones JSONB NOT NULL DEFAULT '[]';
-- ALTER TABLE coupons ADD COLUMN IF NOT EXISTS cap_amount NUMERIC;
-- ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_per_user INTEGER;

-- 3.10  khata_summary  (wallet balance per user)
CREATE TABLE khata_summary (
  phone      TEXT        PRIMARY KEY,
  balance    NUMERIC     NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.11  khata_entries  (wallet transaction ledger)
CREATE TABLE khata_entries (
  id              TEXT        PRIMARY KEY,
  phone           TEXT        NOT NULL,
  type            TEXT        NOT NULL,
  amount          NUMERIC     NOT NULL DEFAULT 0,
  running_balance NUMERIC,
  note            TEXT,
  date            DATE,
  time            TEXT,
  order_id        TEXT,
  order_status    TEXT,
  source          TEXT,  -- 'user' | 'admin' | 'admin_bulk' — matches orders.source
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.12  notifications
CREATE TABLE notifications (
  id         TEXT        PRIMARY KEY,
  type       TEXT,
  priority   TEXT,
  group_id   TEXT,
  title      TEXT,
  body       TEXT,
  meta       JSONB       NOT NULL DEFAULT '{}',
  is_read    BOOLEAN     NOT NULL DEFAULT false,
  read_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.13  admin_settings  (key-value config store)
CREATE TABLE admin_settings (
  key        TEXT        PRIMARY KEY,
  value      TEXT        NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3.14  nu_coupon_sent  (tracks new-user coupon dispatch)
CREATE TABLE nu_coupon_sent (
  phone        TEXT        PRIMARY KEY,
  name         TEXT,
  sent_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  coupon_code  TEXT,
  notif_id     TEXT        -- links to notifications.id for traceability
);


-- ── STEP 4: SEED DEFAULT admin_settings ──────────────────────

INSERT INTO admin_settings (key, value, updated_at) VALUES
  ('khata_enabled',    'false', now()),
  ('order_cutoff_config', '{"cutoffHour":21,"cutoffMinute":0}', now()),
  ('weekly_schedule',  '[]',    now())
ON CONFLICT (key) DO NOTHING;


-- ── STEP 5: RESTORE STAFF (ADMIN LOGINS) ─────────────────────

INSERT INTO staff (id, username, name, password_hash, role, created_at)
SELECT id, username, name, password_hash, role, created_at
FROM   _staff_backup;

DROP TABLE _staff_backup;


-- ── DONE ─────────────────────────────────────────────────────
-- ✅ All old data wiped
-- ✅ All 14 tables recreated with correct schema
-- ✅ Admin/staff logins preserved
-- ✅ Default admin_settings seeded
-- ============================================================


-- ══════════════════════════════════════════════════════════════
--  LIVE DATABASE MIGRATION — Run once in Supabase SQL Editor
--  Safe to run on existing data. Nothing is deleted.
-- ══════════════════════════════════════════════════════════════

-- orders: add missing columns
ALTER TABLE orders ADD COLUMN IF NOT EXISTS slot         TEXT    DEFAULT NULL;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_type  TEXT    DEFAULT NULL;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_mode TEXT    DEFAULT NULL;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS source       TEXT    NOT NULL DEFAULT 'user';

-- khata_entries: rename order_source → source (same name as orders.source)
ALTER TABLE khata_entries RENAME COLUMN order_source TO source;

-- menu_items: add missing columns
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS veg_type     TEXT        NOT NULL DEFAULT 'veg';
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS sub_items    TEXT;
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS sub_category TEXT;
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS meal_session TEXT        NOT NULL DEFAULT 'both';
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT now();

-- subscribers: add missing columns
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS plan            TEXT    NOT NULL DEFAULT 'morning';
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS pause_morning   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS pause_evening   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS is_delivery_off BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS auto_tiffin     BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE subscribers ALTER COLUMN plan_end DROP NOT NULL;

-- coupons: add missing columns
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS restriction_type TEXT  NOT NULL DEFAULT 'unlimited';
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS allowed_phones   JSONB NOT NULL DEFAULT '[]';
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_per_user     INTEGER;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS cap_amount       NUMERIC;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS auto_delete      BOOLEAN NOT NULL DEFAULT false;
UPDATE coupons SET restriction_type = 'one_time_per_user' WHERE per_user_limit = 1 AND restriction_type = 'unlimited';
UPDATE coupons SET restriction_type = 'limited_total'     WHERE (max_usage IS NOT NULL OR total_usage_limit IS NOT NULL) AND restriction_type = 'unlimited';

-- nu_coupon_sent: add missing columns
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS name        TEXT;
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS notif_id    TEXT;
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS coupon_code TEXT;

-- backfill source values
UPDATE orders        SET source = 'user' WHERE source IS NULL;
UPDATE khata_entries SET source = 'user' WHERE source IS NULL;

-- indexes
CREATE INDEX IF NOT EXISTS idx_orders_refund_type ON orders       (refund_type) WHERE refund_type IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifs_type_unread ON notifications (type, is_read) WHERE is_read = false;

-- ══════════════════════════════════════════════════════════════
--  ✅ Done — all tables up to date
-- ══════════════════════════════════════════════════════════════


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  FILE 2: RUN_THIS_IN_SUPABASE.sql  (v27 migration)          ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ============================================================
--  TIFFO / PURO BITE — v27 Migration
--  Run this ONCE in Supabase SQL Editor
--  Safe to run on your live database — no data is deleted
-- ============================================================

-- 1. Add 'source' column to orders (if not already present)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'user';

-- 2. Rename khata_entries.order_source → source
--    (Makes both tables use the same column name)
ALTER TABLE khata_entries RENAME COLUMN order_source TO source;

-- 3. Backfill any NULL source values in orders
UPDATE orders SET source = 'user'
  WHERE source IS NULL
    AND (user_type = 'daily' OR user_type = 'subscriber');

UPDATE orders SET source = 'admin_bulk'
  WHERE source IS NULL
    AND slot IS NOT NULL;

-- 4. Backfill any NULL source values in khata_entries
UPDATE khata_entries SET source = 'admin'
  WHERE source IS NULL
    AND type IN ('recharge', 'adjustment');

UPDATE khata_entries SET source = 'user'
  WHERE source IS NULL
    AND order_id IS NOT NULL;

-- ✅ Done. Deploy server.js next.
-- ============================================================


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  FILE 3: migration_address_latlong.sql                       ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ══════════════════════════════════════════════════════════════════
-- PuroBite — Address + Lat/Long migration
-- Purpose : Ensure address columns in users + orders can store the
--           full embedded-coordinate format:
--           "Room 5, Ruiya Annexe BHU (latitude=25.317420, longitude=82.987654)"
--           TEXT already supports this — these statements are safe
--           no-ops if the columns already exist and are already TEXT.
-- Run once against your Supabase project (SQL Editor).
-- ══════════════════════════════════════════════════════════════════

-- ── 1. users.address ─────────────────────────────────────────────
-- Already TEXT in schema. This ALTER is a safety guard in case any
-- older migration accidentally set it to VARCHAR(n).
ALTER TABLE users
  ALTER COLUMN address TYPE TEXT;

-- ── 2. orders.address ────────────────────────────────────────────
ALTER TABLE orders
  ALTER COLUMN address TYPE TEXT;

-- ── 3. Index: fast search by address substring (optional but useful
--      for admin panel "search by address" queries)
CREATE INDEX IF NOT EXISTS idx_orders_address  ON orders  USING gin (to_tsvector('simple', coalesce(address, '')));
CREATE INDEX IF NOT EXISTS idx_users_address   ON users   USING gin (to_tsvector('simple', coalesce(address, '')));

-- ══════════════════════════════════════════════════════════════════
-- HOW COORDINATES ARE STORED (no extra columns needed)
-- ══════════════════════════════════════════════════════════════════
--
--  The app embeds GPS in the address string itself:
--
--    "Room 205, Ruiya Annexe Hostel BHU (latitude=25.317420, longitude=82.987654)"
--
--  To query by coordinates directly from SQL (if needed later):
--
--    SELECT order_id, address,
--      regexp_replace(address, '.+latitude=([0-9.]+).+', '\1')::numeric AS lat,
--      regexp_replace(address, '.+longitude=([0-9.]+)\)', '\1')::numeric AS lng
--    FROM orders
--    WHERE address ~ 'latitude=';
--
-- ══════════════════════════════════════════════════════════════════


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  FILE 4: migration_v18_notif_rebuild.sql                     ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ============================================================
-- MIGRATION v18 — Notification Tab Rebuild
-- Run this once against your Supabase database.
-- All statements are safe to re-run (IF NOT EXISTS / DO NOTHING).
-- ============================================================

-- ── 1. notifications table ────────────────────────────────────────────────────
-- The existing schema already has: id, type, priority, group_id, title, body,
-- meta (JSONB), is_read, read_at, created_at.
-- No column additions needed — is_subscriber lives inside the meta JSONB.

-- Ensure the partial index for the NU Coupon pending-list query exists.
-- (may already exist from a prior migration — IF NOT EXISTS handles it)
CREATE INDEX IF NOT EXISTS idx_notifs_type_unread
  ON notifications (type, is_read)
  WHERE is_read = false;

-- Speed up date-range deletion queries (admin delete by range)
CREATE INDEX IF NOT EXISTS idx_notifs_created_at
  ON notifications (created_at);

-- Speed up read-notification queries (Read section rendering)
CREATE INDEX IF NOT EXISTS idx_notifs_is_read
  ON notifications (is_read, created_at DESC);


-- ── 2. nu_coupon_sent table ───────────────────────────────────────────────────
-- Ensure all columns used by the Sent tab are present.
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS name        TEXT;
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS notif_id    TEXT;
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS coupon_code TEXT;
-- sent_at should already exist; this is a safety guard for older installs.
-- (Supabase/Postgres will error if column already exists WITHOUT IF NOT EXISTS,
--  but ADD COLUMN IF NOT EXISTS is safe.)


-- ── 3. Backfill is_subscriber into existing order notification meta ───────────
-- For every existing 'order' notification, look up whether the user (via phone
-- in meta) is in the subscribers table, and stamp is_subscriber accordingly.
-- This is a one-time backfill so old cards show correct View Transaction state.
DO $$
DECLARE
  r RECORD;
  phone_val TEXT;
  sub_exists BOOLEAN;
BEGIN
  FOR r IN
    SELECT id, meta
    FROM notifications
    WHERE type = 'order'
      AND (meta->>'is_subscriber') IS NULL
  LOOP
    phone_val := r.meta->>'phone';
    IF phone_val IS NOT NULL THEN
      SELECT EXISTS(
        SELECT 1 FROM subscribers WHERE phone = phone_val
      ) INTO sub_exists;
      UPDATE notifications
        SET meta = meta || jsonb_build_object('is_subscriber', sub_exists)
        WHERE id = r.id;
    END IF;
  END LOOP;
END;
$$;


-- ── 4. Verify (read-only sanity check — produces a count, not an error) ───────
SELECT
  COUNT(*)                                          AS total_order_notifs,
  COUNT(*) FILTER (WHERE meta->>'is_subscriber' = 'true')  AS marked_subscriber,
  COUNT(*) FILTER (WHERE meta->>'is_subscriber' = 'false') AS marked_non_subscriber,
  COUNT(*) FILTER (WHERE (meta->>'is_subscriber') IS NULL) AS not_backfilled
FROM notifications
WHERE type = 'order';

-- Expected: not_backfilled = 0 after migration runs successfully.
-- ============================================================


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  FILE 5: migration_v46_atomic_wallet.sql                     ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ─────────────────────────────────────────────────────────────────────────────
-- PuroBite / Tiffo — v46 Migration: Atomic Wallet RPC
-- Run this ONCE in Supabase SQL Editor → makes wallet updates truly atomic.
-- After running, _atomicWalletUpdate() in server.js will use this instead of
-- the read-modify-write pattern.
-- ─────────────────────────────────────────────────────────────────────────────

-- Function: increment_balance(p_phone, p_delta)
-- Atomically adds p_delta (can be negative) to khata_summary.balance.
-- Uses INSERT ... ON CONFLICT DO UPDATE so it works even if row doesn't exist yet.
-- Returns the new balance.

CREATE OR REPLACE FUNCTION increment_balance(p_phone TEXT, p_delta NUMERIC)
RETURNS NUMERIC
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_new_balance NUMERIC;
BEGIN
  INSERT INTO khata_summary (phone, balance, updated_at)
    VALUES (p_phone, p_delta, NOW())
  ON CONFLICT (phone)
  DO UPDATE
    SET balance    = khata_summary.balance + EXCLUDED.balance,
        updated_at = NOW()
  RETURNING balance INTO v_new_balance;

  RETURN v_new_balance;
END;
$$;

-- Grant execute to the service role (used by server.js via supabase-js)
GRANT EXECUTE ON FUNCTION increment_balance(TEXT, NUMERIC) TO service_role;
GRANT EXECUTE ON FUNCTION increment_balance(TEXT, NUMERIC) TO anon;
GRANT EXECUTE ON FUNCTION increment_balance(TEXT, NUMERIC) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- VERIFY: Run the following in SQL Editor to test:
-- SELECT increment_balance('9999999999', 100);   -- should return 100 (or prior balance + 100)
-- SELECT increment_balance('9999999999', -50);   -- should return 50 (or prior - 50)
-- ─────────────────────────────────────────────────────────────────────────────
