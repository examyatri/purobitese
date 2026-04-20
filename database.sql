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
  sub_items   TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
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
  user_type       TEXT        NOT NULL DEFAULT 'daily',
  rider_id        TEXT,
  slot            TEXT        DEFAULT NULL,
  refund_type     TEXT        DEFAULT NULL,
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
  used_count         INTEGER     NOT NULL DEFAULT 0,
  usage_count        INTEGER     NOT NULL DEFAULT 0,
  expiry_date        DATE,
  is_active          BOOLEAN     NOT NULL DEFAULT true,
  max_cap            NUMERIC,
  used_by            JSONB       NOT NULL DEFAULT '[]',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
  order_source    TEXT,
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


-- ── MIGRATION: Add missing columns to EXISTING live database ─
-- Run this block separately if you already have tables and don't
-- want to wipe data. Safe to run multiple times (IF NOT EXISTS).

ALTER TABLE khata_entries   ADD COLUMN IF NOT EXISTS order_source  TEXT;
ALTER TABLE menu_items      ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE menu_items      ADD COLUMN IF NOT EXISTS veg_type      TEXT NOT NULL DEFAULT 'veg';
ALTER TABLE menu_items      ADD COLUMN IF NOT EXISTS sub_items     TEXT;
ALTER TABLE nu_coupon_sent  ADD COLUMN IF NOT EXISTS coupon_code   TEXT;
ALTER TABLE subscribers     ADD COLUMN IF NOT EXISTS auto_tiffin   BOOLEAN NOT NULL DEFAULT true; -- legacy column, kept for compatibility

-- ── END MIGRATION ─────────────────────────────────────────────

-- ── MIGRATION v_coupons: Coupon restriction fields ─────────────────────────
-- Run this block on existing databases. Safe to run multiple times.

ALTER TABLE coupons ADD COLUMN IF NOT EXISTS restriction_type TEXT    NOT NULL DEFAULT 'unlimited';
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS allowed_phones   JSONB   NOT NULL DEFAULT '[]';
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_per_user     INTEGER;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS cap_amount       NUMERIC;

-- Backfill: existing coupons with per_user_limit=1 → restriction_type = one_time_per_user
UPDATE coupons SET restriction_type = 'one_time_per_user' WHERE per_user_limit = 1 AND restriction_type = 'unlimited';
UPDATE coupons SET restriction_type = 'limited_total'     WHERE (max_usage IS NOT NULL OR total_usage_limit IS NOT NULL) AND restriction_type = 'unlimited';

-- ── END MIGRATION v_coupons ────────────────────────────────────────────────

-- ── MIGRATION v_orders_slot: order slot field ──────────────────────────────
-- Stores 'morning' or 'evening' for admin-created (bulk/udhar) orders.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS slot TEXT DEFAULT NULL;
-- ── END MIGRATION order slot ───────────────────────────────────────────────

-- ── MIGRATION v13: refund_type field ──────────────────────────────────────
-- Tracks how rejected orders were refunded: 'wallet' | 'cash' | 'none'
ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_type TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_orders_refund_type ON orders (refund_type) WHERE refund_type IS NOT NULL;
-- ── END MIGRATION v13 ─────────────────────────────────────────────────────

-- ── MIGRATION v14: Subscriber Tab Upgrade ─────────────────────────────────────
-- Run migration_v14_subscriber_upgrade.sql on existing live databases.
-- For fresh installs this schema is already included above.
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS plan            TEXT    NOT NULL DEFAULT 'morning';
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS pause_morning   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS pause_evening   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS is_delivery_off BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subscribers ALTER COLUMN plan_end DROP NOT NULL;
-- ── END MIGRATION v14 ─────────────────────────────────────────────────────────

-- ── MIGRATION v15: Notification-Centric Coupon Workflow ───────────────────────
-- Nu Coupon Panel moved from Subscribers tab into Notifications tab.
-- Pending list is now derived from unread notifications (type='user').
-- nu_coupon_sent gains name + notif_id for full traceability.
-- deleteNotificationRange now only deletes is_read=true rows.
-- signup handler now fires a type='user' notification with full meta.

ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS name     TEXT;
ALTER TABLE nu_coupon_sent ADD COLUMN IF NOT EXISTS notif_id TEXT;

-- Index to speed up pending-list query (unread user notifications)
CREATE INDEX IF NOT EXISTS idx_notifs_type_unread ON notifications (type, is_read) WHERE is_read = false;
-- ── END MIGRATION v15 ─────────────────────────────────────────────────────────
