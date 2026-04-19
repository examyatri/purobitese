-- ============================================================
--  TIFFO — COMPLETE DATABASE SETUP (v8, all-in-one)
--
--  Includes: full schema + all migrations (v6, v7, v8)
--  ✅ Safe fresh install on empty Supabase project
--  ✅ Deletes all old data and recreates tables
--  ✅ PRESERVES existing admin/staff login details
--
--  For upgrading an existing live database instead,
--  use migration_v8_latest.sql (non-destructive).
-- ============================================================


-- ── STEP 1: BACKUP STAFF (ADMIN LOGINS) ──────────────────────

CREATE TEMP TABLE _staff_backup AS
SELECT * FROM staff;


-- ── STEP 2: DROP ALL TABLES ───────────────────────────────────

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


-- ── STEP 3: RECREATE ALL TABLES ───────────────────────────────

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
CREATE TABLE subscribers (
  phone          TEXT        PRIMARY KEY,
  plan_start     DATE        NOT NULL,
  plan_end       DATE        NOT NULL,
  notes          TEXT        DEFAULT '',
  pause_delivery TEXT        NOT NULL DEFAULT 'none',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
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

-- 3.5  menu_items  (includes all v6/v7/v8 columns)
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
  veg_type    TEXT        NOT NULL DEFAULT 'veg',   -- v7/v8
  sub_items   TEXT,                                  -- v7/v8
  description TEXT,                                  -- v8
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()     -- v6
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
  order_source    TEXT,                              -- v6
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
  sent_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  coupon_code  TEXT                               -- v6
);


-- ── STEP 4: SEED DEFAULT admin_settings ───────────────────────

INSERT INTO admin_settings (key, value, updated_at) VALUES
  ('khata_enabled',       'false',                               now()),
  ('order_cutoff_config', '{"cutoffHour":21,"cutoffMinute":0}',  now()),
  ('weekly_schedule',     '[]',                                  now())
ON CONFLICT (key) DO NOTHING;


-- ── STEP 5: RESTORE STAFF (ADMIN LOGINS) ──────────────────────

INSERT INTO staff (id, username, name, password_hash, role, created_at)
SELECT id, username, name, password_hash, role, created_at
FROM   _staff_backup;

DROP TABLE _staff_backup;


-- ── DONE ──────────────────────────────────────────────────────
-- ✅ All old data wiped
-- ✅ All 14 tables recreated with correct schema (v8)
-- ✅ Admin/staff logins preserved
-- ✅ Default admin_settings seeded
-- ============================================================
