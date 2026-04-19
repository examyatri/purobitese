# Tiffo — Tiffin Delivery Platform

A full-stack home-cooked meal delivery web app with customer, admin, and rider interfaces backed by Supabase.

---

## Project Structure

```
tiffo_fixed/
├── server.js                    # Express API backend (Node.js)
├── index.html                   # Customer-facing storefront & ordering UI
├── admin.html                   # Admin dashboard
├── rider.html                   # Rider panel
├── sw.js                        # Service Worker (PWA offline support)
├── manifest.json                # PWA manifest (customer)
├── manifest-admin.json          # PWA manifest (admin)
├── manifest-rider.json          # PWA manifest (rider)
├── package.json
│
│   ── Database ──
├── database_complete.sql        # ✅ Fresh install: full schema v8, all-in-one
├── migration_v8_latest.sql      # ✅ Existing DB: cumulative upgrade v6+v7+v8
│
│   ── Legacy SQL (reference only) ──
├── database.sql                 # Original base schema (pre-v6)
├── migration_v6_fixes.sql
├── migration_v7_menu_ui.sql
└── migration_v8_schema_sync.sql
```

---

## Database Setup

### Fresh install (empty Supabase project)

Run **one file** in the Supabase SQL Editor:

```
database_complete.sql
```

Includes the full schema with all v6, v7, and v8 columns baked in. Preserves existing admin/staff logins if any exist.

### Upgrading an existing live database

Run **one file** in the Supabase SQL Editor:

```
migration_v8_latest.sql
```

Cumulative, non-destructive migration covering all changes from v6, v7, and v8. Safe to run multiple times (all statements use `IF NOT EXISTS`).

---

## Tech Stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Backend    | Node.js + Express                   |
| Database   | Supabase (PostgreSQL)               |
| Auth       | bcryptjs (password hashing)         |
| Frontend   | Vanilla JS + Tailwind CSS (CDN)     |
| Hosting    | Render (API) + any static host      |

---

## Environment Variables

| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `SUPABASE_URL`         | Your Supabase project URL                        |
| `SUPABASE_SERVICE_KEY` | Supabase service role key (preferred over anon)  |
| `SUPABASE_ANON_KEY`    | Fallback if service key not set                  |
| `API_KEY`              | Secret key shared between frontend and backend   |
| `RENDER_EXTERNAL_URL`  | Auto-set by Render; used for keep-alive pinging  |
| `PORT`                 | Port to listen on (default: 3000)                |

> ⚠️ Never commit `.env` files or expose `API_KEY` / `SUPABASE_SERVICE_KEY` publicly.

---

## Setup & Running

### 1. Install dependencies
```bash
npm install
```

### 2. Set environment variables
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
API_KEY=your-secret-api-key
```

### 3. Set up the database
- **Fresh install:** run `database_complete.sql` in Supabase SQL Editor
- **Existing DB:** run `migration_v8_latest.sql` in Supabase SQL Editor

### 4. Configure frontend
In each HTML file update the `CFG` block near the top of the `<script>` section:
```js
const CFG = {
  API: 'https://your-api.onrender.com/api',
  KEY: 'your-secret-api-key'
};
```

### 5. Start the server
```bash
npm start       # production
npm run dev     # development (nodemon)
```

---

## Key Features

### Customer (`index.html`)
- Phone + password login / signup
- Browse menu (items + thalis) with daily schedule and order cutoff
- Coupon validation and discount at checkout
- Wallet (khata) balance and transaction history
- Subscriber pause delivery (lunch / dinner / both)
- Order history, profile & password management

### Admin (`admin.html`)
- Dashboard: today's orders, revenue, analytics
- Order management: status updates, rider assignment
- Menu management: items, variants, stock, sort order
- Thali builder (grouped menu combos)
- Subscriber management: add, edit, remove, wallet recharge
- Coupon management: create, toggle, delete
- Khata ledger per user
- Rider & staff management
- New-user coupon tracking
- Settings: order cutoff, weekly schedule, khata toggle
- Data cleanup and master delete

### Rider (`rider.html`)
- Rider ID + password login
- View assigned orders, mark as delivered

---

## API

All requests: `POST /api`

```json
{ "action": "actionName", "data": { }, "apiKey": "your-secret-api-key" }
```

All responses:
```json
{ "success": true, ...fields }
{ "success": false, "error": "message" }
```

### Auth
`login` · `checkSession` · `signup` · `adminLogin` · `staffLogin` · `riderLogin` · `updateProfile` · `changePassword` · `resetAdminPassword` · `resetUserPassword` · `adminResetUserPassword`

### Menu & Thalis
`getMenu` · `adminGetMenu` · `getMenuItems` · `addMenuItem` · `updateMenuItem` · `deleteMenuItem` · `updateMenuOrder` · `updateMenuStock` · `getThalis` · `adminGetThalis` · `adminGetThalisAll` · `createThali` · `updateThali` · `deleteThali` · `getThaliItems` · `addThaliItem` · `removeThaliItem`

### Orders
`createOrder` · `getUserOrders` · `adminGetOrders` · `getOrdersByDate` · `updateOrderStatus` · `rejectOrder` · `assignRider` · `bulkOrdersWithBalance` · `adminBulkCreate` · `forceUdharOrder`

### Subscribers & Users
`checkSubscriber` · `adminGetSubscribers` · `getSubscribers` · `addSubscriber` · `updateSubscriber` · `removeSubscriber` · `promoteToSubscriber` · `getUserByPhone` · `adminGetUsers` · `getUsers` · `adminCreateUser` · `pauseUserDelivery` · `updatePauseDelivery` · `getSubscriberPauseStatus`

### Wallet / Khata
`getKhata` · `getSubscriberBalance` · `getAllKhata` · `adminGetAllKhata` · `rechargeWallet` · `manualRefund` · `addKhataEntry`

### Coupons
`applyCoupon` · `validateCoupon` · `getCoupons` · `adminGetCoupons` · `addCoupon` · `createCoupon` · `updateCoupon` · `deleteCoupon`

### Settings
`getOrderCutoff` · `setOrderCutoff` · `getWeeklySchedule` · `setWeeklySchedule` · `getKhataEnabled` · `setKhataEnabled` · `getSettings`

### Notifications
`getNotifications` · `createNotification` · `markNotificationRead` · `markNotificationGroupRead` · `deleteNotification` · `deleteNotificationsByRange` · `deleteNotificationRange` · `purgeOldNotifications`

### Riders & Staff
`addRider` / `createRider` · `updateRider` · `deleteRider` · `getRiders` · `getRiderOrders` · `addStaff` / `createStaff` · `updateStaff` · `deleteStaff` · `getStaff`

### Analytics & Cleanup
`getAnalytics` · `getNuCouponPending` · `getNuCouponSent` · `markNuCouponSent` · `deleteOldNuCouponSent` · `previewCleanup` · `previewDeleteOrders` · `previewDeleteTransactions` · `previewDeleteNotifications` · `deleteOldOrders` · `deleteOldTransactions` · `deleteOldData` · `masterDelete`

---

## Changelog

### v10 (current)
- **Fix:** `checkSession` and `login` were identical — merged into one handler
- **Fix:** `adminLogin` and `staffLogin` were identical — merged into one handler
- **Fix:** `adminGetUsers` and `getUsers` were near-identical — merged into one fall-through handler
- **Fix:** `applyCoupon` was writing `used_count`/`used_by` at validation time, then `createOrder` wrote again on confirm — every coupon was double-counted; `applyCoupon` is now read-only
- **Fix:** `usage_count` in `createOrder` was computed from a stale pre-increment variable alongside `used_count`; both now use a single `newCount`
- **Fix:** `getSettings` returned `khataEnabled: true` when the DB key was absent (`undefined !== false` is always `true`); changed to `=== true`
- **Fix:** `bulkOrdersWithBalance` silently dropped subscribers with no user record; now correctly pushes to `skipped` array with reason
- **Perf:** `updateMenuOrder` was a sequential await loop (N DB round-trips); replaced with `Promise.all`
- **SQL:** All migrations merged into `database_complete.sql` and `migration_v8_latest.sql`

### v9
- **Fix:** `getThaliItems` was trapped inside `adminGetThalisAll` — extracted to own handler
- **Fix:** `removeThaliItem` read `data.id` but frontend sends `data.itemId` — silently deleted nothing
- **Fix:** `deleteOldData` / preview / delete used `data.before_date` but frontend sends `data.before` — deletions never ran
- **Fix:** Coupon limits could be bypassed — `createOrder` never updated `used_count`/`used_by`
- **Fix:** `masterDelete` always failed — confirm string was never sent from admin UI
- **Fix:** Order notifications only fired for subscriber orders — daily orders invisible in notification bell
- **Fix:** `loadAllKhata` called `getAllKhata` (bare rows) instead of `adminGetAllKhata` (enriched with user names)
- **Fix:** `forceBulkAll` now warns about udhar creation for low-balance subscribers

### v8
- Added `menu_items.description` column
- Schema sync: `veg_type`, `sub_items`, `description` baked into base schema

### v7
- Menu UI: veg/nonveg indicator (`veg_type`), sub-items display (`sub_items`)

### v6
- Added `khata_entries.order_source`, `menu_items.created_at`, `nu_coupon_sent.coupon_code`
