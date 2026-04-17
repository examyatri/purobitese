const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const app = express();
app.use(express.json());
app.use(express.text({ type: 'text/plain' }));

// ── CORS ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ── SUPABASE CLIENT ───────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY
);
const SECURE_API_KEY = process.env.API_KEY;
if (!SECURE_API_KEY) {
  console.error('[FATAL] API_KEY environment variable is not set. Server will reject all requests.');
}

// ── KEEP-ALIVE PING ───────────────────────────────────────────
app.get('/ping', (req, res) => {
  res.status(200).json({ status: 'alive', time: new Date().toISOString() });
});
app.get('/', (req, res) => {
  res.status(200).json({ app: 'Puro Bite API v14', status: 'running' });
});

// ── MAIN API ROUTE ────────────────────────────────────────────
app.post('/api', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch {}
  }
  try {
    const { action, data = {}, apiKey } = req.body;
    if (apiKey !== SECURE_API_KEY) return res.json({ success: false, error: 'Unauthorized' });
    let result;
    switch (action) {
      // ── AUTH ──────────────────────────────────────────────
      case 'login':                    result = await loginUser(data);              break;
      case 'signup':                   result = await signupUser(data);             break;
      case 'adminLogin':               result = await adminLogin(data);             break;
      case 'staffLogin':               result = await staffLogin(data);             break;
      case 'updateProfile':            result = await updateProfile(data);          break;
      case 'resetAdminPassword':       result = await resetAdminPassword(data);     break;
      case 'resetUserPassword':        result = await resetUserPassword(data);      break; // NEW v14

      // ── MENU ──────────────────────────────────────────────
      case 'getMenu':                  result = await getMenu(data);                break;
      case 'adminGetMenu':             result = await adminGetMenu();               break;
      case 'addMenuItem':              result = await addMenuItem(data);            break;
      case 'updateMenuItem':           result = await updateMenuItem(data);         break;
      case 'deleteMenuItem':           result = await deleteMenuItem(data);         break;
      case 'updateMenuOrder':          result = await updateMenuOrder(data);        break;
      case 'updateMenuStock':          result = await updateMenuStock(data);        break; // NEW v14

      // ── THALI ─────────────────────────────────────────────
      case 'getThalis':                result = await getThalis();                  break; // NEW v14
      case 'adminGetThalis':           result = await adminGetThalis();             break; // NEW v14
      case 'createThali':              result = await createThali(data);            break; // NEW v14
      case 'updateThali':              result = await updateThali(data);            break; // NEW v14
      case 'deleteThali':              result = await deleteThali(data);            break; // NEW v14
      case 'addThaliItem':             result = await addThaliItem(data);           break; // NEW v14
      case 'removeThaliItem':          result = await removeThaliItem(data);        break; // NEW v14

      // ── ORDERS ────────────────────────────────────────────
      case 'createOrder':              result = await createOrder(data);            break;
      case 'getUserOrders':            result = await getUserOrders(data);          break;
      case 'adminGetOrders':           result = await adminGetOrders();             break;
      case 'getOrdersByDate':          result = await getOrdersByDate(data);        break;
      case 'updateOrderStatus':        result = await updateOrderStatus(data);      break;
      case 'rejectOrder':              result = await rejectOrder(data);            break;
      case 'bulkOrdersWithBalance':    result = await bulkOrdersWithBalance(data);  break;
      case 'adminBulkCreate':          result = await adminBulkCreate(data);        break;
      case 'forceUdharOrder':          result = await forceUdharOrder(data);        break;

      // ── COUPONS ───────────────────────────────────────────
      case 'applyCoupon':              result = await applyCoupon(data);            break;
      case 'createCoupon':             result = await createCoupon(data);           break;
      case 'adminGetCoupons':          result = await adminGetCoupons();            break;
      case 'deleteCoupon':             result = await deleteCoupon(data);           break;

      // ── SUBSCRIBERS ───────────────────────────────────────
      case 'checkSubscriber':          result = await checkSubscriber(data);        break;
      case 'pauseUserDelivery':        result = await pauseUserDelivery(data);      break;
      case 'getSubscriberPauseStatus': result = await getSubscriberPauseStatus(data); break;
      case 'adminGetSubscribers':      result = await adminGetSubscribers();        break;
      case 'addSubscriber':            result = await addSubscriber(data);          break;
      case 'updateSubscriber':         result = await updateSubscriber(data);       break;
      case 'removeSubscriber':         result = await removeSubscriber(data);       break;
      case 'getUserByPhone':           result = await getUserByPhone(data);         break;
      case 'adminCreateUser':          result = await adminCreateUser(data);        break;
      case 'promoteToSubscriber':      result = await promoteToSubscriber(data);    break;

      // ── RIDERS ────────────────────────────────────────────
      case 'createRider':              result = await createRider(data);            break;
      case 'updateRider':              result = await updateRider(data);            break;
      case 'deleteRider':              result = await deleteRider(data);            break;
      case 'riderLogin':               result = await riderLogin(data);             break;
      case 'getRiderOrders':           result = await getRiderOrders(data);         break;
      case 'getRiders':                result = await getRiders();                  break;
      case 'assignRider':              result = await assignRider(data);            break;

      // ── STAFF ─────────────────────────────────────────────
      case 'createStaff':              result = await createStaff(data);            break;
      case 'updateStaff':              result = await updateStaff(data);            break;
      case 'deleteStaff':              result = await deleteStaff(data);            break;
      case 'getStaff':                 result = await getStaff();                   break;

      // ── WALLET / KHATA ────────────────────────────────────
      case 'getKhata':                 result = await getKhata(data);              break;
      case 'getSubscriberBalance':     result = await getSubscriberBalance(data);  break;
      case 'rechargeWallet':           result = await rechargeWallet(data);        break;
      case 'manualRefund':             result = await manualRefund(data);          break;
      case 'adminGetAllKhata':         result = await adminGetAllKhata();          break;
      case 'addKhataEntry':            result = await addKhataEntry(data);         break;

      // ── SETTINGS ──────────────────────────────────────────
      case 'getOrderCutoff':           result = await getOrderCutoff();            break;
      case 'setOrderCutoff':           result = await setOrderCutoff(data);        break;
      case 'getWeeklySchedule':        result = await getWeeklySchedule();         break;
      case 'setWeeklySchedule':        result = await setWeeklySchedule(data);     break;
      case 'getKhataEnabled':          result = await getKhataEnabled();           break;
      case 'setKhataEnabled':          result = await setKhataEnabled(data);       break;

      // ── ANALYTICS / USERS ─────────────────────────────────
      case 'getAnalytics':             result = await getAnalytics();              break;
      case 'getUsers':                 result = await getUsers();                  break;

      // ── NEW USER COUPON SENT (Supabase) ───────────────────
      case 'getNuCouponSent':          result = await getNuCouponSent();           break;
      case 'markNuCouponSent':         result = await markNuCouponSent(data);      break;
      case 'deleteOldNuCouponSent':    result = await deleteOldNuCouponSent();     break;

      // ── NOTIFICATIONS ─────────────────────────────────────
      case 'getNotifications':         result = await getNotifications(data);      break;
      case 'markNotificationRead':     result = await markNotificationRead(data);  break;
      case 'markNotificationGroupRead':result = await markNotificationGroupRead(data); break;
      case 'deleteNotification':       result = await deleteNotification(data);    break;
      case 'deleteNotificationsByRange':result = await deleteNotificationsByRange(data); break;
      case 'purgeOldNotifications':    result = await purgeOldNotifications();     break;
      case 'createNotification':       result = await createNotification(data);    break;

      // ── DATA CLEANUP ──────────────────────────────────────
      case 'deleteOldData':            result = await deleteOldData(data);         break;
      case 'deleteOldOrders':          result = await deleteOldOrders(data);       break;
      case 'deleteOldTransactions':    result = await deleteOldTransactions(data); break;
      case 'previewDeleteOrders':      result = await previewDeleteOrders(data);   break;
      case 'previewDeleteTransactions':result = await previewDeleteTransactions(data); break;

      default: return res.json({ success: false, error: 'Unknown action: ' + action });
    }
    return res.json({ success: true, data: result });
  } catch (err) {
    console.error('API Error:', err);
    return res.json({ success: false, error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════

async function createNotification(data) {
  const { error } = await supabase.from('notifications').insert({
    type:       data.type,
    priority:   data.priority || 'normal',
    group_id:   data.group_id || null,
    title:      data.title,
    body:       data.body,
    meta:       data.meta || {},
    is_read:    false,
    created_at: new Date().toISOString()
  });
  if (error) console.error('[notif] insert error:', error.message);
  return { ok: !error };
}

async function getNotifications(data) {
  await purgeOldNotifications().catch(() => {});
  const limit = Number(data?.limit) || 200;
  const { data: rows, error } = await supabase
    .from('notifications')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error(error.message);
  return rows || [];
}

async function markNotificationRead(data) {
  if (!data.id) throw new Error('id required');
  const { error } = await supabase.from('notifications')
    .update({ is_read: true, read_at: new Date().toISOString() })
    .eq('id', data.id);
  if (error) throw new Error(error.message);
  return { ok: true };
}

async function markNotificationGroupRead(data) {
  if (!data.group_id) throw new Error('group_id required');
  const { error } = await supabase.from('notifications')
    .update({ is_read: true, read_at: new Date().toISOString() })
    .eq('group_id', data.group_id);
  if (error) throw new Error(error.message);
  return { ok: true };
}

async function deleteNotification(data) {
  if (!data.id) throw new Error('id required');
  const { error } = await supabase.from('notifications').delete().eq('id', data.id);
  if (error) throw new Error(error.message);
  return { ok: true };
}

async function deleteNotificationsByRange(data) {
  if (!data.from || !data.to) throw new Error('from and to dates required');
  const from = data.from + 'T00:00:00Z';
  const to   = data.to   + 'T23:59:59Z';
  const { error, count } = await supabase.from('notifications')
    .delete({ count: 'exact' })
    .gte('created_at', from)
    .lte('created_at', to);
  if (error) throw new Error(error.message);
  return { deleted: count || 0 };
}

async function purgeOldNotifications() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { error, count } = await supabase.from('notifications')
    .delete({ count: 'exact' })
    .lt('created_at', cutoff);
  if (error) console.error('[notif] purge error:', error.message);
  return { purged: count || 0 };
}

// ── START SERVER ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Puro Bite API v14 running on port ' + PORT));

// ── SELF PING — keeps Render awake ───────────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || '';
if (SELF_URL) {
  const https = require('https');
  setInterval(() => {
    https.get(SELF_URL + '/ping', (res) => {
      console.log('[KeepAlive] Pinged at ' + new Date().toISOString() + ' — status: ' + res.statusCode);
    }).on('error', (e) => {
      console.error('[KeepAlive] Ping failed:', e.message);
    });
  }, 10 * 60 * 1000);
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function getIST() { return new Date(Date.now() + 5.5 * 3600000); }

// ── ID GENERATORS ─────────────────────────────────────────────
// Order ID  : ORD-20250414-143022-AB7K2
// Thali ID  : THALI-20250414-143022-AB7K2
// Rider ID  : RDR-14042025-0001
// Menu ID   : MENU-AB7K2
// TXN ID    : TXN-20250414-143022-AB7K2
// User ID   : phone number (10-digit)
function generateId(prefix, ist) {
  const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let rand = '';
  for (let i = 0; i < 5; i++) rand += CHARS[Math.floor(Math.random() * CHARS.length)];
  if (!ist) return `${prefix}-${rand}`;
  const yyyy = ist.getUTCFullYear();
  const mm   = String(ist.getUTCMonth() + 1).padStart(2, '0');
  const dd   = String(ist.getUTCDate()).padStart(2, '0');
  const HH   = String(ist.getUTCHours()).padStart(2, '0');
  const MM   = String(ist.getUTCMinutes()).padStart(2, '0');
  const SS   = String(ist.getUTCSeconds()).padStart(2, '0');
  return `${prefix}-${yyyy}${mm}${dd}-${HH}${MM}${SS}-${rand}`;
}
function generateOrderId(ist)  { return generateId('ORD',   ist); }
function generateThaliId(ist)  { return generateId('THALI', ist); }
function generateTxnId(ist)    { return generateId('TXN',   ist); }

async function generateRiderId(ist) {
  const dd   = String(ist.getUTCDate()).padStart(2, '0');
  const mm   = String(ist.getUTCMonth() + 1).padStart(2, '0');
  const yyyy = String(ist.getUTCFullYear());
  const prefix = `RDR-${dd}${mm}${yyyy}`;
  const { count } = await supabase
    .from('riders')
    .select('rider_id', { count: 'exact', head: true })
    .like('rider_id', `${prefix}%`);
  const seq = String((count || 0) + 1).padStart(4, '0');
  return `${prefix}-${seq}`;
}

// ── DATE/TIME UTILITIES ───────────────────────────────────────
function istDateStr(d) {
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}
function istTimeStr(d) {
  let h = d.getUTCHours(), m = d.getUTCMinutes();
  const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ' ' + p;
}
function cleanPhone(p) { return String(p || '').replace(/\D/g, ''); }

function _istFromEpoch(ms) { return new Date(ms + 5.5 * 3600000); }
function _ymd(d) {
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}

function normOrderDate(v) {
  if (!v) return '';
  const s = String(v).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) {
    const p = s.split('/');
    return `${p[2]}-${p[1].padStart(2,'0')}-${p[0].padStart(2,'0')}`;
  }
  if (/^\d{4}\/\d{2}\/\d{2}$/.test(s)) return s.replace(/\//g, '-');
  if (/^\d{4}-\d{2}-\d{2}T/.test(s) || /Z$/.test(s)) {
    const raw = new Date(s);
    if (!isNaN(raw.getTime())) return _ymd(_istFromEpoch(raw.getTime()));
  }
  if (v instanceof Date && !isNaN(v.getTime())) return _ymd(_istFromEpoch(v.getTime()));
  if (/^\d+(\.\d+)?$/.test(s)) {
    const serial = parseFloat(s);
    if (serial > 40000 && serial < 60000) {
      const raw = new Date((serial - 25569) * 86400000);
      if (!isNaN(raw.getTime())) return _ymd(_istFromEpoch(raw.getTime()));
    }
  }
  return '';
}

function normOrderTime(v) {
  if (!v) return '';
  const s = String(v).trim().replace(/[\u00a0\u202f\u2009]/g, ' ');
  const ampm = s.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (ampm) return String(ampm[1]).padStart(2,'0') + ':' + ampm[2] + ' ' + ampm[3].toUpperCase();
  const h24 = s.match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (h24) {
    let h = parseInt(h24[1]), mn = parseInt(h24[2]);
    const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
    return String(h).padStart(2, '0') + ':' + String(mn).padStart(2, '0') + ' ' + p;
  }
  if (/^\d{4}-\d{2}-\d{2}T/.test(s) || /Z$/.test(s)) {
    const raw = new Date(s);
    if (!isNaN(raw.getTime())) {
      const ist = _istFromEpoch(raw.getTime());
      let h = ist.getUTCHours(), mn = ist.getUTCMinutes();
      const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
      return String(h).padStart(2, '0') + ':' + String(mn).padStart(2, '0') + ' ' + p;
    }
  }
  return s;
}

function formatOrder(o) {
  return {
    orderId: o.order_id, userId: o.user_id,
    name: o.name, phone: o.phone, address: o.address,
    items: typeof o.items === 'string' ? o.items : JSON.stringify(o.items),
    totalAmount: o.total_amount, deliveryCharge: o.delivery_charge,
    finalAmount: Number(o.final_amount) || 0,
    couponCode: o.coupon_code || '', discount: o.discount || 0,
    userType: o.user_type || 'daily',
    paymentStatus: o.payment_status || 'pending',
    orderStatus: o.order_status || 'pending',
    date: normOrderDate(o.order_date), time: normOrderTime(o.order_time),
    riderId: o.rider_id || ''
  };
}

function formatMenuItem(i) {
  let variants = [];
  try { variants = i.variant ? JSON.parse(i.variant) : []; } catch { variants = []; }
  return {
    itemId: i.item_id, name: i.name, category: i.category || '',
    price: Number(i.price) || 0, variants,
    imageUrl: i.image_url || '', menuType: i.menu_type || 'morning',
    availability: i.availability, sortOrder: i.sort_order || 9999,
    highlight: i.highlight || '',
    // v14: stock fields
    stockGrams: i.stock_grams !== null && i.stock_grams !== undefined
      ? Number(i.stock_grams)
      : null   // null = unlimited
  };
}

function formatThali(t, items = []) {
  return {
    thaliId:     t.thali_id,
    name:        t.name,
    description: t.description || '',
    price:       Number(t.price) || 0,
    imageUrl:    t.image_url || '',
    isActive:    t.is_active,
    stockQty:    t.stock_qty !== null && t.stock_qty !== undefined
      ? Number(t.stock_qty)
      : null,
    createdAt:   t.created_at,
    items:       items.map(i => ({
      id:              i.id,
      menuItemId:      i.menu_item_id,
      menuItemName:    i.menu_item_name || '',
      variantLabel:    i.variant_label,
      variantPrice:    Number(i.variant_price) || 0,
      variantGrams:    i.variant_grams !== null ? Number(i.variant_grams) : null,
      quantityInThali: Number(i.quantity_in_thali) || 1
    }))
  };
}

function getDefaultDay(d, name) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return { day: name || days[d], open: true, openTime: '07:00', lunchStart: '07:00', lunchEnd: '11:00' };
}

// ═══════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════

async function signupUser(data) {
  if (!data.phone || !data.password || !data.name) throw new Error('Name, phone, password required');
  const ph = cleanPhone(data.phone);
  const { data: existing } = await supabase.from('users').select('phone').eq('phone', ph).maybeSingle();
  if (existing) throw new Error('Phone already registered');
  const hashed = await bcrypt.hash(String(data.password).trim(), 10);
  const { data: user, error } = await supabase.from('users').insert({
    user_id: ph, name: data.name, phone: ph,
    email: data.email || '', address: data.address || '',
    password: hashed, is_subscriber: false
  }).select().single();
  if (error) throw new Error(error.message);
  const signupResult = { userId: user.user_id, name: user.name, phone: user.phone, email: user.email || '', address: user.address || '', isSubscriber: false };
  setImmediate(() => createNotification({
    type: 'user', priority: 'normal',
    title: '🟢 New User Registered',
    body: `${data.name} just signed up`,
    meta: { phone: ph, name: data.name, address: data.address || '' }
  }).catch(() => {}));
  return signupResult;
}

async function loginUser(data) {
  if (!data.phone || !data.password) throw new Error('Phone and password required');
  const ph       = cleanPhone(data.phone);
  const password = String(data.password).trim();
  const { data: user } = await supabase.from('users').select('*').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('User not found');
  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new Error('Incorrect password');

  // v14 FIX: Always verify subscriber status from DB at login time
  // Check both is_subscriber flag AND active row in subscribers table
  const { data: sub } = await supabase
    .from('subscribers')
    .select('is_active')
    .eq('phone', ph)
    .maybeSingle();
  const isSubscriber = !!(sub && sub.is_active);

  // Sync flag if out of date
  if (user.is_subscriber !== isSubscriber) {
    await supabase.from('users').update({ is_subscriber: isSubscriber }).eq('phone', ph);
  }

  return {
    userId:       user.user_id,
    name:         user.name,
    phone:        user.phone,
    email:        user.email  || '',
    address:      user.address || '',
    isSubscriber           // always fresh from DB
  };
}

async function adminLogin(data) {
  if (!data.email || !data.password) throw new Error('Email and password required');
  const email    = String(data.email).trim().toLowerCase();
  const password = String(data.password).trim();
  const { data: setting } = await supabase.from('admin_settings').select('*').eq('admin_id', email).maybeSingle();
  if (!setting) throw new Error('Admin not found');
  const match = await bcrypt.compare(password, setting.password_hash);
  if (!match) throw new Error('Incorrect password');
  return { email, name: 'Admin', role: 'admin' };
}

async function staffLogin(data) {
  if (!data.username || !data.password) throw new Error('Username and password required');
  const username = String(data.username).trim().toLowerCase();
  const password = String(data.password).trim();
  const { data: s } = await supabase.from('staff').select('*').eq('username', username).maybeSingle();
  if (!s) throw new Error('Invalid credentials');
  const match = await bcrypt.compare(password, s.password);
  if (!match) throw new Error('Invalid credentials');
  if (s.status !== 'active') throw new Error('Account is inactive');
  return { username: s.username, name: s.name, role: 'staff' };
}

async function updateProfile(data) {
  if (!data.userId) throw new Error('userId required');
  const updates = {};
  if (data.name    !== undefined) updates.name    = data.name;
  if (data.email   !== undefined) updates.email   = data.email;
  if (data.address !== undefined) updates.address = data.address;
  if (data.newPassword) updates.password = await bcrypt.hash(String(data.newPassword), 10);
  const { error } = await supabase.from('users').update(updates).eq('user_id', data.userId);
  if (error) throw new Error(error.message);
  return true;
}

async function resetAdminPassword(data) {
  if (!data.email) throw new Error('email required');
  if (!data.newPassword || String(data.newPassword).length < 6) throw new Error('Password must be 6+ chars');
  const email  = String(data.email).trim().toLowerCase();
  const { data: row } = await supabase.from('admin_settings').select('admin_id').eq('admin_id', email).maybeSingle();
  if (!row) throw new Error('Admin account not found');
  const hashed = await bcrypt.hash(String(data.newPassword), 10);
  const { error } = await supabase.from('admin_settings').update({ password_hash: hashed }).eq('admin_id', email);
  if (error) throw new Error(error.message);
  return { success: true, message: 'Admin password updated' };
}

// v14 NEW: Admin resets a user's password by phone number
async function resetUserPassword(data) {
  if (!data.phone)       throw new Error('phone required');
  if (!data.newPassword || String(data.newPassword).trim().length < 6)
    throw new Error('New password must be at least 6 characters');
  const ph = cleanPhone(data.phone);
  // Confirm user exists
  const { data: user } = await supabase.from('users').select('user_id, name').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('No user found with this phone number');
  const hashed = await bcrypt.hash(String(data.newPassword).trim(), 10);
  const { error } = await supabase.from('users').update({ password: hashed }).eq('phone', ph);
  if (error) throw new Error(error.message);
  return { success: true, userName: user.name, phone: ph };
}

// ═══════════════════════════════════════════════════════════════
// MENU
// ═══════════════════════════════════════════════════════════════

async function getMenu(data) {
  const ist = getIST();
  const h   = ist.getUTCHours() + ist.getUTCMinutes() / 60;
  const dow = ist.getUTCDay();

  let lunchCutoffH = 11.5;
  try {
    const { data: rows } = await supabase
      .from('admin_settings')
      .select('admin_id, access_level')
      .in('admin_id', [`schedule_${dow}`, 'cutoff_day']);
    if (rows && rows.length) {
      const map = {};
      rows.forEach(r => { map[r.admin_id] = r.access_level; });
      const schedRaw = map[`schedule_${dow}`];
      if (schedRaw) {
        const sched = JSON.parse(schedRaw);
        if (sched && sched.lunchEnd) {
          const [sh, sm] = sched.lunchEnd.split(':').map(Number);
          lunchCutoffH = sh + sm / 60;
        }
      } else if (map['cutoff_day']) {
        const [ch, cm] = map['cutoff_day'].split(':').map(Number);
        lunchCutoffH = ch + cm / 60;
      }
    }
  } catch (_) {}

  const menuType = h < lunchCutoffH ? 'morning' : 'evening';
  const { data: items, error } = await supabase
    .from('menu')
    .select('*')
    .eq('availability', true)
    .eq('menu_type', menuType)
    .order('sort_order', { ascending: true });
  if (error) throw new Error(error.message);
  return (items || []).map(formatMenuItem);
}

async function adminGetMenu() {
  const { data: items, error } = await supabase
    .from('menu').select('*').order('sort_order', { ascending: true });
  if (error) throw new Error(error.message);
  return (items || []).map(formatMenuItem);
}

async function addMenuItem(data) {
  if (!data.name) throw new Error('Item name required');
  const { data: items } = await supabase.from('menu')
    .select('sort_order').order('sort_order', { ascending: false }).limit(1);
  const maxSort    = items?.[0]?.sort_order || 0;
  const menuItemId = generateId('MENU');
  const row = {
    item_id:    menuItemId,
    name:       data.name,
    category:   data.category  || '',
    price:      Number(data.price) || 0,
    variant:    data.variants ? JSON.stringify(data.variants) : null,
    image_url:  data.imageUrl  || '',
    menu_type:  data.menuType  || 'morning',
    availability: true,
    highlight:  data.highlight || '',
    sort_order: data.sortOrder || (maxSort + 1)
  };
  // v14: stock_grams
  if (data.stockGrams !== undefined && data.stockGrams !== null && data.stockGrams !== '') {
    row.stock_grams = Number(data.stockGrams);
  }
  const { data: item, error } = await supabase.from('menu').insert(row).select().single();
  if (error) throw new Error(error.message);
  return { itemId: item.item_id };
}

async function updateMenuItem(data) {
  if (!data.itemId) throw new Error('itemId required');
  const updates = {};
  if (data.name         !== undefined) updates.name         = data.name;
  if (data.category     !== undefined) updates.category     = data.category;
  if (data.price        !== undefined) updates.price        = Number(data.price);
  if (data.variants     !== undefined) updates.variant      = JSON.stringify(data.variants);
  if (data.imageUrl     !== undefined) updates.image_url    = data.imageUrl;
  if (data.menuType     !== undefined) updates.menu_type    = data.menuType;
  if (data.availability !== undefined) updates.availability = data.availability === 'TRUE' || data.availability === true;
  if (data.highlight    !== undefined) updates.highlight    = data.highlight;
  if (data.sortOrder    !== undefined) updates.sort_order   = Number(data.sortOrder);
  // v14: allow null (unlimited) or a number
  if (data.stockGrams !== undefined) {
    updates.stock_grams = (data.stockGrams === null || data.stockGrams === '')
      ? null
      : Number(data.stockGrams);
  }
  const { error } = await supabase.from('menu').update(updates).eq('item_id', data.itemId);
  if (error) throw new Error(error.message);
  return true;
}

async function deleteMenuItem(data) {
  if (!data.itemId) throw new Error('itemId required');
  const { error } = await supabase.from('menu').delete().eq('item_id', data.itemId);
  if (error) throw new Error(error.message);
  return true;
}

async function updateMenuOrder(data) {
  if (!data.items || !Array.isArray(data.items)) throw new Error('items array required');
  const results = await Promise.all(
    data.items.map(item =>
      supabase.from('menu').update({ sort_order: Number(item.sortOrder) }).eq('item_id', item.itemId)
    )
  );
  const failed = results
    .map((r, i) => r.error ? `item ${data.items[i].itemId}: ${r.error.message}` : null)
    .filter(Boolean);
  if (failed.length) throw new Error('Some items failed to reorder: ' + failed.join('; '));
  return true;
}

// v14 NEW: Admin updates stock directly (increase/decrease/reset)
async function updateMenuStock(data) {
  if (!data.itemId) throw new Error('itemId required');
  const stockGrams = (data.stockGrams === null || data.stockGrams === '' || data.stockGrams === undefined)
    ? null
    : Number(data.stockGrams);
  const { error } = await supabase
    .from('menu')
    .update({ stock_grams: stockGrams })
    .eq('item_id', data.itemId);
  if (error) throw new Error(error.message);
  return { itemId: data.itemId, stockGrams };
}

// ═══════════════════════════════════════════════════════════════
// STOCK DEDUCTION HELPERS (v14)
// ═══════════════════════════════════════════════════════════════

// Deduct stock for a list of cart items.
// Each item must have: itemId, selectedVariant (label), qty
// selectedVariantGrams is resolved from the variant list in menu.
// Returns { success: true } or throws with the item name that failed.
async function _deductMenuStock(cartItems) {
  if (!cartItems || !cartItems.length) return;

  // Collect all unique itemIds we need to check
  const itemIds = [...new Set(
    cartItems.filter(i => i.itemId && !i.isThali).map(i => i.itemId)
  )];
  if (!itemIds.length) return;

  // Fetch current stock + variants for those items
  const { data: menuRows, error } = await supabase
    .from('menu')
    .select('item_id, name, stock_grams, variant')
    .in('item_id', itemIds);
  if (error) throw new Error(error.message);

  const menuMap = {};
  (menuRows || []).forEach(r => { menuMap[r.item_id] = r; });

  // Build deduction map: itemId → total grams to deduct
  const deductions = {};
  for (const ci of cartItems) {
    if (ci.isThali) continue; // thali stock handled separately
    const row = menuMap[ci.itemId];
    if (!row || row.stock_grams === null || row.stock_grams === undefined) continue; // unlimited

    // Parse variant to find gram weight
    let variants = [];
    try { variants = row.variant ? JSON.parse(row.variant) : []; } catch {}
    const variant = variants.find(v => v.label === ci.selectedVariant);
    const grams   = variant?.grams ? Number(variant.grams) : 0;
    if (!grams) continue; // variant has no gram tracking

    const totalDeduct = grams * (Number(ci.qty) || 1);
    deductions[ci.itemId] = (deductions[ci.itemId] || 0) + totalDeduct;
  }

  // Validate and deduct
  for (const [itemId, deductGrams] of Object.entries(deductions)) {
    const row = menuMap[itemId];
    if (row.stock_grams < deductGrams) {
      throw new Error(`"${row.name}" is out of stock or has insufficient quantity available`);
    }
    const newStock = row.stock_grams - deductGrams;
    const { error: upErr } = await supabase
      .from('menu')
      .update({ stock_grams: newStock })
      .eq('item_id', itemId);
    if (upErr) throw new Error(`Stock update failed for ${row.name}: ` + upErr.message);
  }
}

// Deduct thali stock + all its component variant stocks
async function _deductThaliStock(thaliId, qty) {
  qty = Number(qty) || 1;

  // 1. Deduct thali-level stock_qty
  const { data: thali, error: tErr } = await supabase
    .from('thalis')
    .select('thali_id, name, stock_qty')
    .eq('thali_id', thaliId)
    .maybeSingle();
  if (tErr) throw new Error(tErr.message);
  if (!thali) throw new Error('Thali not found: ' + thaliId);

  if (thali.stock_qty !== null && thali.stock_qty !== undefined) {
    if (thali.stock_qty < qty) throw new Error(`"${thali.name}" thali is out of stock`);
    await supabase.from('thalis')
      .update({ stock_qty: thali.stock_qty - qty })
      .eq('thali_id', thaliId);
  }

  // 2. Deduct each component's menu item stock
  const { data: components } = await supabase
    .from('thali_items')
    .select('menu_item_id, variant_grams, quantity_in_thali')
    .eq('thali_id', thaliId);

  for (const comp of (components || [])) {
    if (!comp.variant_grams) continue; // no gram tracking for this component
    const gramsNeeded = comp.variant_grams * comp.quantity_in_thali * qty;

    const { data: menuItem } = await supabase
      .from('menu')
      .select('name, stock_grams')
      .eq('item_id', comp.menu_item_id)
      .maybeSingle();
    if (!menuItem || menuItem.stock_grams === null) continue; // unlimited

    if (menuItem.stock_grams < gramsNeeded) {
      throw new Error(`A component of "${thali.name}" (${menuItem.name}) is out of stock`);
    }
    await supabase.from('menu')
      .update({ stock_grams: menuItem.stock_grams - gramsNeeded })
      .eq('item_id', comp.menu_item_id);
  }
}

// ═══════════════════════════════════════════════════════════════
// THALI (v14 NEW)
// ═══════════════════════════════════════════════════════════════

// Helper: fetch thali items with menu item names joined
async function _getThaliItems(thaliId) {
  const { data: rows, error } = await supabase
    .from('thali_items')
    .select('*')
    .eq('thali_id', thaliId);
  if (error) return [];
  if (!rows || !rows.length) return [];

  // Fetch menu item names in one query
  const menuIds = [...new Set(rows.map(r => r.menu_item_id))];
  const { data: menuRows } = await supabase
    .from('menu')
    .select('item_id, name')
    .in('item_id', menuIds);
  const nameMap = {};
  (menuRows || []).forEach(m => { nameMap[m.item_id] = m.name; });

  return rows.map(r => ({ ...r, menu_item_name: nameMap[r.menu_item_id] || '' }));
}

// User-facing: only active thalis
async function getThalis() {
  const { data: thalis, error } = await supabase
    .from('thalis')
    .select('*')
    .eq('is_active', true)
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);

  const result = [];
  for (const t of (thalis || [])) {
    const items = await _getThaliItems(t.thali_id);
    result.push(formatThali(t, items));
  }
  return result;
}

// Admin-facing: all thalis
async function adminGetThalis() {
  const { data: thalis, error } = await supabase
    .from('thalis')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);

  const result = [];
  for (const t of (thalis || [])) {
    const items = await _getThaliItems(t.thali_id);
    result.push(formatThali(t, items));
  }
  return result;
}

async function createThali(data) {
  if (!data.name) throw new Error('Thali name required');
  if (!data.price || Number(data.price) <= 0) throw new Error('Thali price required');
  const ist     = getIST();
  const thaliId = generateThaliId(ist);
  const row = {
    thali_id:    thaliId,
    name:        data.name,
    description: data.description || '',
    price:       Number(data.price),
    image_url:   data.imageUrl || '',
    is_active:   data.isActive !== false,
    stock_qty:   (data.stockQty !== undefined && data.stockQty !== null && data.stockQty !== '')
      ? Number(data.stockQty)
      : null
  };
  const { error } = await supabase.from('thalis').insert(row);
  if (error) throw new Error(error.message);

  // Add components if provided
  if (data.items && Array.isArray(data.items) && data.items.length) {
    await _saveThaliItems(thaliId, data.items);
  }
  return { thaliId };
}

async function updateThali(data) {
  if (!data.thaliId) throw new Error('thaliId required');
  const updates = {};
  if (data.name        !== undefined) updates.name        = data.name;
  if (data.description !== undefined) updates.description = data.description;
  if (data.price       !== undefined) updates.price       = Number(data.price);
  if (data.imageUrl    !== undefined) updates.image_url   = data.imageUrl;
  if (data.isActive    !== undefined) updates.is_active   = data.isActive;
  if (data.stockQty    !== undefined) {
    updates.stock_qty = (data.stockQty === null || data.stockQty === '') ? null : Number(data.stockQty);
  }
  const { error } = await supabase.from('thalis').update(updates).eq('thali_id', data.thaliId);
  if (error) throw new Error(error.message);

  // If items array supplied, replace all components
  if (data.items && Array.isArray(data.items)) {
    // Delete existing
    await supabase.from('thali_items').delete().eq('thali_id', data.thaliId);
    // Re-insert
    if (data.items.length) await _saveThaliItems(data.thaliId, data.items);
  }
  return true;
}

async function deleteThali(data) {
  if (!data.thaliId) throw new Error('thaliId required');
  // thali_items cascade deletes automatically
  const { error } = await supabase.from('thalis').delete().eq('thali_id', data.thaliId);
  if (error) throw new Error(error.message);
  return true;
}

async function addThaliItem(data) {
  if (!data.thaliId || !data.menuItemId || !data.variantLabel) {
    throw new Error('thaliId, menuItemId, variantLabel required');
  }
  const row = {
    thali_id:         data.thaliId,
    menu_item_id:     data.menuItemId,
    variant_label:    data.variantLabel,
    variant_price:    Number(data.variantPrice)    || 0,
    variant_grams:    data.variantGrams !== undefined && data.variantGrams !== null
      ? Number(data.variantGrams) : null,
    quantity_in_thali: Number(data.quantityInThali) || 1
  };
  const { error } = await supabase.from('thali_items').insert(row);
  if (error) throw new Error(error.message);
  return true;
}

async function removeThaliItem(data) {
  if (!data.id) throw new Error('thali_item id required');
  const { error } = await supabase.from('thali_items').delete().eq('id', data.id);
  if (error) throw new Error(error.message);
  return true;
}

// Internal helper: insert multiple thali items at once
async function _saveThaliItems(thaliId, items) {
  const rows = items.map(i => ({
    thali_id:          thaliId,
    menu_item_id:      i.menuItemId,
    variant_label:     i.variantLabel,
    variant_price:     Number(i.variantPrice)    || 0,
    variant_grams:     (i.variantGrams !== undefined && i.variantGrams !== null && i.variantGrams !== '')
      ? Number(i.variantGrams) : null,
    quantity_in_thali: Number(i.quantityInThali) || 1
  }));
  const { error } = await supabase.from('thali_items').insert(rows);
  if (error) throw new Error('Failed to save thali components: ' + error.message);
}

// ═══════════════════════════════════════════════════════════════
// ORDERS
// ═══════════════════════════════════════════════════════════════

async function createOrder(data) {
  if (!data.userId) throw new Error('userId required');
  const items = Array.isArray(data.items) ? data.items : JSON.parse(data.items || '[]');
  if (!items.length) throw new Error('Cart is empty');

  const ist     = getIST();
  const orderId = generateOrderId(ist);
  const ph      = cleanPhone(data.phone);
  const isSub   = data.userType === 'subscriber' && data.payFromWallet;
  const amount  = Number(data.finalAmount) || 0;

  // ── Step 1: Verify subscriber status from DB (v14 fix) ─────
  if (data.userType === 'subscriber') {
    const { data: sub } = await supabase
      .from('subscribers')
      .select('is_active')
      .eq('phone', ph)
      .maybeSingle();
    if (!sub || !sub.is_active) {
      // Not actually a subscriber — treat as daily user, no wallet deduction
      data.userType     = 'daily';
      data.payFromWallet = false;
    }
  }
  const isSub2 = data.userType === 'subscriber' && data.payFromWallet;

  // ── Step 2: Deduct wallet FIRST (before order insert) ──────
  if (isSub2 && amount > 0) {
    const itemSummary = items.map(i =>
      i.name + (i.selectedVariant ? ` (${i.selectedVariant})` : '') + ` ×${i.qty}`
    ).join(', ');
    const noteText = `Tiffin Given (${itemSummary}) | ${orderId}`;
    await deductWalletBalance(ph, amount, noteText, ph); // v14: user_id = phone
  }

  // ── Step 3: Deduct menu stock (v14) ────────────────────────
  try {
    // Regular items
    await _deductMenuStock(items);
    // Thali items
    for (const ci of items) {
      if (ci.isThali && ci.itemId) {
        await _deductThaliStock(ci.itemId, ci.qty || 1);
      }
    }
  } catch (stockErr) {
    // Refund wallet if stock deduction failed
    if (isSub2 && amount > 0) {
      try {
        await rechargeWallet({ phone: ph, amount, note: `Auto-refund — stock error on order ${orderId}` });
      } catch (_) {}
    }
    throw stockErr;
  }

  // ── Step 4: Insert order ────────────────────────────────────
  const { data: order, error } = await supabase.from('orders').insert({
    order_id:       orderId,
    user_id:        data.userId,
    name:           data.name,
    phone:          ph,
    address:        data.address,
    items,
    total_amount:   Number(data.totalAmount)    || 0,
    delivery_charge: Number(data.deliveryCharge) || 0,
    final_amount:   amount,
    coupon_code:    data.couponCode || '',
    discount:       Number(data.discount)        || 0,
    user_type:      data.userType || 'daily',
    payment_status: 'pending',
    order_status:   'pending',
    order_date:     istDateStr(ist),
    order_time:     istTimeStr(ist)
  }).select().single();

  if (error) {
    // Auto-refund wallet on order insert failure
    if (isSub2 && amount > 0) {
      try {
        await rechargeWallet({ phone: ph, amount, note: `Auto-refund — order ${orderId} failed to save` });
      } catch (_) { console.error(`[createOrder] Auto-refund failed for ${ph} ₹${amount}`); }
    }
    throw new Error(error.message);
  }

  if (data.couponCode) await incrementCouponUsage(data.couponCode, ph);

  // Return new wallet balance for immediate UI update (subscribers)
  let newBalance = null;
  if (isSub2) {
    newBalance = await getWalletBalance(ph);
  }

  const orderResult = { orderId: order.order_id, newBalance };
  const _notifGroupId = 'order_' + order.order_id;
  setImmediate(async () => {
    try {
      await createNotification({ type:'order', priority:'high', group_id: _notifGroupId,
        title:'🛒 New Order Placed',
        body:`${data.name} placed an order of ₹${amount}`,
        meta:{ phone:ph, name:data.name, order_id:order.order_id,
               amount, user_type:data.userType||'daily', sub_group:'order', group_id:_notifGroupId }
      });
      await createNotification({ type:'transaction', priority:'normal', group_id: _notifGroupId,
        title:'💳 New Transaction (Order)',
        body:`Payment linked to order ${order.order_id}`,
        meta:{ phone:ph, name:data.name, order_id:order.order_id,
               amount, user_type:data.userType||'daily', sub_group:'txn', group_id:_notifGroupId }
      });
    } catch(_) {}
  });
  return orderResult;
}

async function getUserOrders(data) {
  if (!data.userId) throw new Error('userId required');
  const { data: orders, error } = await supabase
    .from('orders').select('*')
    .eq('user_id', data.userId)
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  return (orders || []).map(formatOrder);
}

async function adminGetOrders() {
  const { data: orders, error } = await supabase
    .from('orders').select('*')
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  return (orders || []).map(formatOrder);
}

async function getOrdersByDate(data) {
  const date = data.date || istDateStr(getIST());
  const { data: orders, error } = await supabase
    .from('orders')
    .select('phone, order_date, order_status')
    .eq('order_date', date)
    .neq('order_status', 'rejected');
  if (error) throw new Error(error.message);
  return (orders || []).map(o => ({
    phone: cleanPhone(o.phone), date: o.order_date, status: o.order_status
  }));
}

// v14: valid statuses — pending → verified → preparing → out for delivery → delivered | rejected
const VALID_ORDER_STATUSES = ['pending','verified','preparing','out for delivery','delivered','rejected'];

async function updateOrderStatus(data) {
  if (!data.orderId) throw new Error('orderId required');
  if (data.status && !VALID_ORDER_STATUSES.includes(data.status)) {
    throw new Error(`Invalid status: ${data.status}. Valid: ${VALID_ORDER_STATUSES.join(', ')}`);
  }
  const updates = {};
  if (data.status)        updates.order_status   = data.status;
  if (data.paymentStatus) updates.payment_status = data.paymentStatus;
  if (data.riderId)       updates.rider_id       = data.riderId;
  const { error } = await supabase.from('orders').update(updates).eq('order_id', data.orderId);
  if (error) throw new Error(error.message);
  return true;
}

async function rejectOrder(data) {
  if (!data.orderId) throw new Error('orderId required');
  const { data: order, error: fetchErr } = await supabase
    .from('orders')
    .select('order_id, user_id, phone, final_amount, user_type, payment_status, order_status')
    .eq('order_id', data.orderId)
    .maybeSingle();
  if (fetchErr) throw new Error(fetchErr.message);
  if (!order) throw new Error('Order not found');
  if (order.order_status === 'rejected') {
    return { rejected: true, refunded: 0, alreadyRejected: true };
  }
  const { error } = await supabase
    .from('orders').update({ order_status: 'rejected' }).eq('order_id', data.orderId);
  if (error) throw new Error(error.message);

  const refundMode = data.refundMode || 'none';
  const amt        = Number(data.refundAmount) || Number(order.final_amount) || 0;
  let refundedAmount = 0;
  if (refundMode === 'wallet' && amt > 0) {
    const ph   = cleanPhone(order.phone);
    const note = data.refundNote
      ? `Refund — ${data.refundNote} | order ${order.order_id}`
      : `Refund — rejected order ${order.order_id}`;
    await rechargeWallet({ phone: ph, amount: amt, note });
    refundedAmount = amt;
  }
  return { rejected: true, refunded: refundedAmount, refundMode };
}

// ── INTERNAL SINGLE ORDER CREATOR ────────────────────────────
async function _createSingleOrder(o, { skipDeduction = false, allowOverdraft = false } = {}) {
  const ph     = cleanPhone(o.phone);
  const amount = Number(o.finalAmount) || 0;
  const items  = Array.isArray(o.items) ? o.items : JSON.parse(o.items || '[]');
  const userId = o.userId || ph; // v14: user_id = phone

  if (!skipDeduction && !allowOverdraft && amount > 0 && o.userType !== 'daily') {
    const bal = await getWalletBalance(ph);
    if (bal < amount) throw new Error(`Insufficient balance ₹${bal} (need ₹${amount})`);
  }

  const ist     = getIST();
  const orderId = generateOrderId(ist);

  const { data: order, error } = await supabase.from('orders').insert({
    order_id:       orderId,
    user_id:        userId,
    name:           o.name,
    phone:          ph,
    address:        o.address || '',
    items,
    total_amount:   amount,
    delivery_charge: 0,
    final_amount:   amount,
    coupon_code:    '',
    discount:       0,
    user_type:      o.userType || 'subscriber',
    payment_status: 'pending',
    order_status:   'pending',
    order_date:     istDateStr(ist),
    order_time:     istTimeStr(ist)
  }).select().single();
  if (error) throw new Error(error.message);

  if (!skipDeduction && amount > 0 && o.userType !== 'daily') {
    const itemSummary = items.map(i =>
      i.name + (i.selectedVariant ? ` (${i.selectedVariant})` : '') + ` ×${i.qty}`
    ).join(', ');
    // v14: user_id = phone
    await deductWalletBalance(ph, amount, `Tiffin Given (${itemSummary || 'tiffin'}) | ${order.order_id}`, ph);
  }

  return order.order_id;
}

async function forceUdharOrder(data) {
  if (!data.phone) throw new Error('phone required');
  const items  = Array.isArray(data.items) ? data.items : JSON.parse(data.items || '[]');
  const ph     = cleanPhone(data.phone);
  const amount = Number(data.amount) || Number(data.finalAmount) || 0;
  const orderId = await _createSingleOrder({
    phone: ph, name: data.name, address: data.address || '',
    items, finalAmount: amount,
    userId: ph, // v14: user_id = phone
    userType: 'subscriber'
  }, { allowOverdraft: true });
  const newBal = await getWalletBalance(ph);
  return { orderId, newBalance: newBal };
}

async function bulkOrdersWithBalance(data) {
  if (!data.orders || !Array.isArray(data.orders)) throw new Error('orders array required');
  const nowIST   = getIST();
  const istHour  = nowIST.getUTCHours();
  const slotName = istHour < 12 ? 'morning' : 'evening';

  const allPhones = data.orders.map(o => cleanPhone(o.phone));
  const { data: pauseRows } = await supabase
    .from('subscribers')
    .select('phone, pause_delivery')
    .in('phone', allPhones);
  const pauseMap = {};
  (pauseRows || []).forEach(r => { pauseMap[cleanPhone(r.phone)] = r.pause_delivery || 'none'; });

  const success = [], failed = [];
  for (const o of data.orders) {
    const ph        = cleanPhone(o.phone);
    const pauseMode = pauseMap[ph] || 'none';
    const slotPaused =
      pauseMode === 'both' ||
      (pauseMode === 'lunch'  && slotName === 'morning') ||
      (pauseMode === 'dinner' && slotName === 'evening');
    if (slotPaused) {
      failed.push({ phone: ph, name: o.name, reason: `Delivery paused (${pauseMode}) for ${slotName} slot` });
      continue;
    }
    try {
      const orderId = await _createSingleOrder({ ...o, phone: ph, userId: ph, userType: 'subscriber' });
      success.push({ phone: ph, name: o.name, orderId });
    } catch (err) { failed.push({ phone: ph, name: o.name, reason: err.message }); }
  }
  return { success, failed, slot: slotName };
}

async function adminBulkCreate(data) {
  if (!data.orders || !Array.isArray(data.orders)) throw new Error('orders array required');
  const nowIST   = getIST();
  const istHour  = nowIST.getUTCHours();
  const slotName = istHour < 12 ? 'morning' : 'evening';
  const todayStr = istDateStr(nowIST);

  const { data: todayOrders } = await supabase
    .from('orders')
    .select('phone, order_time')
    .eq('order_date', todayStr)
    .neq('order_status', 'rejected');

  const alreadyOrderedThisSlot = new Set();
  (todayOrders || []).forEach(o => {
    const normalised = normOrderTime(o.order_time || '');
    const match = normalised.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
    if (match) {
      let h = parseInt(match[1]);
      const isPM = match[3].toUpperCase() === 'PM';
      if (isPM && h !== 12) h += 12;
      if (!isPM && h === 12) h = 0;
      const orderSlot = h < 12 ? 'morning' : 'evening';
      if (orderSlot === slotName) alreadyOrderedThisSlot.add(cleanPhone(o.phone));
    }
  });

  const allPhones = data.orders.map(o => cleanPhone(o.phone));
  const { data: pauseRows } = await supabase
    .from('subscribers')
    .select('phone, pause_delivery')
    .in('phone', allPhones);
  const pauseMap = {};
  (pauseRows || []).forEach(r => { pauseMap[cleanPhone(r.phone)] = r.pause_delivery || 'none'; });

  const success = [], failed = [];
  for (const o of data.orders) {
    const ph = cleanPhone(o.phone);
    if (alreadyOrderedThisSlot.has(ph)) {
      failed.push({ phone: ph, name: o.name, reason: `Already has a ${slotName} order today` });
      continue;
    }
    if (o.userType !== 'daily') {
      const pauseMode = pauseMap[ph] || 'none';
      const slotPaused =
        pauseMode === 'both' ||
        (pauseMode === 'lunch'  && slotName === 'morning') ||
        (pauseMode === 'dinner' && slotName === 'evening');
      if (slotPaused) {
        failed.push({ phone: ph, name: o.name, reason: `Delivery paused (${pauseMode}) for ${slotName} slot` });
        continue;
      }
    }
    try {
      const orderId = await _createSingleOrder(
        { ...o, phone: ph, userId: ph, userType: o.userType || 'subscriber' },
        { skipDeduction: o.userType === 'daily' }
      );
      alreadyOrderedThisSlot.add(ph);
      success.push({ phone: ph, name: o.name, orderId });
    } catch (err) { failed.push({ phone: ph, name: o.name, reason: err.message }); }
  }
  return { success, failed, slot: slotName };
}

// ═══════════════════════════════════════════════════════════════
// COUPONS
// ═══════════════════════════════════════════════════════════════

async function applyCoupon(data) {
  if (!data.code) throw new Error('Coupon code required');
  const { data: coupon } = await supabase
    .from('coupons').select('*').eq('code', data.code.toUpperCase()).maybeSingle();
  if (!coupon) throw new Error('Invalid coupon code');
  if (!coupon.is_active) throw new Error('Coupon is not active');
  if (coupon.expiry_date && new Date(coupon.expiry_date) < new Date()) throw new Error('Coupon has expired');
  if (coupon.user_phone && cleanPhone(coupon.user_phone) !== cleanPhone(data.phone || ''))
    throw new Error('Coupon is not valid for this account');

  const limit = Number(coupon.per_user_limit) || 0;
  if (limit > 0 && data.phone) {
    const ph = cleanPhone(data.phone);
    let usage = {};
    try { usage = JSON.parse(coupon.usage_count || '{}'); } catch { usage = {}; }
    const used = Number(usage[ph]) || 0;
    if (used >= limit) throw new Error(`Coupon usage limit reached (max ${limit} time${limit > 1 ? 's' : ''} per user)`);
  }
  return { code: coupon.code, discountType: coupon.discount_type, discountValue: Number(coupon.discount_value) };
}

async function incrementCouponUsage(code, phone) {
  try {
    const { data: coupon } = await supabase.from('coupons').select('usage_count').eq('code', code).maybeSingle();
    if (!coupon) return;
    let usage = {};
    try { usage = JSON.parse(coupon.usage_count || '{}'); } catch { usage = {}; }
    usage[phone] = (usage[phone] || 0) + 1;
    await supabase.from('coupons').update({ usage_count: JSON.stringify(usage) }).eq('code', code);
  } catch {}
}

async function createCoupon(data) {
  if (!data.code || !data.discountType || !data.discountValue) throw new Error('code, discountType, discountValue required');
  const { error } = await supabase.from('coupons').insert({
    code: data.code.toUpperCase(), discount_type: data.discountType,
    discount_value: Number(data.discountValue),
    expiry_date: data.expiryDate || null, user_phone: data.userPhone || null,
    is_active: true, usage_count: '{}'
  });
  if (error) throw new Error(error.message);
  return true;
}

async function adminGetCoupons() {
  const { data: coupons, error } = await supabase.from('coupons').select('*');
  if (error) throw new Error(error.message);
  return (coupons || []).map(c => ({
    code: c.code, discountType: c.discount_type, discountValue: c.discount_value,
    expiryDate: c.expiry_date, userPhone: c.user_phone, isActive: c.is_active,
    perUserLimit: c.per_user_limit || 0,
    usageCount: (() => { try { return JSON.parse(c.usage_count || '{}'); } catch { return {}; } })()
  }));
}

async function deleteCoupon(data) {
  if (!data.code) throw new Error('code required');
  const { error } = await supabase.from('coupons').delete().eq('code', data.code.toUpperCase());
  if (error) throw new Error(error.message);
  return true;
}

// ═══════════════════════════════════════════════════════════════
// SUBSCRIBERS
// ═══════════════════════════════════════════════════════════════

async function checkSubscriber(data) {
  if (!data.phone) return { isSubscriber: false, pauseDelivery: 'none' };
  const ph = cleanPhone(data.phone);
  const { data: sub } = await supabase
    .from('subscribers').select('is_active, pause_delivery').eq('phone', ph).maybeSingle();
  const isSubscriber = !!(sub && sub.is_active);
  // v14: sync users flag while we're here
  await supabase.from('users').update({ is_subscriber: isSubscriber }).eq('phone', ph);
  return { isSubscriber, pauseDelivery: sub?.pause_delivery || 'none' };
}

async function pauseUserDelivery(data) {
  if (!data.phone) throw new Error('phone required');
  const ph   = cleanPhone(data.phone);
  const mode = data.mode || 'none';
  const { error } = await supabase.from('subscribers').update({ pause_delivery: mode }).eq('phone', ph);
  if (error) throw new Error(error.message);
  if (mode && mode !== 'none') {
    setImmediate(() => createNotification({ type:'pause', priority:'normal',
      title:'⏸️ Subscription Paused',
      body:`${data.name || ph} paused delivery (${mode})`,
      meta:{ phone:ph, name:data.name||ph, mode }
    }).catch(()=>{}));
  }
  return { pauseDelivery: mode };
}

async function getSubscriberPauseStatus(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: sub } = await supabase.from('subscribers').select('pause_delivery').eq('phone', ph).maybeSingle();
  return { pauseDelivery: sub?.pause_delivery || 'none' };
}

async function adminGetSubscribers() {
  const { data: subs,    error } = await supabase.from('subscribers').select('*');
  if (error) throw new Error(error.message);
  const { data: wallets } = await supabase.from('wallet').select('*');
  const balMap = {};
  (wallets || []).forEach(w => { balMap[cleanPhone(w.user_phone)] = Number(w.balance) || 0; });
  return (subs || []).map(s => ({
    phone:         s.phone,
    name:          s.name || '',
    address:       s.address || '',
    startDate:     s.start_date,
    plan:          s.plan || s.plan_type || 'both',
    status:        s.is_active ? 'active' : 'paused',
    pauseDelivery: s.pause_delivery || 'none',
    balance:       balMap[cleanPhone(s.phone)] || 0
  }));
}

async function addSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { error } = await supabase.from('subscribers').insert({
    phone: ph, name: data.name || '', address: data.address || '',
    plan: data.plan || 'both', plan_type: data.plan || 'both',
    is_active: true, start_date: new Date().toISOString().split('T')[0]
  });
  if (error) throw new Error(error.message);
  // v14: sync is_subscriber on users table
  await supabase.from('users').update({ is_subscriber: true }).eq('phone', ph);
  if (data.initialRecharge && Number(data.initialRecharge) > 0) {
    await rechargeWallet({ phone: ph, amount: data.initialRecharge, note: 'Initial recharge' });
  }
  return true;
}

async function updateSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph      = cleanPhone(data.phone);
  const updates = {};
  if (data.name    !== undefined) updates.name      = data.name;
  if (data.address !== undefined) updates.address   = data.address;
  if (data.plan    !== undefined) { updates.plan = data.plan; updates.plan_type = data.plan; }
  if (data.status  !== undefined) updates.is_active = data.status === 'active';
  const { error } = await supabase.from('subscribers').update(updates).eq('phone', ph);
  if (error) throw new Error(error.message);
  // Sync is_subscriber flag
  if (data.status !== undefined) {
    await supabase.from('users')
      .update({ is_subscriber: data.status === 'active' })
      .eq('phone', ph);
  }
  return true;
}

async function removeSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { error } = await supabase.from('subscribers').delete().eq('phone', ph);
  if (error) throw new Error(error.message);
  await supabase.from('users').update({ is_subscriber: false }).eq('phone', ph);
  return true;
}

async function getUserByPhone(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: user } = await supabase.from('users').select('*').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('No registered user found with this phone number');
  const { data: sub } = await supabase.from('subscribers').select('is_active').eq('phone', ph).maybeSingle();
  const isSubscriber  = !!(sub && sub.is_active);
  const balance       = await getWalletBalance(ph);
  return {
    userId:       user.user_id,
    name:         user.name,
    phone:        user.phone,
    email:        user.email    || '',
    address:      user.address  || '',
    isSubscriber,
    balance
  };
}

async function adminCreateUser(data) {
  if (!data.phone || !data.name || !data.password) throw new Error('phone, name, password required');
  const ph = cleanPhone(data.phone);
  const { data: existing } = await supabase.from('users').select('phone').eq('phone', ph).maybeSingle();
  if (existing) throw new Error('Phone already registered');
  const hashed = await bcrypt.hash(String(data.password).trim(), 10);
  const { data: user, error } = await supabase.from('users').insert({
    user_id: ph, name: data.name, phone: ph,
    email: data.email || '', address: data.address || '',
    password: hashed, is_subscriber: false
  }).select().single();
  if (error) throw new Error(error.message);
  if (data.makeSubscriber) {
    const { error: sErr } = await supabase.from('subscribers').insert({
      phone: ph, name: data.name, address: data.address || '',
      plan: data.plan || 'both', plan_type: data.plan || 'both',
      is_active: true, start_date: new Date().toISOString().split('T')[0]
    });
    if (!sErr) {
      await supabase.from('users').update({ is_subscriber: true }).eq('phone', ph);
      if (data.initialRecharge && Number(data.initialRecharge) > 0) {
        await rechargeWallet({ phone: ph, amount: data.initialRecharge, note: 'Initial recharge on account creation' });
      }
    }
  }
  return { userId: user.user_id, name: user.name, phone: user.phone };
}

async function promoteToSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: existing } = await supabase.from('subscribers').select('phone').eq('phone', ph).maybeSingle();
  if (existing) throw new Error('User is already a subscriber');
  const { error } = await supabase.from('subscribers').insert({
    phone: ph, name: data.name || '', address: data.address || '',
    plan: data.plan || 'both', plan_type: data.plan || 'both',
    is_active: true, start_date: new Date().toISOString().split('T')[0]
  });
  if (error) throw new Error(error.message);
  await supabase.from('users').update({ is_subscriber: true }).eq('phone', ph);
  if (data.initialRecharge && Number(data.initialRecharge) > 0) {
    await rechargeWallet({ phone: ph, amount: data.initialRecharge, note: 'Promoted to subscriber' });
  }
  return { promoted: true, phone: ph };
}

// ═══════════════════════════════════════════════════════════════
// RIDERS
// ═══════════════════════════════════════════════════════════════

async function createRider(data) {
  if (!data.name || !data.email || !data.password) throw new Error('name, email, password required');
  const hashed     = await bcrypt.hash(String(data.password), 10);
  const riderEmail = String(data.email).trim().toLowerCase();
  const ist        = getIST();
  const riderId    = await generateRiderId(ist);
  const { data: rider, error } = await supabase.from('riders').insert({
    rider_id: riderId, name: data.name, email: riderEmail, password: hashed
  }).select().single();
  if (error) throw new Error(error.message);
  return { riderId: rider.rider_id };
}

async function updateRider(data) {
  if (!data.riderId) throw new Error('riderId required');
  const updates = {};
  if (data.name  !== undefined) updates.name  = data.name;
  if (data.email !== undefined) updates.email = String(data.email).trim().toLowerCase();
  if (data.password && data.password.length >= 6) updates.password = await bcrypt.hash(String(data.password).trim(), 10);
  const { error } = await supabase.from('riders').update(updates).eq('rider_id', data.riderId);
  if (error) throw new Error(error.message);
  return true;
}

async function deleteRider(data) {
  if (!data.riderId) throw new Error('riderId required');
  const { error } = await supabase.from('riders').delete().eq('rider_id', data.riderId);
  if (error) throw new Error(error.message);
  return true;
}

async function riderLogin(data) {
  if (!data.email || !data.password) throw new Error('Email and password required');
  const email    = String(data.email).trim().toLowerCase();
  const password = String(data.password).trim();
  const { data: rider } = await supabase.from('riders').select('*').eq('email', email).maybeSingle();
  if (!rider) throw new Error('Invalid credentials');
  const match = await bcrypt.compare(password, rider.password);
  if (!match) throw new Error('Invalid credentials');
  return { riderId: rider.rider_id, name: rider.name, email: rider.email };
}

async function getRiderOrders(data) {
  if (!data.riderId) throw new Error('riderId required');
  // v14: rider sees verified/preparing/out for delivery — not raw pending
  const { data: assigned, error: e1 } = await supabase.from('orders').select('*')
    .eq('rider_id', data.riderId)
    .in('order_status', ['verified', 'preparing', 'out for delivery', 'delivered']);
  if (e1) throw new Error(e1.message);

  // Unassigned orders that are verified/preparing — visible to all riders
  const { data: unassigned, error: e2 } = await supabase.from('orders').select('*')
    .is('rider_id', null)
    .in('order_status', ['verified', 'preparing']);
  if (e2) throw new Error(e2.message);

  const seen   = new Set();
  const orders = [...(assigned || []), ...(unassigned || [])].filter(o => {
    if (seen.has(o.order_id)) return false;
    seen.add(o.order_id); return true;
  });
  return orders.map(formatOrder);
}

async function getRiders() {
  const { data: riders, error } = await supabase.from('riders').select('rider_id, name, email');
  if (error) throw new Error(error.message);
  return (riders || []).map(r => ({ riderId: r.rider_id, name: r.name, email: r.email }));
}

async function assignRider(data) {
  if (!data.orderId || !data.riderId) throw new Error('orderId and riderId required');
  const { error } = await supabase.from('orders').update({ rider_id: data.riderId }).eq('order_id', data.orderId);
  if (error) throw new Error(error.message);
  return true;
}

// ═══════════════════════════════════════════════════════════════
// STAFF
// ═══════════════════════════════════════════════════════════════

async function createStaff(data) {
  if (!data.username || !data.name || !data.password) throw new Error('username, name, password required');
  if (data.password.length < 6) throw new Error('Password must be 6+ chars');
  const staffUsername = String(data.username).trim().toLowerCase();
  const hashed        = await bcrypt.hash(String(data.password).trim(), 10);
  const { error } = await supabase.from('staff').insert({
    username: staffUsername, name: data.name, password: hashed, status: 'active'
  });
  if (error) throw new Error(error.message);
  return true;
}

async function updateStaff(data) {
  if (!data.username) throw new Error('username required');
  const updates = {};
  if (data.name   !== undefined) updates.name   = data.name;
  if (data.status !== undefined) updates.status = data.status;
  if (data.password && data.password.length >= 6) updates.password = await bcrypt.hash(String(data.password), 10);
  const { error } = await supabase.from('staff').update(updates).eq('username', data.username);
  if (error) throw new Error(error.message);
  return true;
}

async function deleteStaff(data) {
  if (!data.username) throw new Error('username required');
  const { error } = await supabase.from('staff').delete().eq('username', data.username);
  if (error) throw new Error(error.message);
  return true;
}

async function getStaff() {
  const { data: staff, error } = await supabase.from('staff').select('username, name, status, created_at');
  if (error) throw new Error(error.message);
  return (staff || []).map(s => ({ username: s.username, name: s.name, status: s.status, createdAt: s.created_at }));
}

// ═══════════════════════════════════════════════════════════════
// WALLET / KHATA
// ═══════════════════════════════════════════════════════════════

async function getWalletBalance(phone) {
  const ph = cleanPhone(phone);
  const { data: w } = await supabase.from('wallet').select('balance').eq('user_phone', ph).maybeSingle();
  return Number(w?.balance) || 0;
}

async function _atomicWalletUpdate(phone, delta) {
  const ph = cleanPhone(phone);
  await supabase.from('wallet').upsert(
    { user_phone: ph, balance: 0, last_updated: new Date().toISOString() },
    { onConflict: 'user_phone', ignoreDuplicates: true }
  );
  const { data, error } = await supabase.rpc('wallet_atomic_update', {
    p_phone: ph, p_delta: delta
  });
  if (error) {
    const currentBal = await getWalletBalance(ph);
    const newBal     = currentBal + delta;
    await supabase.from('wallet').upsert(
      { user_phone: ph, balance: newBal, last_updated: new Date().toISOString() },
      { onConflict: 'user_phone' }
    );
    return newBal;
  }
  return Number(data) || 0;
}

// v14 FIX: Always set BOTH user_id=phone AND user_phone=phone
async function deductWalletBalance(phone, amount, note, userId) {
  const ph     = cleanPhone(phone);
  const uid    = cleanPhone(userId || phone); // v14: user_id = phone
  const newBal = await _atomicWalletUpdate(ph, -amount);
  const ist    = getIST();
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id:    uid,   // v14: always phone number
    user_phone: ph,
    amount:     -amount,
    type:       'debit',
    note:       note || '',
    created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] deduct insert failed:', kErr.message, '| phone:', ph);
  return newBal;
}

async function getSubscriberBalance(data) {
  if (!data.phone) throw new Error('phone required');
  return { balance: await getWalletBalance(data.phone) };
}

// v14 FIX: Always set both user_id and user_phone in recharge
async function rechargeWallet(data) {
  if (!data.phone || !data.amount) throw new Error('phone and amount required');
  const ph     = cleanPhone(data.phone);
  const amt    = Math.abs(Number(data.amount));
  const newBal = await _atomicWalletUpdate(ph, amt);
  const ist    = getIST();
  // v14: user_id = phone (no DB lookup needed)
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id:    ph,    // v14: user_id = phone
    user_phone: ph,
    amount:     amt,
    type:       'credit',
    note:       data.note || 'Recharge',
    created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] recharge insert failed:', kErr.message, '| phone:', ph);
  // Fire notification only for explicit admin/staff recharges (has rechargedBy set)
  if (data.rechargedBy) {
    setImmediate(() => createNotification({ type:'recharge', priority:'normal',
      title:'🔁 Wallet Recharged',
      body:`₹${amt} added to ${data.userName||ph} by ${data.rechargedBy}`,
      meta:{ phone:ph, name:data.userName||ph, amount:amt, note:data.note||'Recharge', recharged_by:data.rechargedBy }
    }).catch(()=>{}));
  }
  return { newBalance: newBal };
}

async function addKhataEntry(data) {
  if (!data.phone) throw new Error('phone required');
  const ph     = cleanPhone(data.phone);
  const amount = Number(data.amount) || 0;
  const newBal = await _atomicWalletUpdate(ph, amount);
  const ist    = getIST();
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id:    ph,    // v14: user_id = phone
    user_phone: ph,
    amount,
    type:       amount >= 0 ? 'credit' : 'debit',
    note:       data.note || '',
    created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] addEntry insert failed:', kErr.message, '| phone:', ph);
  return { newBalance: newBal };
}

async function manualRefund(data) {
  if (!data.phone)                         throw new Error('phone required');
  if (!data.amount || Number(data.amount) <= 0) throw new Error('amount must be > 0');
  const ph   = cleanPhone(data.phone);
  const amt  = Number(data.amount);
  const note = data.note || `Manual refund${data.orderId ? ' — order ' + data.orderId : ''}`;
  const result = await rechargeWallet({ phone: ph, amount: amt, note });
  return { newBalance: result.newBalance, refunded: amt };
}

async function getKhata(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);

  // v14: user_id = phone — fetch all rows by either field (covers legacy data too)
  const { data: byPhone } = await supabase
    .from('khata_transactions')
    .select('*')
    .or(`user_phone.eq.${ph},user_id.eq.${ph}`)
    .order('created_at', { ascending: true });

  // Deduplicate by id (in case a row matched both conditions)
  const seen = new Set();
  const txns = (byPhone || []).filter(t => {
    if (seen.has(t.id)) return false;
    seen.add(t.id); return true;
  });

  // Backfill any orphans that are missing user_id or user_phone
  const orphans = txns.filter(t => !t.user_id || !t.user_phone);
  if (orphans.length) {
    await supabase.from('khata_transactions')
      .update({ user_id: ph, user_phone: ph })
      .in('id', orphans.map(t => t.id));
  }

  let running = 0;
  const entries = txns.map(t => {
    running += Number(t.amount) || 0;
    // FIX v14: created_at is stored as IST time via getIST().toISOString()
    // (i.e. IST clock value written into UTC field — no offset should be added).
    // Reading it as a plain Date and using UTC accessors gives the correct IST time.
    const ist = new Date(t.created_at);
    return {
      entryId:        t.id,
      phone:          ph,
      type:           t.type === 'credit' ? 'recharge' : 'tiffin_given',
      amount:         Number(t.amount),
      note:           t.note || '',
      runningBalance: running,
      date:           istDateStr(ist),
      time:           istTimeStr(ist)
    };
  });

  const computedBal = running;
  // Sync wallet table to match transaction sum
  await supabase.from('wallet').upsert(
    { user_phone: ph, balance: computedBal, last_updated: new Date().toISOString() },
    { onConflict: 'user_phone' }
  );
  return { entries, balance: computedBal };
}

async function adminGetAllKhata() {
  const [
    { data: subs },
    { data: wallets },
    { data: txnCounts }
  ] = await Promise.all([
    supabase.from('subscribers').select('phone, name'),
    supabase.from('wallet').select('user_phone, balance'),
    // v14: count by user_phone (always set now)
    supabase.from('khata_transactions').select('user_phone, id')
  ]);

  const balMap = {};
  (wallets || []).forEach(w => {
    if (w.user_phone) balMap[cleanPhone(w.user_phone)] = Number(w.balance) || 0;
  });

  const countMap = {};
  (txnCounts || []).forEach(t => {
    const ph = t.user_phone ? cleanPhone(t.user_phone) : null;
    if (!ph) return;
    countMap[ph] = (countMap[ph] || 0) + 1;
  });

  return (subs || []).map(s => {
    const ph = cleanPhone(s.phone);
    return {
      phone:      s.phone,
      name:       s.name || '',
      balance:    balMap[ph] || 0,
      entryCount: countMap[ph] || 0,
      entries:    []
    };
  });
}

// ═══════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════

async function upsertSetting(key, value) {
  await supabase.from('admin_settings').upsert(
    { admin_id: key, access_level: String(value) },
    { onConflict: 'admin_id' }
  );
}

async function getOrderCutoff() {
  const { data: rows } = await supabase.from('admin_settings').select('*');
  const map = {};
  (rows || []).forEach(r => { map[r.admin_id] = r.access_level; });
  const sched = {};
  for (let d = 0; d <= 6; d++) {
    try { sched[d] = JSON.parse(map['schedule_' + d] || 'null') || getDefaultDay(d); }
    catch { sched[d] = getDefaultDay(d); }
  }
  return {
    enabled:     map['cutoff_enabled'] === 'true',
    cutoffDay:   map['cutoff_day']   || '11:30',
    cutoffNight: map['cutoff_night'] || '20:00',
    schedule:    sched
  };
}

async function setOrderCutoff(data) {
  await upsertSetting('cutoff_enabled', data.enabled ? 'true' : 'false');
  if (data.cutoffDay)   await upsertSetting('cutoff_day',   data.cutoffDay);
  if (data.cutoffNight) await upsertSetting('cutoff_night', data.cutoffNight);
  return true;
}

async function getWeeklySchedule() {
  const { data: rows } = await supabase.from('admin_settings').select('*');
  const map = {};
  (rows || []).forEach(r => { map[r.admin_id] = r.access_level; });
  const result = {};
  for (let d = 0; d <= 6; d++) {
    try { result[d] = JSON.parse(map['schedule_' + d] || 'null') || getDefaultDay(d); }
    catch { result[d] = getDefaultDay(d); }
  }
  return result;
}

async function setWeeklySchedule(data) {
  if (!data.schedule) throw new Error('schedule required');
  for (let d = 0; d <= 6; d++) {
    if (data.schedule[d]) await upsertSetting('schedule_' + d, JSON.stringify(data.schedule[d]));
  }
  return true;
}

async function getKhataEnabled() {
  const { data } = await supabase.from('admin_settings')
    .select('access_level').eq('admin_id', 'khata_enabled').maybeSingle();
  const v = data?.access_level;
  return { enabled: v === null || v === undefined || v === 'true' || v === '1' };
}

async function setKhataEnabled(data) {
  await upsertSetting('khata_enabled', data.enabled ? 'true' : 'false');
  return true;
}

// ═══════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════

async function getAnalytics() {
  const ist   = getIST();
  const today = istDateStr(ist);
  const { data: orders  } = await supabase.from('orders').select('final_amount, order_date, order_status');
  const { data: users   } = await supabase.from('users').select('user_id');
  const { data: subs    } = await supabase.from('subscribers').select('phone');
  const { data: wallets } = await supabase.from('wallet').select('balance');

  const activeOrders  = (orders || []).filter(o => o.order_status !== 'rejected');
  const todayOrders   = activeOrders.filter(o => normOrderDate(o.order_date) === today);
  const todayRevenue  = todayOrders.reduce((s, o) => s + (Number(o.final_amount) || 0), 0);
  const thisMonth     = ist.getUTCMonth(), thisYear = ist.getUTCFullYear();
  const monthlyRevenue = activeOrders.filter(o => {
    if (!o.order_date) return false;
    const norm = normOrderDate(o.order_date);
    if (/^\d{4}-\d{2}-\d{2}$/.test(norm)) {
      const [y, m] = norm.split('-');
      return parseInt(m) - 1 === thisMonth && parseInt(y) === thisYear;
    }
    return false;
  }).reduce((s, o) => s + (Number(o.final_amount) || 0), 0);
  const totalWalletBalance = (wallets || []).reduce((s, w) => s + (Number(w.balance) || 0), 0);

  return {
    todayOrders:      todayOrders.length,
    todayRevenue,
    monthlyRevenue,
    totalOrders:      activeOrders.length,
    totalUsers:       (users || []).length,
    totalSubscribers: (subs  || []).length,
    totalWalletBalance
  };
}

async function getUsers() {
  const { data: users, error } = await supabase
    .from('users')
    .select('user_id, name, phone, email, address, is_subscriber, created_at');
  if (error) throw new Error(error.message);
  return (users || []).map(u => ({
    userId:       u.user_id,
    name:         u.name,
    phone:        u.phone,
    email:        u.email    || '',
    address:      u.address  || '',
    isSubscriber: !!u.is_subscriber,
    createdAt:    u.created_at
  }));
}

// ═══════════════════════════════════════════════════════════════
// NEW USER COUPON SENT — Supabase (today + yesterday only)
// ═══════════════════════════════════════════════════════════════

async function getNuCouponSent() {
  const { data, error } = await supabase
    .from('nu_coupon_sent')
    .select('phone');
  if (error) throw new Error(error.message);
  return (data || []).map(r => String(r.phone));
}

async function markNuCouponSent(payload) {
  const phone = String(payload.phone || '').replace(/\D/g, '');
  if (!phone) throw new Error('phone required');
  const { error } = await supabase
    .from('nu_coupon_sent')
    .upsert({ phone, sent_at: new Date().toISOString() }, { onConflict: 'phone' });
  if (error) throw new Error(error.message);
  return { ok: true };
}

async function deleteOldNuCouponSent() {
  // Keep today + yesterday; delete anything older than 2 days
  const cutoff = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
  const { error, count } = await supabase
    .from('nu_coupon_sent')
    .delete({ count: 'exact' })
    .lt('sent_at', cutoff);
  if (error) throw new Error(error.message);
  return { deleted: count || 0 };
}

// ═══════════════════════════════════════════════════════════════
// DATA CLEANUP
// ═══════════════════════════════════════════════════════════════

function _parseCutoff(cutoffDate, minDays) {
  if (!cutoffDate) throw new Error('cutoffDate required (YYYY-MM-DD)');
  const cut = new Date(cutoffDate + 'T00:00:00Z');
  if (isNaN(cut.getTime())) throw new Error('Invalid cutoffDate format');
  const minCutoff = new Date(Date.now() + 5.5 * 3600000);
  minCutoff.setUTCDate(minCutoff.getUTCDate() - minDays);
  if (cut > minCutoff) throw new Error(`Cutoff date must be at least ${minDays} days in the past`);
  return cut;
}

function _daysAgoIST(n) {
  const d = new Date(Date.now() + 5.5 * 3600000);
  d.setUTCDate(d.getUTCDate() - n);
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}

async function _orderIdsBefore(cutoffDate) {
  const { data: rows, error } = await supabase.from('orders').select('order_id, order_date');
  if (error) throw new Error(error.message);
  return (rows || [])
    .filter(o => { const norm = normOrderDate(o.order_date); return norm && norm < cutoffDate; })
    .map(o => o.order_id);
}

async function deleteOldOrders(data) {
  _parseCutoff(data.cutoffDate, 5);
  const ids = await _orderIdsBefore(data.cutoffDate);
  if (!ids.length) return { deleted: 0, cutoffDate: data.cutoffDate };
  let deleted = 0;
  for (let i = 0; i < ids.length; i += 500) {
    const batch = ids.slice(i, i + 500);
    const { error, count } = await supabase.from('orders').delete({ count: 'exact' }).in('order_id', batch);
    if (error) throw new Error(error.message);
    deleted += count || batch.length;
  }
  return { deleted, cutoffDate: data.cutoffDate };
}

async function previewDeleteOrders(data) {
  _parseCutoff(data.cutoffDate, 5);
  const ids = await _orderIdsBefore(data.cutoffDate);
  return { count: ids.length };
}

async function deleteOldTransactions(data) {
  _parseCutoff(data.cutoffDate, 45);
  const { error, count } = await supabase
    .from('khata_transactions')
    .delete({ count: 'exact' })
    .lt('created_at', data.cutoffDate + 'T00:00:00Z');
  if (error) throw new Error(error.message);
  return { deleted: count || 0, cutoffDate: data.cutoffDate };
}

async function previewDeleteTransactions(data) {
  _parseCutoff(data.cutoffDate, 45);
  const { count, error } = await supabase
    .from('khata_transactions')
    .select('*', { count: 'exact', head: true })
    .lt('created_at', data.cutoffDate + 'T00:00:00Z');
  if (error) throw new Error(error.message);
  return { count: count || 0 };
}

async function deleteOldData(data) {
  const months        = Number(data.months) || 3;
  const ordersCutoff  = _daysAgoIST(months * 30);
  const txnMinCutoff  = _daysAgoIST(45);
  const txnCutoff     = ordersCutoff < txnMinCutoff ? ordersCutoff : txnMinCutoff;
  const orders = await deleteOldOrders({ cutoffDate: ordersCutoff })
    .catch(e => ({ deleted: 0, error: e.message }));
  const txns   = await deleteOldTransactions({ cutoffDate: txnCutoff })
    .catch(e => ({ deleted: 0, error: e.message }));
  return {
    deletedOrders: orders.deleted, deletedKhata: txns.deleted,
    ordersCutoff,  txnCutoff,
    ordersError:   orders.error || null,
    txnsError:     txns.error   || null
  };
}
