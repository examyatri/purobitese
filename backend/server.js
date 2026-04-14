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
// Uses SERVICE_ROLE key so the server retains full DB access
// after RLS is enabled (Fix #10).
// Add SUPABASE_SERVICE_KEY to your Render environment variables.
// Get it from: Supabase Dashboard → Project Settings → API → service_role key
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY // fallback for existing deploys
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
  res.status(200).json({ app: 'Puro Bite API', status: 'running' });
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
      case 'login': result = await loginUser(data); break;
      case 'signup': result = await signupUser(data); break;
      case 'adminLogin': result = await adminLogin(data); break;
      case 'staffLogin': result = await staffLogin(data); break;
      case 'updateProfile': result = await updateProfile(data); break;
      case 'getMenu': result = await getMenu(data); break;
      case 'adminGetMenu': result = await adminGetMenu(); break;
      case 'addMenuItem': result = await addMenuItem(data); break;
      case 'updateMenuItem': result = await updateMenuItem(data); break;
      case 'deleteMenuItem': result = await deleteMenuItem(data); break;
      case 'updateMenuOrder': result = await updateMenuOrder(data); break;
      case 'createOrder': result = await createOrder(data); break;
      case 'getUserOrders': result = await getUserOrders(data); break;
      case 'adminGetOrders': result = await adminGetOrders(); break;
      case 'getOrdersByDate': result = await getOrdersByDate(data); break;
      case 'updateOrderStatus': result = await updateOrderStatus(data); break;
      case 'rejectOrder': result = await rejectOrder(data); break;
      case 'bulkOrdersWithBalance': result = await bulkOrdersWithBalance(data); break;
      case 'adminBulkCreate': result = await adminBulkCreate(data); break;
      case 'applyCoupon': result = await applyCoupon(data); break;
      case 'createCoupon': result = await createCoupon(data); break;
      case 'adminGetCoupons': result = await adminGetCoupons(); break;
      case 'deleteCoupon': result = await deleteCoupon(data); break;
      case 'pauseUserDelivery': result = await pauseUserDelivery(data); break;
      case 'getSubscriberPauseStatus': result = await getSubscriberPauseStatus(data); break;
      case 'checkSubscriber': result = await checkSubscriber(data); break;
      case 'adminGetSubscribers': result = await adminGetSubscribers(); break;
      case 'addSubscriber': result = await addSubscriber(data); break;
      case 'updateSubscriber': result = await updateSubscriber(data); break;
      case 'removeSubscriber': result = await removeSubscriber(data); break;
      case 'getUserByPhone': result = await getUserByPhone(data); break;
      case 'adminCreateUser': result = await adminCreateUser(data); break;
      case 'promoteToSubscriber': result = await promoteToSubscriber(data); break;
      case 'createRider': result = await createRider(data); break;
      case 'updateRider': result = await updateRider(data); break;
      case 'deleteRider': result = await deleteRider(data); break;
      case 'riderLogin': result = await riderLogin(data); break;
      case 'getRiderOrders': result = await getRiderOrders(data); break;
      case 'getRiders': result = await getRiders(); break;
      case 'assignRider': result = await assignRider(data); break;
      case 'createStaff': result = await createStaff(data); break;
      case 'updateStaff': result = await updateStaff(data); break;
      case 'deleteStaff': result = await deleteStaff(data); break;
      case 'getStaff': result = await getStaff(); break;
      case 'getKhata': result = await getKhata(data); break;
      case 'getSubscriberBalance': result = await getSubscriberBalance(data); break;
      case 'rechargeWallet': result = await rechargeWallet(data); break;
      case 'manualRefund': result = await manualRefund(data); break;
      case 'adminGetAllKhata': result = await adminGetAllKhata(); break;
      case 'addKhataEntry': result = await addKhataEntry(data); break;
      case 'getOrderCutoff': result = await getOrderCutoff(); break;
      case 'setOrderCutoff': result = await setOrderCutoff(data); break;
      case 'getWeeklySchedule': result = await getWeeklySchedule(); break;
      case 'setWeeklySchedule': result = await setWeeklySchedule(data); break;
      case 'getKhataEnabled': result = await getKhataEnabled(); break;
      case 'setKhataEnabled': result = await setKhataEnabled(data); break;
      case 'getAnalytics': result = await getAnalytics(); break;
      case 'getUsers': result = await getUsers(); break;
      case 'resetAdminPassword': result = await resetAdminPassword(data); break;
      case 'forceUdharOrder': result = await forceUdharOrder(data); break;
      case 'deleteOldData': result = await deleteOldData(data); break;
      case 'deleteOldOrders': result = await deleteOldOrders(data); break;
      case 'deleteOldTransactions': result = await deleteOldTransactions(data); break;
      case 'previewDeleteOrders': result = await previewDeleteOrders(data); break;
      case 'previewDeleteTransactions': result = await previewDeleteTransactions(data); break;
      default: return res.json({ success: false, error: 'Unknown action: ' + action });
    }
    return res.json({ success: true, data: result });
  } catch (err) {
    console.error('API Error:', err);
    return res.json({ success: false, error: err.message });
  }
});

// ── START SERVER ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Puro Bite API running on port ' + PORT));

// ── SELF PING — Render ko jagte rakhta hai ────────────────────
// Using built-in https module (no extra packages needed)
const SELF_URL = process.env.RENDER_EXTERNAL_URL || '';
if (SELF_URL) {
  const https = require('https');
  setInterval(() => {
    https.get(SELF_URL + '/ping', (res) => {
      console.log('[KeepAlive] Pinged at ' + new Date().toISOString() + ' — status: ' + res.statusCode);
    }).on('error', (e) => {
      console.error('[KeepAlive] Ping failed:', e.message);
    });
  }, 10 * 60 * 1000); // every 10 minutes
}

//──────────────────────────────────────────────────────────────
// HELPERS
//──────────────────────────────────────────────────────────────
function getIST() { return new Date(Date.now() + 5.5 * 3600000); }

//──────────────────────────────────────────────────────────────
// STRUCTURED ID GENERATORS
// Order ID : O + DDMMYY + HHMMSS + 5 random digits
//            e.g. O110426143022A8F3K  — unique, no DB count needed
// Rider ID : R + DDMMYYYY + 4-digit sequence  e.g. R110420260001
// User  ID : phone number (10-digit, set at registration)
//──────────────────────────────────────────────────────────────
function generateId(prefix, ist) {
  // Shared ID generator — prefix: ORD, TXN, RDR, MENU etc.
  const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let rand = '';
  for (let i = 0; i < 5; i++) rand += CHARS[Math.floor(Math.random() * CHARS.length)];
  if (!ist) return `${prefix}-${rand}`; // for MENU IDs (no timestamp needed)
  const yyyy = ist.getUTCFullYear();
  const mm   = String(ist.getUTCMonth() + 1).padStart(2, '0');
  const dd   = String(ist.getUTCDate()).padStart(2, '0');
  const HH   = String(ist.getUTCHours()).padStart(2, '0');
  const MM   = String(ist.getUTCMinutes()).padStart(2, '0');
  const SS   = String(ist.getUTCSeconds()).padStart(2, '0');
  return `${prefix}-${yyyy}${mm}${dd}-${HH}${MM}${SS}-${rand}`;
}
function generateOrderId(ist) { return generateId('ORD', ist); }
// e.g. ORD-20250414-143022-AB7K2

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
// e.g. RDR-14042025-0001

// ── UNIFIED DATE/TIME FORMAT ──────────────────────────────────
// Standard internal format: date = "YYYY-MM-DD", time = "HH:MM AM/PM"
// All DB writes, reads, and comparisons use this format.
function istDateStr(d) {
  // Returns YYYY-MM-DD (standard internal format)
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

// ─────────────────────────────────────────────────────────────────
// GLOBAL DATE/TIME NORMALISATION  (server-side)
// normOrderDate : any input  →  "YYYY-MM-DD"   (canonical internal)
// normOrderTime : any input  →  "HH:MM AM/PM"  (canonical internal)
// istDateFromRaw: helper – IST date string from a real JS Date
// ─────────────────────────────────────────────────────────────────
function _istFromEpoch(ms) {
  // Returns a Date whose UTC fields represent IST clock time
  return new Date(ms + 5.5 * 3600000);
}
function _ymd(d) {
  // d is an IST-shifted Date; read UTC fields to get IST calendar date
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}
function normOrderDate(v) {
  if (!v) return '';
  const s = String(v).trim();
  // 1. Already YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  // 2. DD/MM/YYYY  (legacy Indian format)
  if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) {
    const p = s.split('/');
    const dd = p[0].padStart(2,'0'), mm = p[1].padStart(2,'0'), yyyy = p[2];
    // Disambiguate: if first part > 12 it must be day, else assume DD/MM
    return `${yyyy}-${mm}-${dd}`;
  }
  // 3. YYYY/MM/DD
  if (/^\d{4}\/\d{2}\/\d{2}$/.test(s)) return s.replace(/\//g, '-');
  // 4. ISO datetime string  (e.g. Supabase created_at, order_date fallback)
  if (/^\d{4}-\d{2}-\d{2}T/.test(s) || /Z$/.test(s)) {
    const raw = new Date(s);
    if (!isNaN(raw.getTime())) return _ymd(_istFromEpoch(raw.getTime()));
  }
  // 5. JS Date object
  if (v instanceof Date && !isNaN(v.getTime())) return _ymd(_istFromEpoch(v.getTime()));
  // 6. Numeric Excel/Sheets serial (days since 1899-12-30)
  if (/^\d+(\.\d+)?$/.test(s)) {
    const serial = parseFloat(s);
    if (serial > 40000 && serial < 60000) { // plausible date range
      const ms = (serial - 25569) * 86400000; // convert to Unix ms
      const raw = new Date(ms);
      if (!isNaN(raw.getTime())) return _ymd(_istFromEpoch(raw.getTime()));
    }
  }
  return ''; // unrecognised — return empty so callers can handle gracefully
}

function normOrderTime(v) {
  if (!v) return '';
  const s = String(v).trim().replace(/[\u00a0\u202f\u2009]/g, ' ');
  // 1. Already HH:MM AM/PM  — normalise case and zero-pad hour
  const ampm = s.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (ampm) {
    return String(ampm[1]).padStart(2,'0') + ':' + ampm[2] + ' ' + ampm[3].toUpperCase();
  }
  // 2. 24-hour HH:MM or HH:MM:SS
  const h24 = s.match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (h24) {
    let h = parseInt(h24[1]), mn = parseInt(h24[2]);
    const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
    return String(h).padStart(2, '0') + ':' + String(mn).padStart(2, '0') + ' ' + p;
  }
  // 3. ISO datetime string — extract IST time
  if (/^\d{4}-\d{2}-\d{2}T/.test(s) || /Z$/.test(s)) {
    const raw = new Date(s);
    if (!isNaN(raw.getTime())) {
      const ist = _istFromEpoch(raw.getTime());
      let h = ist.getUTCHours(), mn = ist.getUTCMinutes();
      const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
      return String(h).padStart(2, '0') + ':' + String(mn).padStart(2, '0') + ' ' + p;
    }
  }
  return s; // pass through — display as-is if unrecognised
}
function formatOrder(o) {
  return {
    orderId: o.order_id, userId: o.user_id,
    name: o.name, phone: o.phone, address: o.address,
    items: typeof o.items === 'string' ? o.items : JSON.stringify(o.items),
    totalAmount: o.total_amount, deliveryCharge: o.delivery_charge,
    finalAmount: Number(o.final_amount) || 0,
    couponCode: o.coupon_code || '', discount: o.discount || 0,
    userType: o.user_type || 'daily', paymentStatus: o.payment_status || 'pending',
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
    price: Number(i.price) || 0, variants, imageUrl: i.image_url || '',
    menuType: i.menu_type || 'morning', availability: i.availability,
    sortOrder: i.sort_order || 9999, highlight: i.highlight || ''
  };
}
function getDefaultDay(d, name) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return { day: name || days[d], open: true, openTime: '07:00', lunchStart: '07:00', lunchEnd: '11:00' };
}

//──────────────────────────────────────────────────────────────
// AUTH
//──────────────────────────────────────────────────────────────
async function signupUser(data) {
  if (!data.phone || !data.password || !data.name) throw new Error('Name, phone, password required');
  const ph = cleanPhone(data.phone);
  const { data: existing } = await supabase.from('users').select('phone').eq('phone', ph).maybeSingle();
  if (existing) throw new Error('Phone already registered');
  const hashed = await bcrypt.hash(String(data.password).trim(), 10);
  // User ID = phone number (structured ID system)
  const { data: user, error } = await supabase.from('users').insert({
    user_id: ph, name: data.name, phone: ph, email: data.email || '', address: data.address || '', password: hashed
  }).select().single();
  if (error) throw new Error(error.message);
  return { userId: user.user_id, name: user.name, phone: user.phone, email: user.email || '', address: user.address || '' };
}
async function loginUser(data) {
  if (!data.phone || !data.password) throw new Error('Phone and password required');
  const ph = cleanPhone(data.phone);
  const password = String(data.password).trim(); // trim: mobile keyboards add trailing spaces
  const { data: user } = await supabase.from('users').select('*').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('User not found');
  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new Error('Incorrect password');
  return { userId: user.user_id, name: user.name, phone: user.phone, email: user.email || '', address: user.address || '' };
}
async function adminLogin(data) {
  if (!data.email || !data.password) throw new Error('Email and password required');
  const email = String(data.email).trim().toLowerCase();
  const password = String(data.password).trim();
  const { data: setting } = await supabase.from('admin_settings').select('*').eq('admin_id', email).maybeSingle();
  if (!setting) throw new Error('Admin not found');
  const match = await bcrypt.compare(password, setting.password_hash);
  if (!match) throw new Error('Incorrect password');
  return { email, name: 'Admin', role: 'admin' };
}
async function resetAdminPassword(data) {
  if (!data.email) throw new Error('email required');
  if (!data.newPassword || String(data.newPassword).length < 6) throw new Error('Password must be 6+ chars');
  const email  = String(data.email).trim().toLowerCase();
  // Verify admin exists before updating
  const { data: row } = await supabase.from('admin_settings').select('admin_id').eq('admin_id', email).maybeSingle();
  if (!row) throw new Error('Admin account not found');
  const hashed = await bcrypt.hash(String(data.newPassword), 10);
  const { error } = await supabase.from('admin_settings').update({ password_hash: hashed }).eq('admin_id', email);
  if (error) throw new Error(error.message);
  return { success: true, message: 'Password updated' };
}
async function updateProfile(data) {
  if (!data.userId) throw new Error('userId required');
  const updates = {};
  if (data.name !== undefined) updates.name = data.name;
  if (data.email !== undefined) updates.email = data.email;
  if (data.address !== undefined) updates.address = data.address;
  if (data.newPassword) updates.password = await bcrypt.hash(String(data.newPassword), 10);
  const { error } = await supabase.from('users').update(updates).eq('user_id', data.userId);
  if (error) throw new Error(error.message);
  return true;
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

//──────────────────────────────────────────────────────────────
// MENU
//──────────────────────────────────────────────────────────────
async function getMenu(data) {
  const ist = getIST();
  const h   = ist.getUTCHours() + ist.getUTCMinutes() / 60;
  const dow = ist.getUTCDay(); // 0 = Sun … 6 = Sat

  // Determine lunch cutoff from today's weekly schedule (same source as admin panel)
  // Falls back to legacy cutoff_day setting, then to hardcoded 11:30
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
  } catch (_) { /* use default 11.5 on any error */ }

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
  const { data: items, error } = await supabase.from('menu').select('*').order('sort_order', { ascending: true });
  if (error) throw new Error(error.message);
  return (items || []).map(formatMenuItem);
}
async function addMenuItem(data) {
  if (!data.name) throw new Error('Item name required');
  const { data: items } = await supabase.from('menu').select('sort_order').order('sort_order', { ascending: false }).limit(1);
  const maxSort = items?.[0]?.sort_order || 0;
  const menuItemId = generateId('MENU');
  const { data: item, error } = await supabase.from('menu').insert({
    item_id: menuItemId,
    name: data.name, category: data.category || '', price: Number(data.price) || 0,
    variant: data.variants ? JSON.stringify(data.variants) : null,
    image_url: data.imageUrl || '', menu_type: data.menuType || 'morning',
    availability: true, highlight: data.highlight || '', sort_order: data.sortOrder || (maxSort + 1)
  }).select().single();
  if (error) throw new Error(error.message);
  return { itemId: item.item_id };
}
async function updateMenuItem(data) {
  if (!data.itemId) throw new Error('itemId required');
  const updates = {};
  if (data.name !== undefined) updates.name = data.name;
  if (data.category !== undefined) updates.category = data.category;
  if (data.price !== undefined) updates.price = Number(data.price);
  if (data.variants !== undefined) updates.variant = JSON.stringify(data.variants);
  if (data.imageUrl !== undefined) updates.image_url = data.imageUrl;
  if (data.menuType !== undefined) updates.menu_type = data.menuType;
  if (data.availability !== undefined) updates.availability = data.availability === 'TRUE' || data.availability === true;
  if (data.highlight !== undefined) updates.highlight = data.highlight;
  if (data.sortOrder !== undefined) updates.sort_order = Number(data.sortOrder);
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
  // Run all updates in parallel — faster and errors are now caught
  const results = await Promise.all(
    data.items.map(item =>
      supabase.from('menu')
        .update({ sort_order: Number(item.sortOrder) })
        .eq('item_id', item.itemId)
    )
  );
  // Collect any failures and report them clearly
  const failed = results
    .map((r, i) => r.error ? `item ${data.items[i].itemId}: ${r.error.message}` : null)
    .filter(Boolean);
  if (failed.length) throw new Error('Some items failed to reorder: ' + failed.join('; '));
  return true;
}

//──────────────────────────────────────────────────────────────
// ORDERS
//──────────────────────────────────────────────────────────────
async function createOrder(data) {
  if (!data.userId) throw new Error('userId required');
  const items = Array.isArray(data.items) ? data.items : JSON.parse(data.items || '[]');
  if (!items.length) throw new Error('Cart is empty');
  const ist     = getIST();
  const orderId = generateOrderId(ist);
  const ph      = cleanPhone(data.phone);
  const isSub   = data.userType === 'subscriber' && data.payFromWallet;
  const amount  = Number(data.finalAmount) || 0;

  // ── Step 1: Deduct wallet FIRST (before order insert) ──────
  // This way if order insert fails, we refund — never the other way around.
  if (isSub && amount > 0) {
    const itemSummary = items.map(i => i.name + (i.selectedVariant ? ` (${i.selectedVariant})` : '') + ` ×${i.qty}`).join(', ');
    const noteText = `Tiffin Given (${itemSummary}) | ${orderId}`;
    await deductWalletBalance(ph, amount, noteText, data.userId);
  }

  // ── Step 2: Insert order ────────────────────────────────────
  const { data: order, error } = await supabase.from('orders').insert({
    order_id: orderId,
    user_id: data.userId, name: data.name, phone: ph, address: data.address,
    items, total_amount: Number(data.totalAmount) || 0, delivery_charge: Number(data.deliveryCharge) || 0,
    final_amount: amount, coupon_code: data.couponCode || '', discount: Number(data.discount) || 0,
    user_type: data.userType || 'daily', payment_status: 'pending', order_status: 'pending',
    order_date: istDateStr(ist), order_time: istTimeStr(ist)
  }).select().single();

  if (error) {
    // ── Step 3: Order insert failed — auto-refund wallet so balance stays correct ──
    if (isSub && amount > 0) {
      try {
        await rechargeWallet({ phone: ph, amount, note: `Auto-refund — order ${orderId} failed to save` });
      } catch (_) { /* best-effort refund — log to console */ console.error(`[createOrder] Auto-refund failed for ${ph} ₹${amount}`); }
    }
    throw new Error(error.message);
  }

  if (data.couponCode) await incrementCouponUsage(data.couponCode, ph);
  return { orderId: order.order_id };
}
async function getUserOrders(data) {
  if (!data.userId) throw new Error('userId required');
  const { data: orders, error } = await supabase.from('orders').select('*').eq('user_id', data.userId).order('order_date', { ascending: false });
  if (error) throw new Error(error.message);
  return (orders || []).map(formatOrder);
}
async function adminGetOrders() {
  const { data: orders, error } = await supabase.from('orders').select('*').order('order_date', { ascending: false });
  if (error) throw new Error(error.message);
  return (orders || []).map(formatOrder);
}
// Returns only orders for a specific date (YYYY-MM-DD) — used by bulk auto-select
// to check "already ordered today" without fetching all orders
async function getOrdersByDate(data) {
  const date = data.date || istDateStr(getIST());
  const { data: orders, error } = await supabase
    .from('orders')
    .select('phone, order_date, order_status')
    .eq('order_date', date)
    .neq('order_status', 'rejected');
  if (error) throw new Error(error.message);
  return (orders || []).map(o => ({ phone: cleanPhone(o.phone), date: o.order_date, status: o.order_status }));
}
// ─────────────────────────────────────────────────────────────
// updateOrderStatus
// Wallet is already deducted at order-creation time for subscriber
// orders (createOrder / _createSingleOrder).  Admin here only:
//   1. Changes order_status  (e.g. pending → preparing → out for delivery → delivered)
//   2. Sets payment_status   (e.g. pending → paid)  — for non-subscriber cash confirmation
//   3. Assigns a rider
// No second wallet deduction happens here.
// ─────────────────────────────────────────────────────────────
async function updateOrderStatus(data) {
  if (!data.orderId) throw new Error('orderId required');
  const updates = { order_status: data.status };
  if (data.paymentStatus) updates.payment_status = data.paymentStatus;
  if (data.riderId)        updates.rider_id       = data.riderId;
  const { error } = await supabase.from('orders').update(updates).eq('order_id', data.orderId);
  if (error) throw new Error(error.message);
  return true;
}
// ─────────────────────────────────────────────────────────────
// rejectOrder
// Admin must explicitly choose refund mode:
//   refundMode = 'wallet' → credit wallet + khata entry (shows in user wallet, PDF, everywhere)
//   refundMode = 'cash'   → order rejected only, NO wallet entry (cash given in person)
//   refundMode = 'none'   → no refund (e.g. non-subscriber, or admin discretion)
// ─────────────────────────────────────────────────────────────
async function rejectOrder(data) {
  if (!data.orderId) throw new Error('orderId required');

  // Fetch the order
  const { data: order, error: fetchErr } = await supabase
    .from('orders')
    .select('order_id, user_id, phone, final_amount, user_type, payment_status, order_status')
    .eq('order_id', data.orderId)
    .maybeSingle();
  if (fetchErr) throw new Error(fetchErr.message);
  if (!order) throw new Error('Order not found');

  // Guard: already rejected — do nothing more
  if (order.order_status === 'rejected') {
    return { rejected: true, refunded: 0, alreadyRejected: true };
  }

  // Mark rejected
  const { error } = await supabase
    .from('orders')
    .update({ order_status: 'rejected' })
    .eq('order_id', data.orderId);
  if (error) throw new Error(error.message);

  // Refund handling — driven entirely by admin's explicit choice
  const refundMode = data.refundMode || 'none'; // 'wallet' | 'cash' | 'none'
  const amt = Number(data.refundAmount) || Number(order.final_amount) || 0;
  let refundedAmount = 0;

  if (refundMode === 'wallet' && amt > 0) {
    const ph   = cleanPhone(order.phone);
    const note = data.refundNote
      ? `Refund — ${data.refundNote} | order ${order.order_id}`
      : `Refund — rejected order ${order.order_id}`;
    await rechargeWallet({ phone: ph, amount: amt, note });
    refundedAmount = amt;
  }
  // refundMode === 'cash' → order rejected, nothing recorded (cash given in person)
  // refundMode === 'none' → order rejected, no refund

  return { rejected: true, refunded: refundedAmount, refundMode };
}
// ─────────────────────────────────────────────────────────────
// UNIFIED BULK ORDER CREATOR
// Used by: bulkOrdersWithBalance, adminBulkCreate, forceUdharOrder
// Guarantees: structured order ID, wallet deduction + khata entry,
//             balance check (skippable for udhar), full data consistency
//
// Options (second arg):
//   skipDeduction : true  → do NOT deduct wallet (daily user orders)
//   allowOverdraft: true  → skip balance check, allow balance to go negative (udhar)
// ─────────────────────────────────────────────────────────────
async function _createSingleOrder(o, { skipDeduction = false, allowOverdraft = false } = {}) {
  const ph     = cleanPhone(o.phone);
  const amount = Number(o.finalAmount) || 0;
  const items  = Array.isArray(o.items) ? o.items : JSON.parse(o.items || '[]');
  const userId = o.userId || ph;

  // Balance check — only when deducting AND not explicitly allowing overdraft
  if (!skipDeduction && !allowOverdraft && amount > 0 && o.userType !== 'daily') {
    const bal = await getWalletBalance(ph);
    if (bal < amount) throw new Error(`Insufficient balance ₹${bal} (need ₹${amount})`);
  }

  const ist     = getIST();
  const orderId = generateOrderId(ist);

  const { data: order, error } = await supabase.from('orders').insert({
    order_id: orderId,
    user_id: userId, name: o.name, phone: ph, address: o.address || '',
    items,
    total_amount: amount, delivery_charge: 0, final_amount: amount,
    coupon_code: '', discount: 0,
    user_type: o.userType || 'subscriber',
    payment_status: 'pending', order_status: 'pending',
    order_date: istDateStr(ist), order_time: istTimeStr(ist)
  }).select().single();
  if (error) throw new Error(error.message);

  // Deduct wallet + record khata for subscriber orders (unless explicitly skipped)
  if (!skipDeduction && amount > 0 && o.userType !== 'daily') {
    const itemSummary = items.map(i => i.name + (i.selectedVariant ? ` (${i.selectedVariant})` : '') + ` ×${i.qty}`).join(', ');
    await deductWalletBalance(ph, amount, `Tiffin Given (${itemSummary || 'tiffin'}) | ${order.order_id}`, userId);
  }

  return order.order_id;
}

async function forceUdharOrder(data) {
  if (!data.phone) throw new Error('phone required');
  const items = Array.isArray(data.items) ? data.items : JSON.parse(data.items || '[]');
  const ph = cleanPhone(data.phone);
  const amount = Number(data.amount) || Number(data.finalAmount) || 0;
  // Get user_id from DB (may differ from phone for legacy accounts)
  const { data: user } = await supabase.from('users').select('user_id').eq('phone', ph).maybeSingle();
  const orderId = await _createSingleOrder({
    phone: ph, name: data.name, address: data.address || '',
    items, finalAmount: amount,
    userId: user?.user_id || ph,
    userType: 'subscriber'
  }, { allowOverdraft: true }); // udhar — deducts even if balance goes negative
  const newBal = await getWalletBalance(ph);
  return { orderId, newBalance: newBal };
}

async function bulkOrdersWithBalance(data) {
  if (!data.orders || !Array.isArray(data.orders)) throw new Error('orders array required');

  // Determine current slot (same logic as adminBulkCreate)
  const nowIST  = getIST();
  const istHour = nowIST.getUTCHours();
  const slotName = istHour < 12 ? 'morning' : 'evening';

  // Fetch pause_delivery for all phones in one query
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
    // Pause delivery slot guard
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
      const orderId = await _createSingleOrder({ ...o, phone: ph, userType: 'subscriber' });
      // skipDeduction defaults to false — wallet deducted, balance checked
      success.push({ phone: ph, name: o.name, orderId });
    } catch (err) { failed.push({ phone: ph, name: o.name, reason: err.message }); }
  }
  return { success, failed, slot: slotName };
}

// adminBulkCreate — single entry point for all bulk creation (subscribers + daily)
// Slot guard: each subscriber/user gets at most 1 order per slot per day.
//   morning slot  = order_time hour < 12 (00:00–11:59 IST)
//   evening slot  = order_time hour >= 12 (12:00–23:59 IST)
async function adminBulkCreate(data) {
  if (!data.orders || !Array.isArray(data.orders)) throw new Error('orders array required');

  // Determine which slot we are currently in (IST hour)
  const nowIST    = getIST();
  const istHour   = nowIST.getUTCHours(); // IST hours (already shifted)
  const slotName  = istHour < 12 ? 'morning' : 'evening';
  const todayStr  = istDateStr(nowIST);

  // Build a set of phones that already have an order in today's current slot
  // to prevent duplicate bulk orders for the same slot.
  const { data: todayOrders } = await supabase
    .from('orders')
    .select('phone, order_time')
    .eq('order_date', todayStr)
    .neq('order_status', 'rejected');

  const alreadyOrderedThisSlot = new Set();
  (todayOrders || []).forEach(o => {
    // Use normOrderTime — handles all stored formats (HH:MM AM/PM, 24h, ISO, legacy variants)
    const normalised = normOrderTime(o.order_time || '');
    // normalised is "HH:MM AM/PM" — parse to 24h hour
    const match = normalised.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
    if (match) {
      let h = parseInt(match[1]);
      const isPM = match[3].toUpperCase() === 'PM';
      if (isPM && h !== 12) h += 12;
      if (!isPM && h === 12) h = 0;
      const orderSlot = h < 12 ? 'morning' : 'evening';
      if (orderSlot === slotName) {
        alreadyOrderedThisSlot.add(cleanPhone(o.phone));
      }
    }
  });

  // Build pause_delivery map for all subscribers in this bulk run — one query, no N+1
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
    // Slot duplicate guard
    if (alreadyOrderedThisSlot.has(ph)) {
      failed.push({ phone: ph, name: o.name, reason: `Already has a ${slotName} order today` });
      continue;
    }
    // Pause delivery slot guard — skip subscriber if their paused slot matches current slot
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
        { ...o, phone: ph, userType: o.userType || 'subscriber' },
        { skipDeduction: o.userType === 'daily' }  // daily users: no wallet deduction
      );
      alreadyOrderedThisSlot.add(ph); // prevent double-processing within same bulk run
      success.push({ phone: ph, name: o.name, orderId });
    } catch (err) { failed.push({ phone: ph, name: o.name, reason: err.message }); }
  }
  return { success, failed, slot: slotName };
}

//──────────────────────────────────────────────────────────────
// COUPONS
//──────────────────────────────────────────────────────────────
async function applyCoupon(data) {
  if (!data.code) throw new Error('Coupon code required');
  const { data: coupon } = await supabase.from('coupons').select('*').eq('code', data.code.toUpperCase()).maybeSingle();
  if (!coupon) throw new Error('Invalid coupon code');
  if (!coupon.is_active) throw new Error('Coupon not active');
  if (coupon.expiry_date && new Date(coupon.expiry_date) < new Date()) throw new Error('Coupon expired');
  if (coupon.user_phone && cleanPhone(coupon.user_phone) !== cleanPhone(data.phone || '')) throw new Error('Coupon not valid for this user');

  // Per-user usage limit check
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
    let usage = {}; try { usage = JSON.parse(coupon.usage_count || '{}'); } catch { usage = {}; }
    usage[phone] = (usage[phone] || 0) + 1;
    await supabase.from('coupons').update({ usage_count: JSON.stringify(usage) }).eq('code', code);
  } catch {}
}
async function createCoupon(data) {
  if (!data.code || !data.discountType || !data.discountValue) throw new Error('code, discountType, discountValue required');
  const { error } = await supabase.from('coupons').insert({
    code: data.code.toUpperCase(), discount_type: data.discountType, discount_value: Number(data.discountValue),
    expiry_date: data.expiryDate || null, user_phone: data.userPhone || null, is_active: true, usage_count: '{}'
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

//──────────────────────────────────────────────────────────────
// SUBSCRIBERS
//──────────────────────────────────────────────────────────────
async function checkSubscriber(data) {
  if (!data.phone) return { isSubscriber: false, pauseDelivery: 'none' };
  const ph = cleanPhone(data.phone);
  const { data: sub } = await supabase.from('subscribers').select('is_active, pause_delivery').eq('phone', ph).maybeSingle();
  return {
    isSubscriber: !!(sub && sub.is_active),
    pauseDelivery: sub?.pause_delivery || 'none' // 'none' | 'lunch' | 'dinner' | 'both'
  };
}
async function pauseUserDelivery(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const mode = data.mode || 'none'; // 'none' | 'lunch' | 'dinner' | 'both'
  const { error } = await supabase.from('subscribers').update({ pause_delivery: mode }).eq('phone', ph);
  if (error) throw new Error(error.message);
  return { pauseDelivery: mode };
}
async function getSubscriberPauseStatus(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: sub } = await supabase.from('subscribers').select('pause_delivery').eq('phone', ph).maybeSingle();
  return { pauseDelivery: sub?.pause_delivery || 'none' };
}
async function adminGetSubscribers() {
  const { data: subs, error } = await supabase.from('subscribers').select('*');
  if (error) throw new Error(error.message);
  const { data: wallets } = await supabase.from('wallet').select('*');
  // Normalize phone to 10 digits for reliable lookup — prevents mismatch if wallet
  // stored cleaned phone but subscriber table has formatted phone (or vice versa)
  const balMap = {};
  (wallets || []).forEach(w => { balMap[cleanPhone(w.user_phone)] = Number(w.balance) || 0; });
  return (subs || []).map(s => ({
    phone: s.phone, name: s.name || '', address: s.address || '',
    startDate: s.start_date, plan: s.plan || s.plan_type || 'both',
    status: s.is_active ? 'active' : 'paused',
    pauseDelivery: s.pause_delivery || 'none',
    balance: balMap[cleanPhone(s.phone)] || 0
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
  // Sync is_subscriber flag on users table
  await supabase.from('users').update({ is_subscriber: true }).eq('phone', ph);
  if (data.initialRecharge && Number(data.initialRecharge) > 0) {
    await rechargeWallet({ phone: ph, amount: data.initialRecharge, note: 'Initial recharge' });
  }
  return true;
}
async function updateSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone); const updates = {};
  if (data.name !== undefined) updates.name = data.name;
  if (data.address !== undefined) updates.address = data.address;
  if (data.plan !== undefined) { updates.plan = data.plan; updates.plan_type = data.plan; }
  if (data.status !== undefined) updates.is_active = data.status === 'active';
  const { error } = await supabase.from('subscribers').update(updates).eq('phone', ph);
  if (error) throw new Error(error.message);
  return true;
}
async function removeSubscriber(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { error } = await supabase.from('subscribers').delete().eq('phone', ph);
  if (error) throw new Error(error.message);
  // Clear is_subscriber flag on users table
  await supabase.from('users').update({ is_subscriber: false }).eq('phone', ph);
  return true;
}
async function getUserByPhone(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: user } = await supabase.from('users').select('*').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('No registered user found with this phone number');
  const { data: sub } = await supabase.from('subscribers').select('is_active').eq('phone', ph).maybeSingle();
  return { userId: user.user_id, name: user.name, phone: user.phone, email: user.email || '', address: user.address || '', isSubscriber: !!(sub && sub.is_active) };
}
// ─────────────────────────────────────────────────────────────────
// ADMIN CREATE USER
// Admin manually creates a user account with optional subscriber + wallet
// ─────────────────────────────────────────────────────────────────
async function adminCreateUser(data) {
  if (!data.phone || !data.name || !data.password) throw new Error('phone, name, password required');
  const ph = cleanPhone(data.phone);
  // Check duplicate
  const { data: existing } = await supabase.from('users').select('phone').eq('phone', ph).maybeSingle();
  if (existing) throw new Error('Phone already registered');
  const hashed = await bcrypt.hash(String(data.password).trim(), 10);
  // Create user
  const { data: user, error } = await supabase.from('users').insert({
    user_id: ph, name: data.name, phone: ph,
    email: data.email || '', address: data.address || '',
    password: hashed, is_subscriber: false
  }).select().single();
  if (error) throw new Error(error.message);
  // If admin wants to make them a subscriber right away
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
  // Sync is_subscriber flag on users table
  await supabase.from('users').update({ is_subscriber: true }).eq('phone', ph);
  if (data.initialRecharge && Number(data.initialRecharge) > 0) {
    await rechargeWallet({ phone: ph, amount: data.initialRecharge, note: 'Promoted to subscriber' });
  }
  return { promoted: true, phone: ph };
}

//──────────────────────────────────────────────────────────────
// RIDERS
//──────────────────────────────────────────────────────────────
async function createRider(data) {
  if (!data.name || !data.email || !data.password) throw new Error('name, email, password required');
  const hashed = await bcrypt.hash(String(data.password), 10);
  const riderEmail = String(data.email).trim().toLowerCase();
  const ist = getIST();
  const riderId = await generateRiderId(ist);
  const { data: rider, error } = await supabase.from('riders').insert({
    rider_id: riderId, name: data.name, email: riderEmail, password: hashed
  }).select().single();
  if (error) throw new Error(error.message);
  return { riderId: rider.rider_id };
}
async function updateRider(data) {
  if (!data.riderId) throw new Error('riderId required');
  const updates = {};
  if (data.name !== undefined) updates.name = data.name;
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
  // Normalize: trim + lowercase so "Rider@Gmail.com " == "rider@gmail.com"
  const email = String(data.email).trim().toLowerCase();
  const password = String(data.password).trim();
  const { data: rider } = await supabase.from('riders').select('*').eq('email', email).maybeSingle();
  if (!rider) throw new Error('Invalid credentials');
  const match = await bcrypt.compare(password, rider.password);
  if (!match) throw new Error('Invalid credentials');
  return { riderId: rider.rider_id, name: rider.name, email: rider.email };
}
async function getRiderOrders(data) {
  if (!data.riderId) throw new Error('riderId required');
  // Orders assigned to this rider (all active statuses)
  const { data: assigned, error: e1 } = await supabase.from('orders').select('*')
    .eq('rider_id', data.riderId)
    .in('order_status', ['out for delivery', 'delivered', 'preparing']);
  if (e1) throw new Error(e1.message);
  // Unassigned orders in pending/preparing — visible to all riders
  const { data: unassigned, error: e2 } = await supabase.from('orders').select('*')
    .is('rider_id', null)
    .in('order_status', ['preparing', 'pending']);
  if (e2) throw new Error(e2.message);
  // Merge + deduplicate
  const seen = new Set();
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

//──────────────────────────────────────────────────────────────
// STAFF
//──────────────────────────────────────────────────────────────
async function createStaff(data) {
  if (!data.username || !data.name || !data.password) throw new Error('username, name, password required');
  if (data.password.length < 6) throw new Error('Password must be 6+ chars');
  const staffUsername = String(data.username).trim().toLowerCase();
  const hashed = await bcrypt.hash(String(data.password).trim(), 10);
  const { error } = await supabase.from('staff').insert({ username: staffUsername, name: data.name, password: hashed, status: 'active' });
  if (error) throw new Error(error.message);
  return true;
}
async function updateStaff(data) {
  if (!data.username) throw new Error('username required');
  const updates = {};
  if (data.name !== undefined) updates.name = data.name;
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

//──────────────────────────────────────────────────────────────
// WALLET / KHATA
//──────────────────────────────────────────────────────────────
async function getWalletBalance(phone) {
  const ph = cleanPhone(phone);
  const { data: w } = await supabase.from('wallet').select('balance').eq('user_phone', ph).maybeSingle();
  return Number(w?.balance) || 0;
}

// ── Atomic wallet update ───────────────────────────────────────
// Uses a single SQL expression to avoid read-modify-write race conditions.
// delta > 0 = credit, delta < 0 = debit. Returns new balance.
async function _atomicWalletUpdate(phone, delta) {
  const ph = cleanPhone(phone);
  // Ensure row exists first (upsert with 0 if new)
  await supabase.from('wallet').upsert(
    { user_phone: ph, balance: 0, last_updated: new Date().toISOString() },
    { onConflict: 'user_phone', ignoreDuplicates: true }
  );
  // Atomic increment/decrement via RPC
  const { data, error } = await supabase.rpc('wallet_atomic_update', {
    p_phone: ph,
    p_delta: delta
  });
  if (error) {
    // RPC not available — fall back to read-modify-write (safe for single-server deploy)
    const currentBal = await getWalletBalance(ph);
    const newBal = currentBal + delta;
    await supabase.from('wallet').upsert(
      { user_phone: ph, balance: newBal, last_updated: new Date().toISOString() },
      { onConflict: 'user_phone' }
    );
    return newBal;
  }
  return Number(data) || 0;
}

async function deductWalletBalance(phone, amount, note, userId) {
  const ph = cleanPhone(phone);
  const newBal = await _atomicWalletUpdate(ph, -amount);
  const ist = getIST();
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id: userId || null, user_phone: ph, amount: -amount, type: 'debit',
    note: note || '', created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] deduct insert failed:', kErr.message, '| phone:', ph);
  return newBal;
}
async function getSubscriberBalance(data) {
  if (!data.phone) throw new Error('phone required');
  return { balance: await getWalletBalance(data.phone) };
}
async function rechargeWallet(data) {
  if (!data.phone || !data.amount) throw new Error('phone and amount required');
  const ph = cleanPhone(data.phone);
  const amt = Math.abs(Number(data.amount));
  const newBal = await _atomicWalletUpdate(ph, amt);
  const ist = getIST();
  const { data: user } = await supabase.from('users').select('user_id').eq('phone', ph).maybeSingle();
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id: user?.user_id || null, user_phone: ph, amount: amt, type: 'credit',
    note: data.note || 'Recharge', created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] recharge insert failed:', kErr.message, '| phone:', ph);
  return { newBalance: newBal };
}
async function addKhataEntry(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const amount = Number(data.amount) || 0;
  const newBal = await _atomicWalletUpdate(ph, amount);
  const { data: user } = await supabase.from('users').select('user_id').eq('phone', ph).maybeSingle();
  const ist = getIST();
  const { error: kErr } = await supabase.from('khata_transactions').insert({
    user_id: user?.user_id || null, user_phone: ph, amount, type: amount >= 0 ? 'credit' : 'debit',
    note: data.note || '', created_at: ist.toISOString()
  });
  if (kErr) console.error('[khata] addEntry insert failed:', kErr.message, '| phone:', ph);
  return { newBalance: newBal };
}

// ── MANUAL REFUND (admin) ─────────────────────────────────────
// Refunds any amount to a subscriber wallet with a khata entry.
// Works for any order — rejected, delivered, or cash orders admin wants to credit.
async function manualRefund(data) {
  if (!data.phone) throw new Error('phone required');
  if (!data.amount || Number(data.amount) <= 0) throw new Error('amount must be > 0');
  const ph = cleanPhone(data.phone);
  const amt = Number(data.amount);
  const note = data.note || `Manual refund${data.orderId ? ' — order ' + data.orderId : ''}`;
  const result = await rechargeWallet({ phone: ph, amount: amt, note });
  return { newBalance: result.newBalance, refunded: amt };
}
async function getKhata(data) {
  if (!data.phone) throw new Error('phone required');
  const ph = cleanPhone(data.phone);
  const { data: user } = await supabase.from('users').select('user_id').eq('phone', ph).maybeSingle();

  let txns = [];
  if (user?.user_id) {
    // Primary path: subscriber has a users account — fetch by user_id
    const { data: t } = await supabase.from('khata_transactions').select('*')
      .eq('user_id', user.user_id).order('created_at', { ascending: true });
    txns = t || [];
    // Also fetch any orphan rows stored only by phone (e.g. admin-added subscriber
    // whose user_id was null at insert time) and merge — deduplicate by id
    const { data: byPhone } = await supabase.from('khata_transactions').select('*')
      .eq('user_phone', ph).is('user_id', null).order('created_at', { ascending: true });
    if (byPhone && byPhone.length) {
      const seen = new Set(txns.map(t => t.id));
      const orphans = byPhone.filter(t => !seen.has(t.id));
      // Backfill user_id on orphan rows so future queries find them via user_id
      if (orphans.length) {
        await supabase.from('khata_transactions')
          .update({ user_id: user.user_id })
          .in('id', orphans.map(t => t.id));
        orphans.forEach(t => { t.user_id = user.user_id; });
      }
      txns = [...txns, ...orphans].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    }
  } else {
    // Fallback: admin-added subscriber with no users account — query by user_phone
    const { data: t } = await supabase.from('khata_transactions').select('*')
      .eq('user_phone', ph).order('created_at', { ascending: true });
    txns = t || [];
  }
  // ── BALANCE FIX: compute from transaction sum — always accurate ──
  let running = 0;
  const entries = txns.map(t => {
    running += Number(t.amount) || 0;
    const ist = new Date(new Date(t.created_at).getTime() + 5.5 * 3600000);
    return {
      entryId: t.id, phone: ph,
      type: t.type === 'credit' ? 'recharge' : 'tiffin_given',
      amount: Number(t.amount), note: t.note || '',
      runningBalance: running,
      date: istDateStr(ist), time: istTimeStr(ist)
    };
  });
  const computedBal = running; // sum of all transactions = true balance
  // Sync wallet table so getSubscriberBalance always matches
  await supabase.from('wallet').upsert(
    { user_phone: ph, balance: computedBal, last_updated: new Date().toISOString() },
    { onConflict: 'user_phone' }
  );
  return { entries, balance: computedBal };
}
async function adminGetAllKhata() {
  // Fetch subscribers, wallets, users, and all transactions in parallel
  const [
    { data: subs },
    { data: wallets },
    { data: users },
    { data: txnCounts }
  ] = await Promise.all([
    supabase.from('subscribers').select('phone, name'),
    supabase.from('wallet').select('user_phone, balance'),
    supabase.from('users').select('user_id, phone'),
    // Fetch user_phone + user_id — covers all insert paths
    supabase.from('khata_transactions').select('user_phone, user_id, id')
  ]);

  // Build balance map — normalize phone for reliable lookup
  const balMap = {};
  (wallets || []).forEach(w => {
    if (w.user_phone) balMap[cleanPhone(w.user_phone)] = Number(w.balance) || 0;
  });

  // Build user_id → phone map (for transactions stored without user_phone)
  const userIdToPhone = {};
  (users || []).forEach(u => {
    if (u.user_id && u.phone) userIdToPhone[u.user_id] = cleanPhone(u.phone);
  });

  // Count transactions per phone — handle both storage paths:
  // Path A: user_phone set directly (new inserts after Fix #2)
  // Path B: only user_id set (old inserts before Fix #2) — resolve via userIdToPhone
  const countMap = {};
  (txnCounts || []).forEach(t => {
    let ph = t.user_phone ? cleanPhone(t.user_phone) : null;
    if (!ph && t.user_id) ph = userIdToPhone[t.user_id] || null;
    if (!ph) return;
    countMap[ph] = (countMap[ph] || 0) + 1;
  });

  return (subs || []).map(s => {
    const ph = cleanPhone(s.phone);
    return {
      phone: s.phone,
      name: s.name || '',
      balance: balMap[ph] || 0,
      entryCount: countMap[ph] || 0,
      entries: []   // full entries loaded on demand via getKhata when admin clicks View
    };
  });
}

//──────────────────────────────────────────────────────────────
// SETTINGS
//──────────────────────────────────────────────────────────────
async function upsertSetting(key, value) {
  await supabase.from('admin_settings').upsert({ admin_id: key, access_level: String(value) }, { onConflict: 'admin_id' });
}
async function getOrderCutoff() {
  const { data: rows } = await supabase.from('admin_settings').select('*');
  const map = {};
  (rows || []).forEach(r => { map[r.admin_id] = r.access_level; });
  const sched = {};
  for (let d = 0; d <= 6; d++) { try { sched[d] = JSON.parse(map['schedule_' + d] || 'null') || getDefaultDay(d); } catch { sched[d] = getDefaultDay(d); } }
  return { enabled: map['cutoff_enabled'] === 'true', cutoffDay: map['cutoff_day'] || '11:30', cutoffNight: map['cutoff_night'] || '20:00', schedule: sched };
}
async function setOrderCutoff(data) {
  await upsertSetting('cutoff_enabled', data.enabled ? 'true' : 'false');
  if (data.cutoffDay) await upsertSetting('cutoff_day', data.cutoffDay);
  if (data.cutoffNight) await upsertSetting('cutoff_night', data.cutoffNight);
  return true;
}
async function getWeeklySchedule() {
  const { data: rows } = await supabase.from('admin_settings').select('*');
  const map = {}; (rows || []).forEach(r => { map[r.admin_id] = r.access_level; });
  const result = {};
  for (let d = 0; d <= 6; d++) { try { result[d] = JSON.parse(map['schedule_' + d] || 'null') || getDefaultDay(d); } catch { result[d] = getDefaultDay(d); } }
  return result;
}
async function setWeeklySchedule(data) {
  if (!data.schedule) throw new Error('schedule required');
  for (let d = 0; d <= 6; d++) { if (data.schedule[d]) await upsertSetting('schedule_' + d, JSON.stringify(data.schedule[d])); }
  return true;
}
async function getKhataEnabled() {
  const { data } = await supabase.from('admin_settings').select('access_level').eq('admin_id', 'khata_enabled').maybeSingle();
  const v = data?.access_level;
  return { enabled: v === null || v === undefined || v === 'true' || v === '1' };
}
async function setKhataEnabled(data) {
  await upsertSetting('khata_enabled', data.enabled ? 'true' : 'false');
  return true;
}

//──────────────────────────────────────────────────────────────
// ANALYTICS
//──────────────────────────────────────────────────────────────
async function getAnalytics() {
  const ist = getIST(); const today = istDateStr(ist);
  const { data: orders } = await supabase.from('orders').select('final_amount, order_date, order_status');
  const { data: users } = await supabase.from('users').select('user_id');
  const { data: subs } = await supabase.from('subscribers').select('phone');
  const { data: wallets } = await supabase.from('wallet').select('balance');
  // FIX: exclude rejected orders from all counts and revenue calculations
  const activeOrders = (orders || []).filter(o => o.order_status !== 'rejected');
  const todayOrders = activeOrders.filter(o => normOrderDate(o.order_date) === today);
  const todayRevenue = todayOrders.reduce((s, o) => s + (Number(o.final_amount) || 0), 0);
  const thisMonth = ist.getUTCMonth(), thisYear = ist.getUTCFullYear();
  const monthlyRevenue = activeOrders.filter(o => {
    if (!o.order_date) return false;
    const norm = normOrderDate(o.order_date);
    if (/^\d{4}-\d{2}-\d{2}$/.test(norm)) {
      const [y, m] = norm.split('-');
      return parseInt(m) - 1 === thisMonth && parseInt(y) === thisYear;
    }
    return false;
  }).reduce((s, o) => s + (Number(o.final_amount) || 0), 0);
  // FIX: renamed totalWallet -> totalWalletBalance to match admin panel (a.totalWalletBalance)
  const totalWalletBalance = (wallets || []).reduce((s, w) => s + (Number(w.balance) || 0), 0);
  return { todayOrders: todayOrders.length, todayRevenue, monthlyRevenue, totalOrders: activeOrders.length, totalUsers: (users || []).length, totalSubscribers: (subs || []).length, totalWalletBalance };
}
async function getUsers() {
  const { data: users, error } = await supabase.from('users').select('user_id, name, phone, email, address, created_at');
  if (error) throw new Error(error.message);
  return (users || []).map(u => ({ userId: u.user_id, name: u.name, phone: u.phone, email: u.email || '', address: u.address || '', createdAt: u.created_at }));
}

//──────────────────────────────────────────────────────────────
// DELETE OLD DATA
//──────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
// DATA CLEANUP — separate endpoints for orders and transactions
// Orders     : minimum 5 days old, any custom cutoff date
// Transactions: minimum 45 days old, any custom cutoff date
// cutoffDate param: "YYYY-MM-DD" — delete everything BEFORE this date
// ─────────────────────────────────────────────────────────────
function _parseCutoff(cutoffDate, minDays) {
  if (!cutoffDate) throw new Error('cutoffDate required (YYYY-MM-DD)');
  const cut = new Date(cutoffDate + 'T00:00:00Z');
  if (isNaN(cut.getTime())) throw new Error('Invalid cutoffDate format');
  const minCutoff = new Date(Date.now() + 5.5 * 3600000);
  minCutoff.setUTCDate(minCutoff.getUTCDate() - minDays);
  if (cut > minCutoff) throw new Error(`Cutoff date must be at least ${minDays} days in the past`);
  return cut;
}

// ── Helper: compute YYYY-MM-DD string N days ago (IST) ────────
function _daysAgoIST(n) {
  const d = new Date(Date.now() + 5.5 * 3600000);
  d.setUTCDate(d.getUTCDate() - n);
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}

// ── Safe order IDs collector ──────────────────────────────────
// Fetches all order IDs whose normalised date (YYYY-MM-DD) is
// strictly before cutoffDate.  Works regardless of how order_date
// was originally stored (YYYY-MM-DD, DD/MM/YYYY, ISO string, etc.)
async function _orderIdsBefore(cutoffDate) {
  // Fetch only order_id + order_date — minimal payload
  const { data: rows, error } = await supabase
    .from('orders')
    .select('order_id, order_date');
  if (error) throw new Error(error.message);
  return (rows || [])
    .filter(o => {
      const norm = normOrderDate(o.order_date);
      return norm && norm < cutoffDate; // safe YYYY-MM-DD string compare
    })
    .map(o => o.order_id);
}

async function deleteOldOrders(data) {
  _parseCutoff(data.cutoffDate, 5); // validates min 5 days — throws if too recent
  const ids = await _orderIdsBefore(data.cutoffDate);
  if (!ids.length) return { deleted: 0, cutoffDate: data.cutoffDate };
  // Delete in batches of 500 to stay within Supabase IN-clause limits
  let deleted = 0;
  for (let i = 0; i < ids.length; i += 500) {
    const batch = ids.slice(i, i + 500);
    const { error, count } = await supabase
      .from('orders')
      .delete({ count: 'exact' })
      .in('order_id', batch);
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
  _parseCutoff(data.cutoffDate, 45); // validates min 45 days — throws if too recent
  // Use server-side date filter — avoids large JS-side IN clause
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

// Legacy endpoint — uses separate cutoff dates for orders vs transactions
// Orders:       cutoff = months ago (min 5 days enforced)
// Transactions: cutoff = max(months ago, 45 days ago) — never deletes recent transactions
async function deleteOldData(data) {
  const months = Number(data.months) || 3;
  // Compute cutoff date from months param
  const ordersCutoff = _daysAgoIST(months * 30);
  // Transactions need min 45 days — use whichever is older
  const txnMinCutoff  = _daysAgoIST(45);
  const txnCutoff     = ordersCutoff < txnMinCutoff ? ordersCutoff : txnMinCutoff;

  const orders = await deleteOldOrders({ cutoffDate: ordersCutoff })
    .catch(e => ({ deleted: 0, error: e.message }));
  const txns = await deleteOldTransactions({ cutoffDate: txnCutoff })
    .catch(e => ({ deleted: 0, error: e.message }));

  return {
    deletedOrders   : orders.deleted,
    deletedKhata    : txns.deleted,
    ordersCutoff,
    txnCutoff,
    // Surface errors so callers know what happened instead of silent 0
    ordersError     : orders.error || null,
    txnsError       : txns.error   || null
  };
}
