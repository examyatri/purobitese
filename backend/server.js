'use strict';

// ─── DEPENDENCIES ────────────────────────────────────────────────────────────
const express = require('express');
const https   = require('https');
const { createClient } = require('@supabase/supabase-js');
const bcrypt  = require('bcryptjs');

// ─── SETUP ───────────────────────────────────────────────────────────────────
const app = express();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY
);

const SECURE_API_KEY = process.env.API_KEY;
if (!SECURE_API_KEY) console.error('[FATAL] API_KEY env var not set');

const SALT_ROUNDS = 10;

// ─── SELF-PING ────────────────────────────────────────────────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || '';
if (SELF_URL) {
  setInterval(() => {
    https.get(SELF_URL + '/ping', r => console.log('[keep-alive]', r.statusCode))
         .on('error', e => console.error('[keep-alive error]', e.message));
  }, 10 * 60 * 1000);
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

function generateOrderId(ist)  { return generateId('ORD',   ist); }
function generateThaliId(ist)  { return generateId('THALI', ist); }
function generateTxnId(ist)    { return generateId('TXN',   ist); }

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
    items: typeof o.items === 'string' ? JSON.parse(o.items) : (o.items || [])
  };
}

function formatMenuItem(i) {
  return {
    ...i,
    variants: typeof i.variants === 'string' ? JSON.parse(i.variants) : (i.variants || [])
  };
}

function formatThali(t, items = []) {
  return { ...t, items };
}

// ─── PRIVATE HELPERS ─────────────────────────────────────────────────────────

async function _atomicWalletUpdate(phone, delta) {
  const { data: rows } = await supabase
    .from('khata_summary')
    .select('balance')
    .eq('phone', phone)
    .single();
  const newBalance = ((rows?.balance) ?? 0) + delta;
  await supabase
    .from('khata_summary')
    .upsert({ phone, balance: newBalance, updated_at: new Date().toISOString() }, { onConflict: 'phone' });
  return newBalance;
}

async function _createTxnEntry(phone, orderId, amount, newBalance, type, source, ist) {
  await supabase.from('khata_entries').insert({
    id:              generateTxnId(ist),
    phone,
    type,
    amount,
    running_balance: newBalance,
    note:            'Order ' + orderId,
    date:            istDateStr(ist),
    time:            istTimeStr(ist),
    order_id:        orderId,
    order_status:    'pending',
    order_source:    source,
    created_at:      new Date().toISOString()
  });
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

async function _deductThaliStock(thali_id, qty = 1) {
  const { data: row } = await supabase
    .from('thalis')
    .select('stock_qty')
    .eq('thali_id', thali_id)
    .single();
  if (row && row.stock_qty !== null) {
    await supabase
      .from('thalis')
      .update({ stock_qty: Math.max(0, row.stock_qty - qty) })
      .eq('thali_id', thali_id);
  }
}

async function _deductMenuStock(items) {
  for (const item of items) {
    if (item.isThali === true) {
      await _deductThaliStock(item.item_id, item.qty || 1);
    } else {
      const { data: row } = await supabase
        .from('menu_items')
        .select('stock_grams')
        .eq('item_id', item.item_id)
        .single();
      if (row && row.stock_grams !== null) {
        await supabase
          .from('menu_items')
          .update({ stock_grams: Math.max(0, row.stock_grams - (item.stock_grams || 100) * item.qty) })
          .eq('item_id', item.item_id);
      }
    }
  }
}

async function _createSingleOrder({ user, items, deliveryCharge, khataEnabled, ist, coupon, source = 'customer', slot = 'morning' }) {
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
      const { data: cpnRow } = await supabase.from('coupons').select('used_count,usage_count,used_by').eq('code', coupon.code).single();
      if (cpnRow) {
        let ub=[]; try{ub=JSON.parse(cpnRow.used_by||'[]');}catch{ub=[];}
        await supabase.from('coupons').update({
          used_count:  (cpnRow.used_count||0)+1,
          usage_count: (cpnRow.usage_count||0)+1,
          used_by:     JSON.stringify([...ub, ...(user.phone ? [user.phone] : [])])
        }).eq('code', coupon.code);
      }
    } catch(_) {}
  }
  const finalAmount = subtotal + deliveryCharge - discount;
  const orderId  = generateOrderId(ist);
  const dateStr  = istDateStr(ist);
  const timeStr  = istTimeStr(ist);
  let newBal = null;

  if (khataEnabled && user.is_subscriber) {
    newBal = await _atomicWalletUpdate(user.phone, -finalAmount);
    const txnType = newBal < 0 ? 'tiffin_udhar' : 'tiffin_given';
    await _createTxnEntry(user.phone, orderId, -finalAmount, newBal, txnType, source, ist);
    await _createNotification({
      type:     'order',
      priority: 'high',
      group_id: orderId,
      title:    'New Order',
      body:     user.name + ' placed order ' + orderId,
      meta:     { orderId, phone: user.phone }
    });
  }

  await _deductMenuStock(items);

  await supabase.from('orders').insert({
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
    user_type:       user.is_subscriber ? 'subscriber' : 'daily',
    rider_id:        null,
    slot:            source === 'admin' ? (slot || 'morning') : null,
    date:            dateStr,
    time:            timeStr,
    created_at:      new Date().toISOString()
  });

  return { orderId, finalAmount, walletBalance: newBal };
}

// ─── HEALTH ROUTES ────────────────────────────────────────────────────────────
app.get('/',     (_req, res) => res.json({ app: 'Tiffo API', status: 'running', version: 'v1' }));
app.get('/ping', (_req, res) => res.json({ status: 'alive', time: new Date().toISOString() }));

// ─── MAIN ENDPOINT ────────────────────────────────────────────────────────────
app.post('/api', async (req, res) => {
  const { action, data = {}, apiKey } = req.body;

  if (apiKey !== SECURE_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  const ist = getIST();

  try {
    switch (action) {

      // ── AUTH ──────────────────────────────────────────────────────────────

      case 'checkSession': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'Session invalid' });
        const valid = await bcrypt.compare(data.password, user.password_hash);
        if (!valid) return res.json({ success: false, error: 'Session invalid' });
        const { data: sub }     = await supabase.from('subscribers').select('*').eq('phone', phone).single();
        const { data: balRow }  = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
        const { password_hash, ...safeUser } = user;
        return res.json({ success: true, user: safeUser, subscriber: sub || null, walletBalance: balRow?.balance || 0 });
      }

      case 'login': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'Session invalid' });
        const valid = await bcrypt.compare(data.password, user.password_hash);
        if (!valid) return res.json({ success: false, error: 'Session invalid' });
        const { data: sub }    = await supabase.from('subscribers').select('*').eq('phone', phone).single();
        const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
        const { password_hash, ...safeUser } = user;
        return res.json({ success: true, user: safeUser, subscriber: sub || null, walletBalance: balRow?.balance || 0 });
      }

      case 'signup': {
        const phone = cleanPhone(data.phone);
        const { data: existing } = await supabase.from('users').select('phone').eq('phone', phone).single();
        if (existing) return res.json({ success: false, error: 'Phone already registered' });
        const hash = await bcrypt.hash(data.password, SALT_ROUNDS);
        const createdAt = new Date().toISOString();
        await supabase.from('users').insert({
          user_id:       phone,
          name:          data.name,
          phone,
          email:         data.email || null,
          address:       data.address || null,
          password_hash: hash,
          created_at:    createdAt
        });
        return res.json({
          success: true,
          user: { user_id: phone, name: data.name, phone, email: data.email || null, address: data.address || null, created_at: createdAt },
          subscriber:    null,
          walletBalance: 0
        });
      }

      case 'adminLogin': {
        const { data: staff } = await supabase.from('staff').select('*').eq('username', data.username).single();
        if (!staff) return res.json({ success: false, error: 'Invalid credentials' });
        const valid = await bcrypt.compare(data.password, staff.password_hash);
        if (!valid) return res.json({ success: false, error: 'Invalid credentials' });
        const { password_hash, ...safeStaff } = staff;
        return res.json({ success: true, staff: safeStaff });
      }

      case 'staffLogin': {
        const { data: staff } = await supabase.from('staff').select('*').eq('username', data.username).single();
        if (!staff) return res.json({ success: false, error: 'Invalid credentials' });
        const valid = await bcrypt.compare(data.password, staff.password_hash);
        if (!valid) return res.json({ success: false, error: 'Invalid credentials' });
        const { password_hash, ...safeStaff } = staff;
        return res.json({ success: true, staff: safeStaff });
      }

      case 'updateProfile': {
        const phone = cleanPhone(data.phone);
        const updates = {};
        if (data.name    !== undefined) updates.name    = data.name;
        if (data.email   !== undefined) updates.email   = data.email;
        if (data.address !== undefined) updates.address = data.address;
        await supabase.from('users').update(updates).eq('phone', phone);
        return res.json({ success: true });
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
          sub_items:   data.sub_items || null,
          created_at:  new Date().toISOString()
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
        for (const entry of (data.order || [])) {
          await supabase.from('menu_items').update({ sort_order: entry.sort_order }).eq('item_id', entry.item_id);
        }
        return res.json({ success: true });
      }

      case 'updateMenuStock': {
        await supabase.from('menu_items').update({ stock_grams: data.stock_grams }).eq('item_id', data.item_id);
        return res.json({ success: true });
      }

      // ── THALIS ────────────────────────────────────────────────────────────

      case 'getThalis': {
        const { data: thalis } = await supabase.from('thalis').select('*').eq('is_active', true);
        const result = [];
        for (const t of (thalis || [])) {
          const { data: items } = await supabase.from('thali_items').select('*').eq('thali_id', t.thali_id);
          result.push(formatThali(t, items || []));
        }
        return res.json({ success: true, thalis: result });
      }

      case 'adminGetThalis': {
        const { data: thalis } = await supabase.from('thalis').select('*');
        const result = [];
        for (const t of (thalis || [])) {
          const { data: items } = await supabase.from('thali_items').select('*').eq('thali_id', t.thali_id);
          result.push(formatThali(t, items || []));
        }
        return res.json({ success: true, thalis: result });
      }

      case 'addThali':
      case 'createThali': {
        const thali_id = generateThaliId(ist);
        await supabase.from('thalis').insert({
          thali_id,
          name:        data.name,
          description: data.description || null,
          image_url:   data.image_url || null,
          price:       data.price,
          stock_qty:   data.stock_qty ?? null,
          is_active:   true,
          created_at:  new Date().toISOString()
        });
        return res.json({ success: true, thali_id });
      }

      case 'updateThali': {
        const tid = data.thali_id || data.id; // normalize: frontend may send data.id
        const updates = { ...data };
        delete updates.thali_id;
        delete updates.id;
        await supabase.from('thalis').update(updates).eq('thali_id', tid);
        return res.json({ success: true });
      }

      case 'deleteThali': {
        const tid = data.thali_id || data.id;
        await supabase.from('thali_items').delete().eq('thali_id', tid);
        await supabase.from('thalis').delete().eq('thali_id', tid);
        return res.json({ success: true });
      }

      case 'addThaliItem': {
        await supabase.from('thali_items').insert({
          thali_id:       data.thali_id,
          menu_item_id:   data.menu_item_id,
          variant_label:  data.variant_label || null,
          menu_item_name: data.menu_item_name || null,
          created_at:     new Date().toISOString()
        });
        return res.json({ success: true });
      }

      case 'removeThaliItem': {
        await supabase.from('thali_items').delete().eq('id', data.id);
        return res.json({ success: true });
      }

      // ── ORDERS ────────────────────────────────────────────────────────────

      case 'createOrder': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        const address = data.address || user.address;
        if (!address) return res.json({ success: false, error: 'Delivery address required' });
        const { data: khataRow } = await supabase.from('admin_settings').select('value').eq('key', 'khata_enabled').single();
        const khataEnabled = JSON.parse(khataRow?.value || 'false');
        const { data: subRow } = await supabase.from('subscribers').select('*').eq('phone', phone).single();
        user.is_subscriber = !!subRow;
        user.address = address;
        if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
          return res.json({ success: false, error: 'Order items required' });
        }
        if (user.is_subscriber && khataEnabled) {
          const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', phone).single();
          const currentBal = balRow?.balance || 0;
          const subtotal   = data.items.reduce((s, i) => s + i.price * i.qty, 0);
          const dc         = data.deliveryCharge || 0;
          let disc = 0;
          if (data.coupon) {
            if (data.coupon.discount_type === 'percent' || data.coupon.discount_type === 'percent_cap') {
              disc = Math.round(subtotal * data.coupon.discount_value / 100);
              const cap = data.coupon.cap_amount ?? data.coupon.max_cap ?? null;
              if (cap != null && disc > cap) disc = cap;
            } else {
              disc = data.coupon.discount_value;
            }
          }
          const finalEst = subtotal + dc - disc;
          if (currentBal < finalEst) return res.json({ success: false, error: 'Insufficient wallet balance' });
        }
        const result = await _createSingleOrder({
          user, items: data.items, deliveryCharge: data.deliveryCharge || 0,
          khataEnabled, ist, coupon: data.coupon || null, source: 'customer'
        });
        return res.json({ success: true, orderId: result.orderId, finalAmount: result.finalAmount, walletBalance: result.walletBalance });
      }

      case 'getUserOrders': {
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('user_id', cleanPhone(data.phone))
          .order('created_at', { ascending: false });
        return res.json({ success: true, orders: (rows || []).map(formatOrder) });
      }

      case 'adminGetOrders': {
        let query = supabase.from('orders').select('*');
        if (data.date) query = query.eq('date', data.date);
        query = query.order('created_at', { ascending: false });
        const { data: rows } = await query;
        return res.json({ success: true, orders: (rows || []).map(formatOrder) });
      }

      case 'getOrdersByDate': {
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('date', data.date)
          .order('created_at', { ascending: false });
        return res.json({ success: true, orders: (rows || []).map(formatOrder) });
      }

      case 'updateOrderStatus': {
        const VALID_ORDER_STATUSES = ['pending', 'confirmed', 'preparing', 'out_for_delivery', 'delivered', 'rejected', 'cancelled'];
        if (!data.status || !VALID_ORDER_STATUSES.includes(data.status)) {
          return res.json({ success: false, error: 'Invalid order status' });
        }
        const updates = { order_status: data.status };
        if (data.riderId) updates.rider_id = data.riderId;
        await supabase.from('orders').update(updates).eq('order_id', data.orderId);
        if (data.status === 'delivered') {
          await supabase.from('khata_entries').update({ order_status: 'delivered' }).eq('order_id', data.orderId);
        }
        return res.json({ success: true });
      }

      case 'rejectOrder': {
        const { data: order } = await supabase.from('orders').select('*').eq('order_id', data.orderId).single();
        await supabase.from('orders').update({ order_status: 'rejected' }).eq('order_id', data.orderId);
        if (order && order.user_type === 'subscriber') {
          const newBal = await _atomicWalletUpdate(order.phone, +order.final_amount);
          await supabase.from('khata_entries').insert({
            id:              generateTxnId(ist),
            phone:           order.phone,
            type:            'adjustment',
            amount:          +order.final_amount,
            running_balance: newBal,
            note:            'Refund: Order rejected',
            date:            istDateStr(ist),
            time:            istTimeStr(ist),
            order_id:        data.orderId,
            order_status:    'rejected',
            order_source:    'admin',
            created_at:      new Date().toISOString()
          });
          await _createNotification({
            type:     'order',
            priority: 'high',
            group_id: data.orderId,
            title:    'Order Rejected',
            body:     'Order ' + data.orderId + ' rejected. ₹' + order.final_amount + ' refunded.',
            meta:     { orderId: data.orderId, phone: order.phone }
          });
        }
        return res.json({ success: true });
      }

      case 'bulkOrdersWithBalance': {
        const today = istDateStr(ist);
        const { data: subs } = await supabase.from('subscribers').select('*').gte('plan_end', today);
        const success = [], skipped = [];
        for (const sub of (subs || [])) {
          const { data: user } = await supabase.from('users').select('*').eq('phone', sub.phone).single();
          if (!user) continue;
          const { data: balRow } = await supabase.from('khata_summary').select('balance').eq('phone', sub.phone).single();
          const balance = balRow?.balance || 0;
          if (balance >= (data.orderAmount || 0)) {
            const result = await _createSingleOrder({
              user: { ...user, is_subscriber: true },
              items: data.items, deliveryCharge: data.deliveryCharge || 0,
              khataEnabled: true, ist, coupon: null, source: 'admin', slot: data.slot || 'morning'
            });
          }
        }
        return res.json({ success: true, created: success.length, skipped: skipped.length, details: { success, skipped } });
      }

      case 'adminBulkCreate': {
        if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
          return res.json({ success: false, error: 'Order items required' });
        }
        const today = istDateStr(ist);
        const { data: subs } = await supabase.from('subscribers').select('*').gte('plan_end', today);
        const success = [], skipped = [];
        for (const sub of (subs || [])) {
          const { data: user } = await supabase.from('users').select('*').eq('phone', sub.phone).single();
          if (!user) { skipped.push({ phone: sub.phone, reason: 'user not found' }); continue; }
          try {
            const result = await _createSingleOrder({
              user: { ...user, is_subscriber: true },
              items: data.items, deliveryCharge: data.deliveryCharge || 0,
              khataEnabled: true, ist, coupon: null, source: 'admin', slot: data.slot || 'morning'
            });
          }
        }
        return res.json({ success: true, created: success.length, skipped: skipped.length, details: { success, skipped } });
      }

      case 'forceUdharOrder': {
        const phone = cleanPhone(data.phone);
        const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        user.is_subscriber = true;
        const result = await _createSingleOrder({
          user, items: data.items, deliveryCharge: data.deliveryCharge || 0,
          khataEnabled: true, ist, source: 'admin', slot: data.slot || 'morning'
        });
        return res.json({ success: true, orderId: result.orderId, walletBalance: result.walletBalance });
      }

      case 'assignRider': {
        await supabase.from('orders').update({ rider_id: data.riderId }).eq('order_id', data.orderId);
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

      // ── SUBSCRIBERS ──────────────────────────────────────────────────────

      case 'checkSubscriber': {
        const { data: row } = await supabase.from('subscribers').select('*').eq('phone', cleanPhone(data.phone)).single();
        return res.json({ success: true, isSubscriber: !!row, subscriber: row || null });
      }

      case 'getSubscriberPauseStatus': {
        const { data: row } = await supabase.from('subscribers').select('pause_delivery').eq('phone', cleanPhone(data.phone)).single();
        return res.json({ success: true, pauseMode: row?.pause_delivery || 'none' });
      }

      case 'pauseUserDelivery': {
        const allowed = ['none', 'lunch', 'dinner', 'both'];
        if (!allowed.includes(data.mode)) return res.json({ success: false, error: 'Invalid mode' });
        await supabase.from('subscribers').update({ pause_delivery: data.mode }).eq('phone', cleanPhone(data.phone));
        return res.json({ success: true, pauseMode: data.mode });
      }

      case 'adminGetSubscribers': {
        const { data: subs } = await supabase.from('subscribers').select('*');
        const enriched = [];
        for (const s of (subs || [])) {
          const { data: u }   = await supabase.from('users').select('name, address').eq('phone', s.phone).single();
          const { data: bal } = await supabase.from('khata_summary').select('balance').eq('phone', s.phone).single();
          enriched.push({ ...s, name: u?.name || null, address: u?.address || null, balance: bal?.balance || 0 });
        }
        return res.json({ success: true, subscribers: enriched });
      }

      case 'addSubscriber': {
        await supabase.from('subscribers').insert({
          phone:          cleanPhone(data.phone),
          plan_start:     data.plan_start,
          plan_end:       data.plan_end,
          notes:          data.notes || '',
          pause_delivery: 'none',
          created_at:     new Date().toISOString()
        });
        return res.json({ success: true });
      }

      case 'updateSubscriber': {
        await supabase.from('subscribers').update({
          plan_start: data.plan_start,
          plan_end:   data.plan_end,
          notes:      data.notes
        }).eq('phone', cleanPhone(data.phone));
        return res.json({ success: true });
      }

      case 'removeSubscriber': {
        await supabase.from('subscribers').delete().eq('phone', cleanPhone(data.phone));
        return res.json({ success: true });
      }

      case 'getUserByPhone': {
        const { data: user } = await supabase.from('users').select('*').eq('phone', cleanPhone(data.phone)).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        const { password_hash, ...safe } = user;
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
        if (data.addAsSubscriber) {
          await supabase.from('subscribers').insert({
            phone,
            plan_start:     data.plan_start || istDateStr(ist),
            plan_end:       data.plan_end   || istDateStr(ist),
            notes:          data.notes      || '',
            pause_delivery: 'none',
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
          plan_start:     data.plan_start,
          plan_end:       data.plan_end,
          notes:          '',
          pause_delivery: 'none',
          created_at:     new Date().toISOString()
        });
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
        return res.json({ success: true, rider: safe });
      }

      case 'getRiderOrders': {
        const twoDaysAgo = istDateStr(new Date(Date.now() + 5.5 * 3_600_000 - 2 * 86_400_000));
        const { data: rows } = await supabase
          .from('orders').select('*')
          .eq('rider_id', data.riderId)
          .gte('date', twoDaysAgo)
          .order('created_at', { ascending: false });
        return res.json({ success: true, orders: (rows || []).map(formatOrder) });
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
        return res.json({ success: true, balance: sumRow?.balance || 0, entries: entries || [] });
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
          order_source:    'admin',
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
          order_source:    'admin',
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
        const enriched = [];
        for (const k of (rows || [])) {
          const { data: u } = await supabase.from('users').select('name').eq('phone', k.phone).single();
          enriched.push({ ...k, name: u?.name || null });
        }
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
          order_source:    data.order_source || 'admin',
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
        return res.json({ success: true });
      }

      case 'getKhataEnabled': {
        const { data: row } = await supabase.from('admin_settings').select('value').eq('key', 'khata_enabled').single();
        return res.json({ success: true, enabled: JSON.parse(row?.value || 'false') === true });
      }

      case 'setKhataEnabled': {
        await supabase.from('admin_settings').upsert({ key: 'khata_enabled', value: JSON.stringify(!!data.enabled), updated_at: new Date().toISOString() }, { onConflict: 'key' });
        return res.json({ success: true });
      }

      // ── ANALYTICS ─────────────────────────────────────────────────────────

      case 'getAnalytics': {
        const today      = istDateStr(ist);
        const monthStart = today.slice(0, 7) + '-01';
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
        const [
          r1, r2, r3, r4, r5, r6, r7, r8
        ] = await Promise.all([
          supabase.from('orders').select('*', { count: 'exact', head: true }).eq('date', today),
          supabase.from('orders').select('final_amount').eq('date', today).neq('order_status', 'rejected'),
          supabase.from('orders').select('final_amount').gte('date', monthStart).neq('order_status', 'rejected'),
          supabase.from('orders').select('*', { count: 'exact', head: true }),
          supabase.from('users').select('*', { count: 'exact', head: true }),
          supabase.from('subscribers').select('*', { count: 'exact', head: true }),
          supabase.from('khata_summary').select('balance'),
          supabase.from('users').select('*', { count: 'exact', head: true }).gte('created_at', thirtyDaysAgo)
        ]);
        const todayRevenue = (r2.data || []).reduce((s, o) => s + (o.final_amount || 0), 0);
        const monthRevenue = (r3.data || []).reduce((s, o) => s + (o.final_amount || 0), 0);
        const totalWalletBalance = (r7.data || []).reduce((s, k) => s + (k.balance || 0), 0);
        return res.json({
          success: true,
          todayOrders:         r1.count || 0,
          todayRevenue,
          monthRevenue,
          totalOrders:         r4.count || 0,
          totalUsers:          r5.count || 0,
          subscriberCount:     r6.count || 0,
          totalWalletBalance,
          newUsers30d:         r8.count || 0
        });
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
        const list       = rows || [];
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

      case 'deleteNotificationsByRange': {
        const { count } = await supabase.from('notifications').delete({ count: 'exact' }).gte('created_at', data.from).lte('created_at', data.to);
        return res.json({ success: true, deleted: count || 0 });
      }

      case 'purgeOldNotifications': {
        const cutoff = new Date(Date.now() - 24 * 3_600_000).toISOString();
        await supabase.from('notifications').delete().lt('created_at', cutoff);
        return res.json({ success: true });
      }

      // ── NEW USER COUPON ───────────────────────────────────────────────────

      case 'getNuCouponPending': {
        // Users registered in last 7 days who haven't been sent a coupon yet
        const sevenDaysAgo = new Date(Date.now() - 7 * 86_400_000).toISOString();
        const { data: newUsers } = await supabase.from('users').select('phone, name, created_at').gte('created_at', sevenDaysAgo);
        const { data: sentRows } = await supabase.from('nu_coupon_sent').select('phone');
        const sentPhones = new Set((sentRows || []).map(r => r.phone));
        const pending = (newUsers || []).filter(u => !sentPhones.has(u.phone));
        return res.json({ success: true, records: pending });
      }

      case 'getNuCouponSent': {
        const { data: rows } = await supabase.from('nu_coupon_sent').select('*').order('sent_at', { ascending: false });
        return res.json({ success: true, records: rows || [] });
      }

      case 'markNuCouponSent': {
        await supabase.from('nu_coupon_sent').upsert({
          phone:       cleanPhone(data.phone),
          sent_at:     new Date().toISOString(),
          coupon_code: data.coupon_code
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
        const [r1, r2] = await Promise.all([
          supabase.from('orders').delete({ count: 'exact' }).lte('date', data.before_date),
          supabase.from('khata_entries').delete({ count: 'exact' }).lte('date', data.before_date)
        ]);
        return res.json({ success: true, ordersDeleted: r1.count || 0, txnsDeleted: r2.count || 0 });
      }

      case 'masterDelete': {
        if (data.confirm !== 'DELETE_ALL_TIFFO_DATA') {
          return res.json({ success: false, error: 'Confirmation string mismatch' });
        }
        await Promise.all([
          supabase.from('orders').delete().neq('order_id', ''),
          supabase.from('khata_entries').delete().neq('id', ''),
          supabase.from('notifications').delete().neq('id', ''),
          supabase.from('nu_coupon_sent').delete().neq('phone', '')
        ]);
        return res.json({ success: true, message: 'Master delete completed' });
      }

      // ── INDEX (CUSTOMER) ALIASES ──────────────────────────────────────────
      case 'updatePauseDelivery':
        { const allowed = ['none', 'lunch', 'dinner', 'both'];
          const mode = data.pauseMode || data.mode;
          if (!allowed.includes(mode)) return res.json({ success: false, error: 'Invalid mode' });
          await supabase.from('subscribers').update({ pause_delivery: mode }).eq('phone', cleanPhone(data.phone));
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
          const safe = (rows || []).map(u => { const { password_hash, ...s } = u; return s; });
          return res.json({ success: true, users: safe }); }

      case 'getMenuItems':
        { const { data: items } = await supabase.from('menu_items').select('*').order('sort_order', { ascending: true });
          return res.json({ success: true, items: (items || []).map(formatMenuItem) }); }

      case 'getCoupons':
        { const { data: rows, error: cErr } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
          if (cErr) throw new Error('DB error: ' + cErr.message);
          return res.json({ success: true, coupons: rows || [] }); }

      case 'addCoupon':
        { if (!data.code) return res.json({ success: false, error: 'Coupon code required' });
          await supabase.from('coupons').insert({
            code:             (data.code || '').toUpperCase(),
            discount_type:     data.discount_type,
            discount_value:    data.discount_value,
            expiry_date:       data.expiry_date || null,
            is_active:         true,
            min_order:         data.min_order ?? null,
            min_order_amount:  data.min_order ?? null,
            max_usage:         data.max_usage ?? null,
            total_usage_limit: data.max_usage ?? null,
            per_user_limit:    data.per_user_limit ?? null,
            max_per_user:      data.per_user_limit ?? null,
            cap_amount:        data.cap_amount ?? null,
            max_cap:           data.cap_amount ?? null,
            restriction_type:  data.restriction_type || 'unlimited',
            allowed_phones:    JSON.stringify(data.allowed_phones || []),
            used_count:        0,
            usage_count:       0,
            used_by:           '[]',
            created_at:        new Date().toISOString()
          });
          return res.json({ success: true }); }

      case 'updateCoupon':
        { const updates = { ...data }; delete updates.id;
          await supabase.from('coupons').update(updates).eq('id', data.id);
          return res.json({ success: true }); }

      case 'getSubscribers':
        { const { data: subs } = await supabase.from('subscribers').select('*').order('plan_start', { ascending: false });
          const result = [];
          for (const s of (subs || [])) {
            const { data: u } = await supabase.from('users').select('name, address').eq('phone', s.phone).single();
            result.push({ ...s, name: u?.name || '', address: u?.address || '' });
          }
          return res.json({ success: true, subscribers: result }); }

      case 'getAllKhata':
        { const { data: rows } = await supabase.from('khata_summary').select('*');
          return res.json({ success: true, khata: rows || [] }); }

      case 'adminGetThalisAll':
        { const { data: thalis } = await supabase.from('thalis').select('*');
          const result = [];
          for (const t of (thalis || [])) {
            const { data: items } = await supabase.from('thali_items').select('*').eq('thali_id', t.thali_id);
            result.push(formatThali(t, items || []));
          }
          return res.json({ success: true, thalis: result }); }
        { const { data: items } = await supabase.from('thali_items').select('*').eq('thali_id', data.thaliId);
          return res.json({ success: true, items: items || [] }); }

      case 'getSettings':
        { const { data: rows } = await supabase.from('admin_settings').select('*');
          const map = {};
          for (const r of (rows || [])) { try { map[r.key] = JSON.parse(r.value); } catch { map[r.key] = r.value; } }
          return res.json({ success: true, settings: {
            cutoff:         map['order_cutoff_config'] || {},
            weeklySchedule: map['weekly_schedule']     || [],
            khataEnabled:   map['khata_enabled']       !== false
          }}); }

      case 'adminResetUserPassword':
        { const hash = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
          await supabase.from('users').update({ password_hash: hash }).eq('phone', cleanPhone(data.phone));
          return res.json({ success: true }); }

      case 'deleteNotificationRange':
        { await supabase.from('notifications').delete()
            .gte('created_at', data.from).lte('created_at', data.to);
          return res.json({ success: true }); }

      case 'previewCleanup':
        { const type = (data.type || '').toLowerCase();
          if (type === 'orders') {
            const { count } = await supabase.from('orders').select('*', { count: 'exact', head: true }).lte('date', data.before);
            return res.json({ success: true, count: count || 0 });
          } else if (type === 'transactions') {
            const { count } = await supabase.from('khata_entries').select('*', { count: 'exact', head: true }).lte('date', data.before);
            return res.json({ success: true, count: count || 0 });
          } else if (type === 'notifications') {
            const { count } = await supabase.from('notifications').select('*', { count: 'exact', head: true }).lte('created_at', data.before);
            return res.json({ success: true, count: count || 0 });
          }
          return res.json({ success: false, error: 'Unknown cleanup type' }); }

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
