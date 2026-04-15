import express from 'express';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// ── SUPABASE CLIENT ───────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY!
);
const SECURE_API_KEY = process.env.API_KEY;

// ── HELPERS ───────────────────────────────────────────────────
function getIST() { return new Date(Date.now() + 5.5 * 3600000); }

function generateId(prefix: string, ist?: Date) {
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

function cleanPhone(p: string) { return String(p || '').replace(/\D/g, ''); }

function istDateStr(d: Date) {
  return d.getUTCFullYear() + '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
    String(d.getUTCDate()).padStart(2, '0');
}

function istTimeStr(d: Date) {
  let h = d.getUTCHours(), m = d.getUTCMinutes();
  const p = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ' ' + p;
}

// ── AUTH ACTIONS ──────────────────────────────────────────────
async function loginUser(data: any) {
  if (!data.phone || !data.password) throw new Error('Phone and password required');
  const ph = cleanPhone(data.phone);
  const { data: user } = await supabase.from('users').select('*').eq('phone', ph).maybeSingle();
  if (!user) throw new Error('User not found');
  const match = await bcrypt.compare(String(data.password).trim(), user.password);
  if (!match) throw new Error('Incorrect password');

  // Fresh subscriber check
  const { data: sub } = await supabase.from('subscribers').select('is_active, tiffin_status').eq('phone', ph).maybeSingle();
  const isSubscriber = !!(sub && sub.is_active);
  
  return { 
    userId: user.user_id, 
    name: user.name, 
    phone: user.phone, 
    email: user.email || '', 
    address: user.address || '', 
    isSubscriber,
    tiffinStatus: sub?.tiffin_status || 'on'
  };
}

async function signupUser(data: any) {
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
  return { userId: user.user_id, name: user.name, phone: user.phone, email: user.email || '', address: user.address || '', isSubscriber: false };
}

async function resetUserPassword(data: any) {
  if (!data.phone || !data.newPassword) throw new Error('Phone and new password required');
  const ph = cleanPhone(data.phone);
  const hashed = await bcrypt.hash(String(data.newPassword).trim(), 10);
  const { error } = await supabase.from('users').update({ password: hashed }).eq('phone', ph);
  if (error) throw new Error(error.message);
  return { success: true };
}

// ── MENU ACTIONS ──────────────────────────────────────────────
async function getMenu() {
  const { data, error } = await supabase.from('menu').select('*').eq('availability', true).order('sort_order');
  if (error) throw new Error(error.message);
  return data;
}

async function adminGetMenu() {
  const { data, error } = await supabase.from('menu').select('*').order('sort_order');
  if (error) throw new Error(error.message);
  return data;
}

async function updateMenuStock(data: any) {
  const { itemId, stockGrams } = data;
  const { error } = await supabase.from('menu').update({ stock_grams: stockGrams }).eq('item_id', itemId);
  if (error) throw new Error(error.message);
  return { success: true };
}

// ── THALI ACTIONS ─────────────────────────────────────────────
async function createThali(data: any) {
  const ist = getIST();
  const thaliId = generateId('THALI', ist);
  const { error } = await supabase.from('thalis').insert({
    thali_id: thaliId,
    name: data.name,
    description: data.description,
    price: data.price,
    image_url: data.imageUrl,
    is_active: true,
    stock_qty: data.stockQty || null
  });
  if (error) throw new Error(error.message);
  return { thaliId };
}

async function getThalis() {
  const { data, error } = await supabase.from('thalis').select('*').eq('is_active', true);
  if (error) throw new Error(error.message);
  return data;
}

async function adminGetThalis() {
  const { data, error } = await supabase.from('thalis').select('*');
  if (error) throw new Error(error.message);
  return data;
}

// ── ORDER ACTIONS ─────────────────────────────────────────────
async function createOrder(data: any) {
  const ist = getIST();
  const orderId = generateId('ORD', ist);
  const items = data.items; // Array of { itemId, qty, variantLabel, isThali }

  // Stock Deduction Logic
  for (const item of items) {
    if (item.isThali) {
      // Deduct Thali stock
      const { data: thali } = await supabase.from('thalis').select('stock_qty').eq('thali_id', item.itemId).single();
      if (thali && thali.stock_qty !== null) {
        if (thali.stock_qty < item.qty) throw new Error(`Thali ${item.name} is out of stock`);
        await supabase.from('thalis').update({ stock_qty: thali.stock_qty - item.qty }).eq('thali_id', item.itemId);
      }
      // Also deduct components? Prompt says "deduct stock from each component variant"
      const { data: components } = await supabase.from('thali_items').select('*').eq('thali_id', item.itemId);
      if (components) {
        for (const comp of components) {
          const { data: menuI } = await supabase.from('menu').select('stock_grams').eq('item_id', comp.menu_item_id).single();
          if (menuI && menuI.stock_grams !== null) {
            const deduct = (comp.variant_grams || 0) * comp.quantity_in_thali * item.qty;
            if (menuI.stock_grams < deduct) throw new Error(`Component ${comp.menu_item_id} out of stock for Thali`);
            await supabase.from('menu').update({ stock_grams: menuI.stock_grams - deduct }).eq('item_id', comp.menu_item_id);
          }
        }
      }
    } else {
      // Deduct Menu item stock
      const { data: menuI } = await supabase.from('menu').select('stock_grams, variant').eq('item_id', item.itemId).single();
      if (menuI && menuI.stock_grams !== null) {
        let grams = 0;
        try {
          const variants = JSON.parse(menuI.variant || '[]');
          const v = variants.find((x: any) => x.label === item.variantLabel);
          grams = v ? (v.grams || 0) : 0;
        } catch {}
        const totalDeduct = grams * item.qty;
        if (menuI.stock_grams < totalDeduct) throw new Error(`${item.name} is out of stock`);
        await supabase.from('menu').update({ stock_grams: menuI.stock_grams - totalDeduct }).eq('item_id', item.itemId);
      }
    }
  }

  // Wallet Deduction for Subscribers
  if (data.userType === 'subscriber') {
    const { data: wallet } = await supabase.from('wallet').select('balance').eq('user_phone', data.phone).single();
    if (!wallet || wallet.balance < data.finalAmount) throw new Error('Insufficient wallet balance');
    const newBal = wallet.balance - data.finalAmount;
    await supabase.from('wallet').update({ balance: newBal }).eq('user_phone', data.phone);
    // Log transaction
    await supabase.from('khata_transactions').insert({
      user_id: data.phone, // Khata fix: user_id = phone
      user_phone: data.phone,
      amount: -data.finalAmount,
      type: 'debit',
      note: `Order ${orderId}`,
      created_at: ist.toISOString()
    });
  }

  const { error } = await supabase.from('orders').insert({
    order_id: orderId,
    user_id: data.userId,
    name: data.name,
    phone: data.phone,
    address: data.address,
    items: JSON.stringify(items),
    total_amount: data.totalAmount,
    delivery_charge: data.deliveryCharge,
    final_amount: data.finalAmount,
    coupon_code: data.couponCode,
    discount: data.discount,
    user_type: data.userType,
    order_status: 'pending',
    payment_status: 'pending',
    order_date: istDateStr(ist),
    order_time: istTimeStr(ist)
  });
  if (error) throw new Error(error.message);
  return { orderId };
}

async function updateOrderStatus(data: any) {
  const { orderId, status } = data;
  const { error } = await supabase.from('orders').update({ order_status: status }).eq('order_id', orderId);
  if (error) throw new Error(error.message);
  return { success: true };
}

// ── MAIN API ROUTE ────────────────────────────────────────────
app.post('/api', async (req, res) => {
  try {
    const { action, data = {}, apiKey } = req.body;
    if (apiKey !== SECURE_API_KEY) return res.json({ success: false, error: 'Unauthorized' });
    
    let result;
    switch (action) {
      case 'login': result = await loginUser(data); break;
      case 'signup': result = await signupUser(data); break;
      case 'resetUserPassword': result = await resetUserPassword(data); break;
      case 'getMenu': result = await getMenu(); break;
      case 'adminGetMenu': result = await adminGetMenu(); break;
      case 'updateMenuStock': result = await updateMenuStock(data); break;
      case 'createThali': result = await createThali(data); break;
      case 'getThalis': result = await getThalis(); break;
      case 'adminGetThalis': result = await adminGetThalis(); break;
      case 'createOrder': result = await createOrder(data); break;
      case 'updateOrderStatus': result = await updateOrderStatus(data); break;
      case 'getUsers': {
        const { data: users } = await supabase.from('users').select('*');
        const { data: wallets } = await supabase.from('wallet').select('*');
        const { data: subs } = await supabase.from('subscribers').select('phone, tiffin_status');
        result = users?.map(u => ({
          ...u,
          isSubscriber: u.is_subscriber,
          tiffinStatus: subs?.find(s => s.phone === u.phone)?.tiffin_status || 'on',
          balance: wallets?.find(w => w.user_phone === u.phone)?.balance || 0
        }));
        break;
      }
      case 'getAnalytics': {
        const { count: users } = await supabase.from('users').select('*', { count: 'exact', head: true });
        const today = istDateStr(getIST());
        const { count: orders } = await supabase.from('orders').select('*', { count: 'exact', head: true }).eq('order_date', today);
        result = { totalUsers: users || 0, todayOrders: orders || 0 };
        break;
      }
      case 'adminGetOrders': {
        const { data: ords } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
        result = ords?.map(o => ({ ...o, orderId: o.order_id, finalAmount: o.final_amount, orderStatus: o.order_status }));
        break;
      }
      case 'riderLogin': {
        const { data: rider } = await supabase.from('riders').select('*').eq('email', data.email).single();
        if (!rider || rider.password !== data.password) throw new Error('Invalid rider credentials');
        result = { riderId: rider.rider_id, name: rider.name };
        break;
      }
      case 'getRiderOrders': {
        const { data: ords } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
        result = ords?.map(o => ({ ...o, orderId: o.order_id, date: o.order_date, orderStatus: o.order_status }));
        break;
      }
      case 'getKhata': {
        const { data: entries } = await supabase.from('khata_transactions').select('*').eq('user_phone', data.phone).order('created_at', { ascending: false });
        const { data: wallet } = await supabase.from('wallet').select('balance').eq('user_phone', data.phone).single();
        result = { entries, balance: wallet?.balance || 0 };
        break;
      }
      case 'checkSubscriber': {
        const { data: sub } = await supabase.from('subscribers').select('*').eq('phone', data.phone).maybeSingle();
        result = { 
          isSubscriber: !!(sub && sub.is_active),
          tiffinStatus: sub?.tiffin_status || 'on'
        };
        break;
      }
      case 'updateTiffinStatus': {
        const { phone, status } = data;
        const { error } = await supabase.from('subscribers').update({ tiffin_status: status }).eq('phone', phone);
        if (error) throw new Error(error.message);
        result = { success: true };
        break;
      }
      case 'getSubscriberBalance': {
        const { data: wallet } = await supabase.from('wallet').select('balance').eq('user_phone', data.phone).single();
        result = { balance: wallet?.balance || 0 };
        break;
      }
      case 'createBulkOrders': {
        const ist = getIST();
        const today = istDateStr(ist);
        const hour = ist.getUTCHours();
        const mealType = hour < 15 ? 'morning' : 'evening'; // Simple cutoff logic
        
        // 1. Get all active subscribers
        const { data: subs } = await supabase.from('subscribers').select('*, users(*)').eq('is_active', true);
        if (!subs) throw new Error('No subscribers found');

        // 2. Get today's orders to avoid duplicates
        const { data: todayOrders } = await supabase.from('orders').select('phone').eq('order_date', today);
        const orderedPhones = new Set(todayOrders?.map(o => o.phone) || []);

        let createdCount = 0;
        for (const sub of subs) {
          const status = sub.tiffin_status || 'on';
          const phone = sub.phone;
          
          // Skip if already ordered
          if (orderedPhones.has(phone)) continue;

          // Skip based on tiffin status
          if (status === 'both_off') continue;
          if (mealType === 'morning' && status === 'morning_off') continue;
          if (mealType === 'evening' && status === 'evening_off') continue;

          // Create default order (e.g., Standard Thali)
          // For simplicity, we'll assume a default thali exists or just create a placeholder order
          // In a real app, you'd fetch the default thali ID
          const orderId = generateId('BULK', ist);
          const user = sub.users;
          
          const { error } = await supabase.from('orders').insert({
            order_id: orderId,
            user_id: user.user_id,
            name: user.name,
            phone: user.phone,
            address: user.address,
            items: JSON.stringify([{ name: 'Standard Tiffin (Bulk)', qty: 1, price: 60, isThali: true }]),
            total_amount: 60,
            delivery_charge: 0,
            final_amount: 60,
            user_type: 'subscriber',
            order_status: 'verified',
            payment_status: 'pending',
            order_date: today,
            order_time: istTimeStr(ist)
          });

          if (!error) {
            // Deduct from wallet
            const { data: wallet } = await supabase.from('wallet').select('balance').eq('user_phone', phone).single();
            if (wallet && wallet.balance >= 60) {
              await supabase.from('wallet').update({ balance: wallet.balance - 60 }).eq('user_phone', phone);
              await supabase.from('khata_transactions').insert({
                user_id: phone,
                user_phone: phone,
                amount: -60,
                type: 'debit',
                note: `Bulk Order ${orderId}`,
                created_at: ist.toISOString()
              });
            }
            createdCount++;
          }
        }
        result = { createdCount };
        break;
      }
      // Add more as needed...
      default: return res.json({ success: false, error: 'Unknown action: ' + action });
    }
    return res.json({ success: true, data: result });
  } catch (err: any) {
    return res.json({ success: false, error: err.message });
  }
});

// ── VITE MIDDLEWARE ───────────────────────────────────────────
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
