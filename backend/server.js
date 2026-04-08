const express = require(‘express’);
const { createClient } = require(’@supabase/supabase-js’);
const bcrypt = require(‘bcryptjs’);

const app = express();
app.use(express.json());
app.use(express.text({ type: ‘text/plain’ }));

// ── CORS ──────────────────────────────────────────────────────
app.use((req, res, next) => {
res.setHeader(‘Access-Control-Allow-Origin’, ‘*’);
res.setHeader(‘Access-Control-Allow-Methods’, ‘POST, GET, OPTIONS’);
res.setHeader(‘Access-Control-Allow-Headers’, ‘Content-Type’);
if (req.method === ‘OPTIONS’) return res.status(200).end();
next();
});

// ── SUPABASE CLIENT ───────────────────────────────────────────
const supabase = createClient(
process.env.SUPABASE_URL,
process.env.SUPABASE_ANON_KEY
);

const SECURE_API_KEY = process.env.API_KEY || ‘PB_SECURE_API_KEY_2026’;

// ── KEEP-ALIVE PING ───────────────────────────────────────────
app.get(’/ping’, (req, res) => {
res.status(200).json({ status: ‘alive’, time: new Date().toISOString() });
});

app.get(’/’, (req, res) => {
res.status(200).json({ app: ‘Puro Bite API’, status: ‘running’ });
});

// ── MAIN API ROUTE ────────────────────────────────────────────
app.post(’/api’, async (req, res) => {
if (typeof req.body === ‘string’) {
try { req.body = JSON.parse(req.body); } catch {}
}
try {
const { action, data = {}, apiKey } = req.body;
if (apiKey !== SECURE_API_KEY) return res.json({ success: false, error: ‘Unauthorized’ });

```
let result;
switch (action) {
  case 'login':                result = await loginUser(data); break;
  case 'signup':               result = await signupUser(data); break;
  case 'adminLogin':           result = await adminLogin(data); break;
  case 'staffLogin':           result = await staffLogin(data); break;
  case 'updateProfile':        result = await updateProfile(data); break;
  case 'getMenu':              result = await getMenu(data); break;
  case 'adminGetMenu':         result = await adminGetMenu(); break;
  case 'addMenuItem':          result = await addMenuItem(data); break;
  case 'updateMenuItem':       result = await updateMenuItem(data); break;
  case 'deleteMenuItem':       result = await deleteMenuItem(data); break;
  case 'updateMenuOrder':      result = await updateMenuOrder(data); break;
  case 'createOrder':          result = await createOrder(data); break;
  case 'getUserOrders':        result = await getUserOrders(data); break;
  case 'adminGetOrders':       result = await adminGetOrders(); break;
  case 'updateOrderStatus':    result = await updateOrderStatus(data); break;
  case 'rejectOrder':          result = await rejectOrder(data); break;
  case 'bulkOrdersWithBalance':result = await bulkOrdersWithBalance(data); break;
  case 'adminBulkCreate':      result = await adminBulkCreate(data); break;
  case 'applyCoupon':          result = await applyCoupon(data); break;
  case 'createCoupon':         result = await createCoupon(data); break;
  case 'adminGetCoupons':      result = await adminGetCoupons(); break;
  case 'deleteCoupon':         result = await deleteCoupon(data); break;
  case 'checkSubscriber':      result = await checkSubscriber(data); break;
  case 'adminGetSubscribers':  result = await adminGetSubscribers(); break;
  case 'addSubscriber':        result = await addSubscriber(data); break;
  case 'updateSubscriber':     result = await updateSubscriber(data); break;
  case 'removeSubscriber':     result = await removeSubscriber(data); break;
  case 'getUserByPhone':       result = await getUserByPhone(data); break;
  case 'promoteToSubscriber':  result = await promoteToSubscriber(data); break;
  case 'createRider':          result = await createRider(data); break;
  case 'updateRider':          result = await updateRider(data); break;
  case 'deleteRider':          result = await deleteRider(data); break;
  case 'riderLogin':           result = await riderLogin(data); break;
  case 'getRiderOrders':       result = await getRiderOrders(data); break;
  case 'getRiders':            result = await getRiders(); break;
  case 'assignRider':          result = await assignRider(data); break;
  case 'createStaff':          result = await createStaff(data); break;
  case 'updateStaff':          result = await updateStaff(data); break;
  case 'deleteStaff':          result = await deleteStaff(data); break;
  case 'getStaff':             result = await getStaff(); break;
  case 'getKhata':             result = await getKhata(data); break;
  case 'getSubscriberBalance': result = await getSubscriberBalance(data); break;
  case 'rechargeWallet':       result = await rechargeWallet(data); break;
  case 'adminGetAllKhata':     result = await adminGetAllKhata(); break;
  case 'addKhataEntry':        result = await addKhataEntry(data); break;
  case 'getOrderCutoff':       result = await getOrderCutoff(); break;
  case 'setOrderCutoff':       result = await setOrderCutoff(data); break;
  case 'getWeeklySchedule':    result = await getWeeklySchedule(); break;
  case 'setWeeklySchedule':    result = await setWeeklySchedule(data); break;
  case 'getKhataEnabled':      result = await getKhataEnabled(); break;
  case 'setKhataEnabled':      result = await setKhataEnabled(data); break;
  case 'getAnalytics':         result = await getAnalytics(); break;
  case 'getUsers':             result = await getUsers(); break;
  case 'resetAdminPassword':   result = await resetAdminPassword(data); break;
  case 'forceUdharOrder':      result = await forceUdharOrder(data); break;
  case 'deleteOldData':        result = await deleteOldData(data); break;
  default: return res.json({ success: false, error: 'Unknown action: ' + action });
}
return res.json({ success: true, data: result });
```

} catch (err) {
console.error(‘API Error:’, err);
return res.json({ success: false, error: err.message });
}
});

// ── START SERVER ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(’Puro Bite API running on port ’ + PORT));

// ── SELF PING — Render ko jagte rakhta hai ────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || ‘http://localhost:’ + PORT;
setInterval(function() {
fetch(SELF_URL + ‘/ping’)
.then(function() { console.log(’[KeepAlive] Pinged at ’ + new Date().toISOString()); })
.catch(function(e) { console.error(’[KeepAlive] Ping failed:’, e.message); });
}, 10 * 60 * 1000);

//──────────────────────────────────────────────────────────────
// HELPERS
//──────────────────────────────────────────────────────────────
function getIST() { return new Date(Date.now() + 5.5 * 3600000); }
function istDateStr(d) {
return String(d.getUTCDate()).padStart(2,‘0’) + ‘/’ +
String(d.getUTCMonth()+1).padStart(2,‘0’) + ‘/’ + d.getUTCFullYear();
}
function istTimeStr(d) {
let h = d.getUTCHours(), m = d.getUTCMinutes();
const p = h >= 12 ? ‘PM’ : ‘AM’; h = h % 12 || 12;
return String(h).padStart(2,‘0’) + ‘:’ + String(m).padStart(2,‘0’) + ’ ’ + p;
}
function cleanPhone(p) { return String(p || ‘’).replace(/\D/g, ‘’); }

function normOrderDate(v) {
if (!v) return ‘’;
const s = String(v).trim();
if (/^\d{2}/\d{2}/\d{4}$/.test(s)) return s;
if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
const [yyyy,mm,dd] = s.split(’-’); return dd+’/’+mm+’/’+yyyy;
}
if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
const ist = new Date(new Date(s).getTime() + 5.5*3600000);
if (!isNaN(ist.getTime())) return String(ist.getUTCDate()).padStart(2,‘0’)+’/’+String(ist.getUTCMonth()+1).padStart(2,‘0’)+’/’+ist.getUTCFullYear();
}
return s;
}
function normOrderTime(v) {
if (!v) return ‘’;
const s = String(v).trim();
if (/^\d{1,2}:\d{2}\s*(AM|PM)$/i.test(s)) return s;
const m = s.match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
if (m) {
let h=parseInt(m[1]),mn=parseInt(m[2]); const p=h>=12?‘PM’:‘AM’; h=h%12||12;
return String(h).padStart(2,‘0’)+’:’+String(mn).padStart(2,‘0’)+’ ‘+p;
}
if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
const ist=new Date(new Date(s).getTime()+5.5*3600000);
if (!isNaN(ist.getTime())) { let h=ist.getUTCHours(),mn=ist.getUTCMinutes(); const p=h>=12?‘PM’:‘AM’; h=h%12||12; return String(h).padStart(2,‘0’)+’:’+String(mn).padStart(2,‘0’)+’ ‘+p; }
}
return s;
}
function formatOrder(o) {
return {
orderId: o.order_id, userId: o.user_id,
name: o.name, phone: o.phone, address: o.address,
items: typeof o.items===‘string’ ? o.items : JSON.stringify(o.items),
totalAmount: o.total_amount, deliveryCharge: o.delivery_charge,
finalAmount: Number(o.final_amount)||0,
couponCode: o.coupon_code||’’, discount: o.discount||0,
userType: o.user_type||‘daily’, paymentStatus: o.payment_status||‘pending’,
orderStatus: o.order_status||‘pending’,
date: normOrderDate(o.order_date), time: normOrderTime(o.order_time),
riderId: o.rider_id||’’
};
}
function formatMenuItem(i) {
let variants=[];
try { variants=i.variant?JSON.parse(i.variant):[]; } catch { variants=[]; }
return {
itemId: i.item_id, name: i.name, category: i.category||’’,
price: Number(i.price)||0, variants, imageUrl: i.image_url||’’,
menuType: i.menu_type||‘morning’, availability: i.availability,
sortOrder: i.sort_order||9999, highlight: i.highlight||’’
};
}
function getDefaultDay(d, name) {
const days=[‘Sun’,‘Mon’,‘Tue’,‘Wed’,‘Thu’,‘Fri’,‘Sat’];
return { day: name||days[d], open:true, openTime:‘07:00’, lunchStart:‘07:00’, lunchEnd:‘11:30’, dinnerStart:‘11:30’, dinnerEnd:‘19:30’ };
}

//──────────────────────────────────────────────────────────────
// AUTH
//──────────────────────────────────────────────────────────────
async function signupUser(data) {
if (!data.phone||!data.password||!data.name) throw new Error(‘Name, phone, password required’);
const ph=cleanPhone(data.phone);
const {data:existing}=await supabase.from(‘users’).select(‘phone’).eq(‘phone’,ph).maybeSingle();
if (existing) throw new Error(‘Phone already registered’);
const hashed=await bcrypt.hash(String(data.password),10);
const {data:user,error}=await supabase.from(‘users’).insert({
name:data.name, phone:ph, email:data.email||’’, address:data.address||’’, password:hashed, role:‘customer’
}).select().single();
if (error) throw new Error(error.message);
return { userId:user.user_id, name:user.name, phone:user.phone, email:user.email||’’, address:user.address||’’ };
}

async function loginUser(data) {
if (!data.phone||!data.password) throw new Error(‘Phone and password required’);
const ph=cleanPhone(data.phone);
const {data:user}=await supabase.from(‘users’).select(’*’).eq(‘phone’,ph).maybeSingle();
if (!user) throw new Error(‘User not found’);
const match=await bcrypt.compare(String(data.password),user.password);
if (!match) throw new Error(‘Incorrect password’);
return { userId:user.user_id, name:user.name, phone:user.phone, email:user.email||’’, address:user.address||’’ };
}

async function adminLogin(data) {
if (!data.email||!data.password) throw new Error(‘Email and password required’);
const email=String(data.email).trim().toLowerCase();
const {data:setting}=await supabase.from(‘admin_settings’).select(’*’).eq(‘admin_id’,email).maybeSingle();
if (!setting) throw new Error(‘Admin not found’);
const match=await bcrypt.compare(String(data.password),setting.password_hash);
if (!match) throw new Error(‘Incorrect password’);
return { email, name:‘Admin’, role:‘admin’ };
}

async function resetAdminPassword(data) {
if (!data.newPassword||String(data.newPassword).length<6) throw new Error(‘Password must be 6+ characters’);
const hashed=await bcrypt.hash(String(data.newPassword),10);
const email=data.email||‘visaryhal2022@vishal.com’;
const {error}=await supabase.from(‘admin_settings’).update({password_hash:hashed}).eq(‘admin_id’,email);
if (error) throw new Error(error.message);
return { success:true, message:‘Password updated’ };
}

async function updateProfile(data) {
if (!data.userId) throw new Error(‘userId required’);
const updates={};
if (data.name!==undefined) updates.name=data.name;
if (data.email!==undefined) updates.email=data.email;
if (data.address!==undefined) updates.address=data.address;
if (data.newPassword) updates.password=await bcrypt.hash(String(data.newPassword),10);
const {error}=await supabase.from(‘users’).update(updates).eq(‘user_id’,data.userId);
if (error) throw new Error(error.message);
return true;
}

async function staffLogin(data) {
if (!data.username||!data.password) throw new Error(‘Username and password required’);
const {data:s}=await supabase.from(‘staff’).select(’*’).eq(‘username’,data.username).maybeSingle();
if (!s) throw new Error(‘Invalid credentials’);
const match=await bcrypt.compare(String(data.password),s.password);
if (!match) throw new Error(‘Invalid credentials’);
if (s.status!==‘active’) throw new Error(‘Account is inactive’);
return { username:s.username, name:s.name, role:‘staff’ };
}

//──────────────────────────────────────────────────────────────
// MENU
//──────────────────────────────────────────────────────────────
async function getMenu(data) {
const ist=getIST(); const h=ist.getUTCHours()+ist.getUTCMinutes()/60;
const menuType=h<11.5?‘morning’:‘evening’;
const {data:items,error}=await supabase.from(‘menu’).select(’*’).eq(‘availability’,true).eq(‘menu_type’,menuType).order(‘sort_order’,{ascending:true});
if (error) throw new Error(error.message);
return (items||[]).map(formatMenuItem);
}

async function adminGetMenu() {
const {data:items,error}=await supabase.from(‘menu’).select(’*’).order(‘sort_order’,{ascending:true});
if (error) throw new Error(error.message);
return (items||[]).map(formatMenuItem);
}

async function addMenuItem(data) {
if (!data.name) throw new Error(‘Item name required’);
const {data:items}=await supabase.from(‘menu’).select(‘sort_order’).order(‘sort_order’,{ascending:false}).limit(1);
const maxSort=items?.[0]?.sort_order||0;
const {data:item,error}=await supabase.from(‘menu’).insert({
name:data.name, category:data.category||’’, price:Number(data.price)||0,
variant:data.variants?JSON.stringify(data.variants):null,
image_url:data.imageUrl||’’, menu_type:data.menuType||‘morning’,
availability:true, highlight:data.highlight||’’, sort_order:data.sortOrder||(maxSort+1)
}).select().single();
if (error) throw new Error(error.message);
return { itemId:item.item_id };
}

async function updateMenuItem(data) {
if (!data.itemId) throw new Error(‘itemId required’);
const updates={};
if (data.name!==undefined) updates.name=data.name;
if (data.category!==undefined) updates.category=data.category;
if (data.price!==undefined) updates.price=Number(data.price);
if (data.variants!==undefined) updates.variant=JSON.stringify(data.variants);
if (data.imageUrl!==undefined) updates.image_url=data.imageUrl;
if (data.menuType!==undefined) updates.menu_type=data.menuType;
if (data.availability!==undefined) updates.availability=data.availability===‘TRUE’||data.availability===true;
if (data.highlight!==undefined) updates.highlight=data.highlight;
if (data.sortOrder!==undefined) updates.sort_order=Number(data.sortOrder);
const {error}=await supabase.from(‘menu’).update(updates).eq(‘item_id’,data.itemId);
if (error) throw new Error(error.message);
return true;
}

async function deleteMenuItem(data) {
if (!data.itemId) throw new Error(‘itemId required’);
const {error}=await supabase.from(‘menu’).delete().eq(‘item_id’,data.itemId);
if (error) throw new Error(error.message);
return true;
}

async function updateMenuOrder(data) {
if (!data.items||!Array.isArray(data.items)) throw new Error(‘items array required’);
for (const item of data.items) {
await supabase.from(‘menu’).update({sort_order:Number(item.sortOrder)}).eq(‘item_id’,item.itemId);
}
return true;
}

//──────────────────────────────────────────────────────────────
// ORDERS
//──────────────────────────────────────────────────────────────
async function createOrder(data) {
if (!data.userId) throw new Error(‘userId required’);
const items=Array.isArray(data.items)?data.items:JSON.parse(data.items||’[]’);
if (!items.length) throw new Error(‘Cart is empty’);
const ist=getIST();
const {data:order,error}=await supabase.from(‘orders’).insert({
user_id:data.userId, name:data.name, phone:cleanPhone(data.phone), address:data.address,
items, total_amount:Number(data.totalAmount)||0, delivery_charge:Number(data.deliveryCharge)||0,
final_amount:Number(data.finalAmount)||0, coupon_code:data.couponCode||’’, discount:Number(data.discount)||0,
user_type:data.userType||‘daily’, payment_status:‘pending’, order_status:‘pending’,
order_date:istDateStr(ist), order_time:istTimeStr(ist)
}).select().single();
if (error) throw new Error(error.message);
if (data.userType===‘subscriber’&&data.payFromWallet) {
await deductWalletBalance(cleanPhone(data.phone), Number(data.finalAmount)||0, ’Order ’+order.order_id, data.userId);
}
if (data.couponCode) await incrementCouponUsage(data.couponCode, cleanPhone(data.phone));
return { orderId:order.order_id };
}

async function getUserOrders(data) {
if (!data.userId) throw new Error(‘userId required’);
const {data:orders,error}=await supabase.from(‘orders’).select(’*’).eq(‘user_id’,data.userId).order(‘order_date’,{ascending:false});
if (error) throw new Error(error.message);
return (orders||[]).map(formatOrder);
}

async function adminGetOrders() {
const {data:orders,error}=await supabase.from(‘orders’).select(’*’).order(‘order_date’,{ascending:false});
if (error) throw new Error(error.message);
return (orders||[]).map(formatOrder);
}

async function updateOrderStatus(data) {
if (!data.orderId) throw new Error(‘orderId required’);
const updates={order_status:data.status};
if (data.paymentStatus) updates.payment_status=data.paymentStatus;
if (data.riderId) updates.rider_id=data.riderId;
const {error}=await supabase.from(‘orders’).update(updates).eq(‘order_id’,data.orderId);
if (error) throw new Error(error.message);
return true;
}

async function rejectOrder(data) {
if (!data.orderId) throw new Error(‘orderId required’);
const {error}=await supabase.from(‘orders’).update({order_status:‘rejected’}).eq(‘order_id’,data.orderId);
if (error) throw new Error(error.message);
return true;
}

async function forceUdharOrder(data) {
if (!data.userId) throw new Error(‘userId required’);
const items=Array.isArray(data.items)?data.items:JSON.parse(data.items||’[]’);
const ist=getIST();
const {data:order,error}=await supabase.from(‘orders’).insert({
user_id:data.userId, name:data.name, phone:cleanPhone(data.phone), address:data.address||’’,
items, total_amount:Number(data.totalAmount)||0, delivery_charge:0, final_amount:Number(data.finalAmount)||0,
coupon_code:’’, discount:0, user_type:‘subscriber’, payment_status:‘pending’, order_status:‘pending’,
order_date:istDateStr(ist), order_time:istTimeStr(ist)
}).select().single();
if (error) throw new Error(error.message);
return { orderId:order.order_id };
}

async function bulkOrdersWithBalance(data) {
if (!data.orders||!Array.isArray(data.orders)) throw new Error(‘orders array required’);
const success=[],failed=[];
for (const o of data.orders) {
const ph=cleanPhone(o.phone); const amount=Number(o.finalAmount)||0;
try {
const bal=await getWalletBalance(ph);
if (bal<amount) { failed.push({phone:ph,name:o.name,reason:‘Low balance Rs.’+bal}); continue; }
const ist=getIST();
const {data:order,error}=await supabase.from(‘orders’).insert({
user_id:o.userId||ph, name:o.name, phone:ph, address:o.address||’’,
items:o.items, total_amount:amount, delivery_charge:0, final_amount:amount,
coupon_code:’’, discount:0, user_type:‘subscriber’, payment_status:‘pending’, order_status:‘pending’,
order_date:istDateStr(ist), order_time:istTimeStr(ist)
}).select().single();
if (error) throw new Error(error.message);
await deductWalletBalance(ph,amount,’Order ’+order.order_id,o.userId);
success.push({phone:ph,name:o.name,orderId:order.order_id});
} catch(err) { failed.push({phone:ph,name:o.name,reason:err.message}); }
}
return { success, failed };
}

async function adminBulkCreate(data) {
if (!data.orders||!Array.isArray(data.orders)) throw new Error(‘orders array required’);
const success=[],failed=[];
for (const o of data.orders) {
try {
const ph=cleanPhone(o.phone); const amount=Number(o.finalAmount)||0;
if (o.deductWallet&&amount>0) {
const bal=await getWalletBalance(ph);
if (bal<amount) { failed.push({phone:ph,name:o.name,reason:‘Low balance Rs.’+bal}); continue; }
}
const ist=getIST();
const {data:order,error}=await supabase.from(‘orders’).insert({
user_id:o.userId||ph, name:o.name, phone:ph, address:o.address||’’,
items:Array.isArray(o.items)?o.items:JSON.parse(o.items||’[]’),
total_amount:amount, delivery_charge:0, final_amount:amount,
coupon_code:’’, discount:0, user_type:o.userType||‘daily’, payment_status:‘pending’, order_status:‘pending’,
order_date:istDateStr(ist), order_time:istTimeStr(ist)
}).select().single();
if (error) throw new Error(error.message);
if (o.deductWallet&&amount>0) await deductWalletBalance(ph,amount,’Bulk Order ’+order.order_id,o.userId);
success.push({phone:ph,name:o.name,orderId:order.order_id});
} catch(err) { failed.push({phone:o.phone,name:o.name,reason:err.message}); }
}
return { success, failed };
}

//──────────────────────────────────────────────────────────────
// COUPONS
//──────────────────────────────────────────────────────────────
async function applyCoupon(data) {
if (!data.code) throw new Error(‘Coupon code required’);
const {data:coupon}=await supabase.from(‘coupons’).select(’*’).eq(‘code’,data.code.toUpperCase()).maybeSingle();
if (!coupon) throw new Error(‘Invalid coupon code’);
if (!coupon.is_active) throw new Error(‘Coupon not active’);
if (coupon.expiry_date&&new Date(coupon.expiry_date)<new Date()) throw new Error(‘Coupon expired’);
if (coupon.user_phone&&cleanPhone(coupon.user_phone)!==cleanPhone(data.phone||’’)) throw new Error(‘Coupon not valid for your account’);
return { code:coupon.code, discountType:coupon.discount_type, discountValue:Number(coupon.discount_value)||0 };
}

async function incrementCouponUsage(code,phone) {
try {
const {data:coupon}=await supabase.from(‘coupons’).select(‘usage_count’).eq(‘code’,code).maybeSingle();
if (!coupon) return;
let usage={}; try { usage=JSON.parse(coupon.usage_count||’{}’); } catch { usage={}; }
usage[phone]=(usage[phone]||0)+1;
await supabase.from(‘coupons’).update({usage_count:JSON.stringify(usage)}).eq(‘code’,code);
} catch {}
}

async function createCoupon(data) {
if (!data.code||!data.discountType||!data.discountValue) throw new Error(‘code, discountType, discountValue required’);
const {error}=await supabase.from(‘coupons’).insert({
code:data.code.toUpperCase(), discount_type:data.discountType, discount_value:Number(data.discountValue),
expiry_date:data.expiryDate||null, user_phone:data.userPhone||null, is_active:true, usage_count:’{}’
});
if (error) throw new Error(error.message);
return true;
}

async function adminGetCoupons() {
const {data:coupons,error}=await supabase.from(‘coupons’).select(’*’);
if (error) throw new Error(error.message);
return (coupons||[]).map(c=>({
code:c.code, discountType:c.discount_type, discountValue:c.discount_value,
expiryDate:c.expiry_date, userPhone:c.user_phone, isActive:c.is_active,
perUserLimit:c.per_user_limit||0,
usageCount:(()=>{ try { return JSON.parse(c.usage_count||’{}’); } catch { return {}; } })()
}));
}

async function deleteCoupon(data) {
if (!data.code) throw new Error(‘code required’);
const {error}=await supabase.from(‘coupons’).delete().eq(‘code’,data.code.toUpperCase());
if (error) throw new Error(error.message);
return true;
}

//──────────────────────────────────────────────────────────────
// SUBSCRIBERS
//──────────────────────────────────────────────────────────────
async function checkSubscriber(data) {
if (!data.phone) return { isSubscriber:false };
const ph=cleanPhone(data.phone);
const {data:sub}=await supabase.from(‘subscribers’).select(‘is_active’).eq(‘phone’,ph).maybeSingle();
return { isSubscriber:!!(sub&&sub.is_active) };
}

async function adminGetSubscribers() {
const {data:subs,error}=await supabase.from(‘subscribers’).select(’*’);
if (error) throw new Error(error.message);
const {data:wallets}=await supabase.from(‘wallet’).select(’*’);
const balMap={};
(wallets||[]).forEach(w=>{ balMap[w.user_phone]=Number(w.balance)||0; });
return (subs||[]).map(s=>({
phone:s.phone, name:s.name||’’, address:s.address||’’,
startDate:s.start_date, plan:s.plan||s.plan_type||‘both’,
status:s.is_active?‘active’:‘paused’, balance:balMap[s.phone]||0
}));
}

async function addSubscriber(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone);
const {error}=await supabase.from(‘subscribers’).insert({
phone:ph, name:data.name||’’, address:data.address||’’,
plan:data.plan||‘both’, plan_type:data.plan||‘both’,
is_active:true, start_date:new Date().toISOString().split(‘T’)[0]
});
if (error) throw new Error(error.message);
if (data.initialRecharge&&Number(data.initialRecharge)>0) {
await rechargeWallet({phone:ph, amount:data.initialRecharge, note:‘Initial recharge’});
}
return true;
}

async function updateSubscriber(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone); const updates={};
if (data.name!==undefined) updates.name=data.name;
if (data.address!==undefined) updates.address=data.address;
if (data.plan!==undefined) { updates.plan=data.plan; updates.plan_type=data.plan; }
if (data.status!==undefined) updates.is_active=data.status===‘active’;
const {error}=await supabase.from(‘subscribers’).update(updates).eq(‘phone’,ph);
if (error) throw new Error(error.message);
return true;
}

async function removeSubscriber(data) {
if (!data.phone) throw new Error(‘phone required’);
const {error}=await supabase.from(‘subscribers’).delete().eq(‘phone’,cleanPhone(data.phone));
if (error) throw new Error(error.message);
return true;
}

async function getUserByPhone(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone);
const {data:user}=await supabase.from(‘users’).select(’*’).eq(‘phone’,ph).maybeSingle();
if (!user) throw new Error(‘No registered user found with this phone number’);
const {data:sub}=await supabase.from(‘subscribers’).select(‘is_active’).eq(‘phone’,ph).maybeSingle();
return { userId:user.user_id, name:user.name, phone:user.phone, email:user.email||’’, address:user.address||’’, alreadySubscriber:!!(sub&&sub.is_active) };
}

async function promoteToSubscriber(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone);
const {data:existing}=await supabase.from(‘subscribers’).select(‘phone’).eq(‘phone’,ph).maybeSingle();
if (existing) throw new Error(‘User is already a subscriber’);
const {error}=await supabase.from(‘subscribers’).insert({
phone:ph, name:data.name||’’, address:data.address||’’,
plan:data.plan||‘both’, plan_type:data.plan||‘both’,
is_active:true, start_date:new Date().toISOString().split(‘T’)[0]
});
if (error) throw new Error(error.message);
if (data.initialRecharge&&Number(data.initialRecharge)>0) {
await rechargeWallet({phone:ph, amount:data.initialRecharge, note:‘Promoted to subscriber’});
}
return { promoted:true, phone:ph };
}

//──────────────────────────────────────────────────────────────
// RIDERS
//──────────────────────────────────────────────────────────────
async function createRider(data) {
if (!data.name||!data.email||!data.password) throw new Error(‘name, email, password required’);
const hashed=await bcrypt.hash(String(data.password),10);
const {data:rider,error}=await supabase.from(‘riders’).insert({name:data.name,email:data.email,password:hashed}).select().single();
if (error) throw new Error(error.message);
return { riderId:rider.rider_id };
}

async function updateRider(data) {
if (!data.riderId) throw new Error(‘riderId required’);
const updates={};
if (data.name!==undefined) updates.name=data.name;
if (data.email!==undefined) updates.email=data.email;
if (data.password&&data.password.length>=6) updates.password=await bcrypt.hash(String(data.password),10);
const {error}=await supabase.from(‘riders’).update(updates).eq(‘rider_id’,data.riderId);
if (error) throw new Error(error.message);
return true;
}

async function deleteRider(data) {
if (!data.riderId) throw new Error(‘riderId required’);
const {error}=await supabase.from(‘riders’).delete().eq(‘rider_id’,data.riderId);
if (error) throw new Error(error.message);
return true;
}

async function riderLogin(data) {
if (!data.email||!data.password) throw new Error(‘Email and password required’);
const {data:rider}=await supabase.from(‘riders’).select(’*’).eq(‘email’,data.email).maybeSingle();
if (!rider) throw new Error(‘Invalid credentials’);
const match=await bcrypt.compare(String(data.password),rider.password);
if (!match) throw new Error(‘Invalid credentials’);
return { riderId:rider.rider_id, name:rider.name, email:rider.email };
}

async function getRiderOrders(data) {
if (!data.riderId) throw new Error(‘riderId required’);
const {data:orders,error}=await supabase.from(‘orders’).select(’*’)
.or(‘rider_id.eq.’+data.riderId+’,order_status.eq.preparing,order_status.eq.pending’);
if (error) throw new Error(error.message);
return (orders||[]).map(formatOrder);
}

async function getRiders() {
const {data:riders,error}=await supabase.from(‘riders’).select(‘rider_id, name, email’);
if (error) throw new Error(error.message);
return (riders||[]).map(r=>({riderId:r.rider_id, name:r.name, email:r.email}));
}

async function assignRider(data) {
if (!data.orderId||!data.riderId) throw new Error(‘orderId and riderId required’);
const {error}=await supabase.from(‘orders’).update({rider_id:data.riderId}).eq(‘order_id’,data.orderId);
if (error) throw new Error(error.message);
return true;
}

//──────────────────────────────────────────────────────────────
// STAFF
//──────────────────────────────────────────────────────────────
async function createStaff(data) {
if (!data.username||!data.name||!data.password) throw new Error(‘username, name, password required’);
if (data.password.length<6) throw new Error(‘Password must be 6+ chars’);
const hashed=await bcrypt.hash(String(data.password),10);
const {error}=await supabase.from(‘staff’).insert({username:data.username, name:data.name, password:hashed, status:data.status||‘active’, created_at:new Date().toISOString()});
if (error) throw new Error(error.message);
return true;
}

async function updateStaff(data) {
if (!data.username) throw new Error(‘username required’);
const updates={};
if (data.name!==undefined) updates.name=data.name;
if (data.status!==undefined) updates.status=data.status;
if (data.password&&data.password.length>=6) updates.password=await bcrypt.hash(String(data.password),10);
const {error}=await supabase.from(‘staff’).update(updates).eq(‘username’,data.username);
if (error) throw new Error(error.message);
return true;
}

async function deleteStaff(data) {
if (!data.username) throw new Error(‘username required’);
const {error}=await supabase.from(‘staff’).delete().eq(‘username’,data.username);
if (error) throw new Error(error.message);
return true;
}

async function getStaff() {
const {data:staff,error}=await supabase.from(‘staff’).select(‘username, name, status, created_at’);
if (error) throw new Error(error.message);
return (staff||[]).map(s=>({username:s.username, name:s.name, status:s.status, createdAt:s.created_at}));
}

//──────────────────────────────────────────────────────────────
// WALLET / KHATA
//──────────────────────────────────────────────────────────────
async function getWalletBalance(phone) {
const ph=cleanPhone(phone);
const {data:w}=await supabase.from(‘wallet’).select(‘balance’).eq(‘user_phone’,ph).maybeSingle();
return Number(w?.balance)||0;
}

async function deductWalletBalance(phone,amount,note,userId) {
const ph=cleanPhone(phone);
const currentBal=await getWalletBalance(ph);
const newBal=currentBal-amount;
await supabase.from(‘wallet’).upsert({user_phone:ph, balance:newBal, last_updated:new Date().toISOString()},{onConflict:‘user_phone’});
const ist=getIST();
await supabase.from(‘khata_transactions’).insert({user_id:userId||null, amount:-amount, type:‘debit’, description:note||‘Deduction’, created_at:ist.toISOString()});
return newBal;
}

async function getSubscriberBalance(data) {
if (!data.phone) throw new Error(‘phone required’);
return { balance:await getWalletBalance(data.phone) };
}

async function rechargeWallet(data) {
if (!data.phone||!data.amount) throw new Error(‘phone and amount required’);
const ph=cleanPhone(data.phone); const amt=Math.abs(Number(data.amount));
const currentBal=await getWalletBalance(ph); const newBal=currentBal+amt;
await supabase.from(‘wallet’).upsert({user_phone:ph, balance:newBal, last_updated:new Date().toISOString()},{onConflict:‘user_phone’});
const ist=getIST();
const {data:user}=await supabase.from(‘users’).select(‘user_id’).eq(‘phone’,ph).maybeSingle();
await supabase.from(‘khata_transactions’).insert({user_id:user?.user_id||null, amount:amt, type:‘credit’, description:data.note||‘Wallet recharge’, created_at:ist.toISOString()});
return { newBalance:newBal };
}

async function addKhataEntry(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone); const amount=Number(data.amount)||0;
const currentBal=await getWalletBalance(ph); const newBal=currentBal+amount;
await supabase.from(‘wallet’).upsert({user_phone:ph, balance:newBal, last_updated:new Date().toISOString()},{onConflict:‘user_phone’});
const {data:user}=await supabase.from(‘users’).select(‘user_id’).eq(‘phone’,ph).maybeSingle();
const ist=getIST();
await supabase.from(‘khata_transactions’).insert({user_id:user?.user_id||null, amount, type:amount>=0?‘credit’:‘debit’, description:data.note||’’, created_at:ist.toISOString()});
return { newBalance:newBal };
}

async function getKhata(data) {
if (!data.phone) throw new Error(‘phone required’);
const ph=cleanPhone(data.phone);
const {data:user}=await supabase.from(‘users’).select(‘user_id’).eq(‘phone’,ph).maybeSingle();
let txns=[];
if (user) {
const {data:t}=await supabase.from(‘khata_transactions’).select(’*’).eq(‘user_id’,user.user_id).order(‘created_at’,{ascending:true});
txns=t||[];
}
const bal=await getWalletBalance(ph);
let running=0;
const entries=txns.map(t=>{
running+=Number(t.amount)||0;
const ist=new Date(new Date(t.created_at).getTime()+5.5*3600000);
return { entryId:t.id, phone:ph, type:t.type===‘credit’?‘recharge’:‘tiffin_given’, amount:Number(t.amount), note:t.description||’’, orderId:’’, date:istDateStr(ist), time:istTimeStr(ist), createdBy:‘system’, runningBalance:running };
});
return { entries, balance:bal };
}

async function adminGetAllKhata() {
const {data:subs}=await supabase.from(‘subscribers’).select(‘phone, name’);
const {data:wallets}=await supabase.from(‘wallet’).select(’*’);
const balMap={};
(wallets||[]).forEach(w=>{ balMap[w.user_phone]=Number(w.balance)||0; });
return (subs||[]).map(s=>({ phone:s.phone, name:s.name||’’, balance:balMap[s.phone]||0, entryCount:0 }));
}

//──────────────────────────────────────────────────────────────
// SETTINGS
//──────────────────────────────────────────────────────────────
async function upsertSetting(key,value) {
await supabase.from(‘admin_settings’).upsert({admin_id:key, access_level:String(value)},{onConflict:‘admin_id’});
}

async function getOrderCutoff() {
const {data:rows}=await supabase.from(‘admin_settings’).select(’*’);
const map={};
(rows||[]).forEach(r=>{ map[r.admin_id]=r.access_level; });
const sched={};
for (let d=0;d<=6;d++) { try { sched[d]=JSON.parse(map[‘schedule_’+d]||‘null’)||getDefaultDay(d); } catch { sched[d]=getDefaultDay(d); } }
return { enabled:map[‘cutoff_enabled’]===‘true’, cutoffDay:map[‘cutoff_day’]||‘11:30’, cutoffNight:map[‘cutoff_night’]||‘19:30’, weeklySchedule:sched };
}

async function setOrderCutoff(data) {
await upsertSetting(‘cutoff_enabled’,data.enabled?‘true’:‘false’);
if (data.cutoffDay) await upsertSetting(‘cutoff_day’,data.cutoffDay);
if (data.cutoffNight) await upsertSetting(‘cutoff_night’,data.cutoffNight);
return true;
}

async function getWeeklySchedule() {
const {data:rows}=await supabase.from(‘admin_settings’).select(’*’);
const map={}; (rows||[]).forEach(r=>{ map[r.admin_id]=r.access_level; });
const result={}; const days=[‘Sun’,‘Mon’,‘Tue’,‘Wed’,‘Thu’,‘Fri’,‘Sat’];
for (let d=0;d<=6;d++) { try { result[d]=JSON.parse(map[‘schedule_’+d]||‘null’)||getDefaultDay(d,days[d]); } catch { result[d]=getDefaultDay(d,days[d]); } }
return result;
}

async function setWeeklySchedule(data) {
if (!data.schedule) throw new Error(‘schedule required’);
for (let d=0;d<=6;d++) { if (data.schedule[d]) await upsertSetting(‘schedule_’+d,JSON.stringify(data.schedule[d])); }
return true;
}

async function getKhataEnabled() {
const {data}=await supabase.from(‘admin_settings’).select(‘access_level’).eq(‘admin_id’,‘khata_enabled’).maybeSingle();
const v=data?.access_level;
return { enabled:v===null||v===undefined||v===‘true’||v===‘1’ };
}

async function setKhataEnabled(data) {
await upsertSetting(‘khata_enabled’,data.enabled?‘true’:‘false’);
return true;
}

//──────────────────────────────────────────────────────────────
// ANALYTICS
//──────────────────────────────────────────────────────────────
async function getAnalytics() {
const ist=getIST(); const today=istDateStr(ist);
const {data:orders}=await supabase.from(‘orders’).select(‘final_amount, order_date, order_status’);
const {data:users}=await supabase.from(‘users’).select(‘user_id’);
const {data:subs}=await supabase.from(‘subscribers’).select(‘phone’);
const {data:wallets}=await supabase.from(‘wallet’).select(‘balance’);
const todayOrders=(orders||[]).filter(o=>normOrderDate(o.order_date)===today);
const todayRevenue=todayOrders.reduce((s,o)=>s+(Number(o.final_amount)||0),0);
const thisMonth=ist.getUTCMonth(), thisYear=ist.getUTCFullYear();
const monthlyRevenue=(orders||[]).filter(o=>{
if (!o.order_date) return false;
const norm=normOrderDate(o.order_date); const parts=norm.split(’/’);
if (parts.length===3) return parseInt(parts[1])-1===thisMonth&&parseInt(parts[2])===thisYear;
return false;
}).reduce((s,o)=>s+(Number(o.final_amount)||0),0);
const totalWallet=(wallets||[]).reduce((s,w)=>s+(Number(w.balance)||0),0);
return { todayOrders:todayOrders.length, todayRevenue, monthlyRevenue, totalOrders:(orders||[]).length, totalUsers:(users||[]).length, totalSubscribers:(subs||[]).length, totalWalletBalance:totalWallet };
}

async function getUsers() {
const {data:users,error}=await supabase.from(‘users’).select(‘user_id, name, phone, email, address, created_at’);
if (error) throw new Error(error.message);
return (users||[]).map(u=>({userId:u.user_id, name:u.name, phone:u.phone, email:u.email||’’, address:u.address||’’, createdAt:u.created_at}));
}

//──────────────────────────────────────────────────────────────
// DELETE OLD DATA
//──────────────────────────────────────────────────────────────
async function deleteOldData(data) {
const months=Number(data.months)||3;
const cutoff=new Date(Date.now()+5.5*3600000);
cutoff.setUTCMonth(cutoff.getUTCMonth()-months);
let deletedOrders=0;
try {
const {data:allOrders}=await supabase.from(‘orders’).select(‘order_id, order_date’);
const oldOrderIds=(allOrders||[]).filter(o=>{ const norm=normOrderDate(o.order_date); if (!norm) return false; const [dd,mm,yyyy]=norm.split(’/’); return new Date(Number(yyyy),Number(mm)-1,Number(dd))<cutoff; }).map(o=>o.order_id);
if (oldOrderIds.length>0) { const {error}=await supabase.from(‘orders’).delete().in(‘order_id’,oldOrderIds); if (!error) deletedOrders=oldOrderIds.length; }
} catch(e) { console.error(‘Delete orders error:’,e.message); }
let deletedKhata=0;
try {
const {data:allTxns}=await supabase.from(‘khata_transactions’).select(‘id, created_at’);
const oldTxnIds=(allTxns||[]).filter(t=>t.created_at&&new Date(t.created_at)<cutoff).map(t=>t.id);
if (oldTxnIds.length>0) { const {error}=await supabase.from(‘khata_transactions’).delete().in(‘id’,oldTxnIds); if (!error) deletedKhata=oldTxnIds.length; }
} catch(e) { console.error(‘Delete khata error:’,e.message); }
const cutoffStr=String(cutoff.getUTCDate()).padStart(2,‘0’)+’/’+String(cutoff.getUTCMonth()+1).padStart(2,‘0’)+’/’+cutoff.getUTCFullYear();
return { deletedOrders, deletedKhata, cutoffDate:cutoffStr };
}
