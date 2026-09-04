const ADMIN_TOKEN = "SepehrSky.1394.sepehr";

const RATE_LIMIT = 120;
const RATE_WINDOW_MS = 60_000;

const suspiciousPatterns = [
"/.env",
"/.git/",
"/wp-admin",
"/wp-login",
"/phpmyadmin",
"/adminer",
"/config.php",
"/xmlrpc.php",
"/.well-known/security.txt"
];

const rateMap = new Map();

function json(data, status = 200) {
return new Response(JSON.stringify(data, null, 2), {
status,
headers: {
"content-type": "application/json; charset=UTF-8",
"cache-control": "no-store"
}
});
}

function getIP(request) {
return (
request.headers.get("CF-Connecting-IP") ||
request.headers.get("True-Client-IP") ||
"unknown"
);
}

function getCountry(request) {
return request.headers.get("CF-IPCountry") || "XX";
}

function isSuspicious(path) {
const p = path.toLowerCase();

return suspiciousPatterns.some(pattern =>
p.includes(pattern.toLowerCase())
);
}

function rateLimited(ip) {
const now = Date.now();
const item = rateMap.get(ip);

if (!item || now - item.start > RATE_WINDOW_MS) {
rateMap.set(ip, {
start: now,
count: 1
});

return false;

}

item.count++;

return item.count > RATE_LIMIT;
}

async function isBlocked(env, ip) {
if (!env.SECURITY_KV || ip === "unknown") {
return false;
}

const value = await env.SECURITY_KV.get(block:${ip});
return value === "1";
}

async function saveSecurityEvent(env, event) {
if (!env.SECURITY_KV) return;

const id = ${Date.now()}-${crypto.randomUUID()};

await env.SECURITY_KV.put(
event:${id},
JSON.stringify(event),
{
expirationTtl: 60 * 60 * 24 * 7
}
);
}

async function blockIP(env, ip) {
if (!env.SECURITY_KV) {
throw new Error("SECURITY_KV is not configured.");
}

await env.SECURITY_KV.put(block:${ip}, "1");
}

async function unblockIP(env, ip) {
if (!env.SECURITY_KV) {
throw new Error("SECURITY_KV is not configured.");
}

await env.SECURITY_KV.delete(block:${ip});
}

async function listBlockedIPs(env) {
if (!env.SECURITY_KV) return [];

const result = await env.SECURITY_KV.list({
prefix: "block:",
limit: 100
});

return result.keys.map(k =>
k.name.substring("block:".length)
);
}

async function getRecentEvents(env) {
if (!env.SECURITY_KV) return [];

const result = await env.SECURITY_KV.list({
prefix: "event:",
limit: 100
});

const events = [];

for (const key of result.keys) {
const value = await env.SECURITY_KV.get(key.name);

if (!value) continue;  

try {  
  events.push(JSON.parse(value));  
} catch {}

}

events.sort((a, b) => b.time - a.time);

return events.slice(0, 50);
}

function checkAdmin(request) {
const authorization = request.headers.get("Authorization") || "";

return authorization === Bearer ${ADMIN_TOKEN};
}

function securityDashboard() {
return new Response(`<!doctype html>

<html lang="fa" dir="rtl">  
<head>  
<meta charset="utf-8">  
<meta name="viewport" content="width=device-width,initial-scale=1">  
<title>SepehrSky Security</title>  <style>  
* {  
  box-sizing: border-box;  
}  
  
body {  
  margin: 0;  
  font-family: Arial, sans-serif;  
  background: #07111f;  
  color: white;  
}  
  
header {  
  padding: 24px;  
  background: #0c1b2e;  
  border-bottom: 1px solid #20344d;  
}  
  
h1 {  
  margin: 0;  
}  
  
main {  
  max-width: 1100px;  
  margin: auto;  
  padding: 20px;  
}  
  
.login,  
.panel {  
  background: #0c1b2e;  
  border: 1px solid #20344d;  
  border-radius: 18px;  
  padding: 20px;  
  margin-bottom: 20px;  
}  
  
input {  
  width: 100%;  
  padding: 13px;  
  margin: 8px 0;  
  border-radius: 10px;  
  border: 1px solid #304967;  
  background: #07111f;  
  color: white;  
}  
  
button {  
  border: 0;  
  border-radius: 10px;  
  padding: 12px 16px;  
  cursor: pointer;  
  margin: 5px;  
}  
  
.grid {  
  display: grid;  
  grid-template-columns: repeat(auto-fit,minmax(180px,1fr));  
  gap: 15px;  
}  
  
.card {  
  background: #101f33;  
  border-radius: 15px;  
  padding: 20px;  
}  
  
.number {  
  font-size: 30px;  
  font-weight: bold;  
  margin-top: 8px;  
}  
  
table {  
  width: 100%;  
  border-collapse: collapse;  
}  
  
th,  
td {  
  text-align: right;  
  padding: 10px;  
  border-bottom: 1px solid #20344d;  
}  
  
.small {  
  opacity: .7;  
  font-size: 13px;  
}  
  
.hidden {  
  display: none;  
}  
  
.danger {  
  background: #8b2635;  
  color: white;  
}  
  
#loginMsg {  
  color: #ff7184;  
}  
</style>  </head>  <body>  <header>  
  <h1>🛡️ SepehrSky Security</h1>  
  <div class="small">Private security dashboard</div>  
</header>  <main>  <section id="login" class="login">  
  <h2>🔐 ورود مدیر</h2>  <input
id="token"
type="password"
placeholder="Admin token"

> 

  <button onclick="login()">  
    ورود  
  </button>    <p id="loginMsg"></p>  
</section>  <section id="dashboard" class="hidden">    <div class="grid">  <div class="card">  
  👥 Requests  
  <div id="requests" class="number">—</div>  
</div>  

<div class="card">  
  🌍 Countries  
  <div id="countries" class="number">—</div>  
</div>  

<div class="card">  
  🚨 Suspicious  
  <div id="suspicious" class="number">—</div>  
</div>  

<div class="card">  
  🚫 Blocked  
  <div id="blocked" class="number">—</div>  
</div>

  </div>    <div class="panel">  <h2>🚫 مسدود کردن IP</h2>  

<input  
  id="blockIP"  
  placeholder="IP address"  
>  

<button class="danger" onclick="block()">  
  Block  
</button>  

<button onclick="loadData()">  
  🔄 Refresh  
</button>

  </div>    <div class="panel">  <h2>🚨 Recent Security Events</h2>  

<table>  

  <thead>  
    <tr>  
      <th>IP</th>  
      <th>Country</th>  
      <th>Path</th>  
      <th>Status</th>  
      <th>Time</th>  
    </tr>  
  </thead>  

  <tbody id="events"></tbody>  

</table>

  </div>  </section>  </main>  <script>  
let auth = "";  
  
async function login() {  
  
  const token =  
    document.getElementById("token").value.trim();  
  
  if (!token) return;  
  
  auth = token;  
  
  try {  
  
    const response = await fetch(  
      "/api/security/stats",  
      {  
        headers: {  
          Authorization: "Bearer " + auth  
        },  
        cache: "no-store"  
      }  
    );  
  
    if (!response.ok) {  
  
      document.getElementById("loginMsg").textContent =  
        "❌ توکن اشتباه است";  
  
      auth = "";  
  
      return;  
    }  
  
    document  
      .getElementById("login")  
      .classList.add("hidden");  
  
    document  
      .getElementById("dashboard")  
      .classList.remove("hidden");  
  
    loadData();  
  
  } catch (error) {  
  
    document.getElementById("loginMsg").textContent =  
      "❌ خطا در اتصال به سرور";  
  
    auth = "";  
  }  
}  
  
async function api(url, options = {}) {  
  
  options.headers = {  
    ...(options.headers || {}),  
    Authorization: "Bearer " + auth  
  };  
  
  options.cache = "no-store";  
  
  return fetch(url, options);  
}  
  
async function loadData() {  
  
  const response =  
    await api("/api/security/stats");  
  
  if (!response.ok) return;  
  
  const data =  
    await response.json();  
  
  document.getElementById("requests")  
    .textContent = data.requests;  
  
  document.getElementById("countries")  
    .textContent = data.countries;  
  
  document.getElementById("suspicious")  
    .textContent = data.suspicious;  
  
  document.getElementById("blocked")  
    .textContent = data.blocked;  
  
  const tbody =  
    document.getElementById("events");  
  
  tbody.innerHTML = "";  
  
  for (const event of data.events) {  
  
    const tr =  
      document.createElement("tr");  
  
    const values = [  
      event.ip,  
      event.country,  
      event.path,  
      event.status,  
      new Date(event.time).toLocaleString()  
    ];  
  
    for (const value of values) {  
      const td = document.createElement("td");  
      td.textContent = value ?? "";  
      tr.appendChild(td);  
    }  
  
    tbody.appendChild(tr);  
  }  
}  
  
async function block() {  
  
  const ip =  
    document.getElementById("blockIP")  
      .value.trim();  
  
  if (!ip) return;  
  
  const response =  
    await api("/api/security/block", {  
      method: "POST",  
      headers: {  
        "Content-Type": "application/json"  
      },  
      body: JSON.stringify({ ip })  
    });  
  
  if (response.ok) {  
  
    document.getElementById("blockIP")  
      .value = "";  
  
    loadData();  
  
    alert("IP blocked");  
  }  
}  
</script>  </body>  
</html>`, {  
    headers: {  
      "content-type": "text/html; charset=UTF-8",  
      "cache-control": "no-store"  
    }  
  });  
}  export default {

async fetch(request, env) {

const url = new URL(request.url);  
const ip = getIP(request);  
const country = getCountry(request);  

// =========================  
// SECURITY DASHBOARD  
// =========================  

if (url.pathname === "/security") {  
  return securityDashboard();  
}  

// =========================  
// ADMIN API  
// =========================  

if (url.pathname.startsWith("/api/security/")) {  

  if (!checkAdmin(request)) {  
    return json({  
      error: "Unauthorized"  
    }, 401);  
  }  

  if (url.pathname === "/api/security/stats") {  

    const events =  
      await getRecentEvents(env);  

    const blocked =  
      await listBlockedIPs(env);  

    const countries =  
      new Set(  
        events.map(e => e.country)  
      );  

    const suspicious =  
      events.filter(  
        e => e.suspicious  
      );  

    return json({  
      requests: events.length,  
      countries: countries.size,  
      suspicious: suspicious.length,  
      blocked: blocked.length,  
      events  
    });  
  }  

  if (  
    url.pathname === "/api/security/block" &&  
    request.method === "POST"  
  ) {  

    let body;  

    try {  
      body = await request.json();  
    } catch {  
      return json({  
        error: "Invalid JSON"  
      }, 400);  
    }  

    const targetIP = body.ip;  

    if (  
      typeof targetIP !== "string" ||  
      !/^[0-9a-fA-F:.]+$/.test(targetIP)  
    ) {  
      return json({  
        error: "Invalid IP"  
      }, 400);  
    }  

    await blockIP(env, targetIP);  

    return json({  
      success: true,  
      blocked: targetIP  
    });  
  }  

  if (  
    url.pathname === "/api/security/unblock" &&  
    request.method === "POST"  
  ) {  

    let body;  

    try {  
      body = await request.json();  
    } catch {  
      return json({  
        error: "Invalid JSON"  
      }, 400);  
    }  

    const targetIP = body.ip;  

    if (  
      typeof targetIP !== "string" ||  
      !/^[0-9a-fA-F:.]+$/.test(targetIP)  
    ) {  
      return json({  
        error: "Invalid IP"  
      }, 400);  
    }  

    await unblockIP(env, targetIP);  

    return json({  
      success: true  
    });  
  }  

  return json({  
    error: "Not found"  
  }, 404);  
}  

// =========================  
// BLOCKED IP  
// =========================  

if (await isBlocked(env, ip)) {  

  return new Response(  
    "Access denied.",  
    {  
      status: 403,  
      headers: {  
        "content-type": "text/plain; charset=UTF-8",  
        "cache-control": "no-store"  
      }  
    }  
  );  
}  

// =========================  
// RATE LIMIT  
// =========================  

if (rateLimited(ip)) {  

  await saveSecurityEvent(env, {  
    time: Date.now(),  
    ip,  
    country,  
    path: url.pathname,  
    method: request.method,  
    suspicious: true,  
    status: "RATE_LIMITED"  
  });  

  return new Response(  
    "Too many requests.",  
    {  
      status: 429,  
      headers: {  
        "retry-after": "60"  
      }  
    }  
  );  
}  

// =========================  
// SUSPICIOUS REQUEST  
// =========================  

const suspicious =  
  isSuspicious(url.pathname);  

if (suspicious) {  

  await saveSecurityEvent(env, {  
    time: Date.now(),  
    ip,  
    country,  
    path: url.pathname,  
    method: request.method,  
    suspicious: true,  
    status: "SUSPICIOUS"  
  });  

  return new Response(  
    "Request blocked.",  
    {  
      status: 403,  
      headers: {  
        "cache-control": "no-store"  
      }  
    }  
  );  
}  

// =========================  
// NORMAL REQUEST  
// =========================  

return env.ASSETS.fetch(request);

}
};
