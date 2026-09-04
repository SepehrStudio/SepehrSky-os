const ADMIN_TOKEN = "SepehrSky.1394.sepehr";

const RATE_LIMIT = 120;
const RATE_WINDOW_MS = 60_000;

const VISITOR_TTL = 60 * 60 * 24 * 7;
const ONLINE_WINDOW = 90_000;

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


// =========================
// Helpers
// =========================

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data, null, 2),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=UTF-8",
        "cache-control":
          "no-store"
      }
    }
  );
}


function getIP(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("True-Client-IP") ||
    "unknown"
  );
}


function getCountry(request) {
  return (
    request.headers.get("CF-IPCountry") ||
    request.cf?.country ||
    "XX"
  );
}


function isSuspicious(path) {
  const p = path.toLowerCase();

  return suspiciousPatterns.some(
    pattern =>
      p.includes(pattern.toLowerCase())
  );
}


function validIP(ip) {
  if (typeof ip !== "string") {
    return false;
  }

  const value = ip.trim();

  if (!value || value.length > 100) {
    return false;
  }

  return /^[0-9a-fA-F:.]+$/.test(value);
}


function rateLimited(ip) {
  const now = Date.now();
  const item = rateMap.get(ip);

  if (
    !item ||
    now - item.start > RATE_WINDOW_MS
  ) {
    rateMap.set(ip, {
      start: now,
      count: 1
    });

    return false;
  }

  item.count++;

  return item.count > RATE_LIMIT;
}


function checkAdmin(request) {
  const authorization =
    request.headers.get("Authorization") || "";

  return authorization ===
    `Bearer ${ADMIN_TOKEN}`;
}


// =========================
// Block System
// =========================

async function isBlocked(env, ip) {

  if (
    !env.SECURITY_KV ||
    ip === "unknown"
  ) {
    return false;
  }

  const value =
    await env.SECURITY_KV.get(
      `block:${ip}`
    );

  return value === "1";
}


async function blockIP(env, ip) {

  if (!env.SECURITY_KV) {
    throw new Error(
      "SECURITY_KV is not configured."
    );
  }

  await env.SECURITY_KV.put(
    `block:${ip}`,
    "1"
  );
}


async function unblockIP(env, ip) {

  if (!env.SECURITY_KV) {
    throw new Error(
      "SECURITY_KV is not configured."
    );
  }

  await env.SECURITY_KV.delete(
    `block:${ip}`
  );
}


async function listBlockedIPs(env) {

  if (!env.SECURITY_KV) {
    return [];
  }

  const result =
    await env.SECURITY_KV.list({
      prefix: "block:",
      limit: 100
    });

  return result.keys.map(
    key =>
      key.name.substring(6)
  );
}


// =========================
// Visitor System
// =========================

async function saveVisitor(
  env,
  visitor
) {

  if (
    !env.SECURITY_KV ||
    visitor.ip === "unknown"
  ) {
    return;
  }

  await env.SECURITY_KV.put(
    `visitor:${visitor.ip}`,
    JSON.stringify(visitor),
    {
      expirationTtl:
        VISITOR_TTL
    }
  );
}


async function getVisitors(env) {

  if (!env.SECURITY_KV) {
    return [];
  }

  const result =
    await env.SECURITY_KV.list({
      prefix: "visitor:",
      limit: 100
    });

  const visitors = [];

  for (
    const key of result.keys
  ) {

    const value =
      await env.SECURITY_KV.get(
        key.name
      );

    if (!value) {
      continue;
    }

    try {

      visitors.push(
        JSON.parse(value)
      );

    } catch {}

  }

  visitors.sort(
    (a, b) =>
      (b.time || 0) -
      (a.time || 0)
  );

  return visitors.slice(0, 100);
}


// =========================
// Security Events
// =========================

async function saveSecurityEvent(
  env,
  event
) {

  if (!env.SECURITY_KV) {
    return;
  }

  const id =
    `${Date.now()}-${crypto.randomUUID()}`;

  await env.SECURITY_KV.put(
    `event:${id}`,
    JSON.stringify(event),
    {
      expirationTtl:
        60 * 60 * 24 * 7
    }
  );
}


async function getRecentEvents(env) {

  if (!env.SECURITY_KV) {
    return [];
  }

  const result =
    await env.SECURITY_KV.list({
      prefix: "event:",
      limit: 100
    });

  const events = [];

  for (
    const key of result.keys
  ) {

    const value =
      await env.SECURITY_KV.get(
        key.name
      );

    if (!value) {
      continue;
    }

    try {

      events.push(
        JSON.parse(value)
      );

    } catch {}

  }

  events.sort(
    (a, b) =>
      (b.time || 0) -
      (a.time || 0)
  );

  return events.slice(0, 50);
}


// =========================
// Dashboard
// =========================

function securityDashboard() {

  return new Response(
`<!doctype html>

<html lang="fa" dir="rtl">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>SepehrSky Security</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family:
    Arial,
    sans-serif;

  background:
    #07111f;

  color:
    white;
}

header {
  padding:
    24px;

  background:
    #0c1b2e;

  border-bottom:
    1px solid #20344d;
}

h1 {
  margin: 0;
}

main {
  max-width:
    1200px;

  margin:
    auto;

  padding:
    20px;
}

.login,
.panel {
  background:
    #0c1b2e;

  border:
    1px solid #20344d;

  border-radius:
    18px;

  padding:
    20px;

  margin-bottom:
    20px;
}

input {
  width:
    100%;

  padding:
    13px;

  margin:
    8px 0;

  border-radius:
    10px;

  border:
    1px solid #304967;

  background:
    #07111f;

  color:
    white;

  outline:
    none;
}

button {
  border:
    0;

  border-radius:
    10px;

  padding:
    11px 16px;

  cursor:
    pointer;

  margin:
    4px;

  font-weight:
    bold;

  touch-action:
    manipulation;
}

button:disabled {
  opacity:
    .5;

  cursor:
    not-allowed;
}

.grid {
  display:
    grid;

  grid-template-columns:
    repeat(
      auto-fit,
      minmax(170px,1fr)
    );

  gap:
    15px;

  margin-bottom:
    20px;
}

.card {
  background:
    #101f33;

  border-radius:
    15px;

  padding:
    20px;
}

.number {
  font-size:
    30px;

  font-weight:
    bold;

  margin-top:
    8px;
}

.online {
  color:
    #55e69b;
}

.offline {
  color:
    #8996a8;
}

.table-wrap {
  width:
    100%;

  overflow-x:
    auto;
}

table {
  width:
    100%;

  border-collapse:
    collapse;

  min-width:
    850px;
}

th,
td {
  text-align:
    right;

  padding:
    11px;

  border-bottom:
    1px solid #20344d;
}

th {
  color:
    #8db7df;
}

.small {
  opacity:
    .7;

  font-size:
    13px;
}

.hidden {
  display:
    none !important;
}

.danger {
  background:
    #8b2635;

  color:
    white;
}

.success {
  background:
    #16794b;

  color:
    white;
}

.refresh {
  background:
    #24486b;

  color:
    white;
}

.status-normal {
  color:
    #55e69b;

  font-weight:
    bold;
}

.status-blocked {
  color:
    #ff7184;

  font-weight:
    bold;
}

.ip {
  direction:
    ltr;

  text-align:
    right;

  font-family:
    monospace;
}

#loginMsg {
  color:
    #ff7184;

  min-height:
    20px;
}

#toast {
  position:
    fixed;

  bottom:
    20px;

  left:
    20px;

  background:
    #10243b;

  border:
    1px solid #31506f;

  padding:
    14px 18px;

  border-radius:
    12px;

  display:
    none;

  z-index:
    9999;
}

</style>

</head>

<body>

<header>

<h1>🛡️ SepehrSky Security</h1>

<div class="small">
Private security dashboard
</div>

</header>

<main>

<section
  id="login"
  class="login"
>

<h2>🔐 ورود مدیر</h2>

<div id="loginForm">

<input
  id="token"
  type="password"
  placeholder="Admin token"
  autocomplete="off"
>

<button
  id="loginButton"
  type="button"
>
🔐 ورود
</button>

</div>

<p id="loginMsg"></p>

</section>


<section
  id="dashboard"
  class="hidden"
>

<div class="grid">

<div class="card">

👥 Visitors

<div
  id="visitors"
  class="number"
>
—
</div>

</div>


<div class="card">

🟢 Online

<div
  id="online"
  class="number online"
>
—
</div>

</div>


<div class="card">

🌍 Countries

<div
  id="countries"
  class="number"
>
—
</div>

</div>


<div class="card">

🚨 Suspicious

<div
  id="suspicious"
  class="number"
>
—
</div>

</div>


<div class="card">

🚫 Blocked

<div
  id="blocked"
  class="number"
>
—
</div>

</div>

</div>


<div class="panel">

<h2>🚫 مدیریت IP</h2>

<input
  id="blockIP"
  placeholder="IP address"
  dir="ltr"
  autocomplete="off"
>

<button
  id="manualBlockButton"
  class="danger"
  type="button"
>
🚫 Block IP
</button>

<button
  id="refreshButton"
  class="refresh"
  type="button"
>
🔄 Refresh
</button>

</div>


<div class="panel">

<h2>👥 بازدیدکنندگان</h2>

<div class="small">
🟢 Online یعنی در ۹۰ ثانیه اخیر heartbeat دریافت شده است.
</div>

<br>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>IP</th>
<th>Country</th>
<th>Status</th>
<th>Last Activity</th>
<th>Path</th>
<th>Action</th>

</tr>

</thead>

<tbody id="visitorTable"></tbody>

</table>

</div>

</div>


<div class="panel">

<h2>🛡️ IP Security List</h2>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>IP</th>
<th>Country</th>
<th>Status</th>
<th>Action</th>

</tr>

</thead>

<tbody id="ipTable"></tbody>

</table>

</div>

</div>


<div class="panel">

<h2>🚨 Recent Security Events</h2>

<div class="table-wrap">

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

</div>

</div>

</section>

</main>

<div id="toast"></div>


<script>

let auth = "";


function showToast(message) {

  const toast =
    document.getElementById(
      "toast"
    );

  toast.textContent =
    message;

  toast.style.display =
    "block";

  setTimeout(() => {

    toast.style.display =
      "none";

  }, 2500);

}


// =========================
// Login
// =========================

async function login() {

  const input =
    document.getElementById(
      "token"
    );

  const msg =
    document.getElementById(
      "loginMsg"
    );

  const button =
    document.getElementById(
      "loginButton"
    );

  const token =
    input.value.trim();


  if (!token) {

    msg.textContent =
      "⚠️ توکن را وارد کن";

    return;

  }


  button.disabled =
    true;

  button.textContent =
    "⏳ بررسی...";


  try {

    const response =
      await fetch(
        "/api/security/stats?t=" +
        Date.now(),
        {
          method:
            "GET",

          headers: {
            "Authorization":
              "Bearer " + token,

            "Cache-Control":
              "no-cache"
          },

          cache:
            "no-store"
        }
      );


    if (!response.ok) {

      msg.textContent =
        response.status === 401
          ? "❌ توکن اشتباه است"
          : "❌ خطای سرور: " +
            response.status;

      return;

    }


    await response.json();


    auth =
      token;


    document
      .getElementById(
        "login"
      )
      .classList
      .add("hidden");


    document
      .getElementById(
        "dashboard"
      )
      .classList
      .remove("hidden");


    await loadData();


  } catch (error) {

    console.error(error);

    msg.textContent =
      "❌ خطا در اتصال به Worker";

  } finally {

    button.disabled =
      false;

    button.textContent =
      "🔐 ورود";

  }

}


document
  .getElementById(
    "loginButton"
  )
  .addEventListener(
    "click",
    login
  );


// =========================
// API
// =========================

async function api(
  url,
  options = {}
) {

  options.headers = {
    ...(options.headers || {}),

    "Authorization":
      "Bearer " + auth
  };

  options.cache =
    "no-store";

  return fetch(
    url,
    options
  );

}


// =========================
// Load
// =========================

async function loadData() {

  try {

    const response =
      await api(
        "/api/security/stats?t=" +
        Date.now()
      );


    if (
      response.status === 401
    ) {

      auth = "";

      document
        .getElementById(
          "dashboard"
        )
        .classList
        .add("hidden");

      document
        .getElementById(
          "login"
        )
        .classList
        .remove("hidden");

      return;

    }


    if (!response.ok) {

      showToast(
        "❌ دریافت اطلاعات ناموفق بود"
      );

      return;

    }


    const data =
      await response.json();


    document
      .getElementById(
        "visitors"
      )
      .textContent =
        data.visitors ?? 0;


    document
      .getElementById(
        "online"
      )
      .textContent =
        data.online ?? 0;


    document
      .getElementById(
        "countries"
      )
      .textContent =
        data.countries ?? 0;


    document
      .getElementById(
        "suspicious"
      )
      .textContent =
        data.suspicious ?? 0;


    document
      .getElementById(
        "blocked"
      )
      .textContent =
        data.blocked ?? 0;


    const visitors =
      Array.isArray(
        data.visitorsList
      )
        ? data.visitorsList
        : [];


    const blockedIPs =
      Array.isArray(
        data.blockedIPs
      )
        ? data.blockedIPs
        : [];


    const blockedSet =
      new Set(
        blockedIPs
      );


    // =====================
    // Visitors
    // =====================

    const visitorTable =
      document.getElementById(
        "visitorTable"
      );

    visitorTable.innerHTML =
      "";


    if (!visitors.length) {

      const tr =
        document.createElement(
          "tr"
        );

      const td =
        document.createElement(
          "td"
        );

      td.colSpan = 6;

      td.textContent =
        "هنوز بازدیدی ثبت نشده است.";

      tr.appendChild(td);

      visitorTable.appendChild(tr);

    } else {

      for (
        const visitor
        of visitors
      ) {

        const tr =
          document.createElement(
            "tr"
          );


        const ipTD =
          document.createElement(
            "td"
          );

        ipTD.textContent =
          visitor.ip || "unknown";

        ipTD.className =
          "ip";


        const countryTD =
          document.createElement(
            "td"
          );

        countryTD.textContent =
          visitor.country || "XX";


        const statusTD =
          document.createElement(
            "td"
          );


        const online =
          Date.now() -
          (visitor.time || 0) <
          90_000;


        statusTD.textContent =
          online
            ? "🟢 Online"
            : "⚪ Offline";


        statusTD.className =
          online
            ? "status-normal"
            : "offline";


        const timeTD =
          document.createElement(
            "td"
          );

        timeTD.textContent =
          visitor.time
            ? new Date(
                visitor.time
              ).toLocaleString()
            : "—";


        const pathTD =
          document.createElement(
            "td"
          );

        pathTD.textContent =
          visitor.path || "/";


        const actionTD =
          document.createElement(
            "td"
          );


        const button =
          document.createElement(
            "button"
          );


        button.type =
          "button";


        if (
          blockedSet.has(
            visitor.ip
          )
        ) {

          button.className =
            "success";

          button.textContent =
            "🟢 Unblock";

          button.addEventListener(
            "click",
            () =>
              unblockIP(
                visitor.ip
              )
          );

        } else {

          button.className =
            "danger";

          button.textContent =
            "🚫 Block";

          button.addEventListener(
            "click",
            () =>
              blockIP(
                visitor.ip
              )
          );

        }


        actionTD.appendChild(
          button
        );


        tr.appendChild(
          ipTD
        );

        tr.appendChild(
          countryTD
        );

        tr.appendChild(
          statusTD
        );

        tr.appendChild(
          timeTD
        );

        tr.appendChild(
          pathTD
        );

        tr.appendChild(
          actionTD
        );


        visitorTable.appendChild(
          tr
        );

      }

    }


    // =====================
    // IP Security
    // =====================

    const ipMap =
      new Map();


    for (
      const visitor
      of visitors
    ) {

      if (
        visitor.ip &&
        !ipMap.has(
          visitor.ip
        )
      ) {

        ipMap.set(
          visitor.ip,
          visitor
        );

      }

    }


    for (
      const ip
      of blockedIPs
    ) {

      if (
        !ipMap.has(ip)
      ) {

        ipMap.set(
          ip,
          {
            ip,
            country:
              "—"
          }
        );

      }

    }


    const ipTable =
      document.getElementById(
        "ipTable"
      );

    ipTable.innerHTML =
      "";


    for (
      const [ip, visitor]
      of ipMap
    ) {

      const tr =
        document.createElement(
          "tr"
        );


      const ipTD =
        document.createElement(
          "td"
        );

      ipTD.textContent =
        ip;

      ipTD.className =
        "ip";


      const countryTD =
        document.createElement(
          "td"
        );

      countryTD.textContent =
        visitor.country ||
        "XX";


      const statusTD =
        document.createElement(
          "td"
        );


      const actionTD =
        document.createElement(
          "td"
        );


      const button =
        document.createElement(
          "button"
        );


      button.type =
        "button";


      if (
        blockedSet.has(ip)
      ) {

        statusTD.textContent =
          "🚫 Blocked";

        statusTD.className =
          "status-blocked";

        button.className =
          "success";

        button.textContent =
          "🟢 Unblock";

        button.addEventListener(
          "click",
          () =>
            unblockIP(ip)
        );

      } else {

        statusTD.textContent =
          "🟢 Normal";

        statusTD.className =
          "status-normal";

        button.className =
          "danger";

        button.textContent =
          "🚫 Block";

        button.addEventListener(
          "click",
          () =>
            blockIP(ip)
        );

      }


      actionTD.appendChild(
        button
      );


      tr.appendChild(
        ipTD
      );

      tr.appendChild(
        countryTD
      );

      tr.appendChild(
        statusTD
      );

      tr.appendChild(
        actionTD
      );


      ipTable.appendChild(
        tr
      );

    }


    // =====================
    // Events
    // =====================

    const events =
      Array.isArray(
        data.events
      )
        ? data.events
        : [];


    const eventsBody =
      document.getElementById(
        "events"
      );

    eventsBody.innerHTML =
      "";


    if (!events.length) {

      const tr =
        document.createElement(
          "tr"
        );

      const td =
        document.createElement(
          "td"
        );

      td.colSpan = 5;

      td.textContent =
        "هنوز رویداد امنیتی ثبت نشده است.";

      tr.appendChild(td);

      eventsBody.appendChild(
        tr
      );

    } else {

      for (
        const event
        of events
      ) {

        const tr =
          document.createElement(
            "tr"
          );


        const values = [

          event.ip,

          event.country,

          event.path,

          event.status,

          event.time
            ? new Date(
                event.time
              ).toLocaleString()
            : ""

        ];


        for (
          const value
          of values
        ) {

          const td =
            document.createElement(
              "td"
            );

          td.textContent =
            value ?? "";

          tr.appendChild(td);

        }


        eventsBody.appendChild(
          tr
        );

      }

    }


  } catch (error) {

    console.error(error);

    showToast(
      "❌ خطا در دریافت اطلاعات"
    );

  }

}


// =========================
// Block
// =========================

async function blockIP(ip) {

  if (!ip) {
    return;
  }


  if (
    !confirm(
      "آیا مطمئنی می‌خواهی این IP مسدود شود؟\n\n" +
      ip
    )
  ) {
    return;
  }


  try {

    const response =
      await api(
        "/api/security/block",
        {
          method:
            "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              ip
            })
        }
      );


    if (response.ok) {

      showToast(
        "🚫 IP مسدود شد"
      );

      await loadData();

    } else {

      showToast(
        "❌ Block ناموفق بود"
      );

    }

  } catch {

    showToast(
      "❌ خطا در Block"
    );

  }

}


// =========================
// Unblock
// =========================

async function unblockIP(ip) {

  if (!ip) {
    return;
  }


  if (
    !confirm(
      "آیا می‌خواهی این IP آزاد شود؟\n\n" +
      ip
    )
  ) {
    return;
  }


  try {

    const response =
      await api(
        "/api/security/unblock",
        {
          method:
            "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              ip
            })
        }
      );


    if (response.ok) {

      showToast(
        "🟢 IP آزاد شد"
      );

      await loadData();

    } else {

      showToast(
        "❌ Unblock ناموفق بود"
      );

    }

  } catch {

    showToast(
      "❌ خطا در Unblock"
    );

  }

}


// =========================
// Manual Block
// =========================

async function blockManual() {

  const input =
    document.getElementById(
      "blockIP"
    );

  const ip =
    input.value.trim();


  if (
    !validIPClient(ip)
  ) {

    showToast(
      "⚠️ IP معتبر وارد کن"
    );

    return;

  }


  await blockIP(ip);

  input.value = "";

}


function validIPClient(ip) {

  if (
    !ip ||
    ip.length > 100
  ) {
    return false;
  }

  return /^[0-9a-fA-F:.]+$/.test(
    ip
  );

}


document
  .getElementById(
    "manualBlockButton"
  )
  .addEventListener(
    "click",
    blockManual
  );


document
  .getElementById(
    "refreshButton"
  )
  .addEventListener(
    "click",
    loadData
  );

</script>

</body>

</html>`,
    {
      headers: {
        "content-type":
          "text/html; charset=UTF-8",

        "cache-control":
          "no-store"
      }
    }
  );
}


// =========================
// Worker
// =========================

export default {

  async fetch(
    request,
    env,
    ctx
  ) {

    const url =
      new URL(request.url);

    const ip =
      getIP(request);

    const country =
      getCountry(request);


    // =====================
    // Dashboard
    // =====================

    if (
      url.pathname ===
      "/security"
    ) {

      return securityDashboard();

    }


    // =====================
    // Heartbeat
    // =====================

    if (
      url.pathname ===
      "/api/presence"
    ) {

      // فقط heartbeat را ثبت می‌کنیم.
      // اطلاعات IP در پاسخ به کاربر برگردانده نمی‌شود.

      if (
        request.method !== "POST"
      ) {

        return json(
          {
            error:
              "Method not allowed"
          },
          405
        );

      }


      if (
        ip !== "unknown"
      ) {

        const visitor = {

          time:
            Date.now(),

          ip:
            ip,

          country:
            country,

          path:
            "/",

          method:
            "HEARTBEAT",

          status:
            "ONLINE"

        };


        ctx.waitUntil(
          saveVisitor(
            env,
            visitor
          )
        );

      }


      return json({
        success:
          true
      });

    }


    // =====================
    // Admin API
    // =====================

    if (
      url.pathname.startsWith(
        "/api/security/"
      )
    ) {

      if (
        !checkAdmin(request)
      ) {

        return json(
          {
            error:
              "Unauthorized"
          },
          401
        );

      }


      // ===================
      // Stats
      // ===================

      if (
        url.pathname ===
          "/api/security/stats" &&
        request.method ===
          "GET"
      ) {

        const visitors =
          await getVisitors(
            env
          );

        const events =
          await getRecentEvents(
            env
          );

        const blockedIPs =
          await listBlockedIPs(
            env
          );


        const now =
          Date.now();


        const onlineVisitors =
          visitors.filter(
            visitor =>
              now -
              (visitor.time || 0)
              <
              ONLINE_WINDOW
          );


        const countries =
          new Set(
            visitors
              .map(
                visitor =>
                  visitor.country
              )
              .filter(Boolean)
          );


        const suspicious =
          events.filter(
            event =>
              event.suspicious
          );


        return json({

          visitors:
            visitors.length,

          online:
            onlineVisitors.length,

          countries:
            countries.size,

          suspicious:
            suspicious.length,

          blocked:
            blockedIPs.length,

          blockedIPs,

          visitorsList:
            visitors,

          events

        });

      }


      // ===================
      // Block
      // ===================

      if (
        url.pathname ===
          "/api/security/block" &&
        request.method ===
          "POST"
      ) {

        let body;

        try {

          body =
            await request.json();

        } catch {

          return json(
            {
              error:
                "Invalid JSON"
            },
            400
          );

        }


        const targetIP =
          typeof body.ip ===
            "string"
            ? body.ip.trim()
            : "";


        if (
          !validIP(targetIP)
        ) {

          return json(
            {
              error:
                "Invalid IP"
            },
            400
          );

        }


        try {

          await blockIP(
            env,
            targetIP
          );

        } catch (error) {

          return json(
            {
              error:
                error.message
            },
            500
          );

        }


        return json({

          success:
            true,

          blocked:
            targetIP

        });

      }


      // ===================
      // Unblock
      // ===================

      if (
        url.pathname ===
          "/api/security/unblock" &&
        request.method ===
          "POST"
      ) {

        let body;

        try {

          body =
            await request.json();

        } catch {

          return json(
            {
              error:
                "Invalid JSON"
            },
            400
          );

        }


        const targetIP =
          typeof body.ip ===
            "string"
            ? body.ip.trim()
            : "";


        if (
          !validIP(targetIP)
        ) {

          return json(
            {
              error:
                "Invalid IP"
            },
            400
          );

        }


        try {

          await unblockIP(
            env,
            targetIP
          );

        } catch (error) {

          return json(
            {
              error:
                error.message
            },
            500
          );

        }


        return json({

          success:
            true,

          unblocked:
            targetIP

        });

      }


      return json(
        {
          error:
            "Not found"
        },
        404
      );

    }


    // =====================
    // Blocked IP
    // =====================

    if (
      await isBlocked(
        env,
        ip
      )
    ) {

      return new Response(
        "Access denied.",
        {
          status:
            403,

          headers: {
            "content-type":
              "text/plain; charset=UTF-8",

            "cache-control":
              "no-store"
          }
        }
      );

    }


    // =====================
    // Rate Limit
    // =====================

    if (
      rateLimited(ip)
    ) {

      ctx.waitUntil(
        saveSecurityEvent(
          env,
          {
            time:
              Date.now(),

            ip,

            country,

            path:
              url.pathname,

            method:
              request.method,

            suspicious:
              true,

            status:
              "RATE_LIMITED"
          }
        )
      );


      return new Response(
        "Too many requests.",
        {
          status:
            429,

          headers: {
            "retry-after":
              "60"
          }
        }
      );

    }


    // =====================
    // Suspicious
    // =====================

    const suspicious =
      isSuspicious(
        url.pathname
      );


    if (suspicious) {

      ctx.waitUntil(
        saveSecurityEvent(
          env,
          {
            time:
              Date.now(),

            ip,

            country,

            path:
              url.pathname,

            method:
              request.method,

            suspicious:
              true,

            status:
              "SUSPICIOUS"
          }
        )
      );


      return new Response(
        "Request blocked.",
        {
          status:
            403,

          headers: {
            "cache-control":
              "no-store"
          }
        }
      );

    }


    // =====================
    // Normal visitor
    // =====================

    ctx.waitUntil(
      saveVisitor(
        env,
        {
          time:
            Date.now(),

          ip,

          country,

          path:
            url.pathname,

          method:
            request.method,

          status:
            "NORMAL"
        }
      )
    );


    // =====================
    // Website
    // =====================

    return env.ASSETS.fetch(
      request
    );

  }

};
