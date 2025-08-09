// Cloudflare Worker — Telegram backend (webhook + простое API на KV)
//
// Маршруты:
//  GET  /health                           -> { ok: true }
//  POST /bot                              -> Telegram webhook
//  POST /api/auth/telegram {initData}     -> проверка подписи WebApp
//  GET  /api/crm/clients                  -> список клиентов (KV)
//  POST /api/crm/clients {name,stage,...} -> добавить клиента
//  GET  /api/tasks                        -> список задач
//  POST /api/tasks {title,tag,due,status} -> добавить задачу
//
// Требуемые переменные/биндинги (настроим в панели):
//  - Secret  BOT_TOKEN     (токен бота)
//  - Secret  JWT_SECRET    (пока не используем для подписи, но оставим)
//  - Variable FRONTEND_URL (URL фронта для кнопки WebApp)
//  - KV binding DB         (KV namespace, ключи: "clients", "tasks")

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(request.headers.get("Origin")) });
    }

    // HEALTH
    if (url.pathname === "/health") {
      return json({ ok: true });
    }

    // TELEGRAM WEBHOOK
    if (url.pathname === "/bot" && request.method === "POST") {
      const update = await request.json();
      const chatId =
        update.message?.chat?.id ||
        update.edited_message?.chat?.id ||
        update.callback_query?.message?.chat?.id;

      const text = update.message?.text?.trim();

      if (chatId) {
        // Кнопка открытия WebApp
        const keyboard = {
          inline_keyboard: [[{ text: "Открыть рабочее пространство", web_app: { url: env.FRONTEND_URL } }]],
        };

        // Примитивные ответы
        const replyText =
          text === "/start"
            ? "Добро пожаловать в Premium Business!"
            : "Нажмите кнопку ниже, чтобы открыть рабочее пространство.";

        await tgSend(env, "sendMessage", { chat_id: chatId, text: replyText, reply_markup: keyboard });
      }
      return json({ ok: true });
    }

    // AUTH через Telegram WebApp initData
    if (url.pathname === "/api/auth/telegram" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const valid = await validateWebAppData(body?.initData, env.BOT_TOKEN);
      if (!valid) return withCors(json({ error: "auth_failed" }, 401), request);
      // Для простоты возвращаем псевдо-токен (можно заменить на реальный JWT)
      return withCors(json({ ok: true, token: "demo-token" }), request);
    }

    // CRM: CLIENTS
    if (url.pathname === "/api/crm/clients" && request.method === "GET") {
      const clients = await kvJson(env.DB, "clients", []);
      return withCors(json(clients), request);
    }
    if (url.pathname === "/api/crm/clients" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const clients = await kvJson(env.DB, "clients", []);
      const item = { id: Date.now(), ...body };
      clients.unshift(item);
      await env.DB.put("clients", JSON.stringify(clients));
      return withCors(json({ id: item.id }), request);
    }

    // TASKS
    if (url.pathname === "/api/tasks" && request.method === "GET") {
      const tasks = await kvJson(env.DB, "tasks", []);
      return withCors(json(tasks), request);
    }
    if (url.pathname === "/api/tasks" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const tasks = await kvJson(env.DB, "tasks", []);
      const item = { id: Date.now(), ...body };
      tasks.unshift(item);
      await env.DB.put("tasks", JSON.stringify(tasks));
      return withCors(json({ id: item.id }), request);
    }

    return new Response("Not found", { status: 404 });
  },
};

// ───────────────── helpers ─────────────────
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  };
}
function withCors(resp, request) {
  const h = new Headers(resp.headers);
  const origin = request.headers.get("Origin") || "*";
  Object.entries(corsHeaders(origin)).forEach(([k, v]) => h.set(k, v));
  return new Response(resp.body, { status: resp.status, headers: h });
}
async function kvJson(DB, key, fallback) {
  const v = await DB.get(key);
  return v ? JSON.parse(v) : fallback;
}
async function tgSend(env, method, payload) {
  return fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

// Проверка initData из Telegram WebApp (HMAC)
async function validateWebAppData(initData, botToken) {
  if (!initData) return false;
  const data = Object.fromEntries(new URLSearchParams(initData));
  const hash = data.hash;
  delete data.hash;
  const sorted = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");

  const enc = new TextEncoder();

  // key1 = HMAC_SHA256("WebAppData", botToken)
  const key1 = await crypto.subtle.importKey("raw", enc.encode("WebAppData"), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const secret = await crypto.subtle.sign("HMAC", key1, enc.encode(botToken));

  const key2 = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key2, enc.encode(sorted));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex === hash;
}
