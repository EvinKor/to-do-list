var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// claudeflare/config/apps.js
var APP_CONFIG = {
  inventory: {
    type: "supabase",
    baseUrl: "https://inventory.mrburstudio.com"
  },
  appointment: {
    type: "odoo",
    baseUrl: "https://appointment.mrburstudio.com",
    clientId: "REPLACE_WITH_APPOINTMENT_ID"
  },
  recruitment: {
    type: "odoo",
    baseUrl: "https://recruitment.mrburstudio.com",
    clientId: "REPLACE_WITH_RECRUITMENT_ID"
  }
};

// claudeflare/auth/odooJwt.js
function parseJwtPayload(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");
  const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const jsonPayload = decodeURIComponent(
    atob(base64).split("").map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join("")
  );
  return JSON.parse(jsonPayload);
}
__name(parseJwtPayload, "parseJwtPayload");
function extractEmail(payload) {
  return payload.email || payload.login || payload.user_email;
}
__name(extractEmail, "extractEmail");

// claudeflare/supabase/profiles.js
async function getProfileByEmail(env, email) {
  const url = `${env.SUPABASE_URL}/rest/v1/profiles?email=eq.${encodeURIComponent(email)}&select=*`;
  const r = await fetch(url, {
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json"
    }
  });
  if (!r.ok) {
    throw new Error(`Supabase error ${r.status}: ${await r.text()}`);
  }
  const rows = await r.json();
  console.log("this rows: ", JSON.stringify(rows[0]));
  return rows[0] ?? null;
}
__name(getProfileByEmail, "getProfileByEmail");

// claudeflare/supabase/rest.js
function buildUrl(env, table, params = {}) {
  const base = `${env.SUPABASE_URL}/rest/v1/${table}`;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === void 0 || v === null) continue;
    qs.set(k, String(v));
  }
  return `${base}?${qs.toString()}`;
}
__name(buildUrl, "buildUrl");
async function sbFetch(env, url) {
  const r = await fetch(url, {
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json"
    }
  });
  if (!r.ok) {
    throw new Error(`Supabase ${r.status}: ${await r.text()}`);
  }
  return r;
}
__name(sbFetch, "sbFetch");
async function sbGetList(env, table, params) {
  const url = buildUrl(env, table, params);
  const r = await sbFetch(env, url);
  return await r.json();
}
__name(sbGetList, "sbGetList");
async function sbGetMaybeSingle(env, table, params) {
  const url = buildUrl(env, table, params);
  const r = await sbFetch(env, url);
  const rows = await r.json();
  return rows?.[0] ?? null;
}
__name(sbGetMaybeSingle, "sbGetMaybeSingle");
function sbHeaders(env) {
  return {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json"
  };
}
__name(sbHeaders, "sbHeaders");
async function sbDelete(env, table, filters) {
  const qs = new URLSearchParams(filters).toString();
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/${table}?${qs}`,
    { method: "DELETE", headers: sbHeaders(env) }
  );
  if (!res.ok) throw new Error(await res.text());
}
__name(sbDelete, "sbDelete");
async function sbInsert(env, table, rows) {
  if (!rows.length) return;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/${table}`,
    {
      method: "POST",
      headers: {
        ...sbHeaders(env),
        Prefer: "return=minimal"
      },
      body: JSON.stringify(rows)
    }
  );
  if (!res.ok) throw new Error(await res.text());
}
__name(sbInsert, "sbInsert");
async function sbUpsert(env, table, rows, conflict = null) {
  if (!rows.length) return;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/${table}`,
    {
      method: "POST",
      headers: {
        ...sbHeaders(env),
        Prefer: `resolution=merge-duplicates,return=minimal${conflict ? `,on_conflict=${conflict}` : ""}`
      },
      body: JSON.stringify(rows)
    }
  );
  if (!res.ok) throw new Error(await res.text());
}
__name(sbUpsert, "sbUpsert");

// claudeflare/supabase/inventoryMeta.js
async function getInventoryMetaByUserId(env, userId) {
  if (!userId) return [];
  return await sbGetList(env, "inventory_meta", {
    user_id: `eq.${userId}`,
    select: "*",
    limit: 1
  });
}
__name(getInventoryMetaByUserId, "getInventoryMetaByUserId");

// claudeflare/supabase/upsertInventory.Meta.js
async function upsertInventoryMeta(env, metaPayload) {
  const url = `${env.SUPABASE_URL}/rest/v1/inventory_meta`;
  const res = await fetch(url, {
    method: "POST",
    // POST + Prefer header => UPSERT
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=representation"
    },
    body: JSON.stringify(metaPayload)
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Upsert inventory_meta failed ${res.status}: ${text}`);
  }
  const data = await res.json();
  return data?.[0] ?? null;
}
__name(upsertInventoryMeta, "upsertInventoryMeta");

// claudeflare/supabase/bootstrap.js
async function supabaseBootstrapByEmail(env, email) {
  const profiles_data = await sbGetMaybeSingle(env, "profiles", {
    email: `eq.${email}`,
    select: "*",
    limit: 1
  });
  if (!profiles_data) {
    return {
      profiles: null,
      setting_data: null,
      meta: [],
      rooms: [],
      rooms_error: null,
      items_data: [],
      history_data: [],
      log_data: []
    };
  }
  const userId = profiles_data.user_id ?? profiles_data.id;
  if (!userId) throw new Error("Profile missing user_id");
  console.log("[bootstrap] profile found:", JSON.stringify({
    email: profiles_data.email,
    id: userId
  }));
  let meta_data = await getInventoryMetaByUserId(env, userId);
  if (!meta_data || meta_data.length === 0) {
    await upsertInventoryMeta(env, {
      user_id: userId,
      // defaults (optional but recommended)
      cat_position_x: 20,
      cat_position_y: 20,
      blueprint: null
    });
    meta_data = await getInventoryMetaByUserId(env, userId);
  }
  const rooms_data = await sbGetList(env, "inventory_rooms", {
    user_id: `eq.${userId}`,
    select: "id,name,pos_x,pos_y"
  });
  const room_ids = (rooms_data || []).map((r) => r.id);
  const items_data = room_ids.length > 0 ? await sbGetList(env, "inventory_items", {
    select: "*,item_batches:inventory_item_batches(*)",
    room_id: `in.(${room_ids.join(",")})`
  }) : [];
  const history_data = await sbGetList(env, "inventory_purchase_history", {
    user_id: `eq.${userId}`,
    select: "*",
    order: "occurred_at.desc"
  });
  const log_data = await sbGetList(env, "inventory_activity_logs", {
    user_id: `eq.${userId}`,
    select: "*",
    order: "created_at.desc"
  });
  const clinicId = profiles_data.clinic_id;
  const setting_data = clinicId ? await sbGetMaybeSingle(env, "apt_settings", {
    clinic_id: `eq.${clinicId}`,
    select: "*",
    limit: 1
  }) : null;
  return {
    profiles: profiles_data,
    setting_data,
    meta: meta_data,
    rooms: rooms_data,
    rooms_error: null,
    items_data,
    history_data,
    log_data
  };
}
__name(supabaseBootstrapByEmail, "supabaseBootstrapByEmail");

// claudeflare/supabase/inventorySync.js
async function inventoryFullSync(env, payload) {
  const {
    user_id,
    blueprint,
    cat_position,
    rooms,
    items,
    item_batches,
    history,
    logs
  } = payload;
  await upsertInventoryMeta(env, {
    user_id,
    blueprint,
    cat_position_x: cat_position.x,
    cat_position_y: cat_position.y
  });
  await sbDelete(env, "inventory_activity_logs", { user_id: `eq.${user_id}` });
  await sbDelete(env, "inventory_purchase_history", { user_id: `eq.${user_id}` });
  await sbDelete(env, "inventory_rooms", { user_id: `eq.${user_id}` });
  await sbInsert(env, "inventory_rooms", rooms.map((r) => ({
    id: r.id,
    user_id,
    name: r.name,
    pos_x: r.pos_x,
    pos_y: r.pos_y
  })));
  const allowedRoomIds = new Set(rooms.map((r) => r.id));
  const filteredItems = items.filter((i) => allowedRoomIds.has(i.room_id)).reduce((m, i) => (m.set(i.id, i), m), /* @__PURE__ */ new Map()).values();
  await sbUpsert(
    env,
    "inventory_items",
    [...filteredItems],
    "id"
  );
  const dedupBatches = /* @__PURE__ */ new Map();
  for (const b of item_batches) {
    const key = `${b.item_id}|${b.expiry_date || "none"}|${b.qty}|${b.unit_price}`;
    dedupBatches.set(key, b);
  }
  await sbInsert(
    env,
    "inventory_item_batches",
    [...dedupBatches.values()]
  );
  await sbInsert(
    env,
    "inventory_purchase_history",
    [...new Map(history.map((h) => [h.id, h])).values()]
  );
  await sbInsert(
    env,
    "inventory_activity_logs",
    [...new Map(logs.map((l) => [l.id, l])).values()]
  );
  return { ok: true };
}
__name(inventoryFullSync, "inventoryFullSync");

// claudeflare/supabase/appointments.js
async function getAppointments(env, clinicId) {
  if (!clinicId) throw new Error("Missing clinicId");
  return await sbGetList(env, "appointments", {
    select: "*",
    clinic_id: `eq.${clinicId}`,
    order: "date.asc,start_time.asc"
  });
}
__name(getAppointments, "getAppointments");

// claudeflare/supabase/whiteboardNotes.js
async function upsertWhiteboardNote(env, row) {
  const baseUrl = env.SUPABASE_URL?.replace(/\/$/, "");
  if (!baseUrl) {
    throw new Error("Missing SUPABASE_URL");
  }
  if (!env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY");
  }
  const url = `${baseUrl}/rest/v1/whiteboard_notes?on_conflict=id`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "resolution=merge-duplicates,return=representation"
    },
    body: JSON.stringify(row)
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(text || `Supabase error ${res.status}`);
  }
  const data = text ? JSON.parse(text) : null;
  return Array.isArray(data) ? data[0] : data;
}
__name(upsertWhiteboardNote, "upsertWhiteboardNote");

// claudeflare/index.js
var claudeflare_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const COOKIE_NAME = "mrbur_sso";
    const COOKIE_DOMAIN = ".mrburstudio.com";
    const DEFAULT_MAX_AGE = 60 * 60;
    const origin = request.headers.get("Origin");
    const allowedOrigins = /* @__PURE__ */ new Set([
      "https://inventory.mrburstudio.com",
      "https://appointment.mrburstudio.com",
      "https://event.mrburstudio.com",
      "https://recruitment.mrburstudio.com",
      "http://localhost:3000"
    ]);
    const isApi = url.pathname.startsWith("/api/");
    const corsHeaders = isApi ? {
      "Access-Control-Allow-Origin": allowedOrigins.has(origin) ? origin : "https://inventory.mrburstudio.com",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, X-Requested-With",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin"
    } : {};
    if (isApi && request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    function getCookie(req, name) {
      const cookie = req.headers.get("Cookie") || "";
      const parts = cookie.split(";").map((v) => v.trim());
      for (const part of parts) {
        if (part.startsWith(name + "=")) {
          return decodeURIComponent(part.slice(name.length + 1));
        }
      }
      return null;
    }
    __name(getCookie, "getCookie");
    function buildSetCookie({ value, maxAge = DEFAULT_MAX_AGE }) {
      return [
        `${COOKIE_NAME}=${encodeURIComponent(value)}`,
        "Path=/",
        `Domain=${COOKIE_DOMAIN}`,
        // ✅ share across subdomains
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        `Max-Age=${maxAge}`
      ].join("; ");
    }
    __name(buildSetCookie, "buildSetCookie");
    function buildClearCookie() {
      return [
        `${COOKIE_NAME}=`,
        "Path=/",
        `Domain=${COOKIE_DOMAIN}`,
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=0"
      ].join("; ");
    }
    __name(buildClearCookie, "buildClearCookie");
    function getTokenFromRequest(req) {
      const cookieToken = getCookie(req, COOKIE_NAME);
      if (cookieToken) return cookieToken;
      const auth = req.headers.get("Authorization");
      if (auth?.startsWith("Bearer ")) return auth.slice(7);
      return null;
    }
    __name(getTokenFromRequest, "getTokenFromRequest");
    function decodeAndValidateToken(token) {
      let payload;
      try {
        payload = parseJwtPayload(token);
      } catch {
        return { ok: false, error: "invalid_token", payload: null };
      }
      if (payload?.exp && payload.exp * 1e3 < Date.now()) {
        return { ok: false, error: "expired", payload: null };
      }
      const email = extractEmail(payload);
      if (!email) return { ok: false, error: "missing_email", payload: null };
      return { ok: true, payload, email };
    }
    __name(decodeAndValidateToken, "decodeAndValidateToken");
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": buildClearCookie(),
          ...corsHeaders
        }
      });
    }
    if (url.pathname === "/api/me" && request.method === "GET") {
      const token = getTokenFromRequest(request);
      if (!token) {
        return new Response(JSON.stringify({ loggedIn: false, user: null }), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response(JSON.stringify({ loggedIn: false, user: null }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            // optional: clear cookie if expired/invalid
            ...decoded.error === "expired" || decoded.error === "invalid_token" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      return new Response(
        JSON.stringify({
          loggedIn: true,
          user: { email: decoded.email, aud: decoded.payload?.aud || null }
        }),
        { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }
    if (url.pathname === "/api/appointments") {
      const auth = request.headers.get("Authorization");
      if (!auth?.startsWith("Bearer ")) {
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
      const token = auth.slice(7);
      let payload;
      try {
        payload = parseJwtPayload(token);
        if (payload?.exp && payload.exp * 1e3 < Date.now()) throw new Error("expired");
      } catch {
        return new Response("Invalid Token", { status: 401, headers: corsHeaders });
      }
      const clinicId = url.searchParams.get("clinicId");
      if (!clinicId) {
        return new Response("Missing clinicId", { status: 400, headers: corsHeaders });
      }
      try {
        const data = await getAppointments(env, clinicId);
        return new Response(JSON.stringify(data), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }
    if (url.pathname === "/api/inventory/sync" && request.method === "POST") {
      const token = getTokenFromRequest(request);
      if (!token) return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            ...decoded.error === "expired" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      const body = await request.json();
      await inventoryFullSync(env, body);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
    if (url.pathname === "/api/bootstrap") {
      const token = getTokenFromRequest(request);
      if (!token) {
        return new Response(JSON.stringify({ loggedIn: false }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response(JSON.stringify({ loggedIn: false, error: decoded.error }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            ...decoded.error === "expired" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      try {
        const result = await supabaseBootstrapByEmail(env, decoded.email);
        return new Response(
          JSON.stringify({
            loggedIn: true,
            user: result
          }),
          { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      } catch (e) {
        return new Response(JSON.stringify({ loggedIn: false, error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }
    if (url.pathname === "/api/verify-token") {
      const token = getTokenFromRequest(request);
      if (!token) {
        return new Response(JSON.stringify({ loggedIn: false }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response(JSON.stringify({ loggedIn: false }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            ...decoded.error === "expired" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      let profile;
      try {
        profile = await getProfileByEmail(env, decoded.email);
      } catch (e) {
        return new Response(JSON.stringify({ loggedIn: false, error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      if (!profile) {
        return new Response(JSON.stringify({ loggedIn: false }), {
          status: 403,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      let meta = [];
      try {
        meta = await getInventoryMetaByUserId(env, profile.user_id);
      } catch {
        meta = [];
      }
      return new Response(
        JSON.stringify({
          loggedIn: true,
          user: {
            profiles: {
              user: {
                user_id: profile.user_id,
                email: profile.email,
                user_metadata: {
                  name: profile.name,
                  account_type: profile.account_type,
                  phone: profile.phone,
                  position: profile.position,
                  company_name: profile.company_name
                }
              }
            },
            meta,
            rooms: [],
            rooms_error: null,
            items_data: [],
            history_data: [],
            log_data: []
          }
        }),
        { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }
    if (url.pathname === "/api/inventory/meta") {
      const token = getTokenFromRequest(request);
      if (!token) return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            ...decoded.error === "expired" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      let profile;
      try {
        profile = await getProfileByEmail(env, decoded.email);
      } catch (e) {
        return new Response(e.message, { status: 500, headers: corsHeaders });
      }
      if (!profile) {
        return new Response("User not found", { status: 403, headers: corsHeaders });
      }
      try {
        const meta = await getInventoryMetaByUserId(env, profile.user_id);
        return new Response(JSON.stringify({ profile, meta }), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (e) {
        return new Response(e.message, { status: 500, headers: corsHeaders });
      }
    }
    if (url.pathname === "/sso/login") {
      const token = url.searchParams.get("token");
      if (!token) return new Response("Missing token", { status: 400 });
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response("Invalid Token", { status: 400 });
      }
      const appCode = decoded.payload.aud;
      const config = APP_CONFIG[appCode];
      if (!config) {
        return new Response(`Unknown App Code: ${appCode}`, { status: 400 });
      }
      const maxAge = DEFAULT_MAX_AGE;
      if (config.type === "supabase") {
        try {
          const profile = await getProfileByEmail(env, decoded.email);
          console.log("[SSO] profile:", profile);
        } catch (e) {
          return new Response(e.message, { status: 500 });
        }
        const finalUrl = `${config.baseUrl}/login`;
        return new Response(null, {
          status: 302,
          headers: {
            "Set-Cookie": buildSetCookie({ value: token, maxAge }),
            Location: finalUrl,
            "Cache-Control": "no-store"
          }
        });
      }
      const MAIN_ODOO_URL = "https://mrbur-staging-bur-2609087.dev.odoo.com";
      const redirectUri = `${config.baseUrl}/auth_oauth/signin`;
      const oauthUrl = `${MAIN_ODOO_URL}/oauth2/auth?client_id=${config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=token&scope=userinfo`;
      return new Response(null, {
        status: 302,
        headers: {
          "Set-Cookie": buildSetCookie({ value: token, maxAge }),
          Location: oauthUrl,
          "Cache-Control": "no-store"
        }
      });
    }
    if ((url.pathname.startsWith("/api/whiteboard-notes/") || url.pathname.startsWith("/whiteboard-notes/")) && request.method === "PUT") {
      const token = getTokenFromRequest(request);
      if (!token) return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      const decoded = decodeAndValidateToken(token);
      if (!decoded.ok) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            ...decoded.error === "expired" ? { "Set-Cookie": buildClearCookie() } : {},
            ...corsHeaders
          }
        });
      }
      const noteId = url.pathname.split("/").pop();
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400, headers: corsHeaders });
      }
      const profile = await getProfileByEmail(env, decoded.email);
      if (!profile) return new Response("User not found", { status: 403, headers: corsHeaders });
      const row = {
        id: noteId,
        whiteboard_id: body.whiteboard_id,
        user_id: profile.user_id,
        // ✅ server controlled
        type: body.type,
        x: body.x ?? 0,
        y: body.y ?? 0,
        width: body.width ?? 256,
        height: body.height ?? 256,
        rotation: body.rotation ?? 0,
        z_index: body.z_index ?? 1,
        title: body.title ?? null,
        content: body.content ?? null,
        color: body.color ?? "yellow",
        font_size: body.font_size ?? 16,
        image_url: body.image_url ?? null,
        updated_at: (/* @__PURE__ */ new Date()).toISOString()
      };
      try {
        const saved = await upsertWhiteboardNote(env, row);
        return new Response(JSON.stringify({ ok: true, note: saved }), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }
    return new Response("SSO Gateway Active", {
      status: 200,
      headers: corsHeaders
    });
  }
};

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-KyEPof/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = claudeflare_default;

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-KyEPof/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
