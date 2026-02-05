export async function upsertWhiteboardNote(env, row) {
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
      Prefer: "resolution=merge-duplicates,return=representation",
    },
    body: JSON.stringify(row),
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(text || `Supabase error ${res.status}`);
  }

  const data = text ? JSON.parse(text) : null;
  return Array.isArray(data) ? data[0] : data;
}
