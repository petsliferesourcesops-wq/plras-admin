var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// index.js
var WORKER_VERSION = "plras-consumer-v2.1-stable";
var index_default = {
  async fetch(req, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,x-api-key"
    };
    if (env.RATE_LIMIT_KV && typeof env.RATE_LIMIT_KV.get === "function") {
      const ip = req.headers.get(
        "CF-Connecting-IP"
      ) || "unknown";
      const key = `ratelimit:${ip}`;
      const current = Number(
        await env.RATE_LIMIT_KV.get(key) || 0
      );
      if (current > 100) {
        return new Response(
          "Rate limited",
          {
            status: 429,
            headers: corsHeaders
          }
        );
      }
      await env.RATE_LIMIT_KV.put(
        key,
        String(current + 1),
        {
          expirationTtl: 60
        }
      );
    }
    const url = new URL(req.url);
    if (url.pathname === "/login" && req.method === "GET") {
      return new Response(
        `
<!DOCTYPE html>
<html>
<body style="font-family:Arial;padding:40px">

<h2>PLRAS Admin Login</h2>

<input
id="pw"
type="password"
placeholder="Password"
/>

<button onclick="login()">
Login
</button>

<script>

async function login(){

const password =
document.getElementById("pw").value;

const res =
await fetch(
"/login",
{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({
password
})
}
);

if(res.ok){

location.href="/admin";

}else{

alert("Wrong password");

}

}

<\/script>

</body>
</html>
`,
        {
          headers: {
            "Content-Type": "text/html",
            ...corsHeaders
          }
        }
      );
    }
    const cookie = req.headers.get("Cookie") || "";
    const authenticated = cookie.split(";").map((c) => c.trim()).includes(
      `plras_admin=${env.ADMIN_PASSWORD}`
    );
    const publicPaths = [
      "/login",
      "/favicon.ico"
    ];
    if (!authenticated && !publicPaths.includes(url.pathname)) {
      return Response.redirect(
        `${url.origin}/login`,
        302
      );
    }
    if (url.pathname === "/login" && req.method === "POST") {
      const body = await req.json();
      const password = body.password;
      if (password === env.ADMIN_PASSWORD) {
        return new Response(
          JSON.stringify({
            ok: true
          }),
          {
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie": `plras_admin=${env.ADMIN_PASSWORD}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
              ...corsHeaders
            }
          }
        );
      }
      return new Response(
        "Unauthorized",
        {
          status: 401,
          headers: corsHeaders
        }
      );
    }
    if (url.pathname === "/logout") {
      return new Response(
        "Logged out",
        {
          headers: {
            "Set-Cookie": "plras_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            ...corsHeaders
          }
        }
      );
    }
    if (url.pathname === "/review") {
      const secret = url.searchParams.get(
        "secret"
      );
      if (!authenticated && secret !== env.REVIEW_SECRET) {
        return new Response(
          "Unauthorized",
          {
            status: 401,
            headers: corsHeaders
          }
        );
      }
    }
    if (url.pathname === "/applications") {
      const apiKey = req.headers.get(
        "x-api-key"
      );
      if (apiKey !== env.ADMIN_SECRET) {
        return new Response(
          "Unauthorized",
          {
            status: 401,
            headers: corsHeaders
          }
        );
      }
    }
    if (url.pathname === "/" || url.pathname === "/admin") {
      const token = await getGoogleAccessToken(env);
      const res = await fetch(
        `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );
      const data = await res.json();
      return new Response(
        getAdminHTML(
          data,
          env.REVIEW_SECRET
        ),
        {
          headers: {
            "Content-Type": "text/html;charset=UTF-8",
            ...corsHeaders
          }
        }
      );
    }
    if (url.pathname === "/review") {
      const submissionId = url.searchParams.get("id");
      const action = url.searchParams.get("action");
      let role = url.searchParams.get("role");
      if (!submissionId || !action) {
        return new Response(
          "Missing params",
          {
            headers: corsHeaders
          }
        );
      }
      const token = await getGoogleAccessToken(
        env
      );
      if (!role) {
        const lookup = await fetch(
          `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all/${submissionId}`,
          {
            headers: {
              Authorization: `Bearer ${token}`
            }
          }
        );
        const lookupData = await lookup.json();
        role = lookupData?.fields?.role?.stringValue || null;
      }
      if (role) {
        await writeFirestore(
          env,
          token,
          `providers/${role}/applications/${submissionId}`,
          {
            status: action,
            reviewed_at: (/* @__PURE__ */ new Date()).toISOString()
          }
        );
      }
      await writeFirestore(
        env,
        token,
        `providers_all/${submissionId}`,
        {
          status: action,
          reviewed_at: (/* @__PURE__ */ new Date()).toISOString()
        }
      );
      console.log(
        "\u{1F4DD} WRITING AUDIT LOG"
      );
      await writeAuditLog(
        env,
        token,
        {
          submissionId,
          action,
          role,
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          ip: req.headers.get(
            "CF-Connecting-IP"
          ) || "unknown",
          user_agent: req.headers.get(
            "User-Agent"
          ) || "unknown"
        }
      );
      console.log(
        "\u2705 AUDIT LOG WRITTEN"
      );
      return new Response(
        `\u2705 ${action}`,
        {
          headers: corsHeaders
        }
      );
    }
    if (url.pathname === "/applications") {
      const token = await getGoogleAccessToken(
        env
      );
      const res = await fetch(
        `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );
      const data = await res.json();
      return new Response(
        JSON.stringify(data),
        {
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders
          }
        }
      );
    }
    return new Response(
      `PLRAS Consumer Alive ${WORKER_VERSION}`,
      {
        headers: corsHeaders
      }
    );
  },
  async queue(batch, env) {
    console.log(
      "\u{1F525} CONSUMER STARTED"
    );
    for (const message of batch.messages) {
      try {
        let data;
        try {
          data = typeof message.body === "string" ? JSON.parse(
            message.body
          ) : message.body;
        } catch (e) {
          console.error(
            "\u274C JSON PARSE FAIL"
          );
          message.ack();
          continue;
        }
        const submissionId = data.submissionId || crypto.randomUUID();
        const role = data.role;
        if (!role) {
          throw new Error(
            "ROLE MISSING"
          );
        }
        console.log(
          "\u{1F4CC} ID:",
          submissionId
        );
        const token = await getGoogleAccessToken(
          env
        );
        const exists = await submissionExists(
          env,
          token,
          submissionId
        );
        if (exists) {
          console.log(
            "\u26A0\uFE0F DUPLICATE BLOCKED"
          );
          message.ack();
          continue;
        }
        const fileObj = extractFile(data);
        let dropboxUrl = null;
        if (fileObj?.url) {
          try {
            dropboxUrl = await uploadToDropbox(
              env,
              fileObj,
              submissionId,
              role
            );
            console.log(
              "\u2705 DROPBOX OK"
            );
          } catch (e) {
            console.error(
              "\u274C DROPBOX FAIL",
              e
            );
            await sendDiscordAlert(
              env,
              `\u274C DROPBOX FAIL
${e}`
            );
          }
        }
        const scoreValue = score(
          data,
          dropboxUrl
        );
        let status = "pending";
        if (!data?.applicant?.email?.includes(
          "@"
        )) {
          status = "rejected";
        }
        const firestoreData = buildFirestoreData(
          data,
          fileObj,
          dropboxUrl,
          scoreValue,
          status,
          submissionId
        );
        const rolePath = `providers/${role}/applications/${submissionId}`;
        const globalPath = `providers_all/${submissionId}`;
        try {
          await writeFirestore(
            env,
            token,
            rolePath,
            firestoreData
          );
          await writeFirestore(
            env,
            token,
            globalPath,
            firestoreData
          );
          console.log(
            "\u2705 FIRESTORE OK"
          );
          try {
            await writeAuditLog(
              env,
              token,
              {
                submissionId,
                action: "APPLICATION_CREATED",
                role,
                timestamp: (/* @__PURE__ */ new Date()).toISOString(),
                ip: "queue",
                user_agent: "cloudflare-queue"
              }
            );
            console.log(
              "\u2705 AUDIT CREATED"
            );
          } catch (e) {
            console.error(
              "\u274C AUDIT FAIL",
              e
            );
          }
        } catch (e) {
          console.error(
            "\u274C FIRESTORE FAIL",
            e
          );
          await sendDiscordAlert(
            env,
            `\u274C FIRESTORE FAIL
${e}`
          );
          throw e;
        }
        const applicant = data?.applicant || {};
        if (applicant.email && env.EMAILJS_SERVICE_ID) {
          try {
            await sendEmailDirect(
              env,
              applicant.email,
              "Application Received \u2014 Pets Life Resources",
              `<p>Hi ${applicant.full_name || "User"}, your application has been received.</p>`
            );
          } catch (e) {
            console.error(
              "\u274C APPLICANT EMAIL FAIL",
              e
            );
            await sendDiscordAlert(
              env,
              `\u274C EMAIL FAIL
${e}`
            );
          }
        }
        const approvers = getApprovers(
          env,
          role
        );
        for (const approverEmail of approvers) {
          try {
            const summary = JSON.stringify(
              data.details || [],
              null,
              2
            ).substring(0, 3e3);
            await sendApproverEmail(
              env,
              approverEmail,
              {
                submissionId,
                full_name: applicant?.full_name || data?.full_name || "Unknown",
                email: applicant?.email || "No email",
                role,
                summary
              }
            );
          } catch (e) {
            console.error(
              "\u274C APPROVER EMAIL FAIL",
              e
            );
            await sendDiscordAlert(
              env,
              `\u274C APPROVER EMAIL FAIL
${e}`
            );
          }
        }
        if (env.GOOGLE_SHEETS_WEBHOOK) {
          try {
            await logToSheets(
              env,
              {
                submissionId,
                role,
                status,
                email: applicant.email,
                timestamp: (/* @__PURE__ */ new Date()).toISOString()
              }
            );
          } catch (e) {
            console.error(
              "\u274C SHEETS FAIL",
              e
            );
            await sendDiscordAlert(
              env,
              `\u274C SHEETS FAIL
${e}`
            );
          }
        }
        await writeFirestore(
          env,
          token,
          `metrics/${submissionId}`,
          {
            submissionId,
            processed_at: (/* @__PURE__ */ new Date()).toISOString(),
            role,
            status,
            score: scoreValue,
            worker_version: "plras-consumer-v2.1-stable"
          }
        );
        message.ack();
      } catch (err) {
        await sendDiscordAlert(
          env,
          `\u274C QUEUE FAIL
${err}`
        );
        console.error(
          "\u274C QUEUE FAIL",
          err
        );
        if (message.attempts >= 3) {
          message.ack();
        } else {
          message.retry({
            delaySeconds: 60
          });
        }
      }
    }
  }
};
async function sendDiscordAlert(env, message) {
  if (!env.DISCORD_WEBHOOK_URL) {
    return;
  }
  try {
    await fetch(
      env.DISCORD_WEBHOOK_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          content: message
        })
      }
    );
  } catch (e) {
    console.error(
      "\u274C DISCORD ALERT FAIL",
      e
    );
  }
}
__name(sendDiscordAlert, "sendDiscordAlert");
async function sendEmailDirect(env, to, subject, html) {
  const payload = {
    service_id: env.EMAILJS_SERVICE_ID,
    template_id: env.EMAILJS_TEMPLATE_ID,
    user_id: env.EMAILJS_PUBLIC_KEY,
    accessToken: env.EMAILJS_PRIVATE_KEY,
    template_params: {
      to_email: to,
      subject,
      message: html
    }
  };
  const res = await fetch(
    "https://api.emailjs.com/api/v1.0/email/send",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    }
  );
  const text = await res.text();
  console.log(
    "\u{1F4E7} EMAIL:",
    text
  );
  if (!res.ok) {
    throw new Error(text);
  }
}
__name(sendEmailDirect, "sendEmailDirect");
function getApprovers(env, role) {
  const map = {
    dog_walker: env.APPROVER_DOG_WALKER,
    pet_sitter: env.APPROVER_PET_SITTER,
    trainer: env.APPROVER_TRAINER,
    groomer: env.APPROVER_GROOMER,
    pet_insurance: env.APPROVER_PET_INSURANCE,
    pet_cremation: env.APPROVER_PET_CREMATION,
    pet_food: env.APPROVER_PET_FOOD,
    pet_adoption: env.APPROVER_PET_ADOPTION,
    breeder: env.APPROVER_BREEDER,
    veterinarian: env.APPROVER_VETERINARIAN,
    others: env.APPROVER_OTHERS,
    pet_taxi: env.APPROVER_PET_TAXI,
    pet_shop: env.APPROVER_PET_SHOP,
    pet_relocation: env.APPROVER_PET_RELOCATION,
    admin: env.APPROVALS_EMAIL
  };
  const emails = map[role];
  if (!emails) {
    console.log(
      "\u26A0\uFE0F NO APPROVER FOR ROLE:",
      role
    );
    return [];
  }
  return emails.split(",").map((e) => e.trim()).filter(Boolean);
}
__name(getApprovers, "getApprovers");
async function sendApproverEmail(env, recipient, data) {
  const approve = `${env.APP_BASE_URL}/review?id=${data.submissionId}&action=approved&role=${data.role}&secret=${env.REVIEW_SECRET}`;
  const reject = `${env.APP_BASE_URL}/review?id=${data.submissionId}&action=rejected&role=${data.role}&secret=${env.REVIEW_SECRET}`;
  const html = `

<h2>
New application received
</h2>

<p>
<b>Submission ID:</b><br>
${data.submissionId}
</p>

<p>
<b>Name:</b><br>
${data.full_name}
</p>

<p>
<b>Role:</b><br>
${data.role}
</p>

<p>
<b>Email:</b><br>
${data.email}
</p>

<p>
<b>Summary:</b>
</p>

<pre>
${data.summary}
</pre>

<br>

<p>
<a href="${approve}">
\u2705 Approve
</a>
</p>

<p>
<a href="${reject}">
\u274C Reject
</a>
</p>

`;
  return await sendEmailDirect(
    env,
    recipient,
    `PLRAS Review - ${data.submissionId}`,
    html
  );
}
__name(sendApproverEmail, "sendApproverEmail");
async function logToSheets(env, data) {
  const res = await fetch(
    `${env.GOOGLE_SHEETS_WEBHOOK}?key=PLRAS_SECRET_123`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(
        data
      )
    }
  );
  console.log(
    "\u{1F4CA} SHEETS:",
    await res.text()
  );
}
__name(logToSheets, "logToSheets");
function extractFile(data) {
  if (!data?.details) {
    return null;
  }
  for (const item of data.details) {
    if (Array.isArray(
      item.value
    )) {
      const file = item.value[0];
      if (file?.url) {
        return file;
      }
    }
    if (item.value?.url) {
      return item.value;
    }
  }
  return null;
}
__name(extractFile, "extractFile");
async function uploadToDropbox(env, fileObj, submissionId, role) {
  const accessToken = await getDropboxAccessToken(
    env
  );
  const fileRes = await fetch(fileObj.url);
  if (!fileRes.ok) {
    throw new Error(
      "FILE FETCH FAIL"
    );
  }
  const buffer = await fileRes.arrayBuffer();
  const path = `/${role}/${submissionId}_${fileObj.name}`;
  const upload = await fetch(
    "https://content.dropboxapi.com/2/files/upload",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Dropbox-API-Arg": JSON.stringify({
          path,
          mode: "add",
          autorename: true
        }),
        "Content-Type": "application/octet-stream"
      },
      body: buffer
    }
  );
  if (!upload.ok) {
    throw new Error(
      await upload.text()
    );
  }
  const share = await fetch(
    "https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        path
      })
    }
  );
  const link = await share.json();
  if (link.error?.[".tag"] === "shared_link_already_exists") {
    const existing = await fetch(
      "https://api.dropboxapi.com/2/sharing/list_shared_links",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          path,
          direct_only: true
        })
      }
    );
    const existingData = await existing.json();
    return existingData.links?.[0]?.url?.replace(
      "?dl=0",
      "?raw=1"
    ) || null;
  }
  return link.url?.replace(
    "?dl=0",
    "?raw=1"
  ) || null;
}
__name(uploadToDropbox, "uploadToDropbox");
async function getDropboxAccessToken(env) {
  const res = await fetch(
    "https://api.dropboxapi.com/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `grant_type=refresh_token&refresh_token=${env.DROPBOX_REFRESH_TOKEN}&client_id=${env.DROPBOX_APP_KEY}&client_secret=${env.DROPBOX_APP_SECRET}`
    }
  );
  const data = await res.json();
  if (!data.access_token) {
    throw new Error(
      JSON.stringify(data)
    );
  }
  return data.access_token;
}
__name(getDropboxAccessToken, "getDropboxAccessToken");
function score(data, url) {
  let s = 0;
  if (data?.applicant?.full_name) {
    s += 10;
  }
  if (data?.applicant?.email) {
    s += 10;
  }
  if (url) {
    s += 30;
  }
  if (data?.details?.length > 5) {
    s += 20;
  }
  return s;
}
__name(score, "score");
function buildFirestoreData(data, fileObj, url, scoreValue, status, submissionId) {
  return {
    submissionId,
    role: data.role,
    status,
    score: scoreValue,
    created_at: (/* @__PURE__ */ new Date()).toISOString(),
    applicant: data.applicant || {},
    files: {
      dropbox_url: url,
      original_name: fileObj?.name || null
    },
    details: data.details || []
  };
}
__name(buildFirestoreData, "buildFirestoreData");
async function submissionExists(env, token, submissionId) {
  const url = `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all/${submissionId}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return res.ok;
}
__name(submissionExists, "submissionExists");
async function writeAuditLog(env, token, data) {
  const id = `${data.submissionId}_${Date.now()}`;
  await writeFirestore(
    env,
    token,
    `audit_logs/${id}`,
    {
      submissionId: data.submissionId,
      action: data.action,
      role: data.role,
      reviewedAt: (/* @__PURE__ */ new Date()).toISOString(),
      reviewer: "admin",
      ip: data.ip || "unknown",
      user_agent: data.user_agent || "unknown"
    }
  );
}
__name(writeAuditLog, "writeAuditLog");
async function writeFirestore(env, token, path, data, updateMask = []) {
  let url = `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/${path}`;
  if (updateMask.length) {
    const params = updateMask.map(
      (field) => `updateMask.fieldPaths=${encodeURIComponent(field)}`
    ).join("&");
    url += `?${params}`;
  }
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      fields: encodeFirestore(
        data
      )
    })
  });
  if (!res.ok) {
    throw new Error(
      await res.text()
    );
  }
}
__name(writeFirestore, "writeFirestore");
function encodeFirestore(obj) {
  const encode = /* @__PURE__ */ __name((v) => {
    if (v === null) {
      return {
        nullValue: null
      };
    }
    if (typeof v === "string") {
      return {
        stringValue: v
      };
    }
    if (typeof v === "number") {
      return {
        doubleValue: v
      };
    }
    if (typeof v === "boolean") {
      return {
        booleanValue: v
      };
    }
    if (Array.isArray(v)) {
      return {
        arrayValue: {
          values: v.map(encode)
        }
      };
    }
    if (typeof v === "object") {
      return {
        mapValue: {
          fields: Object.fromEntries(
            Object.entries(v).map(
              ([k, val]) => [
                k,
                encode(val)
              ]
            )
          )
        }
      };
    }
    return {
      stringValue: String(v)
    };
  }, "encode");
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [
      k,
      encode(v)
    ])
  );
}
__name(encodeFirestore, "encodeFirestore");
async function getGoogleAccessToken(env) {
  const now = Math.floor(
    Date.now() / 1e3
  );
  const header = {
    alg: "RS256",
    typ: "JWT"
  };
  const claim = {
    iss: env.GCP_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };
  const enc = /* @__PURE__ */ __name((obj) => btoa(
    JSON.stringify(obj)
  ).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"), "enc");
  const unsigned = `${enc(header)}.${enc(claim)}`;
  const pem = env.GCP_PRIVATE_KEY.replace(
    /\\n/g,
    "\n"
  );
  const binary = Uint8Array.from(
    atob(
      pem.split(
        "-----"
      )[2]
    ),
    (c) => c.charCodeAt(0)
  );
  const key = await crypto.subtle.importKey(
    "pkcs8",
    binary,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );
  const jwt = `${unsigned}.${btoa(
    String.fromCharCode(
      ...new Uint8Array(sig)
    )
  ).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")}`;
  const res = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    }
  );
  const json = await res.json();
  if (!json.access_token) {
    throw new Error(
      JSON.stringify(json)
    );
  }
  return json.access_token;
}
__name(getGoogleAccessToken, "getGoogleAccessToken");
function getAdminHTML(data, reviewSecret) {
  const documents = data.documents || [];
  const cards = documents.map((doc) => {
    const fields = doc.fields || {};
    const submissionId = fields.submissionId?.stringValue || "N/A";
    const role = fields.role?.stringValue || "Unknown";
    const status = fields.status?.stringValue || "pending";
    const score2 = fields.score?.doubleValue || 0;
    const created = fields.created_at?.stringValue || "";
    const reviewedAt = fields.reviewed_at?.stringValue || "-";
    const reviewedBy = fields.reviewed_by?.stringValue || "-";
    const applicant = fields.applicant?.mapValue?.fields || {};
    const name = applicant.full_name?.stringValue || "Unknown";
    const email = applicant.email?.stringValue || "No email";
    const details = fields.details?.arrayValue?.values || [];
    const summary = JSON.stringify(details).substring(0, 120);
    return `

<tr class="application-row">

<td>
${submissionId}
</td>

<td>
${role}
</td>

<td>

<span
style="
padding:6px 12px;
border-radius:999px;
font-size:12px;
font-weight:bold;
color:white;
background:${status === "approved" ? "#16a34a" : status === "rejected" ? "#dc2626" : "#ca8a04"};
"
>

${status}

</span>

</td>

<td>
${email}
</td>

<td>
${name}
</td>

<td
style="
max-width:300px;
overflow:hidden;
text-overflow:ellipsis;
white-space:nowrap;
"
>
${summary}
</td>

<td>
${score2}
</td>

<td>
${created}
</td>

<td>
${reviewedAt}
</td>

<td>

<b>Reviewer:</b>
${reviewedBy}

<br>

<b>Submission:</b>
${submissionId}

</td>

<td>

<button
onclick="
reviewApplication(
'${submissionId}',
'approved',
'${role}'
)
"
style="
background:#16a34a;
color:white;
padding:8px 14px;
border:none;
border-radius:8px;
cursor:pointer;
"
>
Approve
</button>

<button
onclick="
reviewApplication(
'${submissionId}',
'rejected',
'${role}'
)
"
style="
background:#dc2626;
color:white;
padding:8px 14px;
border:none;
border-radius:8px;
cursor:pointer;
margin-left:8px;
"
>
Reject
</button>

</td>

</tr>

`;
  }).join("");
  return `

<!DOCTYPE html>
<html>

<head>

<title>
PLRAS Admin Dashboard
</title>

<style>

body{
  font-family:Arial;
  background:#f3f4f6;
  padding:30px;
}

h1{
  margin-bottom:20px;
}

.topbar{
  display:flex;
  gap:10px;
  margin-bottom:20px;
}

button{
  padding:12px 18px;
  border:none;
  border-radius:8px;
  cursor:pointer;
}

.reload{
  background:#2563eb;
  color:white;
}

.logout{
  background:#dc2626;
  color:white;
}

table{
  width:100%;
  border-collapse:collapse;
  background:white;
}

th,
td{
  border:1px solid #ddd;
  padding:12px;
  text-align:left;
  vertical-align:top;
}

th{
  background:#111827;
  color:white;
}

tr:nth-child(even){
  background:#f9fafb;
}

.search{
  width:300px;
  padding:10px;
  margin-bottom:20px;
  border-radius:8px;
  border:1px solid #ccc;
}

</style>

</head>

<body>

<h1>
PLRAS Admin Dashboard \u{1F680}
</h1>

<input
id="searchBox"
class="search"
placeholder="Search applications..."
/>

<div class="topbar">

<button
class="reload"
onclick="location.reload()"
>
Reload
</button>

<button
class="logout"
onclick="logout()"
>
Logout
</button>

</div>

<table>

<thead>

<tr>

<th>ID</th>
<th>Role</th>
<th>Status</th>
<th>Email</th>
<th>Name</th>
<th>Summary</th>
<th>Score</th>
<th>Created</th>
<th>Reviewed</th>
<th>Audit</th>
<th>Actions</th>

</tr>

</thead>

<tbody>

${cards || `
<tr>
<td colspan="11">
No applications found
</td>
</tr>
`}

</tbody>

</table>

<script>

document
.getElementById("searchBox")
.addEventListener(
  "input",
  function(){

    const value =
      this.value.toLowerCase();

    document
    .querySelectorAll(
      ".application-row"
    )
    .forEach(row => {

      row.style.display =
        row.innerText
          .toLowerCase()
          .includes(value)
        ? ""
        : "none";

    });

  }
);

async function logout(){

  await fetch("/logout");

  location.href="/login";
}

async function reviewApplication(
  id,
  action,
  role
){

  const res =
    await fetch(
      \`/review?id=\${id}&action=\${action}&role=\${role}\`
    );

  if(res.ok){

    alert(\`\u2705 \${action}\`);

    location.reload();

  }else{

    alert("Review failed");

  }

}

<\/script>

</body>
</html>

`;
}
__name(getAdminHTML, "getAdminHTML");

// ../../../../../../../../AppData/Roaming/npm/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
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

// .wrangler/tmp/bundle-hQM487/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default
];
var middleware_insertion_facade_default = index_default;

// ../../../../../../../../AppData/Roaming/npm/node_modules/wrangler/templates/middleware/common.ts
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

// .wrangler/tmp/bundle-hQM487/middleware-loader.entry.ts
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
