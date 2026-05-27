const WORKER_VERSION =
  "plras-consumer-v2.1-stable";

export default {

  async fetch(req, env) {

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,x-api-key"
    };

// =========================
// RATE LIMIT
// =========================
if (
  env.RATE_LIMIT_KV &&
  typeof env.RATE_LIMIT_KV.get === "function"
) {
  const ip =
    req.headers.get(
      "CF-Connecting-IP"
    ) || "unknown";

  const key =
    `ratelimit:${ip}`;

  const current =
    Number(
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

// =========================
// LOGIN PAGE
// =========================
if (
  url.pathname === "/login" &&
  req.method === "GET"
) {

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

</script>

</body>
</html>
`,
{
headers:{
"Content-Type":"text/html",
...corsHeaders
}
}
);

}

    // =========================
    // ADMIN COOKIE AUTH
    // =========================
    const cookie =
      req.headers.get("Cookie") || "";

    const authenticated =
cookie
  .split(";")
  .map(c => c.trim())
  .includes(
        `plras_admin=${env.ADMIN_PASSWORD}`
      );

    // Allow login endpoint
    const publicPaths = [
  "/login",
  "/favicon.ico"
];

    // Block all admin routes
    if (
      !authenticated &&
      !publicPaths.includes(url.pathname)
    ) {

      return Response.redirect(
        `${url.origin}/login`,
        302
      );
    }

    // =========================
    // LOGIN
    // =========================
    if (
      url.pathname === "/login" &&
      req.method === "POST"
    ) {

      const body =
        await req.json();

      const password =
        body.password;

      if (
        password ===
        env.ADMIN_PASSWORD
      ) {

        return new Response(
          JSON.stringify({
            ok: true
          }),
          {
            headers: {
              "Content-Type":
                "application/json",

              "Set-Cookie":
                `plras_admin=${env.ADMIN_PASSWORD}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,

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

    // =========================
    // LOGOUT
    // =========================
    if (
      url.pathname === "/logout"
    ) {

      return new Response(
        "Logged out",
        {
          headers: {
            "Set-Cookie":
              "plras_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",

            ...corsHeaders
          }
        }
      );
    }

    // =========================
// REVIEW AUTH
// =========================
if (
  url.pathname === "/review"
) {

  const secret =
    url.searchParams.get(
      "secret"
    );

  if (
    !authenticated &&
    secret !== env.REVIEW_SECRET
  ) {

    return new Response(
      "Unauthorized",
      {
        status: 401,
        headers: corsHeaders
      }
    );
  }
}

    // =========================
    // APPLICATIONS AUTH
    // =========================
    if (
      url.pathname === "/applications"
    ) {

      const apiKey =
        req.headers.get(
          "x-api-key"
        );

      if (
        apiKey !==
        env.ADMIN_SECRET
      ) {

        return new Response(
          "Unauthorized",
          {
            status: 401,
            headers: corsHeaders
          }
        );
      }
    }

    // =========================
    // ADMIN DASHBOARD
    // =========================
    if (
      url.pathname === "/" ||
      url.pathname === "/admin"
    ) {

      const token =
        await getGoogleAccessToken(env);

      const res =
        await fetch(
          `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all`,
          {
            headers: {
              Authorization:
                `Bearer ${token}`
            }
          }
        );

      const data =
        await res.json();

      return new Response(
        getAdminHTML(
          data,
          env.REVIEW_SECRET
        ),
        {
          headers: {
            "Content-Type":
              "text/html;charset=UTF-8",
            ...corsHeaders
          }
        }
      );
    }

    // =========================
    // REVIEW
    // =========================
    if (
      url.pathname === "/review"
    ) {

      const submissionId =
        url.searchParams.get("id");

      const action =
        url.searchParams.get("action");

      let role =
        url.searchParams.get("role");

      if (
        !submissionId ||
        !action
      ) {

        return new Response(
          "Missing params",
          {
            headers: corsHeaders
          }
        );
      }

      const token =
        await getGoogleAccessToken(
          env
        );

      // =========================
      // AUTO RESOLVE ROLE
      // =========================
      if (!role) {

        const lookup =
          await fetch(
            `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all/${submissionId}`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );

        const lookupData =
          await lookup.json();

        role =
          lookupData?.fields?.role?.stringValue ||
          null;
      }

      // =========================
      // ROLE WRITE
      // =========================
      if (role) {

        await writeFirestore(
          env,
          token,
          `providers/${role}/applications/${submissionId}`,
          {
            status: action,
            reviewed_at:
              new Date().toISOString()
          }
        );
      }

      // =========================
      // GLOBAL WRITE
      // =========================
      await writeFirestore(
        env,
        token,
        `providers_all/${submissionId}`,
        {
          status: action,
          reviewed_at:
            new Date().toISOString()
        }
      );

      // =========================
      // AUDIT LOG
      // =========================
      console.log(
        "📝 WRITING AUDIT LOG"
      );

      await writeAuditLog(
        env,
        token,
        {
          submissionId,
          action,
          role,

          timestamp:
            new Date().toISOString(),

          ip:
            req.headers.get(
              "CF-Connecting-IP"
            ) || "unknown",

          user_agent:
            req.headers.get(
              "User-Agent"
            ) || "unknown"
        }
      );

      console.log(
        "✅ AUDIT LOG WRITTEN"
      );

      return new Response(
        `✅ ${action}`,
        {
          headers: corsHeaders
        }
      );
    }

    // =========================
    // APPLICATIONS
    // =========================
    if (
      url.pathname === "/applications"
    ) {

      const token =
        await getGoogleAccessToken(
          env
        );

      const res =
        await fetch(
          `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all`,
          {
            headers: {
              Authorization:
                `Bearer ${token}`
            }
          }
        );

      const data =
        await res.json();

      return new Response(
        JSON.stringify(data),
        {
          headers: {
            "Content-Type":
              "application/json",
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
      "🔥 CONSUMER STARTED"
    );

    for (
      const message of batch.messages
    ) {

      try {

        // =========================
        // PARSE
        // =========================
        let data;

        try {

          data =
            typeof message.body ===
            "string"
              ? JSON.parse(
                  message.body
                )
              : message.body;

        } catch (e) {

          console.error(
            "❌ JSON PARSE FAIL"
          );

          message.ack();
          continue;
        }

        // =========================
        // IDS
        // =========================
        const submissionId =
          data.submissionId ||
          crypto.randomUUID();

        const role =
          data.role;

        if (!role) {
          throw new Error(
            "ROLE MISSING"
          );
        }

        console.log(
          "📌 ID:",
          submissionId
        );

        // =========================
        // GOOGLE TOKEN
        // =========================
        const token =
          await getGoogleAccessToken(
            env
          );

        // =========================
        // IDEMPOTENCY
        // =========================
        const exists =
          await submissionExists(
            env,
            token,
            submissionId
          );

        if (exists) {

          console.log(
            "⚠️ DUPLICATE BLOCKED"
          );

          message.ack();
          continue;
        }

        // =========================
        // FILE
        // =========================
        const fileObj =
          extractFile(data);

        let dropboxUrl =
          null;

        if (fileObj?.url) {

          try {

            dropboxUrl =
              await uploadToDropbox(
                env,
                fileObj,
                submissionId,
                role
              );

            console.log(
              "✅ DROPBOX OK"
            );

          } catch (e) {

            console.error(
              "❌ DROPBOX FAIL",
              e
            );

            await sendDiscordAlert(
              env,
              `❌ DROPBOX FAIL\n${e}`
            );
          }
        }

        // =========================
        // SCORE
        // =========================
        const scoreValue =
          score(
            data,
            dropboxUrl
          );

        // =========================
        // STATUS
        // =========================
        let status =
          "pending";

        if (
          !data?.applicant?.email?.includes(
            "@"
          )
        ) {

          status =
            "rejected";
        }

        // =========================
        // FIRESTORE OBJECT
        // =========================
        const firestoreData =
          buildFirestoreData(
            data,
            fileObj,
            dropboxUrl,
            scoreValue,
            status,
            submissionId
          );

        // =========================
        // PATHS
        // =========================
        const rolePath =
          `providers/${role}/applications/${submissionId}`;

        const globalPath =
          `providers_all/${submissionId}`;

        // =========================
        // FIRESTORE WRITES
        // =========================
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
            "✅ FIRESTORE OK"
          );

          // =========================
          // AUDIT LOG
          // =========================
          try {

            await writeAuditLog(
              env,
              token,
              {
                submissionId,
                action:
                  "APPLICATION_CREATED",

                role,

                timestamp:
                  new Date().toISOString(),

                ip: "queue",

                user_agent:
                  "cloudflare-queue"
              }
            );

            console.log(
              "✅ AUDIT CREATED"
            );

          } catch (e) {

            console.error(
              "❌ AUDIT FAIL",
              e
            );
          }

        } catch (e) {

          console.error(
            "❌ FIRESTORE FAIL",
            e
          );

          await sendDiscordAlert(
            env,
            `❌ FIRESTORE FAIL\n${e}`
          );

          throw e;
        }

        // =========================
        // EMAILS
        // =========================
        const applicant =
          data?.applicant || {};

        if (
          applicant.email &&
          env.EMAILJS_SERVICE_ID
        ) {

          try {

            await sendEmailDirect(
              env,
              applicant.email,
              "Application Received — Pets Life Resources",
              `<p>Hi ${applicant.full_name || "User"}, your application has been received.</p>`
            );

          } catch (e) {

            console.error(
              "❌ APPLICANT EMAIL FAIL",
              e
            );

            await sendDiscordAlert(
              env,
              `❌ EMAIL FAIL\n${e}`
            );
          }
        }

     // =========================
// APPROVAL EMAILS
// =========================
const approvers =
  getApprovers(
    env,
    role
  );

for (
  const approverEmail of approvers
) {

  try {

    const summary =
      JSON.stringify(
        data.details || [],
        null,
        2
      ).substring(0,3000);

    await sendApproverEmail(
      env,
      approverEmail,
      {
        submissionId,

        full_name:
          applicant?.full_name ||
          data?.full_name ||
          "Unknown",

        email:
          applicant?.email ||
          "No email",

        role,

        summary
      }
    );

  } catch (e) {

    console.error(
      "❌ APPROVER EMAIL FAIL",
      e
    );

    await sendDiscordAlert(
      env,
      `❌ APPROVER EMAIL FAIL\n${e}`
    );

  }

}

        // =========================
        // SHEETS
        // =========================
        if (
          env.GOOGLE_SHEETS_WEBHOOK
        ) {

          try {

            await logToSheets(
              env,
              {
                submissionId,
                role,
                status,
                email:
                  applicant.email,
                timestamp:
                  new Date().toISOString()
              }
            );

          } catch (e) {

            console.error(
              "❌ SHEETS FAIL",
              e
            );

            await sendDiscordAlert(
              env,
              `❌ SHEETS FAIL\n${e}`
            );
          }
        }

        await writeFirestore(
          env,
          token,
          `metrics/${submissionId}`,
          {
            submissionId,
            processed_at:
              new Date().toISOString(),

            role,

            status,

            score: scoreValue,

            worker_version:
  "plras-consumer-v2.1-stable"
          }
        );

        // =========================
        // SUCCESS
        // =========================
        message.ack();

      } catch (err) {

        await sendDiscordAlert(
          env,
          `❌ QUEUE FAIL\n${err}`
        );

        console.error(
          "❌ QUEUE FAIL",
          err
        );

        if (
          message.attempts >= 3
        ) {

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

// =========================
// DISCORD ALERT
// =========================
async function sendDiscordAlert(
  env,
  message
) {

  if (
    !env.DISCORD_WEBHOOK_URL
  ) {
    return;
  }

  try {

    await fetch(
      env.DISCORD_WEBHOOK_URL,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          content: message
        })
      }
    );

  } catch (e) {

    console.error(
      "❌ DISCORD ALERT FAIL",
      e
    );
  }
}

// =========================
// EMAIL (EMAILJS)
// =========================
async function sendEmailDirect(
  env,
  to,
  subject,
  html
) {

  const payload = {

    service_id:
      env.EMAILJS_SERVICE_ID,

    template_id:
      env.EMAILJS_TEMPLATE_ID,

    user_id:
      env.EMAILJS_PUBLIC_KEY,

    accessToken:
      env.EMAILJS_PRIVATE_KEY,

    template_params: {

      to_email: to,

      subject,

      message: html
    }
  };

  const res =
    await fetch(
      "https://api.emailjs.com/api/v1.0/email/send",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify(payload)
      }
    );

  const text =
    await res.text();

  console.log(
    "📧 EMAIL:",
    text
  );

  if (!res.ok) {

    throw new Error(text);
  }
}

// =========================
// APPROVERS
// =========================
function getApprovers(
  env,
  role
) {

  const map = {

    dog_walker:
      env.APPROVER_DOG_WALKER,

    pet_sitter:
      env.APPROVER_PET_SITTER,

    trainer:
      env.APPROVER_TRAINER,

    groomer:
      env.APPROVER_GROOMER,

    pet_insurance:
      env.APPROVER_PET_INSURANCE,

    pet_cremation:
      env.APPROVER_PET_CREMATION,

    pet_food:
      env.APPROVER_PET_FOOD,

    pet_adoption:
      env.APPROVER_PET_ADOPTION,

    breeder:
      env.APPROVER_BREEDER,

    veterinarian:
      env.APPROVER_VETERINARIAN,

    others:
      env.APPROVER_OTHERS,

    pet_taxi:
      env.APPROVER_PET_TAXI,

    pet_shop:
      env.APPROVER_PET_SHOP,

    pet_relocation:
      env.APPROVER_PET_RELOCATION,

    admin:
      env.APPROVALS_EMAIL
  };

  const emails =
    map[role];

  if (!emails) {

    console.log(
      "⚠️ NO APPROVER FOR ROLE:",
      role
    );

    return [];
  }

  return emails
    .split(",")
    .map(e => e.trim())
    .filter(Boolean);
}
// =========================
// APPROVER EMAIL
// =========================
async function sendApproverEmail(
  env,
  recipient,
  data
){

  const approve =
    `${env.APP_BASE_URL}/review?id=${data.submissionId}&action=approved&role=${data.role}&secret=${env.REVIEW_SECRET}`;

  const reject =
    `${env.APP_BASE_URL}/review?id=${data.submissionId}&action=rejected&role=${data.role}&secret=${env.REVIEW_SECRET}`;

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
✅ Approve
</a>
</p>

<p>
<a href="${reject}">
❌ Reject
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

// =========================
// SHEETS
// =========================
async function logToSheets(
  env,
  data
) {

  const res =
    await fetch(
      `${env.GOOGLE_SHEETS_WEBHOOK}?key=PLRAS_SECRET_123`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify(
          data
        )
      }
    );

  console.log(
    "📊 SHEETS:",
    await res.text()
  );
}

// =========================
// FILE EXTRACTION
// =========================
function extractFile(data) {

  if (!data?.details) {
    return null;
  }

  for (
    const item of data.details
  ) {

    if (
      Array.isArray(
        item.value
      )
    ) {

      const file =
        item.value[0];

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

// =========================
// DROPBOX
// =========================
async function uploadToDropbox(
  env,
  fileObj,
  submissionId,
  role
) {

  const accessToken =
    await getDropboxAccessToken(
      env
    );

  const fileRes =
    await fetch(fileObj.url);

  if (!fileRes.ok) {
    throw new Error(
      "FILE FETCH FAIL"
    );
  }

  const buffer =
    await fileRes.arrayBuffer();

  const path =
    `/${role}/${submissionId}_${fileObj.name}`;

  // =========================
  // UPLOAD
  // =========================
  const upload =
    await fetch(
      "https://content.dropboxapi.com/2/files/upload",
      {
        method: "POST",
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "Dropbox-API-Arg":
            JSON.stringify({
              path,
              mode: "add",
              autorename: true
            }),
          "Content-Type":
            "application/octet-stream"
        },
        body: buffer
      }
    );

  if (!upload.ok) {
    throw new Error(
      await upload.text()
    );
  }

  // =========================
  // =========================
// SHARE LINK
// =========================
const share =
  await fetch(
    "https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings",
    {
      method: "POST",
      headers: {
        Authorization:
          `Bearer ${accessToken}`,
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify({
        path
      })
    }
  );

const link =
  await share.json();

if (
  link.error?.[".tag"] ===
  "shared_link_already_exists"
) {

  const existing =
    await fetch(
      "https://api.dropboxapi.com/2/sharing/list_shared_links",
      {
        method: "POST",
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          path,
          direct_only: true
        })
      }
    );

  const existingData =
    await existing.json();

  return (
    existingData.links?.[0]?.url
      ?.replace(
        "?dl=0",
        "?raw=1"
      ) || null
  );
}

return (
  link.url?.replace(
    "?dl=0",
    "?raw=1"
  ) || null
);
}

// =========================
// DROPBOX TOKEN
// =========================
async function getDropboxAccessToken(
  env
) {

  const res =
    await fetch(
      "https://api.dropboxapi.com/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body:
          `grant_type=refresh_token` +
          `&refresh_token=${env.DROPBOX_REFRESH_TOKEN}` +
          `&client_id=${env.DROPBOX_APP_KEY}` +
          `&client_secret=${env.DROPBOX_APP_SECRET}`
      }
    );

  const data =
    await res.json();

  if (
    !data.access_token
  ) {

    throw new Error(
      JSON.stringify(data)
    );
  }

  return data.access_token;
}

// =========================
// SCORE
// =========================
function score(
  data,
  url
) {

  let s = 0;

  if (
    data?.applicant?.full_name
  ) {
    s += 10;
  }

  if (
    data?.applicant?.email
  ) {
    s += 10;
  }

  if (url) {
    s += 30;
  }

  if (
    data?.details?.length > 5
  ) {
    s += 20;
  }

  return s;
}

// =========================
// FIRESTORE DATA
// =========================
function buildFirestoreData(
  data,
  fileObj,
  url,
  scoreValue,
  status,
  submissionId
) {

  return {
    submissionId,
    role: data.role,
    status,
    score: scoreValue,

    created_at:
      new Date().toISOString(),

    applicant:
      data.applicant || {},

    files: {
      dropbox_url: url,
      original_name:
        fileObj?.name || null
    },

    details:
      data.details || []
  };
}

// =========================
// IDEMPOTENCY CHECK
// =========================
async function submissionExists(
  env,
  token,
 submissionId
) {

  const url =
    `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/providers_all/${submissionId}`;

  const res =
    await fetch(url, {
      headers: {
        Authorization:
          `Bearer ${token}`
      }
    });

  return res.ok;
}

// =========================
// AUDIT LOG
// =========================
async function writeAuditLog(
  env,
  token,
  data
) {

  const id =
    `${data.submissionId}_${Date.now()}`;

  await writeFirestore(
    env,
    token,
    `audit_logs/${id}`,
    {
      submissionId:
        data.submissionId,

      action:
        data.action,

      role:
        data.role,

      reviewedAt:
        new Date().toISOString(),

      reviewer:
        "admin",

      ip:
        data.ip || "unknown",

      user_agent:
        data.user_agent || "unknown"
    }
  );
}

// =========================
// FIRESTORE WRITE
// =========================
async function writeFirestore(
  env,
  token,
  path,
  data,
  updateMask = []
) {

  let url =
    `https://firestore.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/databases/(default)/documents/${path}`;

  if (
    updateMask.length
  ) {

    const params =
      updateMask
        .map(
          field =>
            `updateMask.fieldPaths=${encodeURIComponent(field)}`
        )
        .join("&");

    url += `?${params}`;
  }

  const res =
    await fetch(url, {
      method: "PATCH",
      headers: {
        Authorization:
          `Bearer ${token}`,
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify({
        fields:
          encodeFirestore(
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

// =========================
// FIRESTORE ENCODER
// =========================
function encodeFirestore(
  obj
) {

  const encode = (v) => {

    if (v === null) {

      return {
        nullValue: null
      };
    }

    if (
      typeof v === "string"
    ) {

      return {
        stringValue: v
      };
    }

    if (
      typeof v === "number"
    ) {

      return {
        doubleValue: v
      };
    }

    if (
      typeof v === "boolean"
    ) {

      return {
        booleanValue: v
      };
    }

    if (
      Array.isArray(v)
    ) {

      return {
        arrayValue: {
          values:
            v.map(encode)
        }
      };
    }

    if (
      typeof v === "object"
    ) {

      return {
        mapValue: {
          fields:
            Object.fromEntries(
              Object.entries(v)
                .map(
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
      stringValue:
        String(v)
    };
  };

  return Object.fromEntries(
    Object.entries(obj)
      .map(([k, v]) => [
        k,
        encode(v)
      ])
  );
}

// =========================
// GOOGLE TOKEN
// =========================
async function getGoogleAccessToken(
  env
) {

  const now =
    Math.floor(
      Date.now() / 1000
    );

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const claim = {
    iss:
      env.GCP_CLIENT_EMAIL,

    scope:
      "https://www.googleapis.com/auth/datastore",

    aud:
      "https://oauth2.googleapis.com/token",

    iat: now,
    exp: now + 3600
  };

  const enc = (obj) =>
    btoa(
      JSON.stringify(obj)
    )
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const unsigned =
    `${enc(header)}.${enc(claim)}`;

  const pem =
    env.GCP_PRIVATE_KEY
      .replace(
        /\\n/g,
        "\n"
      );

  const binary =
    Uint8Array.from(
      atob(
        pem.split(
          "-----"
        )[2]
      ),
      c =>
        c.charCodeAt(0)
    );

  const key =
    await crypto.subtle.importKey(
      "pkcs8",
      binary,
      {
        name:
          "RSASSA-PKCS1-v1_5",
        hash:
          "SHA-256"
      },
      false,
      ["sign"]
    );

  const sig =
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder()
        .encode(unsigned)
    );

  const jwt =
    `${unsigned}.${btoa(
      String.fromCharCode(
        ...new Uint8Array(sig)
      )
    )
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")}`;

  const res =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body:
          `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
      }
    );

  const json =
    await res.json();

  if (
    !json.access_token
  ) {

    throw new Error(
      JSON.stringify(json)
    );
  }

  return json.access_token;
}

// =========================
// ADMIN HTML
// =========================
function getAdminHTML(
  data,
  reviewSecret
) {

  const documents =
    data.documents || [];

  const cards =
    documents.map(doc => {

      const fields =
        doc.fields || {};

      const submissionId =
        fields.submissionId?.stringValue || "N/A";

      const role =
        fields.role?.stringValue || "Unknown";

      const status =
        fields.status?.stringValue || "pending";

      const score =
        fields.score?.doubleValue || 0;

      const created =
        fields.created_at?.stringValue || "";

      const reviewedAt =
        fields.reviewed_at?.stringValue || "-";

      const reviewedBy =
        fields.reviewed_by?.stringValue || "-";

      const applicant =
        fields.applicant?.mapValue?.fields || {};

      const name =
        applicant.full_name?.stringValue || "Unknown";

      const email =
        applicant.email?.stringValue || "No email";

      const details =
        fields.details?.arrayValue?.values || [];

      const summary =
        JSON.stringify(details)
          .substring(0,120);

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
background:${
  status === "approved"
    ? "#16a34a"
    : status === "rejected"
    ? "#dc2626"
    : "#ca8a04"
};
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
${score}
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
PLRAS Admin Dashboard 🚀
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

    alert(\`✅ \${action}\`);

    location.reload();

  }else{

    alert("Review failed");

  }

}

</script>

</body>
</html>

`;
}

