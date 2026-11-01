import "dotenv/config";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

type Session = {
  sub: string;
  email?: string;
  tokens: {
    accessToken: string;
    idToken: string;
  };
  verifiedClaims: {
    issuer: string;
    audience: string;
    authTime?: number;
  };
};

type OpenIdConfiguration = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
};

type JwkKey = {
  kty: string;
  kid: string;
  use?: string;
  alg?: string;
  n: string;
  e: string;
};

type JwksResponse = {
  keys: JwkKey[];
};

type IdTokenHeader = {
  alg: string;
  kid: string;
};

type IdTokenPayload = {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  email?: string;
};

const app = new Hono();
const states = new Map<string, true>();
const sessions = new Map<string, Session>();
let oidcConfig: OpenIdConfiguration;

const requiredEnv = (name: string): string => {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
};

const randomString = (bytes: number): string => {
  return randomBytes(bytes).toString("base64url");
};

const generatePkce = (): { verifier: string; challenge: string } => {
  const verifier = randomString(32);
  const challenge = createHash("sha256").update(verifier).digest("base64url");

  return { verifier, challenge };
};

const fetchOpenIdConfiguration = async (issuerUrl: string): Promise<OpenIdConfiguration> => {
  const trimmedIssuer = issuerUrl.replace(/\/+$/, "");
  const configUrl = `${trimmedIssuer}/.well-known/openid-configuration`;

  const response = await fetch(configUrl);

  if (!response.ok) {
    throw new Error(`failed to fetch OpenID configuration from ${configUrl}: ${response.statusText}`);
  }

  const json = await response.json() as OpenIdConfiguration;

  return {
    issuer: json.issuer,
    authorization_endpoint: json.authorization_endpoint,
    token_endpoint: json.token_endpoint,
    jwks_uri: json.jwks_uri,
    userinfo_endpoint: json.userinfo_endpoint,
  };
};

const fetchJwk = async (jwksUri: string, kid: string): Promise<JwkKey> => {
  const response = await fetch(jwksUri);

  if (!response.ok) {
    throw new Error(`failed to fetch JWKS from ${jwksUri}`);
  }

  const jwks = await response.json() as JwksResponse;
  const key = jwks.keys.find((k) => k.kid === kid);

  if (!key) {
    throw new Error(`key with kid "${kid}" not found in JWKS`);
  }

  return key;
};

const verifyIdToken = async (
  token: string,
  jwksUri: string,
  expectedIssuer: string,
  expectedAudience: string,
  expectedNonce: string,
): Promise<IdTokenPayload> => {
  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("invalid JWT format");
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")) as IdTokenHeader;
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as IdTokenPayload;

  // OpenID Connect Core 1.0 Section 3.1.3.7 — alg の検証
  if (header.alg !== "RS256") {
    throw new Error(`unsupported signature algorithm: ${header.alg}`);
  }

  // 1. JWKS から公開鍵を取得して署名を検証
  const jwk = await fetchJwk(jwksUri, header.kid);
  const publicKey = createPublicKey({ key: jwk as any, format: "jwk" });

  const data = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(signatureB64, "base64url");

  const isValidSignature = verify("sha256", data, publicKey, signature);

  if (!isValidSignature) {
    throw new Error("ID token signature verification failed");
  }

  // 2. OpenID Connect Core 1.0 Section 3.1.3.7 — クレームの厳密な検証
  if (payload.iss !== expectedIssuer) {
    throw new Error(`issuer mismatch: expected ${expectedIssuer}, got ${payload.iss}`);
  }

  if (payload.aud !== expectedAudience) {
    throw new Error(`audience mismatch: expected ${expectedAudience}, got ${payload.aud}`);
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new Error("ID token is expired");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error(`nonce mismatch: expected ${expectedNonce}, got ${payload.nonce}`);
  }

  return payload;
};

app.get("/", (c) => {
  return c.html('<a href="/auth/login">Login</a>');
});

app.get("/auth/login", (c) => {
  const state = randomString(32);
  const nonce = randomString(16);
  const { verifier, challenge } = generatePkce();

  states.set(state, true);

  setCookie(c, "cv", verifier, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 600,
  });

  setCookie(c, "nonce", nonce, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 600,
  });

  const authorizationUrl = new URL(oidcConfig.authorization_endpoint);

  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", requiredEnv("OIDC_CLIENT_ID"));
  authorizationUrl.searchParams.set("redirect_uri", requiredEnv("OIDC_REDIRECT_URI"));
  authorizationUrl.searchParams.set("scope", "openid profile email");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("nonce", nonce);

  // RFC 7636 Section 4.3 — code_challenge と計算方式 S256 を付加
  authorizationUrl.searchParams.set("code_challenge", challenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");

  return c.redirect(authorizationUrl.toString());
});

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");

  if (!code || !state) {
    return c.text("code and state are required", 400);
  }

  if (!states.has(state)) {
    return c.text("invalid state", 400);
  }

  states.delete(state);

  const codeVerifier = getCookie(c, "cv");
  const expectedNonce = getCookie(c, "nonce");

  if (!codeVerifier || !expectedNonce) {
    return c.text("missing security cookies", 400);
  }

  setCookie(c, "cv", "", { httpOnly: true, sameSite: "Lax", path: "/", maxAge: 0 });
  setCookie(c, "nonce", "", { httpOnly: true, sameSite: "Lax", path: "/", maxAge: 0 });

  const tokenResponse = await fetch(oidcConfig.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: requiredEnv("OIDC_REDIRECT_URI"),
      client_id: requiredEnv("OIDC_CLIENT_ID"),
      client_secret: requiredEnv("OIDC_CLIENT_SECRET"),
      // RFC 7636 Section 4.5 — code_verifier を送信して照合
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenResponse.ok) {
    const body = await tokenResponse.text();
    return c.text(`token request failed: ${body}`, 500);
  }

  const tokens = await tokenResponse.json() as {
    access_token: string;
    id_token: string;
  };

  const verifiedPayload = await verifyIdToken(
    tokens.id_token,
    oidcConfig.jwks_uri,
    oidcConfig.issuer,
    requiredEnv("OIDC_CLIENT_ID"),
    expectedNonce,
  );

  const sessionId = randomString(32);
  const session: Session = {
    sub: verifiedPayload.sub,
    email: verifiedPayload.email,
    tokens: {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
    },
    verifiedClaims: {
      issuer: verifiedPayload.iss,
      audience: verifiedPayload.aud,
      authTime: verifiedPayload.auth_time,
    },
  };

  sessions.set(sessionId, session);

  setCookie(c, "sid", sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
  });

  return c.redirect("/me");
});

app.get("/me", async (c) => {
  const sessionId = getCookie(c, "sid");

  if (!sessionId) {
    return c.text("not logged in", 401);
  }

  const session = sessions.get(sessionId);

  if (!session) {
    return c.text("not logged in", 401);
  }

  let userinfo: Record<string, unknown> | null = null;

  if (oidcConfig.userinfo_endpoint) {
    const userinfoResponse = await fetch(oidcConfig.userinfo_endpoint, {
      headers: {
        authorization: `Bearer ${session.tokens.accessToken}`,
      },
    });

    if (userinfoResponse.ok) {
      userinfo = await userinfoResponse.json() as Record<string, unknown>;
    }
  }

  const name = String(userinfo?.name ?? "Guest");
  const email = String(userinfo?.email ?? session.email ?? "No Email");
  const picture = typeof userinfo?.picture === "string" ? userinfo.picture : null;

  return c.html(`
    <!DOCTYPE html>
    <html lang="ja">
      <head>
        <meta charset="utf-8" />
        <title>マイページ</title>
        <style>
          body { font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #333; }
          .card { border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; background: #fafafa; }
          .avatar { width: 64px; height: 64px; border-radius: 50%; object-fit: cover; }
          details { border: 1px solid #eee; border-radius: 6px; padding: 0.75rem; margin-bottom: 1rem; background: #fff; }
          summary { font-weight: bold; cursor: pointer; }
          pre { background: #f4f4f4; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
        </style>
      </head>
      <body>
        <h1>ログイン完了（保護されたマイページ）</h1>
        
        <div class="card">
          ${picture ? `<img src="${picture}" alt="Avatar" class="avatar" referrerpolicy="no-referrer" />` : ""}
          <div>
            <h2 style="margin: 0 0 0.25rem 0;">${name}</h2>
            <div style="color: #666;">${email}</div>
            <div style="font-size: 0.85rem; color: #888;">ID: <code>${session.sub}</code></div>
          </div>
        </div>

        <details open>
          <summary>サーバー側セッションのトークン（BFF パターン）</summary>
          <p style="font-size: 0.85rem; color: #666;">ブラウザには渡さず、サーバー側セッションで安全に保持しているトークンです。</p>
          <pre>${JSON.stringify(session.tokens, null, 2)}</pre>
        </details>

        <details open>
          <summary>検証済み ID トークン情報</summary>
          <pre>${JSON.stringify(session.verifiedClaims, null, 2)}</pre>
        </details>

        <details>
          <summary>UserInfo API の生レスポンス</summary>
          <pre>${JSON.stringify(userinfo, null, 2)}</pre>
        </details>

        <p><a href="/">トップへ戻る</a></p>
      </body>
    </html>
  `);
});

const port = Number(process.env.PORT ?? 3000);

const start = async () => {
  oidcConfig = await fetchOpenIdConfiguration(requiredEnv("OIDC_ISSUER_URL"));
  console.log(`Discovered endpoints from ${oidcConfig.issuer}`);

  serve({
    fetch: app.fetch,
    port,
  });

  console.log(`Server is running on http://localhost:${port}`);
};

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
