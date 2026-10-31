import "dotenv/config";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

type Session = {
  sub: string;
  email?: string;
};

type OpenIdConfiguration = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
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
  };
};

const randomString = (bytes: number): string => {
  return randomBytes(bytes).toString("base64url");
};

const generatePkce = (): { verifier: string; challenge: string } => {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");

  return { verifier, challenge };
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

  const jwk = await fetchJwk(jwksUri, header.kid);
  const publicKey = createPublicKey({ key: jwk as any, format: "jwk" });

  const data = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(signatureB64, "base64url");

  const isValidSignature = verify("sha256", data, publicKey, signature);

  if (!isValidSignature) {
    throw new Error("ID token signature verification failed");
  }

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
  };

  sessions.set(sessionId, session);

  setCookie(c, "sid", sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
  });

  return c.redirect("/me");
});

app.get("/me", (c) => {
  const sessionId = getCookie(c, "sid");

  if (!sessionId) {
    return c.text("not logged in", 401);
  }

  const session = sessions.get(sessionId);

  if (!session) {
    return c.text("not logged in", 401);
  }

  return c.json(session);
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
