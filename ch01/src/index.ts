import "dotenv/config";
import { randomBytes } from "node:crypto";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const app = new Hono();
const states = new Map<string, true>();

const requiredEnv = (name: string): string => {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
};

const randomState = (): string => {
  return randomBytes(32).toString("base64url");
};

const decodeJwtPayload = (token: string): unknown => {
  const [, payload] = token.split(".");

  if (!payload) {
    throw new Error("invalid JWT");
  }

  const json = Buffer.from(payload, "base64url").toString("utf8");

  return JSON.parse(json);
};

app.get("/", (c) => {
  return c.html('<a href="/auth/login">Login</a>');
});

app.get("/auth/login", (c) => {
  const state = randomState();
  states.set(state, true);

  const authorizationUrl = new URL(requiredEnv("OIDC_AUTHORIZATION_ENDPOINT"));

  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", requiredEnv("OIDC_CLIENT_ID"));
  authorizationUrl.searchParams.set("redirect_uri", requiredEnv("OIDC_REDIRECT_URI"));
  authorizationUrl.searchParams.set("scope", "openid profile email");
  authorizationUrl.searchParams.set("state", state);

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

  const tokenResponse = await fetch(requiredEnv("OIDC_TOKEN_ENDPOINT"), {
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

  const idTokenPayload = decodeJwtPayload(tokens.id_token);

  return c.json({
    message: "login succeeded",
    tokens: {
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    },
    idTokenPayload,
  });
});

const port = Number(process.env.PORT ?? 3000);

serve({
  fetch: app.fetch,
  port,
});

console.log(`Server is running on http://localhost:${port}`);
