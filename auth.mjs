/**
 * OAuth 2.1 provider for Cross-Claude MCP.
 *
 * Implements the MCP SDK's OAuthServerProvider interface using invite codes
 * for authorization. Enables Claude Desktop custom connector access.
 *
 * In-memory stores for clients and tokens (acceptable — tokens regenerate
 * on server restart via Claude Desktop's refresh flow).
 */

import { randomUUID, randomBytes } from "crypto";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

// --- In-memory stores ---

const clients = new Map();       // clientId -> OAuthClientInformationFull
const authCodes = new Map();     // code -> { clientId, codeChallenge, redirectUri, expiresAt }
const accessTokens = new Map();  // token -> { clientId, scopes, expiresAt }
const refreshTokens = new Map(); // token -> { clientId, scopes, accessToken }

const ACCESS_TOKEN_TTL = 3600;        // 1 hour
const AUTH_CODE_TTL = 300;            // 5 minutes

// --- Client store ---

export const clientStore = {
  getClient(clientId) {
    return clients.get(clientId);
  },
  registerClient(clientInfo) {
    const clientId = randomUUID();
    const clientSecret = randomBytes(32).toString("hex");
    const full = {
      ...clientInfo,
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    clients.set(clientId, full);
    return full;
  },
};

// --- Authorization page HTML ---

function authPageHTML(params, error) {
  const esc = (s) => (s || "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cross-Claude MCP — Authorize</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.4em; margin-bottom: 0.3em; }
  p { color: #666; font-size: 0.95em; }
  form { margin-top: 24px; }
  input[type=text] { width: 100%; padding: 12px; font-size: 1em; border: 2px solid #ddd; border-radius: 8px; box-sizing: border-box; font-family: monospace; }
  input[type=text]:focus { border-color: #7c3aed; outline: none; }
  button { margin-top: 12px; width: 100%; padding: 12px; font-size: 1em; background: #7c3aed; color: white; border: none; border-radius: 8px; cursor: pointer; }
  button:hover { background: #6d28d9; }
  .error { color: #dc2626; margin-top: 12px; font-size: 0.9em; }
</style>
</head><body>
<h1>Cross-Claude MCP</h1>
<p>Enter your invite code to connect.</p>
${error ? `<p class="error">${esc(error)}</p>` : ""}
<form method="POST" action="/authorize/submit">
  <input type="hidden" name="state" value="${esc(params.state)}">
  <input type="hidden" name="redirect_uri" value="${esc(params.redirectUri)}">
  <input type="hidden" name="code_challenge" value="${esc(params.codeChallenge)}">
  <input type="hidden" name="client_id" value="${esc(params.clientId)}">
  <input type="text" name="invite_code" placeholder="Enter invite code" autofocus required>
  <button type="submit">Connect</button>
</form>
</body></html>`;
}

// --- OAuth provider ---

export class InviteCodeOAuthProvider {
  constructor(db) {
    this.db = db;
  }

  get clientsStore() {
    return clientStore;
  }

  async authorize(client, params, res) {
    res.type("html").send(authPageHTML({
      state: params.state,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      clientId: client.client_id,
    }, null));
  }

  async challengeForAuthorizationCode(_client, authorizationCode) {
    const entry = authCodes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");
    return entry.codeChallenge;
  }

  async exchangeAuthorizationCode(client, authorizationCode, _codeVerifier, _redirectUri, _resource) {
    const entry = authCodes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");
    if (entry.expiresAt < Date.now()) {
      authCodes.delete(authorizationCode);
      throw new Error("Authorization code expired");
    }
    authCodes.delete(authorizationCode);

    const accessToken = randomBytes(32).toString("hex");
    const refreshToken = randomBytes(32).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL;

    accessTokens.set(accessToken, {
      clientId: client.client_id,
      scopes: [],
      expiresAt,
    });
    refreshTokens.set(refreshToken, {
      clientId: client.client_id,
      scopes: [],
      accessToken,
    });

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: refreshToken,
    };
  }

  async exchangeRefreshToken(client, refreshToken, _scopes, _resource) {
    const entry = refreshTokens.get(refreshToken);
    if (!entry || entry.clientId !== client.client_id) {
      throw new Error("Invalid refresh token");
    }

    // Revoke old access token
    accessTokens.delete(entry.accessToken);

    const newAccessToken = randomBytes(32).toString("hex");
    const newRefreshToken = randomBytes(32).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL;

    accessTokens.set(newAccessToken, {
      clientId: client.client_id,
      scopes: [],
      expiresAt,
    });

    // Rotate refresh token
    refreshTokens.delete(refreshToken);
    refreshTokens.set(newRefreshToken, {
      clientId: client.client_id,
      scopes: [],
      accessToken: newAccessToken,
    });

    return {
      access_token: newAccessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: newRefreshToken,
    };
  }

  async verifyAccessToken(token) {
    const entry = accessTokens.get(token);
    if (!entry) throw new InvalidTokenError("Invalid access token");

    return {
      token,
      clientId: entry.clientId,
      scopes: entry.scopes,
      expiresAt: entry.expiresAt,
    };
  }
}

// --- Invite code submission handler (POST /authorize/submit) ---

export function createAuthorizeSubmitHandler(db) {
  return async (req, res) => {
    const { invite_code, state, redirect_uri, code_challenge, client_id } = req.body;

    const redeemed = await db.redeemInviteCode(invite_code);
    if (!redeemed) {
      res.type("html").send(authPageHTML({
        state,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        clientId: client_id,
      }, "Invalid or already-used invite code. Please try again."));
      return;
    }

    // Generate authorization code
    const code = randomBytes(32).toString("hex");
    authCodes.set(code, {
      clientId: client_id,
      codeChallenge: code_challenge,
      redirectUri: redirect_uri,
      expiresAt: Date.now() + AUTH_CODE_TTL * 1000,
    });

    // Redirect back to Claude Desktop with the auth code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);
    res.redirect(redirectUrl.toString());
  };
}
