/**
 * GitHub MCP Server for Cloudflare Workers
 *
 * MCP Streamable HTTP トランスポートを直接実装
 * @hono/mcp / @modelcontextprotocol/sdk に依存しない
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';

// ============================================
// OAuth 2.0 ユーティリティ
// ============================================

const TOKEN_TTL      = 60 * 60 * 24 * 30; // アクセストークン: 30日
const AUTH_CODE_TTL  = 60 * 5;             // 認可コード: 5分

function bufToBase64url(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function strToBase64url(str: string): string {
  return Buffer.from(str, 'utf-8').toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64urlToStr(b64: string): string {
  return Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return bufToBase64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

async function generateAccessToken(clientId: string, secret: string): Promise<string> {
  const exp  = Math.floor(Date.now() / 1000) + TOKEN_TTL;
  const data = `${clientId}.${exp}`;
  const sig  = await hmacSign(data, secret);
  return `${strToBase64url(data)}.${sig}`;
}

async function verifyAccessToken(token: string, secret: string): Promise<boolean> {
  const dot = token.lastIndexOf('.');
  if (dot === -1) return false;
  const dataB64 = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  const data    = base64urlToStr(dataB64);
  const exp     = parseInt(data.split('.')[1] ?? '0', 10);
  if (Math.floor(Date.now() / 1000) > exp) return false;
  return sig === await hmacSign(data, secret);
}

async function generateAuthCode(
  p: { clientId: string; redirectUri: string; codeChallenge: string; state: string },
  secret: string
): Promise<string> {
  const exp     = Math.floor(Date.now() / 1000) + AUTH_CODE_TTL;
  const payload = JSON.stringify({ ...p, exp });
  const b64     = strToBase64url(payload);
  return `${b64}.${await hmacSign(b64, secret)}`;
}

async function verifyAuthCode(
  code: string, secret: string
): Promise<{ clientId: string; redirectUri: string; codeChallenge: string; state: string } | null> {
  const dot = code.lastIndexOf('.');
  if (dot === -1) return null;
  const b64 = code.slice(0, dot);
  const sig = code.slice(dot + 1);
  if (sig !== await hmacSign(b64, secret)) return null;
  const payload = JSON.parse(base64urlToStr(b64));
  if (Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload;
}

async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  const buf      = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const computed = bufToBase64url(buf);
  return computed === challenge;
}

// ============================================
// GitHub API クライアント
// ============================================

function githubFetch(env: Env) {
  const base = env.GITHUB_HOST === 'github.com'
    ? 'https://api.github.com'
    : `https://${env.GITHUB_HOST}/api/v3`;

  return async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(`${base}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${env.GITHUB_PERSONAL_ACCESS_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'User-Agent': 'github-remote-mcp-server/1.0',
        ...(init.headers ?? {}),
      },
    });
    if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
    return res.json() as Promise<T>;
  };
}

// ============================================
// MCP ツール定義
// ============================================

interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, env: Env) => Promise<string>;
}

function buildTools(): ToolDef[] {
  return [
    // ---- デバッグ ----
    {
      name: 'debug_echo',
      description: '渡した引数をそのまま返すデバッグ用ツール（GitHub APIを使いません）',
      inputSchema: {
        type: 'object',
        properties: {
          message: { type: 'string', description: '返すメッセージ' },
        },
      },
      handler: async (a) => JSON.stringify({ echo: a['message'] ?? 'hello', timestamp: new Date().toISOString() }),
    },
    // ---- ユーザー ----
    {
      name: 'get_me',
      description: '認証済みユーザーの情報を返します',
      inputSchema: { type: 'object', properties: {}, required: [] },
      handler: async (_, env) => JSON.stringify(await githubFetch(env)('/user'), null, 2),
    },
    // ---- リポジトリ ----
    {
      name: 'list_repositories',
      description: '認証済みユーザーがアクセスできるリポジトリ一覧を返します',
      inputSchema: {
        type: 'object',
        properties: {
          type:     { type: 'string', enum: ['all','owner','public','private','member'], default: 'owner', description: 'リポジトリの種類' },
          per_page: { type: 'number', default: 30,  description: '1ページあたりの件数（最大100）' },
          page:     { type: 'number', default: 1,   description: 'ページ番号' },
        },
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/user/repos?type=${a['type'] ?? 'owner'}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
    {
      name: 'get_repository',
      description: 'リポジトリの詳細情報を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'リポジトリのオーナー' },
          repo:  { type: 'string', description: 'リポジトリ名' },
        },
        required: ['owner', 'repo'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(`/repos/${a['owner']}/${a['repo']}`), null, 2),
    },
    {
      name: 'search_repositories',
      description: 'GitHubリポジトリを検索します',
      inputSchema: {
        type: 'object',
        properties: {
          query:    { type: 'string', description: '検索クエリ' },
          per_page: { type: 'number', default: 30, description: '1ページあたりの件数' },
          page:     { type: 'number', default: 1,  description: 'ページ番号' },
        },
        required: ['query'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/search/repositories?q=${encodeURIComponent(String(a['query']))}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
    // ---- ファイル ----
    {
      name: 'get_file_contents',
      description: 'リポジトリ内のファイルまたはディレクトリの内容を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'リポジトリのオーナー' },
          repo:  { type: 'string', description: 'リポジトリ名' },
          path:  { type: 'string', description: 'ファイルパス' },
          ref:   { type: 'string', description: 'ブランチ・タグ・SHA（省略可）' },
        },
        required: ['owner', 'repo', 'path'],
      },
      handler: async (a, env) => {
        const qs   = a['ref'] ? `?ref=${encodeURIComponent(String(a['ref']))}` : '';
        const data = await githubFetch(env)<{ content?: string; encoding?: string; type?: string }>(
          `/repos/${a['owner']}/${a['repo']}/contents/${a['path']}${qs}`
        );
        if (data.type === 'file' && data.content && data.encoding === 'base64') {
          return Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf-8');
        }
        return JSON.stringify(data, null, 2);
      },
    },
    // ---- Issue ----
    {
      name: 'list_issues',
      description: 'リポジトリのIssue一覧を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:    { type: 'string', description: 'リポジトリのオーナー' },
          repo:     { type: 'string', description: 'リポジトリ名' },
          state:    { type: 'string', enum: ['open','closed','all'], default: 'open' },
          per_page: { type: 'number', default: 30 },
          page:     { type: 'number', default: 1 },
        },
        required: ['owner', 'repo'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/repos/${a['owner']}/${a['repo']}/issues?state=${a['state'] ?? 'open'}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
    {
      name: 'get_issue',
      description: '特定のIssueの詳細を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:        { type: 'string' },
          repo:         { type: 'string' },
          issue_number: { type: 'number' },
        },
        required: ['owner', 'repo', 'issue_number'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/repos/${a['owner']}/${a['repo']}/issues/${a['issue_number']}`
        ), null, 2),
    },
    {
      name: 'create_issue',
      description: 'リポジトリに新しいIssueを作成します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:     { type: 'string' },
          repo:      { type: 'string' },
          title:     { type: 'string' },
          body:      { type: 'string' },
          labels:    { type: 'array', items: { type: 'string' } },
          assignees: { type: 'array', items: { type: 'string' } },
        },
        required: ['owner', 'repo', 'title'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(`/repos/${a['owner']}/${a['repo']}/issues`, {
          method: 'POST',
          body: JSON.stringify({ title: a['title'], body: a['body'], labels: a['labels'], assignees: a['assignees'] }),
        }), null, 2),
    },
    {
      name: 'search_issues',
      description: 'IssueおよびPull Requestを検索します',
      inputSchema: {
        type: 'object',
        properties: {
          query:    { type: 'string' },
          per_page: { type: 'number', default: 30 },
          page:     { type: 'number', default: 1 },
        },
        required: ['query'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/search/issues?q=${encodeURIComponent(String(a['query']))}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
    // ---- ブランチ ----
    {
      name: 'create_branch',
      description: 'リポジトリに新しいブランチを作成します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:  { type: 'string', description: 'リポジトリのオーナー' },
          repo:   { type: 'string', description: 'リポジトリ名' },
          branch: { type: 'string', description: '作成するブランチ名' },
          sha:    { type: 'string', description: '起点となるコミットSHA（省略時はデフォルトブランチのHEAD）' },
        },
        required: ['owner', 'repo', 'branch'],
      },
      handler: async (a, env) => {
        const gh = githubFetch(env);
        let sha = String(a['sha'] ?? '');
        if (!sha) {
          const repo = await gh<{ default_branch: string }>(`/repos/${a['owner']}/${a['repo']}`);
          const ref  = await gh<{ object: { sha: string } }>(`/repos/${a['owner']}/${a['repo']}/git/ref/heads/${repo.default_branch}`);
          sha = ref.object.sha;
        }
        return JSON.stringify(await gh(`/repos/${a['owner']}/${a['repo']}/git/refs`, {
          method: 'POST',
          body: JSON.stringify({ ref: `refs/heads/${a['branch']}`, sha }),
        }), null, 2);
      },
    },
    // ---- ファイル書き込み ----
    {
      name: 'create_or_update_file',
      description: 'リポジトリのファイルを作成または更新します（コミットを作成します）',
      inputSchema: {
        type: 'object',
        properties: {
          owner:   { type: 'string', description: 'リポジトリのオーナー' },
          repo:    { type: 'string', description: 'リポジトリ名' },
          path:    { type: 'string', description: 'ファイルパス（例: src/index.ts）' },
          message: { type: 'string', description: 'コミットメッセージ' },
          content: { type: 'string', description: 'ファイルの内容（UTF-8テキスト）' },
          branch:  { type: 'string', description: '対象ブランチ名（省略時はデフォルトブランチ）' },
          sha:     { type: 'string', description: '更新時：既存ファイルのSHA（新規作成時は不要）' },
        },
        required: ['owner', 'repo', 'path', 'message', 'content'],
      },
      handler: async (a, env) => {
        const gh      = githubFetch(env);
        const content = Buffer.from(String(a['content']), 'utf-8').toString('base64');
        const body: Record<string, unknown> = {
          message: a['message'],
          content,
          ...(a['branch']  ? { branch: a['branch'] } : {}),
          ...(a['sha']     ? { sha:    a['sha']     } : {}),
        };
        return JSON.stringify(await gh(`/repos/${a['owner']}/${a['repo']}/contents/${a['path']}`, {
          method: 'PUT',
          body: JSON.stringify(body),
        }), null, 2);
      },
    },
    // ---- Pull Request ----
    {
      name: 'create_pull_request',
      description: 'Pull Requestを作成します',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'リポジトリのオーナー' },
          repo:  { type: 'string', description: 'リポジトリ名' },
          title: { type: 'string', description: 'PRのタイトル' },
          body:  { type: 'string', description: 'PRの本文' },
          head:  { type: 'string', description: 'マージ元ブランチ名' },
          base:  { type: 'string', description: 'マージ先ブランチ名（例: main）' },
          draft: { type: 'boolean', description: 'ドラフトPRとして作成するか', default: false },
        },
        required: ['owner', 'repo', 'title', 'head', 'base'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(`/repos/${a['owner']}/${a['repo']}/pulls`, {
          method: 'POST',
          body: JSON.stringify({
            title: a['title'],
            body:  a['body'] ?? '',
            head:  a['head'],
            base:  a['base'],
            draft: a['draft'] ?? false,
          }),
        }), null, 2),
    },
    {
      name: 'list_pull_requests',
      description: 'リポジトリのPull Request一覧を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:    { type: 'string' },
          repo:     { type: 'string' },
          state:    { type: 'string', enum: ['open','closed','all'], default: 'open' },
          per_page: { type: 'number', default: 30 },
          page:     { type: 'number', default: 1 },
        },
        required: ['owner', 'repo'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/repos/${a['owner']}/${a['repo']}/pulls?state=${a['state'] ?? 'open'}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
    {
      name: 'get_pull_request',
      description: '特定のPull Requestの詳細を返します',
      inputSchema: {
        type: 'object',
        properties: {
          owner:       { type: 'string' },
          repo:        { type: 'string' },
          pull_number: { type: 'number' },
        },
        required: ['owner', 'repo', 'pull_number'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/repos/${a['owner']}/${a['repo']}/pulls/${a['pull_number']}`
        ), null, 2),
    },
    // ---- 検索 ----
    {
      name: 'search_code',
      description: 'GitHubリポジトリ内のコードを検索します',
      inputSchema: {
        type: 'object',
        properties: {
          query:    { type: 'string' },
          per_page: { type: 'number', default: 30 },
          page:     { type: 'number', default: 1 },
        },
        required: ['query'],
      },
      handler: async (a, env) =>
        JSON.stringify(await githubFetch(env)(
          `/search/code?q=${encodeURIComponent(String(a['query']))}&per_page=${a['per_page'] ?? 30}&page=${a['page'] ?? 1}`
        ), null, 2),
    },
  ];
}

const TOOLS = buildTools();

// ============================================
// MCP JSON-RPC ハンドラ（Streamable HTTP）
// ============================================

type JsonRpcRequest = {
  jsonrpc: string;
  method: string;
  params?: unknown;
  id?: unknown;
};

async function handleMcp(body: unknown, env: Env): Promise<unknown> {
  const req = body as JsonRpcRequest;
  const id  = req.id ?? null;

  switch (req.method) {
    case 'initialize': {
      const initParams = req.params as { protocolVersion?: string } | undefined;
      const clientVersion = initParams?.protocolVersion ?? '2024-11-05';
      return {
        jsonrpc: '2.0',
        result: {
          protocolVersion: clientVersion,
          capabilities: { tools: {} },
          serverInfo: { name: 'github-mcp-server', version: '1.0.0' },
        },
        id,
      };
    }

    case 'notifications/initialized':
      return null; // notification に応答不要

    case 'ping':
      return { jsonrpc: '2.0', result: {}, id };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        result: {
          tools: TOOLS.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        },
        id,
      };

    case 'tools/call': {
      const params = req.params as { name?: string; arguments?: Record<string, unknown> };
      console.log('[tools/call] tool:', params?.name, 'args:', JSON.stringify(params?.arguments));

      const tool = TOOLS.find(t => t.name === params?.name);
      if (!tool) {
        return {
          jsonrpc: '2.0',
          error: { code: -32601, message: `Tool not found: ${params?.name}` },
          id,
        };
      }
      try {
        const text = await tool.handler(params?.arguments ?? {}, env);
        console.log('[tools/call] success, length:', text.length);
        return {
          jsonrpc: '2.0',
          result: { content: [{ type: 'text', text }], isError: false },
          id,
        };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error('[tools/call] error:', msg);
        return {
          jsonrpc: '2.0',
          result: {
            content: [{ type: 'text', text: `Error: ${msg}` }],
            isError: true,
          },
          id,
        };
      }
    }

    default: {
      // notifications（id なし）は無視
      if (id === null || id === undefined) return null;
      return {
        jsonrpc: '2.0',
        error: { code: -32601, message: `Method not found: ${req.method}` },
        id,
      };
    }
  }
}

// ============================================
// Hono アプリケーション
// ============================================

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// ============================================
// OAuth 2.0 メタデータ（RFC 8414 / RFC 9728）
// ============================================

app.get('/.well-known/oauth-authorization-server', (c) => {
  const base = new URL(c.req.url).origin;
  return c.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/oauth/token`,
    grant_types_supported: ['authorization_code'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  });
});

// RFC 9728: OAuth Protected Resource Metadata
app.get('/.well-known/oauth-protected-resource', (c) => {
  const base = new URL(c.req.url).origin;
  return c.json({
    resource: base,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
  });
});

app.get('/.well-known/oauth-protected-resource/:path{.*}', (c) => {
  const base = new URL(c.req.url).origin;
  return c.json({
    resource: base,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
  });
});

// ============================================
// OAuth 2.0 認可エンドポイント
// ============================================

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

app.get('/authorize', async (c) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = c.req.query();
  if (client_id !== c.env.OAUTH_CLIENT_ID) return c.text('invalid client_id', 400);
  if (code_challenge_method !== 'S256')     return c.text('only S256 is supported', 400);

  return c.html(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GitHub MCP Server - 認証</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 20px; color: #24292f; }
    h1   { font-size: 20px; margin-bottom: 8px; }
    p    { color: #57606a; font-size: 14px; margin-bottom: 24px; }
    button {
      width: 100%; padding: 12px; font-size: 15px; font-weight: 600;
      background: #1f883d; color: #fff; border: none; border-radius: 6px; cursor: pointer;
    }
    button:hover { background: #1a7f37; }
    .logo { font-size: 32px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="logo">🔑</div>
  <h1>GitHub MCP Server へのアクセス</h1>
  <p>Claude が GitHub MCP Server への接続を要求しています。<br>承認するとリポジトリ・Issue・Pull Request などへのアクセスが許可されます。</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id"             value="${escapeHtml(client_id ?? '')}">
    <input type="hidden" name="redirect_uri"          value="${escapeHtml(redirect_uri ?? '')}">
    <input type="hidden" name="state"                 value="${escapeHtml(state ?? '')}">
    <input type="hidden" name="code_challenge"        value="${escapeHtml(code_challenge ?? '')}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <button type="submit">承認する</button>
  </form>
</body>
</html>`);
});

app.post('/authorize', async (c) => {
  const b           = await c.req.parseBody();
  const clientId    = String(b['client_id']    ?? '');
  const redirectUri = String(b['redirect_uri'] ?? '');
  const state       = String(b['state']        ?? '');
  const challenge   = String(b['code_challenge'] ?? '');

  if (clientId !== c.env.OAUTH_CLIENT_ID) return c.text('invalid client_id', 400);

  const code = await generateAuthCode(
    { clientId, redirectUri, codeChallenge: challenge, state },
    c.env.OAUTH_CLIENT_SECRET
  );
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  url.searchParams.set('state', state);
  return c.redirect(url.toString(), 302);
});

// ============================================
// OAuth 2.0 トークンエンドポイント
// ============================================

app.post('/oauth/token', async (c) => {
  const b            = await c.req.parseBody();
  const grantType    = String(b['grant_type']    ?? '');
  const code         = String(b['code']          ?? '');
  const codeVerifier = String(b['code_verifier'] ?? '');
  const redirectUri  = String(b['redirect_uri']  ?? '');

  if (grantType !== 'authorization_code') {
    return c.json({ error: 'unsupported_grant_type' }, 400);
  }
  const payload = await verifyAuthCode(code, c.env.OAUTH_CLIENT_SECRET);
  if (!payload)                            return c.json({ error: 'invalid_grant' }, 400);
  if (payload.redirectUri !== redirectUri) return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
  if (!(await verifyPkce(codeVerifier, payload.codeChallenge))) {
    return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
  }

  const token = await generateAccessToken(payload.clientId, c.env.OAUTH_CLIENT_SECRET);
  return c.json({ access_token: token, token_type: 'Bearer', expires_in: TOKEN_TTL });
});

// ============================================
// Bearer トークン認証ミドルウェア
// ============================================

app.use('/mcp', async (c, next) => {
  const auth  = c.req.header('Authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token || !(await verifyAccessToken(token, c.env.OAUTH_CLIENT_SECRET))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return next();
});

// ============================================
// MCP エンドポイント（Streamable HTTP）
// ============================================

// GET /mcp: クライアントがSSEストリームを確立するためのエンドポイント
app.get('/mcp', async (c) => {
  const accept = c.req.header('Accept') ?? '';
  if (!accept.includes('text/event-stream')) {
    return c.json({ error: 'Accept: text/event-stream required' }, 400);
  }
  // 接続確立のみ行い、空のSSEストリームを返す（通知はPOSTレスポンスで送信）
  return new Response('', {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
    },
  });
});

app.post('/mcp', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null }, 400);
  }

  const accept = c.req.header('Accept') ?? '';
  const useSSE = accept.includes('text/event-stream');
  const method = Array.isArray(body) ? 'batch' : (body as JsonRpcRequest)?.method;
  console.log('[mcp] method:', method, 'useSSE:', useSSE);

  if (useSSE) {
    // SSE レスポンス: ReadableStream を使わず事前計算して返す
    // （Cloudflare Workers では ReadableStream 内の async 処理が途中でカットされる場合がある）
    const requests = Array.isArray(body) ? body : [body];
    const lines: string[] = [];

    for (const req of requests) {
      try {
        const result = await handleMcp(req as unknown, c.env);
        if (result !== null) {
          lines.push(`event: message\ndata: ${JSON.stringify(result)}\n\n`);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error('[mcp] SSE processing error:', msg);
        const errEvent = {
          jsonrpc: '2.0',
          error: { code: -32603, message: msg.slice(0, 500) },
          id: (req as JsonRpcRequest)?.id ?? null,
        };
        lines.push(`event: message\ndata: ${JSON.stringify(errEvent)}\n\n`);
      }
    }

    return new Response(lines.join(''), {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
      },
    });
  }

  // fallback: plain JSON
  if (Array.isArray(body)) {
    const results = (await Promise.all(body.map(r => handleMcp(r, c.env)))).filter(r => r !== null);
    return c.json(results.length === 1 ? results[0] : results);
  }

  const result = await handleMcp(body, c.env);
  if (result === null) return new Response(null, { status: 202 });
  return c.json(result);
});

// ============================================
// ヘルスチェック
// ============================================

app.get('/', (c) =>
  c.json({
    name: 'GitHub MCP Server',
    version: '1.0.0',
    tools: TOOLS.map(t => t.name),
  })
);

export default app;
