import { createHmac } from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import { NextRequest, NextResponse } from 'next/server';
import { getAdminSecret, getWorkflowyApiKey, isAdminAuthenticated, adminSecretMatches, setAdminSessionCookie } from '../../api/admin/_auth';
import { schema, hash, sign, unsign, randomToken, equal, OAuthError, registerClient, clientLabel, authorization, issueCode, exchange, clientRedirects, revokeToken, verifyAccess, type Sql } from './core';

export function issuer(): string {
  const value = process.env.OAUTH_ISSUER || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : '');
  if (!value) throw new OAuthError('OAuth issuer is not configured', 503);
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new OAuthError('Invalid OAuth issuer', 503);
  return url.origin;
}
export const resource = () => `${issuer()}/api/mcp`;
function key(): string {
  const secret = getAdminSecret();
  if (!secret || !getWorkflowyApiKey()) throw new OAuthError('Server credentials are not configured', 503);
  return secret;
}
function owner(): string {
  return createHmac('sha256', key()).update(`oauth-owner:${issuer()}:${getWorkflowyApiKey()}`).digest('hex');
}
let pending: Promise<Sql> | undefined;
async function db(): Promise<Sql> {
  if (!pending) pending = (async () => {
    if (!process.env.DATABASE_URL) throw new OAuthError('Database is not configured', 503);
    const sql = neon(process.env.DATABASE_URL) as Sql;
    await schema(sql);
    return sql;
  })().catch(error => { pending = undefined; throw error; });
  return pending;
}
export async function oauthIdentity(token: string) {
  if (!/^wf_at_[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return verifyAccess(await db(), owner(), token, resource());
}
const baseHeaders = { 'Cache-Control':'no-store', Pragma:'no-cache', 'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff' };
export function json(value: unknown, status = 200) {
  return NextResponse.json(value, { status, headers: { ...baseHeaders, 'Access-Control-Allow-Origin':'*' } });
}
export function metadata(protectedResource: boolean) {
  try {
    const base = issuer();
    return json(protectedResource ? { resource: resource(), authorization_servers: [base], scopes_supported: ['workflowy', 'offline_access'], bearer_methods_supported: ['header'] } : {
      issuer: base, authorization_endpoint: `${base}/oauth/authorize`, token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`, revocation_endpoint: `${base}/oauth/revoke`,
      response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'], revocation_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'], scopes_supported: ['workflowy', 'offline_access'],
      authorization_response_iss_parameter_supported: true,
    });
  } catch { return json({ error: 'temporarily_unavailable' },503); }
}
const esc = (value: string) => value.replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]!));
function html(body: string, status = 200) {
  return new NextResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>WorkFlowy MCP — Approve connection</title><style>body{font:16px/1.7 system-ui;background:#111827;color:#f9fafb;max-width:640px;margin:60px auto;padding:24px}input,button{font:inherit;padding:10px;margin:8px 0}input{width:90%}button{cursor:pointer}a{color:#93c5fd}small{overflow-wrap:anywhere}article{border-top:1px solid #475569;padding:16px 0}</style></head><body>${body}</body></html>`, {
    status, // Native form POSTs need a real Origin for CSRF validation; no-referrer makes it null.
    headers: {...baseHeaders,'Referrer-Policy':'strict-origin','Content-Type':'text/html; charset=utf-8','X-Frame-Options':'DENY',
      'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com/connector_platform_oauth_redirect https://chatgpt.com/connector/oauth/ https://claude.ai/api/mcp/auth_callback https://claude.com/api/mcp/auth_callback; frame-ancestors 'none'; base-uri 'none'"},
  });
}
const CSRF_COOKIE = 'workflowy_oauth_csrf';
function csrf(request: NextRequest, purpose: string, params: string) {
  const nonce = randomToken();
  const proof = sign({ nonce, purpose, params, exp: Date.now()+600000, session: hash(request.cookies.get('workflowy_mcp_admin')?.value || '') },key(),'csrf');
  return { nonce, proof };
}
function setCsrf(response: NextResponse, nonce: string) {
  response.cookies.set(CSRF_COOKIE,nonce,{httpOnly:true,secure:true,sameSite:'lax',path:'/oauth',maxAge:600});
}
function checkCsrf(request: NextRequest, proof: string, purpose: string): string {
  if (request.headers.get('origin') !== issuer()) throw new OAuthError('invalid_request',403);
  const data = unsign(proof,key(),'csrf');
  if (data.purpose !== purpose || !Number.isFinite(data.exp) || data.exp<Date.now() ||
    !equal(data.nonce || '',request.cookies.get(CSRF_COOKIE)?.value || '') || !data.nonce ||
    data.session !== hash(request.cookies.get('workflowy_mcp_admin')?.value || '')) throw new OAuthError('invalid_request',403);
  return data.params;
}
async function boundedBody(request: Request) {
  if (Number(request.headers.get('content-length') || 0)>20000) throw new OAuthError('invalid_request',413);
  const reader = request.body?.getReader();
  if (!reader) return '';
  let size=0; const chunks: Uint8Array[]=[];
  while (true) { const {done,value}=await reader.read(); if(done)break; size+=value.length; if(size>20000){await reader.cancel();throw new OAuthError('invalid_request',413);} chunks.push(value); }
  return Buffer.concat(chunks).toString('utf8');
}
async function loginAllowed(request: Request) {
  const address = request.headers.get('x-vercel-forwarded-for') || 'local';
  const bucket = hash(`${owner()}:${address}`);
  const sql = await db();
  const rows = await sql`INSERT INTO workflowy_oauth_attempts(bucket,count,reset_at) VALUES(${bucket},1,now()+interval '15 minutes')
    ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN workflowy_oauth_attempts.reset_at<now() THEN 1 ELSE workflowy_oauth_attempts.count+1 END,
    reset_at=CASE WHEN workflowy_oauth_attempts.reset_at<now() THEN now()+interval '15 minutes' ELSE workflowy_oauth_attempts.reset_at END RETURNING count`;
  return rows[0].count <= 10;
}
export async function handle(request: NextRequest, action: string): Promise<NextResponse> {
  try {
    if (new URL(request.url).origin !== issuer()) throw new OAuthError('Use the production OAuth URL',400);
    if (request.method === 'GET' && action === 'authorize') {
      const params = new URL(request.url).searchParams;
      const auth = authorization(params,key(),resource());
      const proof = csrf(request,'authorize',params.toString());
      const signedIn = isAdminAuthenticated(request);
      const client = clientLabel(auth.redirect);
      const response = html(`<h1>Allow ${client} to connect</h1><p>This connection can read, search, add, edit, and delete items in your WorkFlowy (secrets are redacted by this server).</p><p>Search data is stored in your configured Neon database. The connection expires after 30 days and can be revoked anytime in <a href="/oauth/connections">Connections</a>.</p><p>Only approve if you started this connection yourself from ${client}.</p><small>Returns to: ${esc(auth.redirect)}</small><form method="post" action="/oauth/authorize"><input type="hidden" name="proof" value="${esc(proof.proof)}">${signedIn ? '<p>You are signed in as the administrator.</p>' : '<p><label>Admin Secret<br><input type="password" name="secret" autocomplete="current-password" required></label></p>'}<button name="decision" value="allow">Allow connection</button> <button name="decision" value="deny" formnovalidate>Cancel</button></form>`);
      setCsrf(response,proof.nonce); return response;
    }
    if (request.method === 'GET' && action === 'connections') {
      if (!isAdminAuthenticated(request)) return html('<h1>Sign-in required</h1><p><a href="/">Sign in to the dashboard</a>, then reopen this page.</p>',401);
      const sql = await db();
      const grants = await sql`SELECT id,redirect_uri,created_at,refresh_expires,revoked FROM workflowy_oauth_grants WHERE owner_key=${owner()} AND code_used ORDER BY created_at DESC LIMIT 100`;
      const proof = csrf(request,'revoke','');
      const response = html(`<h1>Connections</h1><p><a href="/">Back to dashboard</a></p>${grants.length ? grants.map(g => `<article><b>${clientLabel(String(g.redirect_uri))}</b><p>Created: ${esc(String(g.created_at))}<br>Expires: ${esc(String(g.refresh_expires))}</p>${g.revoked ? '<p>Revoked</p>' : `<form method="post" action="/oauth/connections"><input type="hidden" name="proof" value="${esc(proof.proof)}"><input type="hidden" name="grant" value="${esc(g.id)}"><button>Revoke this connection</button></form>`}</article>`).join('') : '<p>No approved connections.</p>'}`);
      setCsrf(response,proof.nonce); return response;
    }
    if (request.method !== 'POST') return json({error:'invalid_request'},405);
    const body = await boundedBody(request);
    if (action === 'register') {
      if (!request.headers.get('content-type')?.startsWith('application/json')) throw new OAuthError('invalid_request');
      let input: any; try { input=JSON.parse(body); } catch { throw new OAuthError('invalid_client_metadata'); }
      if (!input || typeof input !== 'object') throw new OAuthError('invalid_client_metadata');
      return json(registerClient(input,key()),201);
    }
    if (!request.headers.get('content-type')?.startsWith('application/x-www-form-urlencoded')) throw new OAuthError('invalid_request');
    const params = new URLSearchParams(body);
    if (action === 'authorize') {
      const query = checkCsrf(request,params.get('proof') || '','authorize');
      const auth = authorization(new URLSearchParams(query),key(),resource());
      const url = new URL(auth.redirect); url.searchParams.set('iss',issuer());
      if(auth.state)url.searchParams.set('state',auth.state);
      let newLogin = false;
      if(params.get('decision') === 'deny') url.searchParams.set('error','access_denied');
      else {
        if(params.get('decision') !== 'allow')throw new OAuthError('invalid_request');
        if(!isAdminAuthenticated(request)) {
          if(!await loginAllowed(request))return html('<h1>Too many attempts</h1><p>Wait 15 minutes, then start the connection again from your AI app.</p>',429);
          if(!adminSecretMatches(params.get('secret') || ''))return html('<h1>Sign-in failed</h1><p>Check your Admin Secret, go back, and try again.</p>',401);
          newLogin=true;
        }
        url.searchParams.set('code',await issueCode(await db(),owner(),auth));
      }
      const response=NextResponse.redirect(url,303);
      Object.entries(baseHeaders).forEach(([k,v])=>response.headers.set(k,v));
      response.cookies.set(CSRF_COOKIE,'',{path:'/oauth',maxAge:0,secure:true,httpOnly:true,sameSite:'lax'});
      if(newLogin)setAdminSessionCookie(response);
      return response;
    }
    if (action === 'connections') {
      checkCsrf(request,params.get('proof') || '','revoke');
      if(!isAdminAuthenticated(request))throw new OAuthError('access_denied',401);
      const sql=await db();
      await sql`UPDATE workflowy_oauth_grants SET revoked=TRUE WHERE id=${params.get('grant') || ''} AND owner_key=${owner()}`;
      return NextResponse.redirect(`${issuer()}/oauth/connections`,303);
    }
    if(request.headers.has('authorization'))throw new OAuthError('invalid_client',401);
    if(params.has('client_secret') || params.has('client_assertion'))throw new OAuthError('invalid_client',401);
    if(action === 'token')return json(await exchange(await db(),owner(),params,key(),resource()));
    if(action === 'revoke') {
      const client=params.get('client_id') || ''; clientRedirects(client,key());
      await revokeToken(await db(),owner(),params.get('token') || '',client);
      return json({});
    }
    return json({error:'invalid_request'},404);
  } catch(error) {
    return json({error:error instanceof OAuthError ? error.code : 'server_error'},error instanceof OAuthError ? error.status : 500);
  }
}
