import express from 'express';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {SiteStore,random,equal} from './store.mjs';
import {requireVoiceGateCallback,createModerationClient,ModerationRequestError} from '../../packages/node/index.mjs';

const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=')));
const page=(title,body)=>`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title><body><main><h1>${title}</h1>${body}</main></body></html>`;

export async function createSite(config) {
  const {issuer,audience,clientId,clientSecret,kid,model}=config;
  for(const value of [issuer,audience]) {
    const u=new URL(value);
    if(u.origin!==value||u.username||u.password||!(u.protocol==='https:'||(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname))))throw new Error('Use canonical HTTPS origins or explicit loopback development origins');
  }
  if(!clientId||!clientSecret||!kid||!model)throw new Error('Client, secret, pinned kid and model are required');
  const r=await fetch(issuer+'/.well-known/jwks.json',{redirect:'error',signal:AbortSignal.timeout(10_000)});
  if(!r.ok)throw new Error('Issuer JWKS unavailable');
  const all=await r.json(), keys=all.keys.filter(k=>k.kid===kid&&k.kty==='OKP'&&k.crv==='Ed25519'&&k.use==='sig'&&k.alg==='EdDSA');
  if(keys.length!==1)throw new Error('Pinned signing key unavailable');
  const store=new SiteStore(config.database||'chat.sqlite3',{issuer,audience});
  console.warn('WARNING: allowProvisionalCalibration: true; synthetic-provisional voice checks are experimental, not human validation.');
  const moderation=config.moderationClient||createModerationClient({issuer,clientId,clientSecret});
  if(config.adminToken&&!/^[A-Za-z0-9_-]{43,128}$/.test(config.adminToken))throw new Error('SITE_ADMIN_TOKEN must be a random 32-byte base64url token');
  const app=express();app.disable('x-powered-by');
  const secure=audience.startsWith('https:'), pendingCookie=secure?'__Host-ovg_rp_pending':'ovg_rp_pending_local', sessionCookie=secure?'__Host-ovg_rp':'ovg_rp_local';
  const opts={httpOnly:true,secure,sameSite:'lax',path:'/'};
  app.use((req,res,next)=>{res.set({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
    'Content-Security-Policy':`default-src 'none'; form-action 'self' ${issuer}; frame-ancestors 'none'; base-uri 'none'`});next();});
  app.use(express.json({limit:'16kb',strict:true}));
  app.use(express.urlencoded({extended:false,limit:'16kb'}));
  const browser=req=>cookies(req)[pendingCookie]||'';
  const sessionId=req=>cookies(req)[sessionCookie]||'';
  const validBrowser=value=>/^[A-Za-z0-9_-]{43}$/.test(value);
  function csrf(req,res,expected) {
    if(req.headers.origin!==audience||!equal(req.body?.csrf,expected)){res.status(403).send('Invalid request');return false;}return true;
  }
  app.get('/',(req,res)=>{
    // Native form navigation needs a non-null Origin; only these clean pages
    // use same-origin. Callback and issuer responses remain no-referrer.
    res.set('Referrer-Policy','same-origin');
    let b=browser(req);if(!validBrowser(b))b=random();
    res.cookie(pendingCookie,b,{...opts,maxAge:240_000});
    res.send(page('Express Chat',`<p>Enter with VoiceGate. Names are optional.</p><form method="post" action="/voicegate/start"><input type="hidden" name="csrf" value="${b}"><button>Enter Chat</button></form>`));
  });
  app.post('/voicegate/start',(req,res)=>{
    const b=browser(req);if(!validBrowser(b))return res.status(403).send('Start from Enter Chat');
    if(!csrf(req,res,b))return;
    const pending=store.start(b);
    res.cookie(pendingCookie,b,{...opts,maxAge:240_000});
    const q=new URLSearchParams({client_id:clientId,redirect_uri:audience+'/callback',state:pending.state,
      request_nonce:pending.nonce,code_challenge:createHash('sha256').update(pending.code_verifier).digest('base64url'),code_challenge_method:'S256'});
    res.redirect(303,issuer+'/authorize?'+q);
  });
  app.get('/callback',requireVoiceGateCallback({getPending:req=>validBrowser(browser(req))?store.pending(browser(req)):null,
    context:{issuer,audience,jwks:{keys},policy:'phrase-experimental-v1',allowedModels:[model]},clientId,clientSecret,
    redirectUri:audience+'/callback',allowProvisionalCalibration:true,requireModeration:true,
    redeemAtomically:(data,req)=>store.redeem(data,browser(req))}), (req,res)=>{
      res.cookie(sessionCookie,req.voicegate.session,{...opts,maxAge:900_000});res.redirect(303,'/chat');
    });
  async function allowedSession(req,res,{checkCsrf=false}={}) {
    const session=store.session(sessionId(req));
    if(!session){res.status(403).send('Enter with voice to access this page.');return null;}
    if(checkCsrf&&!csrf(req,res,session.csrf))return null;
    const saved=store.receipt(session.sub);
    if(!saved){res.status(403).send('Enter with voice again to renew your moderation receipt.');return null;}
    try {
      const decision=await moderation.check(saved.receipt);
      if(decision.banned){res.status(403).send('Entry is currently restricted by this site.');return null;}
      // Logout or a local ban may have landed while the issuer check awaited.
      const current=store.session(sessionId(req));
      if(!current){res.status(403).send('Enter with voice to access this page.');return null;}
      return current;
    } catch {res.status(503).send('The moderation check is unavailable. Try again shortly.');return null;}
  }
  app.get('/chat',async(req,res)=>{
    const s=await allowedSession(req,res);if(!s)return;
    res.set('Referrer-Policy','same-origin');
    const messages=store.db.prepare('SELECT label,body FROM messages ORDER BY id DESC LIMIT 50').all().reverse();
    res.send(page('Chat',`<p id="label">${escape(s.label)}</p><div id="messages">${messages.map(m=>`<p>${escape(m.label)} · ${escape(m.body)}</p>`).join('')}</div>
      <form method="post" action="/chat"><input type="hidden" name="csrf" value="${s.csrf}"><label>Message <input name="message" maxlength="1000" required></label><button>Send</button></form>
      <form method="post" action="/logout"><input type="hidden" name="csrf" value="${s.csrf}"><button>Sign out</button></form>`));
  });
  app.post('/chat',async(req,res)=>{
    const s=await allowedSession(req,res,{checkCsrf:true});if(!s)return;
    const text=typeof req.body.message==='string'?req.body.message.trim():'';
    if(!text||text.length>1000)return res.status(400).send('Write a message of 1–1000 characters');
    if(!store.message(sessionId(req),text))return res.status(403).send('Entry denied');res.redirect(303,'/chat');
  });
  app.post('/logout',(req,res)=>{
    const s=store.session(sessionId(req));if(!s)return res.redirect(303,'/');
    if(!csrf(req,res,s.csrf))return;
    store.logout(sessionId(req),browser(req));res.clearCookie(sessionCookie,opts);res.clearCookie(pendingCookie,opts);res.redirect(303,'/');
  });
  // This site's administrator acts on a known local user. The encrypted receipt
  // stays server-side; no issuer-wide administrator credential is shared.
  app.post('/admin/moderation',async(req,res)=>{
    if(!config.adminToken)return res.sendStatus(404);
    const auth=req.get('authorization')||'';
    const supplied=auth.startsWith('Bearer ')?auth.slice(7):'';
    if(!/^[A-Za-z0-9_-]{43,128}$/.test(supplied)||!equal(supplied,config.adminToken))return res.sendStatus(401);
    const {subject,action,reason_category,expires_at,idempotency_key}=req.body||{};
    const fields=Object.keys(req.body||{});
    const allowed=action==='ledger'?['subject','action']:['subject','action','reason_category','expires_at','idempotency_key'];
    if(typeof subject!=='string'||!/^v1_[A-Za-z0-9_-]{43}$/.test(subject)||!['ban','unban','ledger'].includes(action)||
        fields.some(key=>!allowed.includes(key))||
        (action!=='ledger'&&(!['spam','harassment','fraud','other'].includes(reason_category)||
          typeof idempotency_key!=='string'||!/^[A-Za-z0-9_-]{16,128}$/.test(idempotency_key)||
          (expires_at!==undefined&&(!Number.isSafeInteger(expires_at)||action!=='ban')))))
      return res.status(400).json({error:'invalid_request'});
    const saved=store.receipt(subject);if(!saved)return res.status(404).json({error:'unknown_or_expired_local_user'});
    if(expires_at!==undefined&&(expires_at<=Math.floor(Date.now()/1000)||expires_at>saved.expires))
      return res.status(400).json({error:'invalid_expiry'});
    try {
      if(action==='ledger')return res.json(await moderation.ledger(saved.receipt,20));
      return res.json(await moderation.event(saved.receipt,{action,reason_category,expires_at,idempotency_key}));
    } catch(error) {
      if(error instanceof ModerationRequestError&&[400,409,429].includes(error.status))
        return res.status(error.status).json({error:error.status===409?'moderation_conflict':'moderation_request_failed'});
      throw error;
    }
  });
  app.use((err,req,res,next)=>{res.status(503).send('Voice entry is temporarily unavailable. Start again from the site.');});
  return {app,store};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  const {app}=await createSite({issuer:process.env.OVG_ISSUER||'http://localhost:8021',audience:process.env.SITE_ORIGIN||'http://127.0.0.1:8022',
    clientId:process.env.OVG_CLIENT_ID,clientSecret:process.env.OVG_CLIENT_SECRET,kid:process.env.OVG_KID,model:process.env.OVG_MODEL,
    database:process.env.SITE_DATABASE,adminToken:process.env.SITE_ADMIN_TOKEN});
  const port=Number(process.env.PORT||8022),host=process.env.SITE_BIND_HOST||'127.0.0.1';
  app.listen(port,host,()=>console.log(`OpenVoiceGate example listening on ${host}:${port}`));
}
