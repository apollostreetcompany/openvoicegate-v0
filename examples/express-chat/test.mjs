import test from 'node:test';
import assert from 'node:assert/strict';
import {SiteStore,random,hash} from './store.mjs';
const issuer='https://issuer.example',audience='https://chat.example';
const setup=()=>new SiteStore(':memory:',{issuer,audience});
function resolved(store,browser,sub='v1_'+random()) {
  const pending=store.start(browser);
  return {pending,proof:{iss:issuer,sub,request_nonce:pending.nonce,jti:random(),ticket_jti:random(),exp:Math.floor(Date.now()/1000)+90,
    identity_outcome:'recognized'},claims:{sub,hidden:false,display_name:'Recognized at issuer',username:''}};
}
test('recognized issuer profile first visit upserts site user, repeat preserves user and hidden changes all sessions',()=>{
 const s=setup(),b=random(),d=resolved(s,b),id=s.redeem(d,b);
 assert.equal(s.session(id).label,'Recognized at issuer');
 const other=random(),again=resolved(s,other,d.proof.sub);again.claims={sub:d.proof.sub,hidden:true};
 const id2=s.redeem(again,other);
 assert.equal(s.db.prepare('SELECT count(*) n FROM users').get().n,1);
 assert.equal(s.session(id).label,s.session(id2).label);assert.equal(s.session(id).hidden,1);
 assert.ok(s.message(id,'hello'));assert.equal(s.db.prepare('SELECT label FROM messages').get().label,s.session(id).label);
 s.db.close();
});
test('pending browser mismatch, replay, local ban rejected',()=>{
 const s=setup(),b=random(),d=resolved(s,b);
 assert.equal(s.redeem(d,random()),false);assert.ok(s.pending(b));
 s.db.prepare('INSERT INTO bans VALUES(?)').run(d.proof.sub);
 assert.equal(s.redeem(d,b),false);assert.ok(s.pending(b));
 s.db.prepare('DELETE FROM bans').run();assert.ok(s.redeem(d,b));assert.equal(s.redeem(d,b),false);
 s.db.close();
});
test('session insertion failure rolls back pending, proof and user; retry then succeeds',()=>{
 const s=setup(),b=random(),d=resolved(s,b);
 s.db.exec("CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'fixture failure'); END");
 assert.throws(()=>s.redeem(d,b));assert.ok(s.pending(b));
 assert.equal(s.db.prepare('SELECT count(*) n FROM redemptions').get().n,0);
 assert.equal(s.db.prepare('SELECT count(*) n FROM users').get().n,0);
 s.db.exec('DROP TRIGGER fail_session');assert.ok(s.redeem(d,b));s.db.close();
});
test('expired pending and logout cannot redeem or post',()=>{
 const s=setup(),b=random(),d=resolved(s,b);
 s.db.prepare('UPDATE pending_requests SET expires=0').run();assert.equal(s.redeem(d,b),false);
 const next=resolved(s,b),id=s.redeem(next,b);assert.ok(id);
 s.start(b);s.logout(id,b);assert.equal(s.pending(b),undefined);assert.equal(s.session(id),undefined);assert.equal(s.message(id,'bad'),false);
 s.db.close();
});

test('form pages preserve Origin and allow issuer navigation; callback stays private; start renews pending cookie',async()=>{
 const {createSite}=await import('./server.mjs');
 const {generateKeyPairSync}=await import('node:crypto');
 const {publicKey}=generateKeyPairSync('ed25519');
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({ok:true,json:async()=>({keys:[{...publicKey.export({format:'jwk'}),kid:'test',use:'sig',alg:'EdDSA'}]})});
 let app,store;
 try {({app,store}=await createSite({issuer,audience,clientId:'fixture',clientSecret:'fixture',kid:'test',model:'fixture',database:':memory:',moderationClient:{check:async()=>({banned:false,expires_at:null,reputation:{checked:false}})}}));}
 finally {globalThis.fetch=old;}
 const server=app.listen(0,'127.0.0.1');
 await new Promise(resolve=>server.once('listening',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 try {
   const home=await fetch(base+'/'),html=await home.text();
   assert.equal(home.headers.get('referrer-policy'),'same-origin');
   assert.ok(home.headers.get('content-security-policy').includes(`form-action 'self' ${issuer};`));
   const b=/name="csrf" value="([^"]+)"/.exec(html)[1];
   const cookie='__Host-ovg_rp_pending='+b;
   const start=await fetch(base+'/voicegate/start',{method:'POST',redirect:'manual',headers:{Origin:audience,Cookie:cookie,
     'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:b})});
   assert.equal(start.status,303);assert.ok(start.headers.get('location').startsWith(issuer+'/authorize?'));
   assert.match(start.headers.get('set-cookie'),/Max-Age=240/);
   assert.match(start.headers.get('set-cookie'),new RegExp(b));
   assert.equal(start.headers.get('referrer-policy'),'no-referrer');
   const bad=await fetch(base+'/voicegate/start',{method:'POST',headers:{Origin:'https://evil.example',Cookie:cookie,
     'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:b})});
   assert.equal(bad.status,403);
   const pending=store.pending(b),proof={iss:issuer,sub:'v1_'+random(),jti:random(),ticket_jti:random(),request_nonce:pending.nonce,exp:Math.floor(Date.now()/1000)+90};
   const id=store.redeem({pending,proof,claims:{sub:proof.sub,hidden:true},
     moderation:{receipt:'mr1.'+'r'.repeat(40),expires_at:Math.floor(Date.now()/1000)+3600}},b);
   const chat=await fetch(base+'/chat',{headers:{Cookie:'__Host-ovg_rp='+id}});
   assert.equal(chat.status,200);assert.equal(chat.headers.get('referrer-policy'),'same-origin');
   const callback=await fetch(base+'/callback');
   assert.equal(callback.status,403);assert.equal(callback.headers.get('referrer-policy'),'no-referrer');
 } finally {await new Promise(resolve=>server.close(resolve));store.db.close();}
});

test('receipts commit atomically and expired receipts are cleaned up',()=>{
 const s=setup(),b=random(),data=resolved(s,b);
 data.moderation={receipt:'mr1.'+'r'.repeat(40),expires_at:Math.floor(Date.now()/1000)+3600};
 s.db.exec("CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'fixture failure'); END");
 assert.throws(()=>s.redeem(data,b));
 assert.equal(s.db.prepare('SELECT count(*) n FROM moderation_receipts').get().n,0);
 s.db.exec('DROP TRIGGER fail_session');assert.ok(s.redeem(data,b));
 assert.equal(s.receipt(data.proof.sub).receipt,data.moderation.receipt);
 s.db.prepare('UPDATE moderation_receipts SET expires=0').run();s.cleanup();
 assert.equal(s.db.prepare('SELECT count(*) n FROM moderation_receipts').get().n,0);s.db.close();
});

test('protected chat gates current sessions and admin actions use stored receipts only',async()=>{
 const {createSite}=await import('./server.mjs');
 const {generateKeyPairSync}=await import('node:crypto');
 const {publicKey}=generateKeyPairSync('ed25519');
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({ok:true,json:async()=>({keys:[{...publicKey.export({format:'jwk'}),kid:'test',use:'sig',alg:'EdDSA'}]})});
 const receipt='mr1.'+'r'.repeat(40),adminToken=random(),events=[];
 let checks=0,decision={banned:false,expires_at:null,reputation:{checked:false}},check=async()=>decision;
 const moderationClient={check:async value=>{assert.equal(value,receipt);checks++;return check();},
  event:async(value,event)=>{assert.equal(value,receipt);events.push(event);return {event:{event_id:'event-fixture'}};},
  ledger:async(value)=>{assert.equal(value,receipt);return {events:[],has_more:false};}};
 let app,store;
 try {({app,store}=await createSite({issuer,audience,clientId:'fixture',clientSecret:'fixture',kid:'test',model:'fixture',database:':memory:',adminToken,moderationClient}));}
 finally {globalThis.fetch=old;}
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const b=random(),data=resolved(store,b);data.moderation={receipt,expires_at:Math.floor(Date.now()/1000)+3600};
 const session=store.redeem(data,b),cookie='__Host-ovg_rp='+session,csrf=store.session(session).csrf;
 const post=body=>fetch(base+'/chat',{method:'POST',redirect:'manual',headers:{Origin:audience,Cookie:cookie,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});
 const admin=(body,token=adminToken)=>fetch(base+'/admin/moderation',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body)});
 try {
  const page=await fetch(base+'/chat',{headers:{Cookie:cookie}});assert.equal(page.status,200);assert.ok(!(await page.text()).includes(receipt));
  const before=checks;assert.equal((await post({csrf:'wrong',message:'forged'})).status,403);assert.equal(checks,before);
  decision={banned:true,expires_at:Math.floor(Date.now()/1000)+60,reputation:{checked:false}};
  assert.equal((await post({csrf,message:'blocked'})).status,403);
  assert.equal(store.db.prepare('SELECT count(*) n FROM messages').get().n,0);
  assert.equal((await fetch(base+'/chat',{headers:{Cookie:cookie}})).status,403);
  check=async()=>{throw new Error('unavailable');};assert.equal((await post({csrf,message:'blocked'})).status,503);
  assert.equal(store.db.prepare('SELECT count(*) n FROM messages').get().n,0);
  const action={subject:data.proof.sub,action:'ban',reason_category:'spam',idempotency_key:'test-operation-123'};
  assert.equal((await admin(action,'bad')).status,401);assert.equal(events.length,0);
  assert.equal((await admin({...action,receipt:'injected'})).status,400);assert.equal(events.length,0);
  assert.equal((await admin(action)).status,200);assert.equal(events.length,1);
  assert.deepEqual(await (await admin({subject:data.proof.sub,action:'ledger'})).json(),{events:[],has_more:false});
  let finish,started;
  const waiting=new Promise(resolve=>{started=resolve;});
  check=()=>new Promise(resolve=>{finish=resolve;started();});
  const inFlight=fetch(base+'/chat',{headers:{Cookie:cookie}});await waiting;
  store.logout(session,b);finish({banned:false});
  assert.equal((await inFlight).status,403);
 } finally {await new Promise(resolve=>server.close(resolve));store.db.close();}
});
