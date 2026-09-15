import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {verifyVoiceProof,requireVoiceGate,InvalidVoiceProof} from './index.mjs';
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const jwks={keys:[{...publicKey.export({format:'jwk'}),kid:'test',use:'sig',alg:'EdDSA'}]};
const context={jwks,issuer:'https://issuer.example',audience:'https://site.example',action:'join-room',
 nonce:'a'.repeat(32),policy:'phrase-experimental-v1'};
function token(patch={},head={}){
 const now=Math.floor(Date.now()/1000);
 const header={alg:'EdDSA',typ:'ovg-proof+jwt',kid:'test',...head};
 const payload={iss:context.issuer,aud:context.audience,iat:now,exp:now+90,action:context.action,
  request_nonce:context.nonce,policy:context.policy,jti:'j'.repeat(24),ticket_jti:'t'.repeat(24),
  challenge_jti:'c'.repeat(24),sub:'v1_'+ 's'.repeat(43),assurance:'experimental',enrollment:false,
  amr:['nonce-speech','voice-profile'],spoof:'not_assessed',calibration_status:'calibrated:human:fixture',...patch};
 const part=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const body=part(header)+'.'+part(payload);
 return body+'.'+sign(null,Buffer.from(body),privateKey).toString('base64url');
}
test('valid proof',()=>assert.equal(verifyVoiceProof(token(),context).action,'join-room'));
for(const [name,patch,head] of [
 ['wrong audience',{aud:'https://evil.example'},{}],
 ['array audience',{aud:[context.audience]},{}],
 ['wrong nonce',{request_nonce:'b'.repeat(32)},{}],
 ['wrong action',{action:'delete-profile'},{}],
 ['expired',{iat:1,exp:91},{}],
 ['future',{iat:9999999999,exp:10000000089},{}],
 ['wrong type',{}, {typ:'ovg-challenge+jwt'}],
 ['wrong algorithm',{}, {alg:'HS256'}],
 ['remote key injection',{}, {jku:'https://evil.example'}],
 ['unapproved enrollment',{enrollment:true,amr:['nonce-speech','voice-enrollment']},{}],
 ['missing calibration',{calibration_status:undefined},{}],
 ['null calibration',{calibration_status:null},{}],
 ['numeric calibration',{calibration_status:1},{}],
 ['object calibration',{calibration_status:{}},{}],
 ['boolean calibration',{calibration_status:true},{}],
 ['array calibration',{calibration_status:[]},{}],
 ['false spoof claim',{spoof:'not-detected'},{}],
 ['future nbf',{nbf:9999999999},{}],
 ['non-integer nbf',{nbf:'soon'},{}],
]) test(name,()=>assert.throws(()=>verifyVoiceProof(token(patch,head),context),InvalidVoiceProof));
test('mandatory atomic redemption',()=>assert.throws(()=>requireVoiceGate({getContext:()=>context}),TypeError));
test('middleware rejects replay',async()=>{
 let used=false,nextCalls=0,status;
 const middleware=requireVoiceGate({getContext:()=>context,redeemAtomically:()=>{if(used)return false;used=true;return true;}});
 const req={body:{voice_proof:token()}};const res={status:x=>{status=x;return res;},json:()=>res};
 await middleware(req,res,()=>nextCalls++);await middleware(req,res,()=>nextCalls++);
 assert.equal(nextCalls,1);assert.equal(status,403);
});

for(const status of ['calibrated:synthetic-provisional:fixture','env-override','uncalibrated-default','',
                     'calibrated:human:fixture']) {
 test(`verifier exposes calibration ${JSON.stringify(status)}`,()=>{
  assert.equal(verifyVoiceProof(token({calibration_status:status}),context).calibration_status,status);
 });
 for(const allowProvisionalCalibration of [false,true]) {
  test(`middleware calibration ${JSON.stringify(status)}, opt-in=${allowProvisionalCalibration}`,async()=>{
   let redemptions=0,nextCalls=0,responseStatus;
   const middleware=requireVoiceGate({getContext:()=>context,allowProvisionalCalibration,
    redeemAtomically:()=>{redemptions++;return true;}});
   const req={body:{voice_proof:token({calibration_status:status})}};
   const res={status:x=>{responseStatus=x;return res;},json:()=>res};
   await middleware(req,res,()=>nextCalls++);
   const accepted=allowProvisionalCalibration||status.startsWith('calibrated:human');
   assert.equal(nextCalls,accepted?1:0);assert.equal(redemptions,accepted?1:0);
   if(accepted) assert.equal(req.voicegate.calibration_status,status);
   else {assert.equal(responseStatus,403);assert.equal(req.voicegate,undefined);}
  });
 }
}
test('middleware defaults to rejecting provisional calibration before redemption',async()=>{
 let redeemed=false,status;
 const middleware=requireVoiceGate({getContext:()=>context,redeemAtomically:()=>{redeemed=true;return true;}});
 const res={status:x=>{status=x;return res;},json:()=>res};
 await middleware({body:{voice_proof:token({calibration_status:'uncalibrated-default'})}},res,()=>assert.fail('accepted'));
 assert.equal(status,403);assert.equal(redeemed,false);
});
test('provisional opt-in requires a boolean',()=>{
 assert.throws(()=>requireVoiceGate({getContext:()=>context,redeemAtomically:()=>true,
  allowProvisionalCalibration:'false'}),TypeError);
});

const {requireVoiceGateCallback,exchangeAuthorizationCode}=await import('./index.mjs');
const hostedPatch={model_set:'test-model',reputation:{checked:false},identity_outcome:'recognized',profile_shared:false};
function callbackFixture(patch={},options={}) {
  const pending={state:'s'.repeat(43),nonce:context.nonce,code_verifier:'v'.repeat(43),expires:Math.floor(Date.now()/1000)+240};
  let redemptions=0,nextCalls=0,responseStatus=0,exchanges=0;
  const claims={sub:'v1_'+'s'.repeat(43),identity_outcome:'recognized',hidden:true};
  const fetch=async (url,req)=>{
    exchanges++;
    assert.equal(url,context.issuer+'/v1/authorize/token');
    assert.equal(req.redirect,'error');
    const data=JSON.parse(req.body);assert.equal(data.code_verifier,pending.code_verifier);
    assert.equal(req.headers.Authorization,'Basic '+Buffer.from('client-id:server-secret').toString('base64'));
    return {ok:true,json:async()=>({token_type:'ovg-proof+jwt',voice_proof:token({...hostedPatch,...patch}),claims,...options.response})};
  };
  const middleware=requireVoiceGateCallback({getPending:()=>pending,context:{...context,allowedModels:['test-model']},
    clientId:'client-id',clientSecret:'server-secret',redirectUri:context.audience+'/callback',
    redeemAtomically:()=>{redemptions++;return 'session';},...options.middleware});
  const run=async query=>{
    const old=globalThis.fetch;globalThis.fetch=fetch;
    try {
      const req={originalUrl:'/callback?'+(query??new URLSearchParams({code:'c'.repeat(43),state:pending.state,iss:context.issuer}))};
      const res={status:n=>{responseStatus=n;return res;},send:()=>res};
      await middleware(req,res,e=>{if(e)throw e;nextCalls++;});
      return {redemptions,nextCalls,responseStatus,exchanges,req};
    } finally {globalThis.fetch=old;}
  };
  return {run,pending};
}
test('hosted callback exchanges server-side and redeems verified proof',async()=>{
 const r=await callbackFixture().run();assert.equal(r.nextCalls,1);assert.equal(r.redemptions,1);assert.equal(r.req.voicegate.session,'session');
});
for(const query of [
 `code=${'c'.repeat(43)}&state=${'x'.repeat(43)}&iss=${context.issuer}`,
 `code=${'c'.repeat(43)}&state=${'s'.repeat(43)}&iss=https://wrong.example`,
 `code=${'c'.repeat(43)}&state=${'s'.repeat(43)}&iss=${context.issuer}&state=${'s'.repeat(43)}`,
 `code=${'c'.repeat(43)}&state=${'s'.repeat(43)}&iss=${context.issuer}&extra=1`,
])test('bad callback rejected before exchange '+query,async()=>{
 const r=await callbackFixture().run(query);assert.equal(r.responseStatus,403);assert.equal(r.exchanges,0);assert.equal(r.redemptions,0);
});
for(const patch of [{model_set:'wrong'},{flow:'identify-or-create-v1'},{identity_outcome:'created'},
 {profile_shared:true},{request_nonce:'bad'.repeat(16)},{calibration_status:'calibrated:synthetic-provisional:fixture'},
 {reputation:{checked:true}},{pid:'private-id'}])test('hosted proof policy rejects '+JSON.stringify(patch),async()=>{
 const r=await callbackFixture(patch).run();assert.equal(r.responseStatus,403);assert.equal(r.redemptions,0);
});
test('hosted callback accepts opt-in reputation advice without extra proof keys',async()=>{
 const r=await callbackFixture({reputation:{checked:true,level:'low',sources_count:2}}).run();
 assert.equal(r.nextCalls,1);assert.equal(r.redemptions,1);
});
for(const reputation of [{checked:true,level:'low',sources_count:2,sites:['https://a.example']},
 {checked:true,level:'critical',sources_count:1},{checked:true,level:'low',sources_count:1.5},
 {checked:false,level:'none',sources_count:0}])
 test('hosted callback rejects leaky or invalid reputation '+JSON.stringify(reputation),async()=>{
  const r=await callbackFixture({reputation}).run();assert.equal(r.responseStatus,403);assert.equal(r.redemptions,0);
 });
test('hosted explicit synthetic-provisional opt-in',async()=>{
 const r=await callbackFixture({calibration_status:'calibrated:synthetic-provisional:fixture'},{middleware:{allowProvisionalCalibration:true}}).run();
 assert.equal(r.redemptions,1);
});
test('hosted hidden response cannot smuggle metadata',async()=>{
 const r=await callbackFixture({}, {response:{claims:{sub:'v1_'+'s'.repeat(43),identity_outcome:'recognized',hidden:true,display_name:'private'}}}).run();
 assert.equal(r.responseStatus,403);assert.equal(r.redemptions,0);
});
test('lost exchange response is not retried',async()=>{
 const old=globalThis.fetch;let calls=0;globalThis.fetch=async()=>{calls++;throw new Error('response lost');};
 try {await assert.rejects(exchangeAuthorizationCode({issuer:context.issuer,clientId:'c',clientSecret:'s',code:'c',codeVerifier:'v',redirectUri:context.audience+'/callback'}));assert.equal(calls,1);}
 finally {globalThis.fetch=old;}
});
test('previous signing kid verifies when JWKS lists both keys',()=>{
 const previous=generateKeyPairSync('ed25519');
 const current=generateKeyPairSync('ed25519');
 const jwks={keys:[
  {...previous.publicKey.export({format:'jwk'}),kid:'local-1',use:'sig',alg:'EdDSA'},
  {...current.publicKey.export({format:'jwk'}),kid:'local-2',use:'sig',alg:'EdDSA'},
 ]};
 const part=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const now=Math.floor(Date.now()/1000);
 const header={alg:'EdDSA',typ:'ovg-proof+jwt',kid:'local-1'};
 const payload={iss:context.issuer,aud:context.audience,iat:now,exp:now+90,action:context.action,
  request_nonce:context.nonce,policy:context.policy,jti:'j'.repeat(24),ticket_jti:'t'.repeat(24),
  challenge_jti:'c'.repeat(24),sub:'v1_'+'s'.repeat(43),assurance:'experimental',enrollment:false,
  amr:['nonce-speech','voice-profile'],spoof:'not_assessed',calibration_status:'calibrated:human:fixture'};
 const body=part(header)+'.'+part(payload);
 const tok=body+'.'+sign(null,Buffer.from(body),previous.privateKey).toString('base64url');
 assert.equal(verifyVoiceProof(tok,{...context,jwks}).action,'join-room');
 const retired={...context,jwks:{keys:jwks.keys.filter(k=>k.kid==='local-2')}};
 assert.throws(()=>verifyVoiceProof(tok,retired),InvalidVoiceProof);
});

for(const response of [{}, {moderation_receipt:'mr1.'+'r'.repeat(2045),moderation_receipt_expires_at:Math.floor(Date.now()/1000)+60},
 {moderation_receipt:'mr1.'+'r'.repeat(40),moderation_receipt_expires_at:1},
 {moderation_receipt:'mr1.'+'r'.repeat(40),moderation_receipt_expires_at:Math.floor(Date.now()/1000)+181*86400}]) {
 test('required moderation rejects missing, overlong or invalid lifetime before redemption '+JSON.stringify(response).slice(0,70),async()=>{
  const result=await callbackFixture({}, {response,middleware:{requireModeration:true}}).run();
  assert.equal(result.responseStatus,403);assert.equal(result.redemptions,0);
 });
}
test('moderation receipt is passed only to atomic server storage',async()=>{
 const receipt='mr1.'+'r'.repeat(40),expiry=Math.floor(Date.now()/1000)+3600;
 let saved;
 const result=await callbackFixture({}, {response:{moderation_receipt:receipt,moderation_receipt_expires_at:expiry},
  middleware:{requireModeration:true,redeemAtomically:data=>{saved=data.moderation;return 'session';}}}).run();
 assert.deepEqual(saved,{receipt,expires_at:expiry});
 assert.ok(!Object.hasOwn(result.req.voicegate,'moderation'));assert.equal(result.nextCalls,1);
});
test('moderation client binds request and rejects malformed or leaky decisions',async()=>{
 const {createModerationClient}=await import('./index.mjs');
 const old=globalThis.fetch;let calls=0;
 const client=createModerationClient({issuer:context.issuer,clientId:'test-client',clientSecret:'test-secret'});
 const receipt='mr1.'+'r'.repeat(40);
 let answer={banned:false,expires_at:null,reputation:{checked:false}};
 globalThis.fetch=async(url,options)=>{
  calls++;assert.equal(url,context.issuer+'/v1/moderation/check');assert.equal(options.redirect,'error');
  assert.deepEqual(JSON.parse(options.body),{receipt});
  assert.equal(options.headers.Authorization,'Basic '+Buffer.from('test-client:test-secret').toString('base64'));
  return {ok:true,json:async()=>answer};
 };
 try {
  assert.deepEqual(await client.check(receipt),answer);
  await assert.rejects(client.check('mr1.'+'r'.repeat(2045)),InvalidVoiceProof);assert.equal(calls,1);
  for(const invalid of [null, {}, {banned:false,reputation:{checked:false}},
   {banned:false,expires_at:null,reputation:{checked:true}},
   {banned:false,expires_at:null,reputation:{checked:false,sites:['another-site']}},
   {banned:false,expires_at:123,reputation:{checked:false}},
   {banned:true,expires_at:null,reputation:{checked:false}}]) {
   answer=invalid;await assert.rejects(client.check(receipt),InvalidVoiceProof);
  }
  answer={banned:false,expires_at:null,reputation:{checked:true,flagged:true}};
  assert.deepEqual(await client.check(receipt),answer);
 } finally {globalThis.fetch=old;}
});

test('moderation event failures retain HTTP status without reflecting remote response text',async()=>{
 const {createModerationClient,ModerationRequestError}=await import('./index.mjs');
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({ok:false,status:409,json:async()=>({detail:'do not reflect this remote content'})});
 try {
  await assert.rejects(createModerationClient({issuer:context.issuer,clientId:'client',clientSecret:'secret'})
   .event('mr1.'+'r'.repeat(40),{action:'ban',reason_category:'spam',idempotency_key:'fixture-request-001'}),
   error=>error instanceof ModerationRequestError&&error.status===409&&!error.message.includes('remote content'));
 } finally {globalThis.fetch=old;}
});
