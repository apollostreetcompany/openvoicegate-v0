import {createPublicKey, verify, timingSafeEqual} from 'node:crypto';

export class InvalidVoiceProof extends Error {}
export class ModerationRequestError extends InvalidVoiceProof {
  constructor(status) {super('Moderation request failed');this.status=status;}
}
const fail = () => { throw new InvalidVoiceProof('Invalid or mismatched VoiceProof'); };
function validReputation(r){
  if(!r||typeof r!=='object'||Array.isArray(r)) return false;
  const keys=Object.keys(r);
  if(r.checked===false && keys.length===1 && keys[0]==='checked') return true;
  return r.checked===true && keys.length===3 &&
    (r.level==='none'||r.level==='low'||r.level==='elevated') &&
    Number.isInteger(r.sources_count) && r.sources_count>=0 && r.sources_count<=10000 &&
    keys.includes('checked') && keys.includes('level') && keys.includes('sources_count');
}
const decode = s => {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) fail();
  const b=Buffer.from(s,'base64url');
  if(b.toString('base64url')!==s) fail();
  return b;
};

/** Cryptographic validation only. Audience, nonce and keys are server-owned.
 * You MUST atomically consume the pending nonce and proof jti, check current
 * bans, and create the application session in your own server transaction.
 * This experimental SDK does not fetch keys from token-controlled locations.
 */
export function verifyVoiceProof(token, context) {
  try {
    if(typeof token!=='string' || token.length>8192) fail();
    const parts=token.split('.');if(parts.length!==3) fail();
    const [h,p,sig]=parts;
    const header=JSON.parse(decode(h).toString('utf8'));
    if(header.alg!=='EdDSA'||header.typ!=='ovg-proof+jwt'||typeof header.kid!=='string') fail();
    if(context.unified && (Object.keys(header).sort().join(',')!=='alg,kid,typ'||header.kid.length>128)) fail();
    if(['jku','jwk','x5u','crit'].some(x=>Object.hasOwn(header,x))) fail();
    const keys=context.jwks?.keys?.filter(k=>k.kid===header.kid && k.kty==='OKP' && k.crv==='Ed25519' && k.use==='sig' && k.alg==='EdDSA');
    if(!keys || keys.length!==1) fail();
    const key=createPublicKey({key:keys[0],format:'jwk'});
    if(!verify(null,Buffer.from(`${h}.${p}`),key,decode(sig))) fail();
    const claims=JSON.parse(decode(p).toString('utf8'));
    if(Object.hasOwn(claims,'mode') && (claims.mode!=='portable'||context.unified||
        ['identity_outcome','profile_shared','flow'].some(k=>Object.hasOwn(claims,k)))) fail();
    const now=Math.floor(Date.now()/1000), maxAge=context.maxAge??90;
    if(!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)) fail();
    if(claims.iat>now||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>maxAge||now-claims.iat>maxAge) fail();
    if(Object.hasOwn(claims,'nbf')&&(!Number.isSafeInteger(claims.nbf)||claims.nbf>now)) fail();
    if(claims.iss!==context.issuer || claims.aud!==context.audience || claims.action!==context.action ||
       claims.request_nonce!==context.nonce || claims.policy!==context.policy) fail();
    for(const f of ['sub','jti','ticket_jti','challenge_jti','request_nonce']) {
      if(typeof claims[f]!=='string'||claims[f].length<16||claims[f].length>128) fail();
    }
    if(!claims.sub.startsWith('v1_')||claims.assurance!=='experimental'||typeof claims.enrollment!=='boolean'||
       typeof claims.calibration_status!=='string') fail();
    if(claims.enrollment&&!context.allowEnrollment) fail();
    const methods=['nonce-speech',claims.enrollment?'voice-enrollment':'voice-profile'];
    if(JSON.stringify(claims.amr)!==JSON.stringify(methods)||claims.spoof!=='not_assessed') fail();
    return Object.freeze(claims);
  } catch(e) {
    if(e instanceof InvalidVoiceProof) throw e;
    fail();
  }
}

/** Express-compatible middleware. getContext and redeemAtomically are required.
 * Never accept nonce, audience or action straight from req.body as authority.
 * redeemAtomically should consume the server-created nonce + jti, check bans
 * and establish a site session; return false on replay. A later next() failure
 * should not make an already consumed proof reusable. Calibration must have a
 * calibrated:human source unless the site opts into provisional experiments via
 * allowProvisionalCalibration: true. A source label does not prove human origin.
 */
export function requireVoiceGate({getContext,redeemAtomically,allowProvisionalCalibration=false}) {
  if(typeof getContext!=='function'||typeof redeemAtomically!=='function') throw new TypeError('Server context and atomic redemption callbacks are required');
  if(typeof allowProvisionalCalibration!=='boolean') throw new TypeError('allowProvisionalCalibration must be a boolean');
  return async (req,res,next)=>{
    try {
      const context=await getContext(req);
      const proof=verifyVoiceProof(req.body?.voice_proof,context);
      if(!allowProvisionalCalibration&&!proof.calibration_status.startsWith('calibrated:human')) fail();
      if(!await redeemAtomically(proof,req)) fail();
      req.voicegate={subject:proof.sub,assurance:proof.assurance,enrollment:proof.enrollment,
        calibration_status:proof.calibration_status};
      return next();
    } catch(e) {
      if(e instanceof InvalidVoiceProof) return res.status(403).json({error:'voice_gate_failed'});
      return next(e); // DB/storage errors must fail closed, not be misreported as a successful gate.
    }
  };
}

/** Confidential-server backchannel. issuer/credentials/redirectUri are deployment
 * configuration; never pass browser-selected URLs here. No retries after an
 * ambiguous exchange: the issuer may already have spent the code.
 */
export async function exchangeAuthorizationCode({issuer,clientId,clientSecret,code,codeVerifier,redirectUri}) {
  const response=await fetch(`${issuer}/v1/authorize/token`, {method:'POST', redirect:'error',
    signal:AbortSignal.timeout(10_000), headers:{'Content-Type':'application/json',
      Authorization:`Basic ${Buffer.from(`${clientId}:${clientSecret}`,'ascii').toString('base64')}`},
    body:JSON.stringify({grant_type:'authorization_code',client_id:clientId,code,
      code_verifier:codeVerifier,redirect_uri:redirectUri})});
  if(!response.ok) throw new InvalidVoiceProof('Authorization exchange failed; restart entry');
  return response.json();
}

/** Express callback wiring; see examples/express-chat for SQLite transactions.
 * getPending MUST return a live, server-stored pending request belonging to the
 * callback browser cookie. context pins issuer/audience/policy/JWKS/model set.
 * redeemAtomically MUST recheck and consume pending+jti, bans, user and session.
 */
export function requireVoiceGateCallback({getPending,context,clientId,clientSecret,redirectUri,
  redeemAtomically,allowProvisionalCalibration=false,requireModeration=false}) {
  if(typeof getPending!=='function'||typeof redeemAtomically!=='function' ||
      typeof allowProvisionalCalibration!=='boolean'||typeof requireModeration!=='boolean'||!Array.isArray(context?.allowedModels)||!context.allowedModels.length)
    throw new TypeError('Pending/atomic callbacks and a model allowlist are required');
  return async (req,res,next)=>{
    try {
      const query=new URL(req.originalUrl, context.audience).searchParams;
      const pending=await getPending(req);
      if(!pending || pending.expires<=Math.floor(Date.now()/1000)) fail();
      const fields=[...query.keys()];
      if(fields.length!==3||new Set(fields).size!==3||!fields.includes('state')||!fields.includes('iss')||
          !(fields.includes('code')||fields.includes('error'))) fail();
      if(query.get('iss')!==context.issuer||!equalState(query.get('state'),pending.state)) fail();
      if(query.has('error')||!/^[A-Za-z0-9_-]{43}$/.test(query.get('code'))) fail();
      const exchanged=await exchangeAuthorizationCode({issuer:context.issuer,clientId,clientSecret,
        code:query.get('code'),codeVerifier:pending.code_verifier,redirectUri});
      const proof=verifyVoiceProof(exchanged.voice_proof,{...context,unified:true,action:'join-room',nonce:pending.nonce,allowEnrollment:true});
      const names=['iss','aud','iat','exp','jti','sub','action','ticket_jti','challenge_jti','request_nonce','policy',
        'enrollment','assurance','amr','model_set','spoof','calibration_status','reputation','identity_outcome','profile_shared'];
      if(Object.keys(proof).length!==names.length||names.some(k=>!Object.hasOwn(proof,k))||
          proof.identity_outcome!==(proof.enrollment?'created':'recognized')||typeof proof.profile_shared!=='boolean'||
          !context.allowedModels.includes(proof.model_set)||!validReputation(proof.reputation)) fail();
      if(!allowProvisionalCalibration&&!proof.calibration_status.startsWith('calibrated:human')) fail();
      const claims=exchanged.claims;
      if(!/^v1_[A-Za-z0-9_-]{43}$/.test(proof.sub)||exchanged.token_type!=='ovg-proof+jwt'||!claims||claims.sub!==proof.sub||
          claims.identity_outcome!==proof.identity_outcome||claims.hidden!==!proof.profile_shared) fail();
      const approved=['sub','identity_outcome','hidden',...(claims.hidden?[]:['display_name','username'])];
      if(Object.keys(claims).length!==approved.length||approved.some(k=>!Object.hasOwn(claims,k))) fail();
      if(!claims.hidden && [['display_name',80],['username',40]].some(([k,n])=>typeof claims[k]!=='string'||
          [...claims[k]].length>n||claims[k].normalize('NFC')!==claims[k]||/\p{C}/u.test(claims[k]))) fail();
      const receipt=exchanged.moderation_receipt, receiptExpiry=exchanged.moderation_receipt_expires_at;
      const hasModeration=typeof receipt==='string' && /^mr1\.[A-Za-z0-9_-]{28,2044}$/.test(receipt) &&
        Number.isSafeInteger(receiptExpiry) && receiptExpiry>Math.floor(Date.now()/1000) && receiptExpiry<=proof.iat+180*86400;
      if(requireModeration&&!hasModeration) fail();
      const moderation=hasModeration?{receipt,expires_at:receiptExpiry}:null;
      const session=await redeemAtomically({proof,claims,pending,moderation},req);
      if(!session) fail();
      req.voicegate={subject:proof.sub,session,calibration_status:proof.calibration_status};
      return next();
    } catch(e) {
      if(e instanceof InvalidVoiceProof) return res.status(403).send('Voice entry failed. Return to the site and start again.');
      return next(e);
    }
  };
}

function equalState(a,b) {
  // Fixed-length random state; both comparisons run on equal-sized buffers.
  return typeof a==='string'&&typeof b==='string'&&/^[A-Za-z0-9_-]{43}$/.test(a)&&
    /^[A-Za-z0-9_-]{43}$/.test(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
}


/** Server-to-server moderation only. Receipts stay in your server-side store.
 * Do not turn user-provided URLs or subjects into lookup authority.
 */
export function createModerationClient({issuer,clientId,clientSecret}) {
  const origin=new URL(issuer);
  if(origin.origin!==issuer||origin.username||origin.password||
      !(origin.protocol==='https:'||(origin.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(origin.hostname)))||
      typeof clientId!=='string'||!clientId||typeof clientSecret!=='string'||!clientSecret)
    throw new TypeError('A pinned issuer and server-owned client credentials are required');
  async function request(action,receipt,extra={}) {
    if(typeof receipt!=='string'||!/^mr1\.[A-Za-z0-9_-]{28,2044}$/.test(receipt))
      throw new InvalidVoiceProof('A valid server-held moderation receipt is required');
    const response=await fetch(`${issuer}/v1/moderation/${action}`,{method:'POST',redirect:'error',
      signal:AbortSignal.timeout(10_000),headers:{'Content-Type':'application/json',
        Authorization:`Basic ${Buffer.from(`${clientId}:${clientSecret}`,'ascii').toString('base64')}`},
      body:JSON.stringify({...extra,receipt})});
    if(!response.ok)throw new ModerationRequestError(response.status);
    return response.json();
  }
  return Object.freeze({
    async check(receipt) {
      const result=await request('check',receipt);
      const advice=result?.reputation;
      const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
        Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
      if(!exact(result,['banned','expires_at','reputation'])||typeof result.banned!=='boolean'||
          (result.banned ? !Number.isSafeInteger(result.expires_at)||result.expires_at<=0 : result.expires_at!==null)||
          !(exact(advice,['checked'])&&advice.checked===false ||
            exact(advice,['checked','flagged'])&&advice.checked===true&&typeof advice.flagged==='boolean'))
        throw new InvalidVoiceProof('Invalid moderation response');
      return result;
    },
    event:(receipt,event)=>request('events',receipt,event),
    ledger:(receipt,limit=20)=>request('ledger',receipt,{limit})
  });
}
