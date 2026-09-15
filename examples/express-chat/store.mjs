import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
export const random=()=>randomBytes(32).toString('base64url');
export const hash=s=>createHash('sha256').update(s).digest('hex');
export const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const now=()=>Math.floor(Date.now()/1000);

export class SiteStore {
  constructor(path,{issuer,audience}) {
    if(path!==':memory:')mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(path);
    if(path!==':memory:')chmodSync(path,0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=2000;
      CREATE TABLE IF NOT EXISTS deployment(issuer TEXT NOT NULL,audience TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS pending_requests(state TEXT PRIMARY KEY, browser TEXT NOT NULL,
        nonce TEXT NOT NULL, code_verifier TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS users(sub TEXT PRIMARY KEY,label TEXT NOT NULL,hidden INTEGER NOT NULL,created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS moderation_receipts(sub TEXT PRIMARY KEY REFERENCES users(sub),receipt TEXT NOT NULL,expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS redemptions(issuer TEXT NOT NULL,jti TEXT NOT NULL,ticket_jti TEXT NOT NULL,
        nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(issuer,jti));
      CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,sub TEXT REFERENCES users(sub),csrf TEXT NOT NULL,expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS bans(sub TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,sub TEXT NOT NULL,label TEXT NOT NULL,body TEXT NOT NULL,created INTEGER NOT NULL);`);
    const binding=this.db.prepare('SELECT * FROM deployment').get();
    if(binding&&(binding.issuer!==issuer||binding.audience!==audience)) throw new Error('Database belongs to a different issuer/site');
    if(!binding)this.db.prepare('INSERT INTO deployment VALUES(?,?)').run(issuer,audience);
    this.issuer=issuer;
  }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {const result=fn();this.db.exec('COMMIT');return result;}
    catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  cleanup() {
    for(const table of ['pending_requests','sessions','redemptions','moderation_receipts'])this.db.prepare(`DELETE FROM ${table} WHERE expires<=?`).run(now());
  }
  start(browser) {
    return this.transaction(()=>{
      this.cleanup();
      this.db.prepare('DELETE FROM pending_requests WHERE browser=?').run(hash(browser));
      if(this.db.prepare('SELECT count(*) AS n FROM pending_requests').get().n>=128)throw new Error('Site entry capacity reached');
      const pending={state:random(),nonce:random(),code_verifier:random(),expires:now()+240};
      this.db.prepare('INSERT INTO pending_requests VALUES(?,?,?,?,?)').run(pending.state,hash(browser),pending.nonce,pending.code_verifier,pending.expires);
      return pending;
    });
  }
  pending(browser) {
    return this.db.prepare('SELECT * FROM pending_requests WHERE browser=? AND expires>?').get(hash(browser),now());
  }
  redeem({proof,claims,pending,moderation},browser) {
    return this.transaction(()=>{
      const time=now(), current=this.pending(browser);
      if(!current||!equal(current.state,pending.state)||current.nonce!==proof.request_nonce||proof.iss!==this.issuer||proof.exp<=time||
          this.db.prepare('SELECT 1 FROM bans WHERE sub=?').get(proof.sub)||
          this.db.prepare('SELECT 1 FROM redemptions WHERE issuer=? AND jti=?').get(this.issuer,proof.jti))return false;
      const label=claims.hidden?'Guest-'+proof.sub.slice(-10):(claims.username||claims.display_name||'Guest-'+proof.sub.slice(-10));
      this.db.prepare('INSERT INTO redemptions VALUES(?,?,?,?,?)').run(this.issuer,proof.jti,proof.ticket_jti,current.nonce,proof.exp);
      this.db.prepare('DELETE FROM pending_requests WHERE state=?').run(current.state);
      this.db.prepare(`INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(sub) DO UPDATE SET label=excluded.label,hidden=excluded.hidden`)
        .run(proof.sub,label,Number(claims.hidden),time);
      if(moderation)this.db.prepare('INSERT INTO moderation_receipts VALUES(?,?,?) ON CONFLICT(sub) DO UPDATE SET receipt=excluded.receipt,expires=excluded.expires')
        .run(proof.sub,moderation.receipt,moderation.expires_at);
      const id=random();
      this.db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(hash(id),proof.sub,random(),time+900);
      return id;
    });
  }
  session(id) {
    return this.db.prepare(`SELECT s.*,u.label,u.hidden FROM sessions s JOIN users u ON u.sub=s.sub
      WHERE s.id=? AND s.expires>? AND NOT EXISTS(SELECT 1 FROM bans b WHERE b.sub=s.sub)`).get(hash(id),now());
  }
  receipt(sub) {
    return this.db.prepare('SELECT receipt,expires FROM moderation_receipts WHERE sub=? AND expires>?').get(sub,now());
  }
  message(id,body) {
    return this.transaction(()=>{
      const session=this.session(id);if(!session)return false;
      this.db.prepare('INSERT INTO messages(sub,label,body,created) VALUES(?,?,?,?)').run(session.sub,session.label,body,now());
      this.db.exec('DELETE FROM messages WHERE id NOT IN(SELECT id FROM messages ORDER BY id DESC LIMIT 100)');return true;
    });
  }
  logout(id,browser) {
    this.transaction(()=>{
      this.db.prepare('DELETE FROM sessions WHERE id=?').run(hash(id));
      this.db.prepare('DELETE FROM pending_requests WHERE browser=?').run(hash(browser));
    });
  }
}
