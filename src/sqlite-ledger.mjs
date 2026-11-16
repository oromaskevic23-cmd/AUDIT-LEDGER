import {DatabaseSync} from 'node:sqlite';
import {append,verifyChain} from './index.mjs';
import {merkleRoot} from './merkle.mjs';
import {signMerkle,verifyMerkleCheckpoint} from './signed-merkle.mjs';
import {ensurePrivateDatabaseFile} from './secure-db.mjs';

// A retained, authenticated checkpoint detects truncation or rewritten prefixes.
// The checkpoint and key must be retained outside the ledger's trust domain.
export function verifyRetainedPrefix(entries,receipt,key,expected){
  try{
    if(!verifyMerkleCheckpoint(receipt,key,expected)||!verifyChain(entries)||entries.length<receipt.payload.size)return false;
    return merkleRoot(entries.slice(0,receipt.payload.size).map(e=>e.hash))===receipt.payload.root;
  }catch{return false;}
}

export class SQLiteLedger {
  #db;#org;#ledger;
  constructor(path,org,ledger){
    if(![org,ledger].every(x=>typeof x==='string'&&x.length>0&&x.length<=128))throw Error('scope');
    ensurePrivateDatabaseFile(path);
    this.#db=new DatabaseSync(path);this.#org=org;this.#ledger=ledger;
    try{
      this.#db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS ledger_meta (id INTEGER PRIMARY KEY CHECK(id=1), org TEXT NOT NULL, ledger TEXT NOT NULL) STRICT; CREATE TABLE IF NOT EXISTS ledger_events (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, event_id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL, hash TEXT NOT NULL) STRICT;');
      this.#tx(()=>{
        this.#db.prepare('INSERT OR IGNORE INTO ledger_meta(id,org,ledger) VALUES(1,?,?)').run(org,ledger);
        this.#scope();
      });
    }catch(error){this.#db.close();throw error;}
  }
  #tx(fn){
    this.#db.exec('BEGIN IMMEDIATE');
    try{const value=fn();this.#db.exec('COMMIT');return value;}
    catch(error){try{this.#db.exec('ROLLBACK');}catch{}throw error;}
  }
  #scope(){
    const row=this.#db.prepare('SELECT org,ledger FROM ledger_meta WHERE id=1').get();
    if(!row||row.org!==this.#org||row.ledger!==this.#ledger)throw Error('ledger scope mismatch');
  }
  #read(){
    this.#scope();
    const rows=this.#db.prepare('SELECT seq,previous,event_id,kind,digest,hash FROM ledger_events ORDER BY seq LIMIT 100001').all();
    const entries=rows.map(r=>({seq:r.seq,prev:r.previous,event:{id:r.event_id,kind:r.kind,digest:r.digest},hash:r.hash}));
    if(!verifyChain(entries))throw Error('ledger integrity failure');
    return entries;
  }
  append(event){
    return this.#tx(()=>{
      const entries=this.#read(),next=append(entries,structuredClone(event)),e=next[next.length-1];
      this.#db.prepare('INSERT INTO ledger_events(seq,previous,event_id,kind,digest,hash) VALUES(?,?,?,?,?,?)').run(e.seq,e.prev,e.event.id,e.event.kind,e.event.digest,e.hash);
      return structuredClone(e);
    });
  }
  snapshot(){return this.#tx(()=>this.#read());}
  signCheckpoint(key){return signMerkle(this.snapshot().map(e=>e.hash),this.#org,this.#ledger,key);}
  verifyRetained(receipt,key){
    try{return verifyRetainedPrefix(this.snapshot(),receipt,key,{org:this.#org,ledger:this.#ledger,size:receipt.payload.size});}catch{return false;}
  }
  close(){this.#db.close();}
}
