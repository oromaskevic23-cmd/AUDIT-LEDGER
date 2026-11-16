import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync,statSync,symlinkSync,writeFileSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SQLiteLedger,verifyRetainedPrefix} from '../src/sqlite-ledger.mjs';
import {verifyMerkleCheckpoint} from '../src/signed-merkle.mjs';
const keys=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const event=id=>({id,kind:'LAB_EVENT',digest:'a'.repeat(64)});
function fixture(fn){const d=mkdtempSync(join(tmpdir(),'sqlite-ledger-'));try{fn(d,join(d,'audit.db'));}finally{rmSync(d,{recursive:true,force:true});}}

test('events persist and a retained checkpoint accepts a genuine extension',()=>fixture((_,path)=>{
  let s=new SQLiteLedger(path,'demo','lab'),checkpoint;
  try{s.append(event('one'));checkpoint=s.signCheckpoint(keys.privateKey);}finally{s.close();}
  s=new SQLiteLedger(path,'demo','lab');try{s.append(event('two'));assert.equal(s.snapshot().length,2);assert.equal(s.verifyRetained(checkpoint,keys.publicKey),true);}finally{s.close();}
}));
test('retained checkpoint detects truncation of an otherwise valid chain',()=>fixture((_,path)=>{
  const s=new SQLiteLedger(path,'demo','lab');let checkpoint;
  try{s.append(event('one'));s.append(event('two'));checkpoint=s.signCheckpoint(keys.privateKey);const db=new DatabaseSync(path);try{db.exec('DELETE FROM ledger_events WHERE seq=2');}finally{db.close();}assert.equal(s.snapshot().length,1);assert.equal(s.verifyRetained(checkpoint,keys.publicKey),false);}finally{s.close();}
}));
test('modified event is detected before reading or appending',()=>fixture((_,path)=>{
  const s=new SQLiteLedger(path,'demo','lab');try{s.append(event('one'));const db=new DatabaseSync(path);try{db.exec("UPDATE ledger_events SET digest='bad'");}finally{db.close();}assert.throws(()=>s.snapshot());assert.throws(()=>s.append(event('two')));}finally{s.close();}
}));
test('database is bound to its organization and ledger',()=>fixture((_,path)=>{
  const s=new SQLiteLedger(path,'demo','lab');s.close();assert.throws(()=>new SQLiteLedger(path,'other','lab'));assert.throws(()=>new SQLiteLedger(path,'demo','other'));
}));
test('duplicate event is rejected across connections',()=>fixture((_,path)=>{
  const a=new SQLiteLedger(path,'demo','lab'),b=new SQLiteLedger(path,'demo','lab');try{a.append(event('one'));assert.throws(()=>b.append(event('one')));assert.equal(b.snapshot().length,1);}finally{a.close();b.close();}
}));
test('checkpoint signature, scope and size are required',()=>fixture((_,path)=>{
  const s=new SQLiteLedger(path,'demo','lab');try{s.append(event('one'));const receipt=s.signCheckpoint(keys.privateKey),entries=s.snapshot();assert.equal(verifyMerkleCheckpoint(receipt,keys.publicKey,{org:'demo',ledger:'lab',size:1}),true);assert.equal(verifyRetainedPrefix(entries,receipt,other.publicKey,{org:'demo',ledger:'lab',size:1}),false);assert.equal(verifyRetainedPrefix(entries,receipt,keys.publicKey,{org:'other',ledger:'lab',size:1}),false);assert.equal(verifyRetainedPrefix(entries,receipt,keys.publicKey,{org:'demo',ledger:'lab',size:2}),false);}finally{s.close();}
}));
test('database is private and rejects symlinks or broad modes on POSIX',{skip:process.platform==='win32'},()=>fixture((d,path)=>{
  const s=new SQLiteLedger(path,'demo','lab');s.close();assert.equal(statSync(path).mode&0o077,0);const link=join(d,'link');symlinkSync(path,link);assert.throws(()=>new SQLiteLedger(link,'demo','lab'));chmodSync(path,0o644);assert.throws(()=>new SQLiteLedger(path,'demo','lab'));
}));
test('memory, URI and invalid scoped input are rejected',()=>{assert.throws(()=>new SQLiteLedger(':memory:','demo','lab'));assert.throws(()=>new SQLiteLedger('file::memory:?cache=shared','demo','lab'));assert.throws(()=>new SQLiteLedger('/tmp/unused','', 'lab'));});
