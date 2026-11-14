import {createHash,sign,verify} from 'node:crypto';
const genesis='0'.repeat(64);
const hash=x=>createHash('sha256').update(x).digest('hex');
function eventBytes(event) {
  if (!event || Object.keys(event).length!==3 || !['id','kind','digest'].every(k=>Object.hasOwn(event,k)) || typeof event.id!=='string' || !event.id || event.id.length>128 || typeof event.kind!=='string' || !event.kind || event.kind.length>128 || typeof event.digest!=='string' || !/^[a-f0-9]{64}$/.test(event.digest)) throw Error('event');
  return [event.id,event.kind,event.digest];
}
const entryHash=(seq,prev,event)=>hash('IMPERIAL:audit:event:v1\n'+JSON.stringify([seq,prev,eventBytes(event)]));
function inspect(entries) {
  let prev=genesis; const ids=new Set();
  for (let i=0;i<entries.length;i++) {
    const e=entries[i]; if (!e || Object.keys(e).length!==4 || e.seq!==i+1 || e.prev!==prev || ids.has(e.event.id) || e.hash!==entryHash(e.seq,e.prev,e.event)) throw Error('chain');
    ids.add(e.event.id); prev=e.hash;
  }
  return prev;
}
export function append(entries,event) {
  const prev=inspect(entries); eventBytes(event);
  if (entries.some(e=>e.event.id===event.id)) throw Error('duplicate');
  const seq=entries.length+1; return [...entries,{seq,prev,event:{...event},hash:entryHash(seq,prev,event)}];
}
const checkpointBytes=(length,head)=>Buffer.from('IMPERIAL:audit:checkpoint:v1\n'+JSON.stringify([length,head]));
export function checkpoint(entries,key) {
  if (key.asymmetricKeyType!=='ed25519') throw Error('key');
  const head=inspect(entries),length=entries.length;
  return {length,head,signature:sign(null,checkpointBytes(length,head),key).toString('hex')};
}
export function verifyLedger(entries,receipt,key) {
  try {
    return key.asymmetricKeyType==='ed25519' && receipt.length===entries.length && receipt.head===inspect(entries) && typeof receipt.signature==='string' && /^[a-f0-9]{128}$/.test(receipt.signature) && verify(null,checkpointBytes(receipt.length,receipt.head),key,Buffer.from(receipt.signature,'hex'));
  } catch { return false; }
}
