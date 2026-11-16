import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {passportBytes} from '../../ZERO-TRUST/src/index.mjs';
import {revocationBytes} from '../../ZERO-TRUST/src/revocation.mjs';
import {RevocationFloor} from '../../ZERO-TRUST/src/revocation-floor.mjs';
import {policyBytes} from '../../GUARDIAN-CORE/src/signed-policy.mjs';
import {vetoBytes} from '../../GUARDIAN-CORE/src/veto.mjs';
import {PolicyFloor} from '../../GUARDIAN-CORE/src/policy-floor.mjs';
import {permitBytes} from '../../APPROVAL-GATEWAY/src/index.mjs';
import {permitDigest,decisionBytes,consumeApprovedPermit} from '../../APPROVAL-GATEWAY/src/decision-bound.mjs';
import {ReplayStore} from '../../APPROVAL-GATEWAY/src/replay-store.mjs';
import {SQLiteLedger} from '../src/sqlite-ledger.mjs';

const [idKey,revKey,policyKey,vetoKey,permitKey,decisionKey,auditKey]=Array.from({length:7},()=>generateKeyPairSync('ed25519'));
const signed=(payload,bytes,key)=>({payload,signature:sign(null,bytes(payload),key.privateKey).toString('hex')});
const scope={sub:'synthetic-agent',org:'demo',aud:'worker',cap:'read'};
const expected={sub:scope.sub,org:scope.org,aud:scope.aud,action:scope.cap,digest:'a'.repeat(64)};
const claim=signed({v:1,kid:'id',...scope,iat:100,exp:200},passportBytes,idKey);
const rev=(epoch=1,revoked=[],iat=100)=>signed({v:1,org:'demo',epoch,iat,exp:iat+60,revoked},revocationBytes,revKey);
const policy=(epoch=1,iat=100)=>signed({v:1,org:'demo',epoch,iat,exp:iat+100,rules:[{action:'read',decision:'REQUIRE_APPROVAL'}]},policyBytes,policyKey);
const veto=(epoch=1,global=false,iat=100)=>signed({v:1,org:'demo',epoch,iat,exp:iat+30,global,actions:[]},vetoBytes,vetoKey);
const identityTrust={identityKeys:new Map([['id',idKey.publicKey]]),revocationKey:revKey.publicKey,minimumEpoch:1};
const policyTrust={org:'demo',policyKey:policyKey.publicKey,vetoKey:vetoKey.publicKey,minimumPolicyEpoch:1,minimumVetoEpoch:1};
const approvalTrust={decisionKey:decisionKey.publicKey,permitKeys:new Map([['permit',permitKey.publicKey]])};
const permitPayload={v:1,kid:'permit',id:'one',...expected,epoch:1,iat:100,exp:180};
const permit=signed(permitPayload,permitBytes,permitKey);
const decision=signed({v:1,permitDigest:permitDigest(permitPayload),policyEpoch:1,vetoEpoch:1,iat:100,exp:130},decisionBytes,decisionKey);

function setup(fn){
  const dir=mkdtempSync(join(tmpdir(),'security-v04-'));
  const paths={rev:join(dir,'rev.db'),policy:join(dir,'policy.db'),replay:join(dir,'replay.db'),audit:join(dir,'audit.db')};
  let r,g,u,a;
  try{r=new RevocationFloor(paths.rev);g=new PolicyFloor(paths.policy);u=new ReplayStore(paths.replay);a=new SQLiteLedger(paths.audit,'demo','lab');fn({paths,r,g,u,a});}
  finally{for(const x of [r,g,u,a])try{x?.close();}catch{}rmSync(dir,{recursive:true,force:true});}
}
function evaluate(c,revocation=rev(),vetoState=veto()){
  const identity=c.r.admit(claim,revocation,identityTrust,scope,120);
  return c.g.evaluate({org:scope.org,action:scope.cap,identityVerified:!!identity},policy(),vetoState,policyTrust,120);
}
function consume(c){
  return consumeApprovedPermit(permit,decision,approvalTrust,expected,{org:'demo',policyEpoch:1,epoch:1,veto:false,observedAt:100},c.u,120);
}

test('verified identity to signed approval and durable audit evidence',()=>setup(c=>{
  assert.equal(evaluate(c).decision,'REQUIRE_APPROVAL');assert.equal(consume(c),true);
  const [item]=c.u.pendingEvents();assert.ok(item);assert.equal(item.permitDigest,permitDigest(permitPayload));c.a.append({id:'outbox-'+item.seq,kind:item.kind,digest:item.permitDigest});
  const receipt=c.a.signCheckpoint(auditKey.privateKey);assert.equal(c.a.verifyRetained(receipt,auditKey.publicKey),true);
  assert.equal(consume(c),false);assert.equal(c.u.pendingEvents().length,1);
}));
test('revocation and signed veto cannot be rolled back after restart',()=>setup(c=>{
  assert.equal(evaluate(c,rev(2,['synthetic-agent'],110)).decision,'DENY');
  assert.equal(c.g.evaluate({org:'demo',action:'read',identityVerified:true},policy(),veto(2,true,110),policyTrust,120).reason,'ARCHITECT_VETO');
  c.r.close();c.g.close();const r=new RevocationFloor(c.paths.rev),g=new PolicyFloor(c.paths.policy);
  try{assert.equal(r.admit(claim,rev(1),identityTrust,scope,120),null);assert.equal(g.evaluate({org:'demo',action:'read',identityVerified:true},policy(),veto(1),policyTrust,120).decision,'DENY');}finally{r.close();g.close();}
}));
test('undelivered consumption evidence survives reopen for later audit import',()=>setup(c=>{
  assert.equal(evaluate(c).decision,'REQUIRE_APPROVAL');assert.equal(consume(c),true);c.u.close();
  const reopened=new ReplayStore(c.paths.replay);
  try{const items=reopened.pendingEvents();assert.equal(items.length,1);c.a.append({id:'outbox-'+items[0].seq,kind:items[0].kind,digest:items[0].permitDigest});assert.equal(c.a.snapshot().length,1);assert.equal(consumeApprovedPermit(permit,decision,approvalTrust,expected,{org:'demo',policyEpoch:1,epoch:1,veto:false,observedAt:100},reopened,120),false);}finally{reopened.close();}
}));
