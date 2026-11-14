import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {passportBytes} from '../../ZERO-TRUST/src/index.mjs';
import {revocationBytes} from '../../ZERO-TRUST/src/revocation.mjs';
import {admitIdentity} from '../../ZERO-TRUST/src/admission.mjs';
import {vetoBytes} from '../../GUARDIAN-CORE/src/veto.mjs';
import {policyBytes,evaluateSigned} from '../../GUARDIAN-CORE/src/signed-policy.mjs';
import {permitBytes} from '../../APPROVAL-GATEWAY/src/index.mjs';
import {permitDigest,decisionBytes,consumeApprovedPermit} from '../../APPROVAL-GATEWAY/src/decision-bound.mjs';
import {ReplayStore} from '../../APPROVAL-GATEWAY/src/replay-store.mjs';
import {append} from '../src/index.mjs';
import {signMerkle,inclusionProof,verifySignedInclusion} from '../src/signed-merkle.mjs';
const [i,r,p,v,a,d,l]=Array.from({length:7},()=>generateKeyPairSync('ed25519'));
const signed=(payload,bytes,k)=>({payload,signature:sign(null,bytes(payload),k.privateKey).toString('hex')});
function run({revoked=[],global=false,tamper=false,policyEpoch=5,used=new Set()}={}){
  const now=120,scope={sub:'agent',org:'demo',aud:'worker',cap:'read'};
  const passport=signed({v:1,kid:'i',...scope,iat:100,exp:200},passportBytes,i);
  const revocation=signed({v:1,org:'demo',epoch:2,iat:100,exp:150,revoked},revocationBytes,r);
  const identity=admitIdentity(passport,revocation,{identityKeys:new Map([['i',i.publicKey]]),revocationKey:r.publicKey,minimumEpoch:2},scope,now);
  const policy=signed({v:1,org:'demo',epoch:5,iat:100,exp:200,rules:[{action:'read',decision:'REQUIRE_APPROVAL'}]},policyBytes,p);
  if(tamper)policy.payload.rules[0].decision='ALLOW';
  const veto=signed({v:1,org:'demo',epoch:2,iat:100,exp:130,global,actions:[]},vetoBytes,v);
  const evaluated=evaluateSigned({org:scope.org,action:scope.cap,identityVerified:!!identity},policy,veto,{org:'demo',policyKey:p.publicKey,vetoKey:v.publicKey,minimumPolicyEpoch:5,minimumVetoEpoch:2},now);
  const expected={sub:scope.sub,org:scope.org,aud:scope.aud,action:scope.cap,digest:'a'.repeat(64)};
  let ok=false;
  if(evaluated.decision==='REQUIRE_APPROVAL'){
    // Synthetic trusted approval fixture; no real issuer or external execution.
    const payload={v:1,kid:'a',id:'one',...expected,epoch:evaluated.epoch,iat:100,exp:180};
    const permit=signed(payload,permitBytes,a);
    const decision=signed({v:1,permitDigest:permitDigest(payload),policyEpoch:evaluated.policyEpoch,vetoEpoch:evaluated.epoch,iat:100,exp:130},decisionBytes,d);
    ok=consumeApprovedPermit(permit,decision,{decisionKey:d.publicKey,permitKeys:new Map([['a',a.publicKey]])},expected,{org:'demo',policyEpoch,epoch:2,veto:false,observedAt:100},used,now);
  }
  const entries=append([],{id:'one',kind:ok?'LAB_PERMIT_CONSUMED':'LAB_DENY',digest:expected.digest});
  const leaves=entries.map(e=>e.hash),receipt=signMerkle(leaves,'demo','lab',l.privateKey);
  assert.equal(verifySignedInclusion(leaves[0],inclusionProof(leaves,0),receipt,l.publicKey,{org:'demo',ledger:'lab',size:1}),true);
  return ok;
}
test('valid bounded flow with signed inclusion evidence',()=>assert.equal(run(),true));
test('revoked identity blocks flow',()=>assert.equal(run({revoked:['agent']}),false));
test('active veto blocks flow',()=>assert.equal(run({global:true}),false));
test('modified policy blocks flow',()=>assert.equal(run({tamper:true}),false));
test('changed policy epoch invalidates decision',()=>assert.equal(run({policyEpoch:6}),false));
test('persistent replay denied after reopening database',()=>{const dir=mkdtempSync(join(tmpdir(),'imperial-v03-'));const path=join(dir,'replay.db');let s;try{s=new ReplayStore(path);assert.equal(run({used:s}),true);s.close();s=new ReplayStore(path);assert.equal(run({used:s}),false);}finally{if(s)s.close();rmSync(dir,{recursive:true,force:true});}});
