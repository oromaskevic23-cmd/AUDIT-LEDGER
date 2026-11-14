import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {passportBytes,verifyIdentity} from '../../ZERO-TRUST/src/index.mjs';
import {evaluate} from '../../GUARDIAN-CORE/src/index.mjs';
import {permitBytes,consumePermit} from '../../APPROVAL-GATEWAY/src/index.mjs';
import {append,checkpoint,verifyLedger} from '../src/index.mjs';
const key=()=>generateKeyPairSync('ed25519');
const identity=key(), permit=key(), audit=key();
const signed=(p,bytes,k)=>({payload:p,signature:sign(null,bytes(p),k.privateKey).toString('hex')});
const keys=k=>new Map([['lab',k.publicKey]]);
const digest=createHash('sha256').update('synthetic artifact').digest('hex');
const p={v:1,kid:'lab',sub:'nca',org:'demo',aud:'worker',cap:'publish',iat:100,exp:200};
const scope={sub:'nca',org:'demo',aud:'worker',action:'publish',digest};
const policy={org:'demo',rules:[{action:'publish',decision:'REQUIRE_APPROVAL'}]};
const snapshot={org:'demo',epoch:1,observedAt:100,global:false,actions:[]};
const state={org:'demo',epoch:1,observedAt:100,veto:false};
const claim=signed(p,passportBytes,identity);
const verified=verifyIdentity(claim,keys(identity),p,100);
const command={v:1,kid:'lab',id:'permit-1',...scope,epoch:1,iat:100,exp:180};
const envelope=signed(command,permitBytes,permit);
test('synthetic approved flow with signed audit checkpoint',()=>{
  assert.equal(verified,true);
  assert.equal(evaluate({identityVerified:verified,org:'demo',action:'publish'},policy,snapshot,100).decision,'REQUIRE_APPROVAL');
  // Lab fixture supplies an already signed permit; no real approval issuer exists.
  const used=new Set(); assert.equal(consumePermit(envelope,keys(permit),scope,state,used,100),true);
  const entries=append([], {id:'event-1',kind:'LAB_PERMIT_CONSUMED',digest});
  assert.equal(verifyLedger(entries,checkpoint(entries,audit.privateKey),audit.publicKey),true);
  assert.equal(consumePermit(envelope,keys(permit),scope,state,used,100),false);
});
test('synthetic veto blocks policy and existing permit; denial is auditable',()=>{
  const veto={...snapshot,epoch:2,actions:['publish']};
  assert.equal(evaluate({identityVerified:verified,org:'demo',action:'publish'},policy,veto,100).reason,'ARCHITECT_VETO');
  assert.equal(consumePermit(envelope,keys(permit),scope,{...state,epoch:2,veto:true},new Set(),100),false);
  const entries=append([], {id:'event-2',kind:'LAB_VETO_DENY',digest});
  assert.equal(verifyLedger(entries,checkpoint(entries,audit.privateKey),audit.publicKey),true);
});
