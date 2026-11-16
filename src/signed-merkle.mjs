import {sign,verify} from 'node:crypto';
import {merkleRoot,inclusionProof,verifyInclusion} from './merkle.mjs';
function bytes(p){
  if(!p||Object.keys(p).length!==5||!['v','org','ledger','size','root'].every(k=>Object.hasOwn(p,k))||p.v!==1||!['org','ledger'].every(k=>typeof p[k]==='string'&&p[k].length>0&&p[k].length<=128)||!Number.isSafeInteger(p.size)||p.size<1||p.size>100000||typeof p.root!=='string'||!/^[a-f0-9]{64}$/.test(p.root))throw Error('checkpoint');
  return Buffer.from('IMPERIAL:merkle-checkpoint:v1\n'+JSON.stringify([p.v,p.org,p.ledger,p.size,p.root]));
}
export function signMerkle(values,org,ledger,key){
  const payload={v:1,org,ledger,size:values.length,root:merkleRoot(values)};
  if(key.asymmetricKeyType!=='ed25519')throw Error('key');
  return {payload,signature:sign(null,bytes(payload),key).toString('hex')};
}
export {inclusionProof};
export function verifyMerkleCheckpoint(receipt,key,expected){
  try{
    const {payload:p,signature:s}=receipt, msg=bytes(p);
    if(p.org!==expected.org||p.ledger!==expected.ledger||!Number.isSafeInteger(expected.size)||p.size!==expected.size||key.asymmetricKeyType!=='ed25519'||typeof s!=='string'||!/^[a-f0-9]{128}$/.test(s)||!verify(null,msg,key,Buffer.from(s,'hex')))return false;
    return true;
  }catch{return false;}
}
export function verifySignedInclusion(value,proof,receipt,key,expected){
  return verifyMerkleCheckpoint(receipt,key,expected)&&verifyInclusion(value,proof,receipt.payload.root,receipt.payload.size);
}
