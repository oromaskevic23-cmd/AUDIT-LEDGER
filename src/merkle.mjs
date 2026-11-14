import {createHash} from 'node:crypto';
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const hash=(...parts)=>createHash('sha256').update(Buffer.concat(parts)).digest('hex');
const leaf=x=>hash(Buffer.from([0]),Buffer.from(x,'hex'));
const pair=(a,b)=>hash(Buffer.from([1]),Buffer.from(a,'hex'),Buffer.from(b,'hex'));
function validate(values){if(!Array.isArray(values)||!values.length||values.length>100000||!values.every(hex))throw Error('leaves');}
function next(row){const out=[];for(let i=0;i<row.length;i+=2)out.push(i+1<row.length?pair(row[i],row[i+1]):row[i]);return out;}
export function merkleRoot(values){validate(values);let row=values.map(leaf);while(row.length>1)row=next(row);return row[0];}
export function inclusionProof(values,index){validate(values);if(!Number.isSafeInteger(index)||index<0||index>=values.length)throw Error('index');let row=values.map(leaf),i=index;const siblings=[];while(row.length>1){const other=i^1;if(other<row.length)siblings.push(row[other]);row=next(row);i=Math.floor(i/2);}return {size:values.length,index,siblings};}
// Trusted root AND tree size must be authenticated by the caller; this is not RFC 9162 wire compatibility.
export function verifyInclusion(value,proof,root,trustedSize){try{if(!hex(value)||!hex(root)||!Number.isSafeInteger(trustedSize)||trustedSize<1||trustedSize>100000||proof.size!==trustedSize||!Number.isSafeInteger(proof.index)||proof.index<0||proof.index>=trustedSize||!Array.isArray(proof.siblings)||proof.siblings.length>17||!proof.siblings.every(hex))return false;let h=leaf(value),i=proof.index,n=trustedSize,k=0;while(n>1){if((i^1)<n){const s=proof.siblings[k++];if(!s)return false;h=i%2?pair(s,h):pair(h,s);}i=Math.floor(i/2);n=Math.ceil(n/2);}return k===proof.siblings.length&&h===root;}catch{return false;}}
