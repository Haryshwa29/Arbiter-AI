const encoder = new TextEncoder();
let cachedSecret, cachedKey;
async function key(secret) {
  if (cachedSecret !== secret) {
    cachedKey = await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
    cachedSecret = secret;
  }
  return cachedKey;
}
const encode = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const decode = text => Uint8Array.from(atob(text.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
const signedMessage = data => encoder.encode('arbiter-demo-history-v1\0'+data);
export async function readHistory(token, secret) {
  if (!token) return {v:1,exp:Date.now()+1800000,processed:0,histories:{}};
  if (typeof token!=='string' || token.length>48000) throw new Error('Invalid demo history');
  const parts=token.split('.');
  if (parts.length!==2 || !await crypto.subtle.verify('HMAC',await key(secret),decode(parts[1]),signedMessage(parts[0]))) throw new Error('Invalid demo history');
  const state=JSON.parse(new TextDecoder().decode(decode(parts[0])));
  if (state.v!==1 || !Number.isFinite(state.exp) || state.exp<Date.now() || state.processed>=500 || Object.keys(state.histories).length>128) throw new Error('Demo history expired or full. Start a new run.');
  return state;
}
export async function advanceHistory(state, signature, decision, secret) {
  const histories=Object.assign(Object.create(null),state.histories);
  const previous=histories[signature] || {total:0,suppressed:0,escalated:0};
  histories[signature]={...previous,total:previous.total+1,suppressed:previous.suppressed+(decision==='suppress'?1:0),escalated:previous.escalated+(decision==='escalate'?1:0)};
  const value=encode(encoder.encode(JSON.stringify({...state,exp:Date.now()+1800000,processed:state.processed+1,histories})));
  return value+'.'+encode(new Uint8Array(await crypto.subtle.sign('HMAC',await key(secret),signedMessage(value))));
}
