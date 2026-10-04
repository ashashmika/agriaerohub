'use strict';
const SnapshotCrypto = {
  encode(bytes) { let text=''; for(const byte of new Uint8Array(bytes))text+=String.fromCharCode(byte);return btoa(text); },
  decode(text) { return Uint8Array.from(atob(text),c=>c.charCodeAt(0)); },
  async key(password,salt) {
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  },
  async encrypt(data,password) {
    if(password.length<16)throw Error('Use a viewing passphrase of at least 16 characters.');
    const salt=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await this.key(password,salt);
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(data)));
    return {version:1,iterations:600000,salt:this.encode(salt),iv:this.encode(iv),ciphertext:this.encode(ciphertext)};
  },
  async decrypt(envelope,password) {
    if(envelope.version!==1||envelope.iterations!==600000)throw Error('Unsupported snapshot format.');
    const key=await this.key(password,this.decode(envelope.salt));
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:this.decode(envelope.iv)},key,this.decode(envelope.ciphertext));
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
};
