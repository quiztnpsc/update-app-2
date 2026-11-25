const APP_VERSION="2026.11.23";

const $=id=>document.getElementById(id),L=['A','B','C','D','E'];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ls={get(k,d){try{const v=localStorage.getItem(k);return v?JSON.parse(v):d}catch(e){return d}},set(k,v){try{localStorage.setItem(k,JSON.stringify(v))}catch(e){}}};
let U=null,DB=null,M=null,Q=[],E='',ans={},idx=0,done=false,filter='all',shown=40,saveT=null;
const hash=s=>{let h=5381;for(const c of s)h=((h<<5)+h+c.charCodeAt(0))>>>0;return String(h)};
const show=v=>['login','home','play','result','admin','notes','live','ansv'].forEach(x=>$(x).classList.toggle('hide',x!==v));
const pk=m=>'pq:p:'+U.id+':'+m;

/* ---------- login ---------- */
let LM='student',ACC=[],HIDDEN=[],INCLAUDE=false;
const CFG=(typeof APP_CONFIG!=='undefined'&&APP_CONFIG)||{};
function makeRTDB(base){
  base=base.replace(/\/+$/,'');const u=p=>base+'/'+p+'.json';
  const J=async r=>{if(!r.ok)throw new Error('db '+r.status);return r.json()};
  return{
    doc:p=>({
      get:async()=>{const v=await J(await fetch(u(p),{cache:'no-store'}));return{exists:v!==null,data:()=>v}},
      set:async o=>{await J(await fetch(u(p),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)}))},
      delete:async()=>{await J(await fetch(u(p),{method:'DELETE'}))}
    }),
    collection:c=>({get:async()=>{const v=(await J(await fetch(u(c),{cache:'no-store'})))||{};return{docs:Object.keys(v).map(id=>({id,data:()=>v[id]}))}}})
  };
}
async function PH(em,pw){try{const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
  const b=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode('pq2|'+em.toLowerCase()),iterations:100000,hash:'SHA-256'},k,256);
  return 'p2$'+[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}catch(e){return H(em+':'+pw)}}
async function pwOK(a,em,pw){return a.pw===await PH(em,pw)||a.pw===await H(em+':'+pw)}
/* ---- up to two (or more) approved admins, each with their own password and key ---- */
const ADMINS=((CFG.admins)||[]).map(e=>String(e).trim().toLowerCase()).filter(Boolean);
const akey=e=>'a_'+hash(e.toLowerCase());
async function kget(n){if(DB){try{const d=await DB.doc('adminkeys/'+n).get();return d.exists?d.data():null}catch(e){return null}}return ls.get('pq:ak:'+n,null)}
async function kset(n,o){ls.set('pq:ak:'+n,o);if(DB){try{await DB.doc('adminkeys/'+n).set(o)}catch(e){}}}
async function wrapPriv(vj,pw){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),k=await wrapKey(pw,salt);
  return{s:b64(salt),iv:b64(iv),ct:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(vj))))}}
async function ensureKeysM(pw,ak){
  const pub=await kget('pub_'+ak),enc=await kget('priv_'+ak);
  if(pub&&enc){try{const k=await wrapKey(pw,ub(enc.s));
    ls.set('pq:priv',JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(enc.iv)},k,ub(enc.ct)))));ls.set('pq:privk',ak);return}catch(e){}}
  const kp=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  const pj=await crypto.subtle.exportKey('jwk',kp.publicKey),vj=await crypto.subtle.exportKey('jwk',kp.privateKey);
  await kset('pub_'+ak,{j:JSON.stringify(pj)});await kset('priv_'+ak,await wrapPriv(vj,pw));
  ls.set('pq:priv',vj);ls.set('pq:privk',ak);
}
async function adminPubs(){
  const ok=new Set(ADMINS.map(akey));let out=[];
  if(DB){try{const r=await DB.collection('adminkeys').get();out=r.docs.filter(d=>d.id.indexOf('pub_')===0&&ok.has(d.id.slice(4))).map(d=>({ak:d.id.slice(4),jwk:JSON.parse(d.data().j)}))}catch(e){}}
  else{ok.forEach(ak=>{const d=ls.get('pq:ak:pub_'+ak,null);if(d)out.push({ak,jwk:JSON.parse(d.j)})})}
  return out;
}
async function encProfileM(pubs,obj){
  const ak=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']),iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},ak,new TextEncoder().encode(JSON.stringify(obj))),rawk=await crypto.subtle.exportKey('raw',ak),eks={};
  for(const p of pubs){const pk=await crypto.subtle.importKey('jwk',p.jwk,RSA,false,['encrypt']);eks[p.ak]=b64(await crypto.subtle.encrypt({name:'RSA-OAEP'},pk,rawk))}
  return{eks,iv:b64(iv),ct:b64(ct)};
}
async function unwrapAes(priv,ek){const pk=await crypto.subtle.importKey('jwk',priv,RSA,false,['decrypt']);return crypto.subtle.decrypt({name:'RSA-OAEP'},pk,ub(ek))}
async function decProfileM(priv,ak,d){
  if(!d.eks||!d.eks[ak])throw new Error('no key');
  const aes=await crypto.subtle.importKey('raw',await unwrapAes(priv,d.eks[ak]),'AES-GCM',false,['decrypt']);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(d.iv)},aes,ub(d.ct))));
}
async function rewrapFor(raw,pubs,priv,ak){
  for(const id in raw){const d=raw[id];if(!d.eks||!d.eks[ak])continue;let ch=false,rk=null;
    for(const p of pubs){if(d.eks[p.ak])continue;try{rk=rk||await unwrapAes(priv,d.eks[ak]);const pk=await crypto.subtle.importKey('jwk',p.jwk,RSA,false,['encrypt']);d.eks[p.ak]=b64(await crypto.subtle.encrypt({name:'RSA-OAEP'},pk,rk));ch=true}catch(e){}}
    if(ch)await setPf(id,d)}
}
async function canEnc(){return ADMINS.length?(await adminPubs()).length>0:!!(await getPub())}
async function ENC(obj){return ADMINS.length?encProfileM(await adminPubs(),obj):encProfile(await getPub(),obj)}
const VIS=()=>MODS.filter(m=>!HIDDEN.includes(m.id));
async function saveHidden(){ls.set('pq:hidden',HIDDEN);if(DB){try{await DB.doc('settings/hidden').set({v:JSON.stringify(HIDDEN)})}catch(e){}}}
async function H(s){try{const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('pq|'+s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}catch(e){return hash(s)}}
const ekey=e=>'s_'+hash(e.toLowerCase());
const nm=a=>((a.first||'')+' '+(a.last||'')).trim()||a.name||'';
const digits=s=>String(s||'').replace(/\D/g,'').slice(-10);
const genPw=()=>Array.from(crypto.getRandomValues(new Uint8Array(8)),x=>'abcdefghjkmnpqrstuvwxyz23456789'[x%31]).join('');
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const RSA={name:'RSA-OAEP',hash:'SHA-256'};
async function encProfile(pub,obj){
  const pk=await crypto.subtle.importKey('jwk',pub,RSA,false,['encrypt']);
  const ak=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']),iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},ak,new TextEncoder().encode(JSON.stringify(obj)));
  const ek=await crypto.subtle.encrypt({name:'RSA-OAEP'},pk,await crypto.subtle.exportKey('raw',ak));
  return{ek:b64(ek),iv:b64(iv),ct:b64(ct)};
}
async function decProfile(priv,d){
  const pk=await crypto.subtle.importKey('jwk',priv,RSA,false,['decrypt']);
  const raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},pk,ub(d.ek));
  const ak=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(d.iv)},ak,ub(d.ct))));
}
async function wrapKey(pw,salt){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function getPub(){
  if(DB){try{const d=await DB.doc('adminkeys/pub').get();if(d.exists)return JSON.parse(d.data().j)}catch(e){}return null}
  return ls.get('pq:adminkey',null);
}
async function getEncPriv(){
  if(DB){try{const d=await DB.doc('adminkeys/priv').get();if(d.exists)return d.data()}catch(e){}return null}
  return ls.get('pq:adminpriv',null);
}
async function storeKeys(pj,vj,pw){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),k=await wrapKey(pw,salt);
  const e={s:b64(salt),iv:b64(iv),ct:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(vj))))};
  ls.set('pq:priv',vj);if(pj){ls.set('pq:adminkey',pj)}ls.set('pq:adminpriv',e);
  if(DB){try{if(pj)await DB.doc('adminkeys/pub').set({j:JSON.stringify(pj)});await DB.doc('adminkeys/priv').set(e)}catch(x){}}
}
async function ensureKeys(pw){
  let pub=await getPub(),enc=await getEncPriv();
  if(DB&&!pub&&!enc){const lp=ls.get('pq:adminkey',null),le=ls.get('pq:adminpriv',null);
    if(lp&&le){try{await DB.doc('adminkeys/pub').set({j:JSON.stringify(lp)});await DB.doc('adminkeys/priv').set(le);pub=lp;enc=le}catch(e){}}}
  if(pub&&enc){try{const k=await wrapKey(pw,ub(enc.s));
    ls.set('pq:priv',JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(enc.iv)},k,ub(enc.ct)))));return}catch(e){}}
  const kp=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  await storeKeys(await crypto.subtle.exportKey('jwk',kp.publicKey),await crypto.subtle.exportKey('jwk',kp.privateKey),pw);
}
async function setPf(k,o){ls.set('pq:pf:'+k,o);if(DB){try{await DB.doc('pf2/'+k).set(o)}catch(e){}}}
function lockLeft(k){const f=ls.get('pq:fail:'+k,null);return f&&f.until>Date.now()?Math.ceil((f.until-Date.now())/1000):0}
function failed(k){let f=ls.get('pq:fail:'+k,{n:0,until:0});if(f.until&&f.until<=Date.now())f={n:0,until:0};f.n++;if(f.n>=5)f.until=Date.now()+60000*Math.min(30,Math.pow(2,f.n-5));ls.set('pq:fail:'+k,f)}
async function init(){
  try{DB=await claude.use('db');INCLAUDE=!!DB}catch(e){DB=null}
  if(!DB&&CFG.rtdb)DB=makeRTDB(CFG.rtdb);
  const s=ls.get('pq:session',null);
  if(s){U=s;enter()}else show('login');
  setTimeout(()=>checkUpdate(false),Math.random()*8000);
  const loop=()=>setTimeout(()=>{checkUpdate(false);loop()},1500000+Math.random()*600000);loop();
  let lastVis=0;document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-lastVis>300000){lastVis=Date.now();checkUpdate(false)}});
}
async function getAcc(k){
  if(DB){try{const d=await DB.doc('accounts/'+k).get();return d.exists?d.data():null}catch(e){}}
  return ls.get('pq:acc:'+k,null);
}
async function setAcc(k,o){ls.set('pq:acc:'+k,o);if(DB){try{await DB.doc('accounts/'+k).set(o)}catch(e){}}}
async function getProf(k){
  if(DB){try{const d=await DB.doc('profiles/'+k).get();return d.exists?d.data():null}catch(e){return null}}
  return ls.get('pq:prof:'+k,null);
}
async function setProf(k,o){ls.set('pq:prof:'+k,o);if(DB){try{await DB.doc('profiles/'+k).set(o)}catch(e){}}}
async function getAccess(k){
  if(DB){try{const d=await DB.doc('access/'+k).get();if(d.exists)return JSON.parse(d.data().m)}catch(e){}}
  return ls.get('pq:access:'+k,[]);
}
async function setAccess(k,a){ls.set('pq:access:'+k,a);if(DB){try{await DB.doc('access/'+k).set({m:JSON.stringify(a)})}catch(e){}}}
const EJ_DEFAULT={s:'service_ixah061',t:'template_qu8z0gi',k:'6Od17mJlk1tGq_9Hb'};
const OTP_MIN=15;
async function emailCfg(){
  if(DB){try{const d=await DB.doc('settings/emailjs').get();if(d.exists&&d.data().k)return d.data()}catch(e){}}
  return ls.get('pq:emailjs',null)||EJ_DEFAULT;
}
let LASTERR='';
async function sendEmail(to,name,otp){
  const c=await emailCfg();if(!c||!c.s||!c.t||!c.k)return 'unconfigured';
  if(INCLAUDE)return 'blocked';
  try{const r=await fetch('https://api.emailjs.com/api/v1.0/email/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({service_id:c.s,template_id:c.t,user_id:c.k,template_params:{email:to,to_email:to,to_name:name,passcode:otp,otp:otp,time:new Date(Date.now()+OTP_MIN*60000).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'}),message:'Your Vettri Namadhey OTP is '+otp+'. It is valid for '+OTP_MIN+' minutes.'}})});
    if(r.ok)return 'sent';LASTERR=(r.status+' '+(await r.text())).slice(0,160);return 'failed'}catch(e){LASTERR=String(e).slice(0,120);return 'failed'}
}
function setMode(m){LM=m;
  const f=m==='forgot',o=m==='otp',ad=m==='admin';
  $('tStu').classList.toggle('on',!ad);$('tAdm').classList.toggle('on',ad);
  const rg=m==='register';['lfirst','llast','lmobile'].forEach(i=>$(i).classList.toggle('hide',!rg));
  $('lotp').classList.toggle('hide',!o);$('lpin').classList.toggle('hide',f);
  $('lpin').placeholder=o?'New password (6+ characters)':'Password (6+ characters)';
  $('lswitch').classList.toggle('hide',!(f||o||rg));$('lforgot').classList.toggle('hide',m!=='student');$('lreg').classList.toggle('hide',m!=='student');
  $('lbtn').textContent=f?'Send OTP to my email':o?'Reset password':rg?'Create account':'Login';
  $('lhelp').textContent=rg?'Create your account. The admin must approve it before you can login. Your name, mobile number and email are visible only to the admin.':ad?'Admin login. First time: the email and password you enter create the admin account.':f?'Enter your registered email. We will email you a 6-digit OTP.':o?'Enter the OTP from your email and choose a new password.':'Student login. New here? Create an account.';
  $('lmsg').style.color='var(--bad)';$('lmsg').textContent=''}
$('tStu').onclick=()=>setMode('student');$('tAdm').onclick=()=>setMode('admin');
$('lswitch').onclick=()=>setMode('student');$('lforgot').onclick=()=>setMode('forgot');$('lreg').onclick=()=>setMode('register');
$('lbtn').onclick=async()=>{
  const em=$('lemail').value.trim().toLowerCase(),pw=$('lpin').value,msg=$('lmsg');
  msg.style.color='var(--bad)';
  if(!/^\S+@\S+\.\S+$/.test(em)){msg.textContent='Enter a valid email address.';return}
  const lk=lockLeft(em);if(lk&&LM!=='register'&&LM!=='forgot'){msg.textContent='Too many attempts. Please try again in '+lk+' seconds.';return}
  msg.textContent='Please wait…';
  if(LM==='register'){
    const f=$('lfirst').value.trim(),l=$('llast').value.trim(),mb=$('lmobile').value.trim();
    if(!f||!l){msg.textContent='Enter your first name and last name.';return}
    if(digits(mb).length<10){msg.textContent='Enter a valid 10-digit mobile number.';return}
    if(pw.length<6){msg.textContent='Password must be at least 6 characters.';return}
    if(!(await canEnc())){msg.textContent=DB?'Registration is not open yet. Please ask the admin to log in once to set it up.':'Sign-up needs the shared database, which is not connected yet. Please tell your admin.';return}
    const k=ekey(em);if(await getAcc(k)){msg.textContent='This email is already registered. Please login.';return}
    await setAcc(k,{name:f,pw:await PH(em,pw),status:'pending'});await setPf(k,await ENC({first:f,last:l,mobile:mb,email:em}));
    ['lfirst','llast','lmobile','lpin'].forEach(i=>$(i).value='');setMode('student');$('lemail').value=em;$('lmsg').style.color='var(--ok)';$('lmsg').textContent='✔ Account created. Please wait for the admin to approve it, then login.';return}
  if(LM==='forgot'){
    const k=ekey(em),a=await getAcc(k);
    if(!a){msg.textContent='No account found for this email. Tap “Back to login”, then “Create new account” to sign up.';return}
    if(!(await emailCfg())?.k){msg.textContent='Email OTP is not set up yet. Please ask the admin to reset your password.';return}
    const sl=ls.get('pq:otpsend',[]).filter(t=>Date.now()-t<86400000);
    if(sl.length&&Date.now()-sl[sl.length-1]<60000){msg.textContent='Please wait a minute before asking for another OTP.';return}
    if(sl.length>=5){msg.textContent='Too many OTP requests today. Please contact the admin.';return}
    const otp=String(100000+crypto.getRandomValues(new Uint32Array(1))[0]%900000);
    const r={h:await H(otp+k),exp:Date.now()+OTP_MIN*60000};
    ls.set('pq:otp:'+k,r);if(DB){try{await DB.doc('otps/'+k).set(r)}catch(e){}}
    const st=await sendEmail(em,a.name||'',otp);if(st==='sent'){sl.push(Date.now());ls.set('pq:otpsend',sl)}
    if(st!=='sent'){msg.textContent=st==='blocked'?'Email cannot be sent from this link (it works only in the installed/hosted app). Please ask the admin to reset your password.':'Could not send the email right now. Please ask the admin to reset your password.';return}
    setMode('otp');$('lmsg').style.color='var(--ok)';$('lmsg').textContent='OTP sent to your email (check spam too). It is valid for '+OTP_MIN+' minutes.';return}
  if(LM==='otp'){
    if(pw.length<6){msg.textContent='New password needs at least 6 characters.';return}
    const k=ekey(em);let r=null;
    if(DB){try{const d=await DB.doc('otps/'+k).get();r=d.exists?d.data():null}catch(e){}}
    if(!r)r=ls.get('pq:otp:'+k,null);
    if(!r||Date.now()>r.exp||(await H($('lotp').value.trim()+k))!==r.h){failed(em);msg.textContent='Wrong or expired OTP.';return}
    const a=await getAcc(k);if(!a){msg.textContent='Account not found.';return}
    a.pw=await PH(em,pw);await setAcc(k,a);localStorage.removeItem('pq:otp:'+k);if(DB)try{await DB.doc('otps/'+k).delete()}catch(e){}
    setMode('student');$('lpin').value='';$('lotp').value='';$('lmsg').style.color='var(--ok)';$('lmsg').textContent='Password changed. Please login with your new password.';return}
  if(pw.length<6){msg.textContent='Password must be at least 6 characters.';return}
  if(LM==='admin'&&ADMINS.length){
    if(!ADMINS.includes(em)){failed(em);msg.textContent='This email is not allowed to be an admin.';return}
    const ak=akey(em);let a=await getAcc(ak);
    if(a&&a.pw){if(!(await pwOK(a,em,pw))){failed(em);msg.textContent='Wrong admin email or password.';return}}
    else{a={name:'Admin',email:em,pw:await PH(em,pw)};await setAcc(ak,a)}
    if(a.pw.indexOf('p2$')!==0){a.pw=await PH(em,pw);await setAcc(ak,a)}
    await ensureKeysM(pw,ak);
    U={id:ak,name:'Admin',email:em,admin:true};
  }else if(LM==='admin'){
    let a=await getAcc('admin');
    if(a&&a.email){if(a.email!==em||!(await pwOK(a,em,pw))){failed(em);msg.textContent='Wrong admin email or password.';return}}
    else{a={name:'Admin',email:em,pw:await PH(em,pw)};await setAcc('admin',a)}
    if(a.pw.indexOf('p2$')!==0){a.pw=await PH(em,pw);await setAcc('admin',a)}
    await ensureKeys(pw);
    U={id:'admin',name:'Admin',email:em,admin:true};
  }else{
    const k=ekey(em),a=await getAcc(k);
    if(!a){msg.textContent='No account found for this email. If you are new, or the data was reset, tap “Create new account” to sign up.';return}
    if(!(await pwOK(a,em,pw))){failed(em);msg.textContent='Wrong password.';return}
    if(a.pw.indexOf('p2$')!==0){a.pw=await PH(em,pw);await setAcc(k,a)}
    if(a.status==='pending'){msg.textContent='Your account is waiting for admin approval. Please try again later.';return}
    U={id:k,name:a.name||a.first||'Student',email:em,admin:false};
  }
  localStorage.removeItem('pq:fail:'+em);ls.set('pq:session',U);$('lpin').value='';msg.textContent='';enter();
};
$('lout').onclick=()=>{persist(true);if(U&&U.admin){localStorage.removeItem('pq:priv');localStorage.removeItem('pq:privk')}ls.set('pq:session',null);location.reload()};

/* ---------- app updates (installed app) ---------- */
const APPV=typeof APP_VERSION==='undefined'?null:APP_VERSION;
if(APPV)$('updChk').classList.remove('hide');
function updNote(h,go){const u=$('upd');u.classList.remove('hide');u.innerHTML=h+(go?' <button class="btn" id="updGo" style="margin-top:8px">Update now</button>':'');if(go)$('updGo').onclick=doUpdate}
async function checkUpdate(manual){
  if(!APPV||location.protocol.indexOf('http')!==0){if(manual)updNote('Updates work in the installed app opened from your web link.');return}
  try{const r=await fetch('version.json?'+Date.now(),{cache:'no-store'});const j=await r.json();
    if(j.v&&j.v!==APPV)updNote('🔔 New version <b>'+esc(j.v)+'</b> is available.'+(j.notes?' '+esc(j.notes):''),true);
    else if(manual)updNote('✔ You have the latest version ('+esc(APPV)+').')}
  catch(e){if(manual)updNote('Could not check for updates. Are you online?')}
}
async function doUpdate(){
  updNote('Updating… please wait');
  try{const c=await caches.open('quiz-app-v1');
    for(const u of ['index.html','app.js','data/meta.js','manifest.webmanifest','./']){const r=await fetch(u,{cache:'no-store'});if(!r.ok)throw 0;await c.put(u,r)}
  }catch(e){updNote('Could not download the update. Check your internet and try again.');return}
  location.reload();
}
$('updChk').onclick=()=>checkUpdate(true);

async function enter(){
  if(U.admin&&ADMINS.length&&!ADMINS.includes((U.email||'').toLowerCase())){ls.set('pq:session',null);U=null;$('bar2').classList.add('hide');show('login');$('lmsg').textContent='This email is not an admin.';return}
  if(!U.admin){const a=await getAcc(U.id);if(a&&a.status==='pending'){ls.set('pq:session',null);U=null;$('bar2').classList.add('hide');show('login');$('lmsg').textContent='Your account is waiting for admin approval.';return}if(!a){ls.set('pq:session',null);U=null;$('bar2').classList.add('hide');show('login');$('lmsg').textContent='This account no longer exists. Please tap “Create new account” to sign up again.';return}}
  await loadCustom();
  $('who').textContent=U.name+(U.admin?' (admin)':'');
  $('admBtn').classList.toggle('hide',!U.admin);updPending();
  $('bar2').classList.remove('hide');
  ACC=U.admin?MODS.map(m=>m.id):await getAccess(U.id);
  const last=ls.get('pq:last:'+U.id,null);
  if(last&&ACC.includes(last)&&!HIDDEN.includes(last))openMod(last);else home();
}

/* ---------- home ---------- */
async function home(){
  show('home');updPending();await loadCustom();await loadContent();await loadSchedule();$('nNotes').textContent=CONTENT.notes.length+' note(s)';const up=CONTENT.classes.filter(c=>classEnd(c)>Date.now()).length;$('nLive').textContent=up?up+' upcoming / live class(es)':'No upcoming classes';
  if(!U.admin)ACC=await getAccess(U.id);
  const ok=VIS().filter(m=>ACC.includes(m.id));
  $('mods').innerHTML=(ok.length?'':'<div class="card">⏳ No tests are unlocked for you yet. Please ask the admin to give you access, then press the <b>Tests</b> button again.</div>')+
  VIS().map(m=>{
    if(!ACC.includes(m.id))return '<div class="card" style="opacity:.55"><b>🔒 '+esc(m.name)+'</b><div class="sub" style="margin:4px 0 0">Locked · ask the admin for access</div></div>';
    const p=ls.get(pk(m.id),{ans:{}}),n=Object.keys(p.ans||{}).length,ws=winState(m.id),started=!!(p.t0||n);
    let tag='';if(ws.st==='soon')tag='🕒 Opens '+fmtDT(ws.s)+(ws.e<Infinity?' · closes '+fmtDT(ws.e):'');else if(ws.st==='closed')tag='⛔ Closed on '+fmtDT(ws.e);else if(ws.e<Infinity)tag='🟢 Open · closes '+fmtDT(ws.e);else if(ws.s)tag='🟢 Open now';
    const can=U.admin||p.done||ws.st==='open'||(ws.st==='closed'&&started);
    return '<div class="card"'+(can?'':' style="opacity:.75"')+'><b>'+esc(m.name)+'</b><div class="sub" style="margin:4px 0 '+(tag?'4':'10')+'px">'+qn(m)+' questions · ⏱ '+limitMin(m)+' min · answered '+n+(p.done?' · submitted':'')+'</div>'+(tag?'<div class="sub" style="margin:0 0 10px">'+tag+'</div>':'')+(can?'<button class="btn" data-m="'+m.id+'">'+(p.done?'View result':n?'Continue':'Start')+'</button>':'')+'</div>';
  }).join('');
}
$('cpBtn').onclick=async()=>{const m=$('cpMsg');m.style.color='var(--bad)';const a=await getAcc(U.id);if(!a){m.textContent='Account not found.';return}
  const o=$('cpOld').value,n=$('cpNew').value;if(n.length<6){m.textContent='New password needs at least 6 characters.';return}
  if(!(await pwOK(a,U.email,o))){m.textContent='Current password is wrong.';return}
  a.pw=await PH(U.email,n);await setAcc(U.id,a);if(U.admin){const v=ls.get('pq:priv',null);if(v){if(ADMINS.length)await kset('priv_'+U.id,await wrapPriv(v,n));else await storeKeys(null,v,n)}}$('cpOld').value=$('cpNew').value='';m.style.color='var(--ok)';m.textContent='Password updated ✔'};
$('mods').onclick=e=>{const b=e.target.closest('button');if(b)openMod(b.dataset.m)};
$('homeBtn').onclick=()=>{persist();ls.set('pq:last:'+U.id,null);M=null;home()};

/* ---------- persistence (survives refresh) ---------- */
function persist(now){
  if(!M||!U)return;
  const d={ans,idx,done,t0:T0},uid=U.id,mid=M.id;
  ls.set(pk(mid),d);ls.set('pq:last:'+uid,mid);
  if(DB){clearTimeout(saveT);const run=()=>DB.doc('prog/'+uid+'_'+mid).set({v:JSON.stringify(d)}).catch(()=>{});
    if(now)run();else saveT=setTimeout(run,2500)}
}
let T0=0,TT=null;
const qn=m=>m.n||(m.q?m.q.length:0);
const limitMin=m=>Math.max(1,Math.round(qn(m)*0.9));   // 90 minutes per 100 questions
const DATAV=typeof DATA_V==='undefined'?'':DATA_V;
function loadModule(m){return new Promise((res,rej)=>{if(m.q)return res();
  const s=document.createElement('script');s.src='data/m_'+m.id+'.js?v='+DATAV;
  s.onload=()=>{if(typeof MD!=='undefined'&&MD[m.id]){Object.assign(m,MD[m.id]);res()}else rej()};s.onerror=rej;document.head.appendChild(s)})}
function fmtT(ms){const s=Math.max(0,Math.ceil(ms/1000)),h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return (h?h+':'+String(m).padStart(2,'0'):m)+':'+String(x).padStart(2,'0')}
let SCHED={},SCT=0;
async function loadSchedule(force){
  if(!force&&SCT&&Date.now()-SCT<20000)return;
  let v=null;
  if(DB){try{const d=await DB.doc('settings/schedule').get();v=d.exists?JSON.parse(d.data().v):{}}catch(e){v=ls.get('pq:schedule',{})}}
  else v=ls.get('pq:schedule',{});
  SCHED=v||{};SCT=Date.now();
}
async function saveSchedule(){ls.set('pq:schedule',SCHED);if(DB){try{await DB.doc('settings/schedule').set({v:JSON.stringify(SCHED)});return true}catch(e){return false}}return true}
function winState(id){const w=SCHED[id];if(!w||(!w.s&&!w.e))return{st:'open',s:0,e:Infinity};
  const n=Date.now(),s=w.s?new Date(w.s).getTime():0,e=w.e?new Date(w.e).getTime():Infinity;
  return{st:n<s?'soon':n>e?'closed':'open',s,e}}
function dl(){let d=T0+limitMin(M)*60000;if(!U.admin){const w=winState(M.id);if(w.e<Infinity)d=Math.min(d,w.e)}return d}
const toLocalInput=iso=>{if(!iso)return'';const d=new Date(iso),p=n=>String(n).padStart(2,'0');return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes())};
function tick(){
  if(!M||done||$('play').classList.contains('hide')){clearInterval(TT);return}
  const left=dl()-Date.now();
  $('timer').textContent='⏱ '+fmtT(left);$('timer').style.color=left<300000?'var(--bad)':'';
  if(left<=0){clearInterval(TT);$('cbox').classList.add('hide');done=true;persist(true);finish(false).then(()=>{$('shareNote').textContent='⏰ Time is up — your test was submitted automatically.'})}
}
function startTimer(){clearInterval(TT);tick();TT=setInterval(tick,1000)}
async function openMod(id){
  if(!ACC.includes(id)||HIDDEN.includes(id)){home();return}
  M=MODS.find(m=>m.id===id);
  await loadSchedule();
  if(!U.admin){const ws=winState(id),pp=ls.get(pk(id),{ans:{}}),started=!!(pp.t0||Object.keys(pp.ans||{}).length);
    if(!pp.done&&(ws.st==='soon'||(ws.st==='closed'&&!started))){M=null;await home();
      $('mods').insertAdjacentHTML('afterbegin','<div class="card" style="border-color:var(--bad)">'+(ws.st==='soon'?'🕒 This test opens on '+fmtDT(ws.s)+'.':'⛔ This test is closed.')+'</div>');return}}
  if(!M.q){$('ld').classList.remove('hide');
    try{await loadModule(M)}catch(e){$('ld').classList.add('hide');M=null;await home();$('mods').insertAdjacentHTML('afterbegin','<div class="card" style="border-color:var(--bad)">Could not load this test. Check your internet and try again.</div>');return}
    $('ld').classList.add('hide')}
  Q=M.q;E=M.E;
  const d=ls.get(pk(id),{ans:{},idx:0,done:false});
  ans=d.ans||{};idx=Math.min(d.idx||0,Q.length-1);done=!!d.done;T0=d.t0||0;filter='all';shown=40;
  if(!done&&!T0)T0=Date.now();
  let auto=false;if(!done&&Date.now()>dl()){done=true;auto=true;persist(true)}
  ls.set('pq:last:'+U.id,id);
  if(done)finish(!auto).then(()=>{if(auto)$('shareNote').textContent='⏰ Time was up — your test was submitted automatically.'});else{$('mtitle').textContent=M.name;buildPal();render();show('play');startTimer()}
  if(DB){try{const s=await DB.doc('prog/'+U.id+'_'+id).get();
    if(s.exists&&M&&M.id===id&&!Object.keys(ans).length){const r=JSON.parse(s.data().v);ans=r.ans||{};idx=r.idx||0;done=!!r.done;T0=r.t0||T0;ls.set(pk(id),r);if(done)finish(true);else{render();startTimer()}}}catch(e){}}
}

/* ---------- quiz ---------- */
const img=(q,k)=>k==='E'?E:q.opts[k];
function box(v,lz,st,mod){const MM=mod||M;
  if(v&&!Array.isArray(v)&&typeof v==='object')return '<div class="tbox"'+(st?' style="'+st+'"':'')+'>'+esc(v.t)+'</div>';
  if(typeof v==='string')return '<div class="imgbox"'+(st?' style="'+st+'"':'')+'><img '+(lz?'loading="lazy" ':'')+'src="'+v+'"></div>';
  const W=MM.W,r=v[3]/W*100;
  return '<div class="imgbox" style="max-width:480px;'+(st||'')+'"><div style="position:relative;overflow:hidden;height:0;padding-bottom:'+r+'%"><img src="'+(MM.sheets||SHEETS)[v[0]]+'" style="position:absolute;left:0;top:0;max-width:none;width:200%;margin-left:-'+(v[1]*100)+'%;margin-top:-'+(v[2]/W*100)+'%"></div></div>';
}

function buildPal(){
  $('pal').innerHTML=Q.map((q,i)=>'<button data-i="'+i+'">'+(i+1)+'</button>').join('');
}
$('pal').onclick=e=>{const b=e.target.closest('button');if(b){idx=+b.dataset.i;render()}};
function render(){
  const q=Q[idx];
  $('prog').textContent='Question '+(idx+1)+' of '+Q.length;
  $('ansct').textContent='Answered: '+Object.keys(ans).length+' / '+Q.length;
  $('barfill').style.width=((idx+1)/Q.length*100)+'%';
  $('qsec').textContent=q.sec||M.name;
  $('stembox').innerHTML=box(q.stem,false);
  $('opts').innerHTML='';
  L.forEach(k=>{if(!img(q,k))return;const b=document.createElement('button');b.className='opt'+(ans[q.n]===k?' sel':'');
    b.innerHTML=box(img(q,k),false);
    b.onclick=()=>{ans[q.n]=k;persist();render()};$('opts').appendChild(b)});
  $('prev').disabled=idx===0;$('next').disabled=idx===Q.length-1;
  [...$('pal').children].forEach((b,i)=>{b.className=(ans[Q[i].n]?'a':'')+(i===idx?' cur':'')});
  persist();
}
$('prev').onclick=()=>{if(idx>0){idx--;render();scrollTo(0,0)}};
$('next').onclick=()=>{if(idx<Q.length-1){idx++;render();scrollTo(0,0)}};
$('clear').onclick=()=>{delete ans[Q[idx].n];render()};
$('submit').onclick=()=>{const left=Q.length-Object.keys(ans).length;
  $('cmsg').textContent=left?'You have '+left+' unanswered question(s). Submit anyway?':'Submit and reveal answers?';
  $('cbox').classList.remove('hide');$('cbox').scrollIntoView({block:'center'})};
$('cno').onclick=()=>$('cbox').classList.add('hide');
$('cyes').onclick=()=>{$('cbox').classList.add('hide');done=true;persist(true);finish(false)};

/* ---------- result ---------- */
const status=q=>{const a=ans[q.n];if(!a)return'skipped';if(a===q.ans)return'correct';if(a==='E')return'skipped';return'wrong'};
async function finish(restored){
  show('result');
  const c={correct:0,wrong:0,skipped:0};Q.forEach(q=>c[status(q)]++);
  $('rtitle').textContent=M.name;
  $('big').textContent=c.correct+' / '+Q.length;
  $('pct').textContent=Math.round(c.correct/Q.length*100)+'% correct';
  $('stats').innerHTML=[['Correct',c.correct],['Wrong',c.wrong],['Skipped / Do not know',c.skipped]].map(x=>'<div class="stat">'+x[0]+'<b>'+x[1]+'</b></div>').join('');
  $('tabs').innerHTML=[['all','All ('+Q.length+')'],['wrong','Wrong ('+c.wrong+')'],['skipped','Skipped ('+c.skipped+')'],['correct','Correct ('+c.correct+')']].map(t=>'<button data-f="'+t[0]+'">'+t[1]+'</button>').join('');
  rev();scrollTo(0,0);
  if(!restored)saveResult(c);
}
function saveResult(c){
  const all=ls.get('pq:res:'+U.id,{});all[M.id]={s:c.correct,t:Q.length,w:c.wrong,k:c.skipped,ts:Date.now()};ls.set('pq:res:'+U.id,all);
  if(DB)DB.doc('results/'+U.id).set({name:U.name,r:JSON.stringify(all)}).catch(()=>{$('shareNote').textContent='Your result could not be shared with the admin (ask the owner for Contributor access).'});
}
$('tabs').onclick=e=>{const b=e.target.closest('button');if(b){filter=b.dataset.f;shown=40;rev()}};
$('more').onclick=()=>{shown+=60;rev()};
function rev(){
  [...$('tabs').children].forEach(b=>b.classList.toggle('on',b.dataset.f===filter));
  const list=Q.filter(q=>filter==='all'||status(q)===filter);
  $('rev').innerHTML=list.slice(0,shown).map(q=>{
    const st=status(q),a=ans[q.n];
    const tg={correct:['✔ Correct','ok'],wrong:['✘ Wrong','bad'],skipped:[a==='E'?'Do not know':'Not answered','']}[st];
    const o=L.map(k=>{if(!img(q,k))return '';let c='opt static';if(k===q.ans)c+=' ok';else if(k===a&&k!=='E')c+=' bad';else if(k===a)c+=' sel';
      return '<div class="'+c+'">'+box(img(q,k),true)+'</div>'}).join('');
    return '<div class="card"><span class="tag">Q'+q.n+'</span> <span class="tag '+tg[1]+'">'+tg[0]+'</span> <span class="tag ok">Correct: '+q.ans+'</span>'+(a&&a!=='E'?' <span class="tag">Yours: '+a+'</span>':'')+''+box(q.stem,true,'margin:10px 0')+''+o+(q.note?'<div class="note"><b>PDF note:</b> '+esc(q.note)+'</div>':'')+'</div>'}).join('')||'<div class="card sub">Nothing here.</div>';
  $('more').classList.toggle('hide',list.length<=shown);
}
$('again').onclick=()=>{if(!U.admin&&winState(M.id).st!=='open'){$('shareNote').textContent='⛔ This test is closed, so it cannot be retaken now.';return}ans={};idx=0;done=false;T0=Date.now();persist(true);buildPal();render();show('play');startTimer();scrollTo(0,0)};
$('back').onclick=()=>{if(Date.now()>dl()){$('shareNote').textContent='⏰ Time is over for this attempt. Use Retake to try again.';return}done=false;persist(true);render();show('play');startTimer();scrollTo(0,0)};
$('toHome').onclick=()=>{ls.set('pq:last:'+U.id,null);M=null;home()};

/* ---------- admin ---------- */
let LOCKOLD=[];
async function loadAdmin(){
  $('admBody').innerHTML='<div class="sub">Loading…</div>';
  let ac=[],raw={},old={},res={},acs={},pf={};
  try{
    if(DB){
      const [a,p,o,r,c]=await Promise.all([DB.collection('accounts').get(),DB.collection('pf2').get(),DB.collection('profiles').get().catch(()=>({docs:[]})),DB.collection('results').get(),DB.collection('access').get()]);
      ac=a.docs.filter(d=>d.id!=='admin'&&d.id.indexOf('a_')!==0).map(d=>({id:d.id,...d.data()}));
      p.docs.forEach(d=>raw[d.id]=d.data());o.docs.forEach(d=>old[d.id]=d.data());
      r.docs.forEach(d=>{try{res[d.id]=JSON.parse(d.data().r)}catch(e){}});
      c.docs.forEach(d=>{try{acs[d.id]=JSON.parse(d.data().m)}catch(e){}});
    }else{
      for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);
        if(k.startsWith('pq:acc:s_'))ac.push({id:k.slice(7),...ls.get(k,{})});
        if(k.startsWith('pq:pf:'))raw[k.slice(6)]=ls.get(k,{});
        if(k.startsWith('pq:prof:'))old[k.slice(8)]=ls.get(k,{})}
      ac.forEach(x=>{res[x.id]=ls.get('pq:res:'+x.id,{});acs[x.id]=ls.get('pq:access:'+x.id,[])});
    }
  }catch(e){$('admBody').innerHTML='<div class="card">Could not load data.</div>';return}
  const priv=ls.get('pq:priv',null),aKey=ls.get('pq:privk',null);
  if(ADMINS.length&&priv&&aKey)await rewrapFor(raw,await adminPubs(),priv,aKey);
  if(await canEnc()){ // move any readable details into the encrypted store
    for(const x of ac){if(raw[x.id])continue;
      const src=old[x.id]||((x.email||x.mobile||x.first||x.last)?{first:x.first||x.name||'',last:x.last||'',mobile:x.mobile||'',email:x.email||''}:null);
      if(!src)continue;
      raw[x.id]=await ENC(src);await setPf(x.id,raw[x.id]);
      if(old[x.id]){localStorage.removeItem('pq:prof:'+x.id);if(DB)try{await DB.doc('profiles/'+x.id).delete()}catch(e){}}
      if(x.email||x.mobile||x.first||x.last)await setAcc(x.id,{name:src.first||x.name||'',pw:x.pw})}}
  if(priv)for(const id in raw){try{pf[id]=ADMINS.length?await decProfileM(priv,aKey,raw[id]):await decProfile(priv,raw[id])}catch(e){}}
  if(!priv)$('pwMsg').classList.remove('hide'),$('pwMsg').innerHTML='🔒 To see student details, please log out and log in as admin again.';
  const lockedIds=Object.keys(raw).filter(id=>!pf[id]);
  LOCKOLD=lockedIds.filter(id=>raw[id]&&raw[id].ek);
  const nShare=lockedIds.filter(id=>raw[id]&&raw[id].eks).length,nOld=LOCKOLD.length;
  $('recShareN').textContent=nShare;$('recOldN').textContent=nOld;
  $('recShare').classList.toggle('hide',!nShare);$('recOld').classList.toggle('hide',!nOld);
  $('recCard').classList.toggle('hide',!(ADMINS.length&&priv&&(nShare||nOld)));
  const c=(await emailCfg())||{};$('ejS').value=c.s||'';$('ejT').value=c.t||'';$('ejK').value=c.k||'';
  qbList();await loadContent();cRender();await loadSchedule(true);schRender();
  const all=ac.map(x=>({id:x.id,...x,...(pf[x.id]||{})})),pend=all.filter(x=>x.status==='pending'),st=all.filter(x=>x.status!=='pending');
  PEND=pend.map(x=>x.id);$('apprCard').classList.toggle('hide',!pend.length);$('apprAll').classList.toggle('hide',pend.length<2);
  $('apprList').innerHTML=pend.map(x=>'<div class="row" style="justify-content:space-between;margin-top:10px;gap:8px"><span><b>'+esc(nm(x)||x.name||'Student')+'</b><br><span class="sub">📧 '+esc(x.email||'—')+'<br>📱 '+esc(x.mobile||'—')+'</span></span><span><button class="btn" data-ap="'+x.id+'">Approve</button> <button class="btn ghost" data-rj="'+x.id+'" style="color:var(--bad)">Reject</button></span></div>').join('');
  updPending();
  $('avStu').innerHTML=st.map(x=>'<option value="'+x.id+'">'+esc(nm(x)||x.name||'Student')+'</option>').join('');$('avTest').innerHTML=VIS().map(m=>'<option value="'+m.id+'">'+esc(m.name)+'</option>').join('');
  const att=m=>st.filter(x=>(res[x.id]||{})[m.id]).length;
  const head='<tr><th>Student details</th>'+VIS().map(m=>'<th title="'+esc(m.name)+'">'+esc(m.short)+'<br><span class="sub">'+att(m)+' attended</span></th>').join('')+'<th></th></tr>';
  const body=st.map(x=>{const a=acs[x.id]||[],r=res[x.id]||{};
    return '<tr><td><b>'+esc(nm(x))+'</b><br><span class="sub">📧 '+esc(x.email||'—')+'<br>📱 '+esc(x.mobile||'—')+'</span></td>'+VIS().map(m=>{const v=r[m.id];
      return '<td><input type="checkbox" data-s="'+x.id+'" data-m="'+m.id+'"'+(a.includes(m.id)?' checked':'')+'> '+(v?'<b>'+v.s+'/'+v.t+'</b><br><span class="sub">✔'+v.s+' ✘'+(v.w??'–')+' ⏭'+(v.k??'–')+'<br>'+new Date(v.ts).toLocaleDateString()+'</span><br><button class="btn ghost" style="padding:4px 8px;font-size:12px;margin-top:4px" data-av="'+x.id+'|'+m.id+'">👁 Answers</button>':'<span class="sub">—</span>')+'</td>'}).join('')+
      '<td><button class="btn ghost" data-all="'+x.id+'">All</button> <button class="btn ghost" data-none="'+x.id+'">None</button> <button class="btn ghost" data-pw="'+x.id+'">Reset password</button> <button class="btn ghost" data-del="'+x.id+'">Reset scores</button> <button class="btn ghost" data-rm="'+x.id+'" style="color:var(--bad)">Remove user</button></td></tr>'}).join('');
  $('admBody').innerHTML=st.length?'<div class="sub" style="margin-bottom:8px">'+st.length+' student(s). Tick a box to give access to a test. Scores appear after the student submits.</div><div class="card" style="overflow:auto"><table>'+head+body+'</table></div>':'<div class="card sub">No students yet. Students create their own accounts from the login page.</div>';
  $('admBody').onchange=async e=>{const c=e.target;if(!c.dataset.s)return;
    let a=await getAccess(c.dataset.s);a=a.filter(x=>x!==c.dataset.m);if(c.checked)a.push(c.dataset.m);await setAccess(c.dataset.s,a)};
  $('admBody').onclick=async e=>{const b=e.target.closest('button');if(!b)return;
    if(b.dataset.all){await setAccess(b.dataset.all,VIS().map(m=>m.id));loadAdmin()}
    else if(b.dataset.none){await setAccess(b.dataset.none,[]);loadAdmin()}
    else if(b.dataset.pw){const id=b.dataset.pw,a=await getAcc(id),p=pf[id]||{};const em=p.email||(a&&a.email);if(a&&!em){$('pwMsg').classList.remove('hide');$('pwMsg').textContent='Log out and log in as admin again, then retry.';return}if(a){const t=genPw();
      a.pw=await PH(em,t);await setAcc(id,a);
      $('pwMsg').classList.remove('hide');$('pwMsg').innerHTML='New temporary password for <b>'+esc(nm(p)||a.name)+'</b> ('+esc(em)+'): <b style="font-size:18px">'+t+'</b><br>Send it to the student. They can change it after login.';scrollTo(0,0)}}
    else if(b.dataset.av){const p=b.dataset.av.split('|'),u=st.find(y=>y.id===p[0])||{};openAnswers(p[0],p[1],nm(u)||u.name||'Student')}
    else if(b.dataset.rm){if(!b.dataset.sure){b.dataset.sure='1';b.textContent='Sure? Click again';return}await removeUser(b.dataset.rm);loadAdmin()}
    else if(b.dataset.del){const id=b.dataset.del;ls.set('pq:res:'+id,{});if(DB)try{await DB.doc('results/'+id).delete()}catch(er){}loadAdmin()}};
}
$('recGo').onclick=async()=>{
  const m=$('recMsg');m.style.color='var(--bad)';const pw=$('recPw').value;if(!pw){m.textContent='Enter the old admin password.';return}
  m.textContent='Working…';
  const enc=(await kget('priv'))||ls.get('pq:adminpriv',null);let vj=null;
  if(enc){try{const k=await wrapKey(pw,ub(enc.s));vj=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(enc.iv)},k,ub(enc.ct))))}catch(e){}}
  if(!vj){m.textContent='That password does not unlock the old details. Use the password of the person who first logged in as admin before the update.';return}
  const raw={};
  if(DB){try{const r=await DB.collection('pf2').get();r.docs.forEach(d=>raw[d.id]=d.data())}catch(e){}}
  else{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);if(k.indexOf('pq:pf:')===0)raw[k.slice(6)]=ls.get(k,{})}}
  let n=0,found=0;
  for(const id in raw){const d=raw[id];if(!d||!d.ek)continue;found++;try{const o=await decProfile(vj,d);await setPf(id,await ENC(o));n++}catch(e){}}
  m.style.color=n?'var(--ok)':'var(--bad)';
  m.textContent=n?'✔ Recovered details of '+n+' student(s).'+(found>n?' '+(found-n)+' could not be unlocked with this password.':''):found?'This password opens the current key, but it does not match these old records (the old key was replaced later), so they cannot be recovered.':'No old-format records were found.';
  $('recPw').value='';loadAdmin()};
$('recDel').onclick=async()=>{const b=$('recDel');
  if(!b.dataset.sure){b.dataset.sure='1';b.textContent='Sure? Their scores are removed too. Click again';return}
  b.dataset.sure='';b.textContent='Remove these students';
  for(const id of LOCKOLD.slice())await removeUser(id);loadAdmin()};
$('ejSave').onclick=async()=>{const c={s:$('ejS').value.trim(),t:$('ejT').value.trim(),k:$('ejK').value.trim()};ls.set('pq:emailjs',c);
  if(DB)try{await DB.doc('settings/emailjs').set(c)}catch(e){}$('ejMsg').style.color='var(--ok)';$('ejMsg').textContent='Saved.'};
$('ejTest').onclick=async()=>{$('ejMsg').style.color='var(--bad)';$('ejMsg').textContent='Sending…';
  const st=await sendEmail(U.email,'Admin','123456');
  $('ejMsg').textContent=st==='sent'?'✔ Test email sent to '+U.email+' (check inbox/spam)':st==='unconfigured'?'Save the three EmailJS values first.':st==='blocked'?'You are on the claude.ai link, which cannot send email. Open the installed/hosted app (Netlify link), log in as admin there, and test again.':'EmailJS refused it: '+LASTERR;
  if(st==='sent')$('ejMsg').style.color='var(--ok)'};
$('admBtn').onclick=()=>{show('admin');loadAdmin();qbShow('')};
async function removeUser(id){
  const mids=MODS.map(m=>m.id);
  ['pq:acc:'+id,'pq:prof:'+id,'pq:pf:'+id,'pq:access:'+id,'pq:res:'+id].forEach(k=>localStorage.removeItem(k));mids.forEach(m=>localStorage.removeItem('pq:p:'+id+':'+m));
  if(DB)for(const p of ['accounts/'+id,'profiles/'+id,'pf2/'+id,'access/'+id,'results/'+id,'otps/'+id,...mids.map(m=>'prog/'+id+'_'+m)]){try{await DB.doc(p).delete()}catch(e){}}
}
/* ---------- custom quizzes ---------- */
async function loadCustom(){
  let list=[];
  HIDDEN=ls.get('pq:hidden',[]);
  if(DB){try{const h=await DB.doc('settings/hidden').get();HIDDEN=h.exists?JSON.parse(h.data().v):[]}catch(e){}}
  if(DB){try{const r=await DB.collection('quizzes').get();list=r.docs.map(d=>({id:d.id,name:d.data().name,q:JSON.parse(d.data().q)}))}catch(e){}}
  else list=ls.get('pq:quizzes',[]);
  for(let i=MODS.length-1;i>=0;i--)if(MODS[i].custom)MODS.splice(i,1);
  list.forEach(c=>MODS.push({id:'c_'+c.id,custom:true,cid:c.id,short:c.name.slice(0,10),name:c.name+' ('+c.q.length+' Q)',E:{t:'E) Do not know / விடை தெரியவில்லை'},
    q:c.q.map((x,i)=>{const o={};['a','b','c','d'].forEach((k,j)=>{if(x[k])o['ABCD'[j]]={t:'ABCD'[j]+') '+x[k]}});return{n:i+1,sec:'',stem:{t:(i+1)+'. '+x.q},opts:o,ans:x.ans,note:null}})}));
}
let QB=[];
function rows(t){const d=(t.split('\n')[0]||'').includes('\t')?'\t':',';const out=[];let r=[],f='',q=false;
  for(let i=0;i<t.length;i++){const c=t[i];
    if(q){if(c==='"'){if(t[i+1]==='"'){f+='"';i++}else q=false}else f+=c}
    else if(c==='"')q=true;else if(c===d){r.push(f);f=''}
    else if(c==='\n'||c==='\r'){if(c==='\r'&&t[i+1]==='\n')i++;r.push(f);f='';if(r.some(x=>x.trim()))out.push(r);r=[]}
    else f+=c}
  r.push(f);if(r.some(x=>x.trim()))out.push(r);return out}
function toQs(text){
  text=text.trim();let items;
  if(text[0]==='[')items=JSON.parse(text).map(x=>[x.q||x.question,x.a||x.A,x.b||x.B,x.c||x.C,x.d||x.D,x.ans||x.answer]);else items=rows(text);
  const out=[];
  items.forEach((r,i)=>{r=r.map(x=>String(x==null?'':x).trim());if(i===0&&/^(question|q)$/i.test(r[0]))return;
    const o=[r[1],r[2],r[3],r[4]];let a=(r[5]||'').toUpperCase();
    if(!(a.length===1&&'ABCD'.includes(a))){const n=parseInt(a);a=n>=1&&n<=4?'ABCD'[n-1]:('ABCD'[o.findIndex(z=>z&&z===r[5])]||'')}
    if(r[0]&&o[0]&&o[1]&&a&&o['ABCD'.indexOf(a)])out.push({q:r[0],a:o[0],b:o[1],c:o[2]||'',d:o[3]||'',ans:a})});
  return out}
function qbShow(m){$('qbList').textContent='Questions in this quiz so far: '+QB.length;$('qbMsg').textContent=m||''}
$('qbFile').onchange=e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{$('qbText').value=String(r.result).replace(/^\uFEFF/,'');qbShow('File loaded. Press "Add these questions".')};r.readAsText(f,'utf-8')};
$('qbParse').onclick=()=>{try{const a=toQs($('qbText').value);QB=QB.concat(a);$('qbText').value='';qbShow(a.length+' question(s) added.')}catch(e){qbShow('Could not read that text. Check the format.')}};
$('qbOne').onclick=()=>{const g=id=>$(id).value.trim(),ans=$('mcor').value,o=[g('mA'),g('mB'),g('mC'),g('mD')];
  if(!g('mq')||!o[0]||!o[1]||!o['ABCD'.indexOf(ans)]){qbShow('Enter the question, at least options A and B, and a correct option that is filled in.');return}
  QB.push({q:g('mq'),a:o[0],b:o[1],c:o[2],d:o[3],ans});['mq','mA','mB','mC','mD'].forEach(i=>$(i).value='');qbShow('Question added.')};
$('qbClear').onclick=()=>{QB=[];qbShow('Cleared.')};
$('qbSave').onclick=async()=>{const n=$('qbName').value.trim();if(!n||!QB.length){qbShow('Enter a quiz name and add at least one question.');return}
  const js=JSON.stringify(QB);if(js.length>220000){qbShow('Too many questions for one quiz. Split it into smaller quizzes (about 300 each).');return}
  const id=Date.now().toString(36);
  if(DB){try{await DB.doc('quizzes/'+id).set({name:n,q:js,ts:Date.now()})}catch(e){qbShow('Could not save the quiz. Check that you have Editor access.');return}}
  else{const l=ls.get('pq:quizzes',[]);l.push({id,name:n,q:QB});ls.set('pq:quizzes',l)}
  QB=[];$('qbName').value='';await loadCustom();qbShow('Quiz saved. Tick it for students in the table above.');loadAdmin()};
$('qbExisting').onclick=async e=>{const b=e.target.closest('button');if(!b)return;
  if(!b.dataset.show&&!b.dataset.sure){b.dataset.sure='1';b.textContent='Sure? Click again';return}
  if(b.dataset.cq){const id=b.dataset.cq;if(DB)try{await DB.doc('quizzes/'+id).delete()}catch(er){}else ls.set('pq:quizzes',ls.get('pq:quizzes',[]).filter(x=>x.id!==id));await loadCustom()}
  else if(b.dataset.hide){HIDDEN=[...HIDDEN,b.dataset.hide];await saveHidden()}
  else if(b.dataset.show){HIDDEN=HIDDEN.filter(x=>x!==b.dataset.show);await saveHidden()}
  loadAdmin()};
function qbList(){
  $('qbExisting').innerHTML=MODS.map(m=>{const h=HIDDEN.includes(m.id);
    const btn=m.custom?'<button class="btn ghost" data-cq="'+m.cid+'">Delete</button>':h?'<button class="btn ghost" data-show="'+m.id+'">Restore</button>':'<button class="btn ghost" data-hide="'+m.id+'">Remove</button>';
    return '<div class="row" style="justify-content:space-between;margin-top:8px;'+(h?'opacity:.5':'')+'"><span>'+esc(m.name)+(h?' <span class="tag">removed</span>':'')+'</span>'+btn+'</div>'}).join('')}

/* ---------- notes & live classes ---------- */
let CONTENT={notes:[],classes:[]};
const safeUrl=u=>{u=String(u||'').trim();return /^https?:\/\/\S+$/i.test(u)||/^[\w\-./]+$/.test(u)?u:''};
const fmtDT=t=>new Date(t).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'});
const classStart=c=>new Date(c.start).getTime(),classEnd=c=>classStart(c)+(+c.dur||60)*60000;
let CT=0,CLOADED=false;
async function loadContent(){
  if(CLOADED&&Date.now()-CT<60000&&!(U&&U.admin))return;
  let c=null;
  if(DB){try{const d=await DB.doc('content/main').get();if(d.exists)c=JSON.parse(d.data().v)}catch(e){}}
  else{
    try{const r=await fetch('content.json?'+Date.now(),{cache:'no-store'});if(r.ok){c=await r.json();ls.set('pq:contentcache',c)}}catch(e){}
    if(!c)c=ls.get('pq:contentcache',null);
    if(U&&U.admin){const dr=ls.get('pq:contentdraft',null);if(dr)c=dr}
  }
  if(!c&&DB&&!INCLAUDE){try{const r=await fetch('content.json?'+Date.now(),{cache:'no-store'});if(r.ok)c=await r.json()}catch(e){}}
  CONTENT={notes:(c&&c.notes)||[],classes:(c&&c.classes)||[]};CT=Date.now();CLOADED=true;
}
async function saveContent(){
  if(DB){try{await DB.doc('content/main').set({v:JSON.stringify(CONTENT)});return true}catch(e){return false}}
  ls.set('pq:contentdraft',CONTENT);return true;
}
let OPENNOTE=null,LVT=null;
function renderNotes(){
  $('nRead').classList.add('hide');$('nList').classList.remove('hide');$('nSearch').classList.remove('hide');
  const q=$('nSearch').value.trim().toLowerCase();
  const list=CONTENT.notes.filter(n=>!q||((n.title||'')+' '+(n.subject||'')+' '+(n.body||'')).toLowerCase().includes(q)).sort((a,b)=>(b.ts||0)-(a.ts||0));
  $('nList').innerHTML=list.map(n=>'<button class="opt" data-n="'+esc(n.id)+'" style="padding:12px"><b>'+esc(n.title)+'</b> '+(n.subject?'<span class="tag">'+esc(n.subject)+'</span>':'')+'<div class="sub" style="margin:4px 0 0">'+esc((n.body||'').slice(0,110))+((n.body||'').length>110?'…':'')+'</div></button>').join('')||'<div class="card sub">No notes yet.</div>';
}
$('nList').onclick=e=>{const b=e.target.closest('button');if(!b)return;const n=CONTENT.notes.find(x=>x.id===b.dataset.n);if(!n)return;
  const u=safeUrl(n.link);
  $('nList').classList.add('hide');$('nSearch').classList.add('hide');$('nRead').classList.remove('hide');
  $('nRead').innerHTML='<button class="btn ghost" id="nBackList">← All notes</button><h2 style="margin:12px 0 4px">'+esc(n.title)+'</h2>'+(n.subject?'<span class="tag">'+esc(n.subject)+'</span> ':'')+'<span class="sub">'+(n.ts?fmtDT(n.ts):'')+'</span><div style="white-space:pre-wrap;margin-top:12px;line-height:1.6">'+esc(n.body||'')+'</div>'+(u?'<p><a class="btn" href="'+esc(u)+'" target="_blank" rel="noopener">Open attached PDF / link</a></p>':'')+(n.fileId?'<p><button class="btn" id="nFileBtn">📎 Open '+esc(n.fileName||'attached file')+'</button> <span class="sub" id="nFileMsg"></span></p>':'');
  if(n.fileId)$('nFileBtn').onclick=()=>openNoteFile(n);
  $('nBackList').onclick=renderNotes;scrollTo(0,0)};
$('nSearch').oninput=renderNotes;
$('goNotes').onclick=async()=>{show('notes');await loadContent();$('nSearch').value='';renderNotes()};
$('nBack').onclick=()=>home();
function renderLive(){
  const now=Date.now(),cl=CONTENT.classes.slice();
  const live=cl.filter(c=>classStart(c)<=now&&classEnd(c)>now),up=cl.filter(c=>classStart(c)>now).sort((a,b)=>classStart(a)-classStart(b)),past=cl.filter(c=>classEnd(c)<=now).sort((a,b)=>classStart(b)-classStart(a)).slice(0,10);
  const card=(c,st)=>{const u=safeUrl(c.link),r=safeUrl(c.rec);let badge='',btn='';
    if(st==='live'){badge='<span class="tag bad">🔴 LIVE NOW</span>';btn=u?'<a class="btn" href="'+esc(u)+'" target="_blank" rel="noopener">Join class</a>':''}
    else if(st==='up'){const m=Math.max(0,Math.round((classStart(c)-now)/60000)),t=m>=1440?Math.floor(m/1440)+' day(s)':m>=60?Math.floor(m/60)+'h '+(m%60)+'m':m+' min';badge='<span class="tag">⏰ Starts in '+t+'</span>';btn=u?'<a class="btn ghost" href="'+esc(u)+'" target="_blank" rel="noopener">Join link</a>':''}
    else{badge='<span class="tag">Ended</span>';btn=r?'<a class="btn ghost" href="'+esc(r)+'" target="_blank" rel="noopener">Watch recording</a>':''}
    return '<div class="card"><b>'+esc(c.title)+'</b> '+(c.subject?'<span class="tag">'+esc(c.subject)+'</span>':'')+'<div class="sub" style="margin:6px 0">📅 '+fmtDT(c.start)+' · '+(c.dur||60)+' min</div>'+(c.desc?'<div style="margin-bottom:8px">'+esc(c.desc)+'</div>':'')+badge+(btn?'<div style="margin-top:10px">'+btn+'</div>':'')+'</div>'};
  $('lvList').innerHTML=live.map(c=>card(c,'live')).join('')+(up.length?'<h3 style="margin:14px 0 6px;font-size:15px">Upcoming</h3>'+up.map(c=>card(c,'up')).join(''):'')+(past.length?'<h3 style="margin:14px 0 6px;font-size:15px">Past classes</h3>'+past.map(c=>card(c,'past')).join(''):'')||'<div class="card sub">No classes scheduled yet.</div>';
}
$('goLive').onclick=async()=>{show('live');await loadContent();renderLive();clearInterval(LVT);LVT=setInterval(()=>{if(!$('live').classList.contains('hide'))renderLive();else clearInterval(LVT)},30000)};
$('lvBack').onclick=()=>{clearInterval(LVT);home()};
/* admin editor for notes & classes */
const rid=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,5);
function cRender(){
  $('cDl').classList.toggle('hide',!!DB);$('cFile').classList.toggle('hide',!(DB&&!INCLAUDE));$('cFileHelp').textContent=(DB&&!INCLAUDE)?'Attach a PDF, image or document (maximum 4 MB).':'File upload works when the app is connected to the shared database (Firebase).';
  $('cHelp').textContent=DB?'Saved instantly for all students.':'Press “Download content.json”, then upload that file to your GitHub repo (replace the old one). Students see the change within a minute.';
  $('cList').innerHTML=CONTENT.notes.map(n=>'<div class="row" style="justify-content:space-between;margin-top:8px"><span>📝 '+esc(n.title)+'</span><button class="btn ghost" data-dn="'+esc(n.id)+'">Delete</button></div>').join('')+CONTENT.classes.map(c=>'<div class="row" style="justify-content:space-between;margin-top:8px"><span>🎥 '+esc(c.title)+' <span class="sub">'+fmtDT(c.start)+'</span></span><button class="btn ghost" data-dc="'+esc(c.id)+'">Delete</button></div>').join('');
}
const FILEMAX=4*1024*1024;
const readB64=f=>new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(String(r.result).split(',')[1]||'');r.onerror=rej;r.readAsDataURL(f)});
$('cAddNote').onclick=async()=>{const g=i=>$(i).value.trim(),m=$('cMsg');m.style.color='var(--bad)';
  const f=$('cFile').files[0];
  if(!g('cTitle')||(!g('cBody')&&!g('cLink')&&!f)){m.textContent='Enter a title, and add note text, a link or a file.';return}
  let fileId='',fileName='',fileType='';
  if(f){
    if(!DB||INCLAUDE){m.textContent='File upload needs the shared database (Firebase).';return}
    if(f.size>FILEMAX){m.textContent='This file is too large. The maximum is 4 MB.';return}
    m.style.color='var(--mute)';m.textContent='Uploading…';
    try{const data=await readB64(f);fileId=rid();fileType=f.type||'application/octet-stream';fileName=f.name;await DB.doc('files/'+fileId).set({name:fileName,type:fileType,data})}
    catch(e){m.style.color='var(--bad)';m.textContent='Upload failed. Check the internet, and that the Firebase rules include "files".';return}
  }
  await loadContent();CONTENT.notes.push({id:rid(),title:g('cTitle'),subject:g('cSubject'),body:$('cBody').value,link:g('cLink'),fileId,fileName,fileType,ts:Date.now()});
  const ok=await saveContent();['cTitle','cSubject','cBody','cLink'].forEach(i=>$(i).value='');$('cFile').value='';m.style.color=ok?'var(--ok)':'var(--bad)';m.textContent=ok?'Note added.':'Could not save.';cRender()};
async function openNoteFile(n){const m=$('nFileMsg');m.textContent='Loading…';
  try{const d=await DB.doc('files/'+n.fileId).get();if(!d.exists)throw 0;const x=d.data(),bin=atob(x.data),arr=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);
    const url=URL.createObjectURL(new Blob([arr],{type:x.type||'application/octet-stream'})),a=document.createElement('a');
    m.innerHTML='<a class="btn" href="'+url+'" target="_blank" rel="noopener">Open</a> <a class="btn ghost" href="'+url+'" download="'+esc(x.name||'file')+'">Download</a>';setTimeout(()=>URL.revokeObjectURL(url),600000)}
  catch(e){m.textContent='Could not open the file. Check your internet.'}}
$('lAdd').onclick=async()=>{const g=i=>$(i).value.trim(),m=$('cMsg');m.style.color='var(--bad)';
  if(!g('lTitle')||!g('lWhen')){m.textContent='Enter a class title and date/time.';return}
  if(g('lLink')&&!safeUrl(g('lLink'))){m.textContent='The join link must start with https://';return}
  await loadContent();CONTENT.classes.push({id:rid(),title:g('lTitle'),subject:g('lSubject'),start:new Date($('lWhen').value).toISOString(),dur:+g('lDur')||60,link:g('lLink'),rec:g('lRec'),desc:g('lDesc')});
  const ok=await saveContent();['lTitle','lSubject','lWhen','lLink','lRec','lDesc'].forEach(i=>$(i).value='');m.style.color=ok?'var(--ok)':'var(--bad)';m.textContent=ok?'Class scheduled.':'Could not save.';cRender()};
$('cList').onclick=async e=>{const b=e.target.closest('button');if(!b)return;
  if(!b.dataset.sure){b.dataset.sure='1';b.textContent='Sure? Click again';return}
  if(b.dataset.dn){const nn=CONTENT.notes.find(x=>x.id===b.dataset.dn);if(nn&&nn.fileId&&DB)try{await DB.doc('files/'+nn.fileId).delete()}catch(er){}CONTENT.notes=CONTENT.notes.filter(x=>x.id!==b.dataset.dn)}
  if(b.dataset.dc)CONTENT.classes=CONTENT.classes.filter(x=>x.id!==b.dataset.dc);
  await saveContent();cRender()};
function schRender(){
  const stTxt=id=>{const w=winState(id);return w.st==='soon'?'🕒 not open yet':w.st==='closed'?'⛔ closed':(SCHED[id]&&(SCHED[id].s||SCHED[id].e))?'🟢 open now':'always open'};
  $('schList').innerHTML=VIS().map(m=>{const w=SCHED[m.id]||{};
    return '<div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--line)"><b>'+esc(m.name)+'</b> <span class="sub">'+stTxt(m.id)+'</span>'+
    '<div class="row" style="margin-top:6px"><label class="sub" style="flex:1;min-width:150px">Opens<input type="datetime-local" data-s="'+m.id+'" value="'+toLocalInput(w.s)+'"></label><label class="sub" style="flex:1;min-width:150px">Closes<input type="datetime-local" data-e="'+m.id+'" value="'+toLocalInput(w.e)+'"></label></div>'+
    '<div style="margin-top:6px"><button class="btn ghost" data-ss="'+m.id+'">Save</button> <button class="btn ghost" data-sc="'+m.id+'">Clear (always open)</button></div></div>'}).join('');
}
$('schList').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const m=$('schMsg');m.style.color='var(--bad)';
  if(b.dataset.sc){delete SCHED[b.dataset.sc];const ok=await saveSchedule();m.style.color='var(--ok)';m.textContent=ok?'Cleared. The test is always open.':'Could not save.';schRender();return}
  if(b.dataset.ss){const id=b.dataset.ss,sv=$('schList').querySelector('[data-s="'+id+'"]').value,ev=$('schList').querySelector('[data-e="'+id+'"]').value;
    if(!sv&&!ev){m.textContent='Choose an opening and/or closing time, or press Clear.';return}
    if(sv&&ev&&new Date(ev)<=new Date(sv)){m.textContent='The closing time must be after the opening time.';return}
    SCHED[id]={s:sv?new Date(sv).toISOString():'',e:ev?new Date(ev).toISOString():''};
    const ok=await saveSchedule();m.style.color=ok?'var(--ok)':'var(--bad)';m.textContent=ok?'Saved. '+(sv?'Opens '+fmtDT(new Date(sv))+'. ':'')+(ev?'Closes '+fmtDT(new Date(ev))+'.':''):'Could not save.';schRender()}};
$('cDl').onclick=()=>{const b=new Blob([JSON.stringify(CONTENT,null,1)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='content.json';a.click()};
/* ---------- admin: see which options a student marked ---------- */
let AV=null;const imgM=(m,q,k)=>k==='E'?m.E:q.opts[k];
async function openAnswers(uid,mid,name){
  const m=MODS.find(x=>x.id===mid);if(!m)return;
  show('ansv');$('avTitle').textContent=name+' — '+m.name;$('avSum').innerHTML='<div class="sub">Loading…</div>';$('avTabs').innerHTML='';$('avList').innerHTML='';$('avMore').classList.add('hide');
  try{if(!m.q)await loadModule(m)}catch(e){$('avSum').innerHTML='<div class="sub">Could not load this test. Check the internet.</div>';return}
  let d=null;
  if(DB){try{const r=await DB.doc('prog/'+uid+'_'+mid).get();if(r.exists)d=JSON.parse(r.data().v)}catch(e){}}
  else d=ls.get('pq:p:'+uid+':'+mid,null);
  if(!d||!d.ans||!Object.keys(d.ans).length){$('avSum').innerHTML='<div class="sub">No saved answers for this test yet.</div>';return}
  AV={m,ans:d.ans,done:!!d.done,f:'all',shown:40};avRender();
}
const avSt=q=>{const a=AV.ans[q.n];if(!a||a==='E')return'skipped';return a===q.ans?'correct':'wrong'};
function avRender(){
  const m=AV.m,ans=AV.ans,c={correct:0,wrong:0,skipped:0};m.q.forEach(q=>c[avSt(q)]++);
  $('avSum').innerHTML='<div class="stats"><div class="stat">Correct<b>'+c.correct+'</b></div><div class="stat">Wrong<b>'+c.wrong+'</b></div><div class="stat">Not answered / Do not know<b>'+c.skipped+'</b></div></div><div class="sub">'+(AV.done?'✔ Submitted':'⏳ In progress (not submitted yet)')+' · '+Object.keys(ans).length+' of '+m.q.length+' marked</div>';
  $('avTabs').innerHTML=[['all','All ('+m.q.length+')'],['wrong','Wrong ('+c.wrong+')'],['correct','Correct ('+c.correct+')'],['skipped','Not answered ('+c.skipped+')']].map(t=>'<button data-f="'+t[0]+'" class="'+(t[0]===AV.f?'on':'')+'">'+t[1]+'</button>').join('');
  const list=m.q.filter(q=>AV.f==='all'||avSt(q)===AV.f);
  $('avList').innerHTML=list.slice(0,AV.shown).map(q=>{const st=avSt(q),a=ans[q.n];
    const tg={correct:['✔ Correct','ok'],wrong:['✘ Wrong','bad'],skipped:[a==='E'?'Do not know':'Not answered','']}[st];
    const o=L.map(k=>{const im=imgM(m,q,k);if(!im)return'';let cl='opt static';if(k===q.ans)cl+=' ok';else if(k===a&&k!=='E')cl+=' bad';else if(k===a)cl+=' sel';
      return'<div class="'+cl+'">'+box(im,true,'',m)+'</div>'}).join('');
    return'<div class="card"><span class="tag">Q'+q.n+'</span> <span class="tag '+tg[1]+'">'+tg[0]+'</span> <span class="tag">Student marked: '+(a||'—')+'</span> <span class="tag ok">Correct: '+q.ans+'</span>'+box(q.stem,true,'margin:10px 0',m)+o+'</div>'}).join('')||'<div class="card sub">Nothing here.</div>';
  $('avMore').classList.toggle('hide',list.length<=AV.shown);
}
$('avTabs').onclick=e=>{const b=e.target.closest('button');if(b&&AV){AV.f=b.dataset.f;AV.shown=40;avRender()}};
$('avMore').onclick=()=>{if(AV){AV.shown+=60;avRender()}};
$('avBack').onclick=()=>{AV=null;show('admin')};
$('avGo').onclick=()=>{const u=$('avStu').value,t=$('avTest').value;if(!u||!t)return;openAnswers(u,t,$('avStu').selectedOptions[0].textContent)};
/* ---------- admin approves new students ---------- */
let PEND=[];
async function updPending(){
  if(!U||!U.admin)return;let n=0;
  try{
    if(DB){const r=await DB.collection('accounts').get();n=r.docs.filter(d=>d.id!=='admin'&&d.id.indexOf('a_')!==0&&d.data().status==='pending').length}
    else{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);if(k.indexOf('pq:acc:s_')===0&&ls.get(k,{}).status==='pending')n++}}
  }catch(e){}
  $('admBtn').textContent=n?'🔔 Admin ('+n+' new)':'Admin';
}
$('apprList').onclick=async e=>{const b=e.target.closest('button');if(!b)return;
  if(b.dataset.ap){const a=await getAcc(b.dataset.ap);if(a){a.status='approved';await setAcc(b.dataset.ap,a)}loadAdmin()}
  else if(b.dataset.rj){if(!b.dataset.sure){b.dataset.sure='1';b.textContent='Sure? Click again';return}await removeUser(b.dataset.rj);loadAdmin()}};
$('apprAll').onclick=async()=>{for(const id of PEND.slice()){const a=await getAcc(id);if(a){a.status='approved';await setAcc(id,a)}}loadAdmin()};
$('admBack').onclick=()=>home();
init();

if('serviceWorker' in navigator&&location.protocol.indexOf('http')===0)navigator.serviceWorker.register('sw.js').catch(function(){});
