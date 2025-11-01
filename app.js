
const BASE_URL = "https://securevalutebackend3-production.up.railway.app/api";

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function strToBuf(str) {
  return new TextEncoder().encode(str);
}
function bufToStr(buf) {
  return new TextDecoder().decode(buf);
}
async function deriveKey(masterPassword, saltBase64) {
  const salt = base64ToBuf(saltBase64);
  const pwKey = await crypto.subtle.importKey(
    "raw",
    strToBuf(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 250000, 
      hash: "SHA-256"
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
  return key;
}

const form = document.getElementById("registerForm");
if (form) {
  const password = document.getElementById("password");
  form.addEventListener("submit", function (e) {
    if (password.value.length < 6) {
      e.preventDefault();
      alert("Password must be at least 6 characters long!");
    }
  });
}




function makeSalt() {
  const s = crypto.getRandomValues(new Uint8Array(16));
  return bufToBase64(s);
}


async function encryptWithPassword(plainText, masterPassword) {
  const saltB64 = makeSalt();
  const key = await deriveKey(masterPassword, saltB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    strToBuf(plainText)
  );
  return {
    ciphertext: bufToBase64(cipherBuf),
    iv: bufToBase64(iv),
    salt: saltB64
  };
}


async function decryptWithPassword(ciphertextB64, ivB64, saltB64, masterPassword) {
  try {
    const key = await deriveKey(masterPassword, saltB64);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuf(ivB64) },
      key,
      base64ToBuf(ciphertextB64)
    );
    return bufToStr(plainBuf);
  } catch (e) {

    return null;
  }
}


function setMsg(text){ const el=document.getElementById('msg'); if(el) el.innerText=text; }
function escapeHtml(text){ if(!text) return ''; return text.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

const registerForm = document.getElementById('registerForm');
if(registerForm){
  registerForm.addEventListener('submit', async (e)=> {
    e.preventDefault();
    const data = { email: document.getElementById('email').value, password: document.getElementById('password').value };
    const res = await fetch(`${BASE_URL}/auth/register`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
   if(res.ok){ 
  setMsg('Registered successfully! Redirecting to login...');
  setTimeout(()=>location.href='index.html',1000);
} else { 
  const msg = await res.text(); 
  alert(msg || 'Registration failed'); 
  setMsg(msg || 'Registration failed');
}

  });
}

const loginForm = document.getElementById('loginForm');
if(loginForm){
  loginForm.addEventListener('submit', async (e)=> {
    e.preventDefault();
    const data = { email: document.getElementById('email').value, password: document.getElementById('password').value };
    const res = await fetch(`${BASE_URL}/auth/login`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
    if(res.ok){
      const json = await res.json();
      localStorage.setItem('token', json.token);
      location.href = 'dashboard.html';
    } else {
      setMsg('Invalid credentials');
    }
  });
}


let MASTER_PASSWORD = null;

document.getElementById('setMasterBtn')?.addEventListener('click', (e) => {
  e.preventDefault();
  const mp = document.getElementById('masterPassword').value;
  if(!mp || mp.length < 6) {
    document.getElementById('masterStatus').innerText = "Master password should be 6+ chars";
    return;
  }
  MASTER_PASSWORD = mp;
  document.getElementById('masterStatus').innerText = "Master key set (session)";

  document.getElementById('masterPassword').value = '';

  loadPasswords();
});

const addForm = document.getElementById('addForm');
if(addForm){
  addForm.addEventListener('submit', async (e)=> {
    e.preventDefault();
    const token = localStorage.getItem('token'); if(!token) return location.href='index.html';
    if(!MASTER_PASSWORD) { alert('Please set Master Password first'); return; }

    const title = document.getElementById('title').value;
    const username = document.getElementById('username').value;
    const passwordField = document.getElementById('passwordField').value;
    const enc = await encryptWithPassword(passwordField, MASTER_PASSWORD);

    const dto = {
      title,
      username,
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      salt: enc.salt,
      notes: ''
    };

    const res = await fetch(`${BASE_URL}/credentials`, {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body: JSON.stringify(dto)
    });

    if(res.ok) {
      document.getElementById('title').value='';
       document.getElementById('username').value=''; 
       document.getElementById('passwordField').value='';
      loadPasswords();
    } else {
      alert('Failed to save credential');
    }
  });
}

async function loadPasswords(){
  const token = localStorage.getItem('token'); if(!token) return location.href='index.html';
  const res = await fetch(`${BASE_URL}/credentials`, { headers: { 'Authorization': 'Bearer '+token }});
  if(res.status===401){ localStorage.removeItem('token'); return location.href='index.html'; }
  const list = await res.json();
  const tbody = document.querySelector('#passwordTable tbody'); tbody.innerHTML='';
  for(const p of list){
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(p.title)}</td>
                    <td>${escapeHtml(p.username)}</td>
                    <td id="pw-${p.id}">********</td>
                    <td>
                      <button onclick="showPassword(${p.id}, '${p.ciphertext}', '${p.iv}', '${p.salt}')">Show</button>
                      <button onclick="deletePassword(${p.id})">Delete</button>
                    </td>`;
    tbody.appendChild(tr);
  }
}

async function showPassword(id, ciphertext, iv, salt) {
  if(!MASTER_PASSWORD) { alert('Please set Master Password first'); return; }
  const plain = await decryptWithPassword(ciphertext, iv, salt, MASTER_PASSWORD);
  if(plain === null) {
    alert('Decryption failed — check your master password');
    return;
  }
  const td = document.getElementById(`pw-${id}`);
  if(td) td.innerText = plain;
}

async function deletePassword(id){
  const token = localStorage.getItem('token');
  await fetch(`${BASE_URL}/credentials/${id}`, { method:'DELETE', headers:{'Authorization':'Bearer '+token}});
  loadPasswords();
}

document.getElementById('logoutBtn')?.addEventListener('click', ()=> { localStorage.removeItem('token'); MASTER_PASSWORD = null; location.href='index.html'; });

if(window.location.pathname.endsWith('dashboard.html')) {

  loadPasswords();
}



const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark-mode');
    themeToggle.textContent = '☀️ Light Mode';
  }

  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    themeToggle.textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
  
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
  });
}
