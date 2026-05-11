import { useState, useEffect, useCallback } from 'react';
import * as crypto from './cryptoUtils';

const API_BASE = '/api';

function readStoredUser() {
  try {
    const savedUser = sessionStorage.getItem('vault_user');
    return savedUser ? JSON.parse(savedUser) : null;
  } catch {
    return null;
  }
}

function App() {
  const [user, setUser] = useState(readStoredUser); // { username, role }

  const handleLogin = (userData) => {
    sessionStorage.setItem('vault_user', JSON.stringify(userData));
    setUser(userData);
  };

  const handleLogout = () => {
    sessionStorage.removeItem('vault_user');
    sessionStorage.removeItem(`vault_priv_${user?.username}`);
    setUser(null);
  };

  return (
    <div className="app-container">
      {!user ? (
        <Auth onLogin={handleLogin} />
      ) : (
        <div className="dashboard-container">
          <header className="header animate-fade-in">
            <div className="header-main">
              <p className="eyebrow">Session</p>
              <h1>Encrypted Vault</h1>
              <p className="header-sub">
                Signed in as <strong>{user.username}</strong>
                <span className={`role-pill role-pill--${user.role}`}>{user.role}</span>
              </p>
            </div>
            <button type="button" className="outline" onClick={handleLogout}>Logout</button>
          </header>
          
          {user.role === 'patient' ? <PatientDashboard user={user} /> : <DoctorDashboard user={user} />}
        </div>
      )}
    </div>
  );
}

function Auth({ onLogin }) {
  const [username, setUsername] = useState('');
  const [role, setRole] = useState('patient');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    const cleanUsername = username.trim();
    if (!cleanUsername) return;
    
    setLoading(true);
    setMsg('');
    try {
      const keys = await crypto.generateKeyPairs();
      
      const res = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: cleanUsername, role, public_key: keys.publicKey })
      });
      
      const data = await res.json();
      
      if (data.status === 'success' || data.message === 'Username already exists') {
        if (data.status === 'error') {
          setMsg("Username exists. Please use a unique name for this demo session.");
          setLoading(false);
          return;
        }

        sessionStorage.setItem(`vault_priv_${cleanUsername}`, keys.privateKey);
        onLogin({ username: cleanUsername, role, publicKey: keys.publicKey });
      } else {
        setMsg(data.message || 'Error occurred');
      }
    } catch {
      setMsg('Network error');
    }
    setLoading(false);
  };

  return (
    <div className="auth-container glass-panel animate-fade-in" style={{marginTop: '10vh'}}>
      <p className="eyebrow">Client-side crypto</p>
      <h1>Zero-Knowledge Vault</h1>
      <p className="lede auth-lede">
        RSA keys are generated in your browser. The server only stores ciphertext and wrapped keys.
      </p>
      <br/>
      <form onSubmit={handleSubmit}>
        <input 
          type="text" 
          placeholder="Enter a unique Username" 
          value={username} 
          onChange={(e) => setUsername(e.target.value)} 
          required 
        />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="patient">Patient</option>
          <option value="doctor">Doctor</option>
        </select>
        <button type="submit" disabled={loading || !username.trim()}>
          {loading ? 'Generating RSA Keys...' : 'Register & Login'}
        </button>
      </form>
      {msg && <div className="notification error">{msg}</div>}
    </div>
  );
}

function PatientDashboard({ user }) {
  const [file, setFile] = useState(null);
  const [records, setRecords] = useState([]);
  const [requests, setRequests] = useState([]);
  const [msg, setMsg] = useState({ text: '', type: '' });
  const [loading, setLoading] = useState(false);

  const fetchRecords = useCallback(async () => {
    const res = await fetch(`${API_BASE}/records?role=patient&username=${encodeURIComponent(user.username)}`);
    const data = await res.json();
    if (data.status === 'success') setRecords(data.records);
  }, [user.username]);

  const fetchRequests = useCallback(async () => {
    const res = await fetch(`${API_BASE}/pending_requests?patient_id=${encodeURIComponent(user.username)}`);
    const data = await res.json();
    if (data.status === 'success') setRequests(data.requests);
  }, [user.username]);

  useEffect(() => {
    const boot = setTimeout(() => {
      void fetchRecords();
      void fetchRequests();
    }, 0);
    const interval = setInterval(() => void fetchRequests(), 5000);
    return () => {
      clearTimeout(boot);
      clearInterval(interval);
    };
  }, [fetchRecords, fetchRequests]);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setMsg({ text: 'Encrypting and signing...', type: '' });
    
    try {
      const buffer = await file.arrayBuffer();
      
      // 1. AES Encrypt
      const { encryptedDataB64, nonceB64, tagB64, rawAesKeyBuffer } = await crypto.encryptDataAESGCM(buffer);
      
      // 2. Sign
      const privKeyStr = sessionStorage.getItem(`vault_priv_${user.username}`);
      const signatureB64 = await crypto.signData(buffer, privKeyStr);
      
      // 3. Wrap Key
      const encAesKey = await crypto.wrapKey(rawAesKeyBuffer, user.publicKey);
      
      // 4. Send
      const payload = {
        patient_id: user.username,
        filename: file.name,
        encrypted_data: encryptedDataB64,
        nonce: nonceB64,
        tag: tagB64,
        signature: signatureB64,
        encrypted_aes_key: encAesKey
      };
      
      const res = await fetch(`${API_BASE}/upload_record`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      
      if (data.status === 'success') {
        setMsg({ text: 'Record securely uploaded to vault!', type: 'success' });
        setFile(null);
        fetchRecords();
      } else {
        setMsg({ text: data.message, type: 'error' });
      }
    } catch (e) {
      console.error(e);
      setMsg({ text: 'Encryption failed', type: 'error' });
    }
    setLoading(false);
  };

  const handleApprove = async (req) => {
    try {
      setMsg({ text: `Approving access for ${req.doctor_id}...`, type: '' });
      // 1. Get my encrypted key
      const res1 = await fetch(`${API_BASE}/my_encrypted_key?record_id=${req.record_id}&user_id=${user.username}`);
      const data1 = await res1.json();
      const myEncKey = data1.encrypted_aes_key;
      
      // 2. Unwrap
      const privKeyStr = sessionStorage.getItem(`vault_priv_${user.username}`);
      const rawAesKeyBuffer = await crypto.unwrapKey(myEncKey, privKeyStr);
      
      // 3. Get doctor's public key
      const res2 = await fetch(`${API_BASE}/public_key/${req.doctor_id}`);
      const data2 = await res2.json();
      const doctorPubKey = data2.public_key;
      
      // 4. Re-wrap
      const doctorEncKey = await crypto.wrapKey(rawAesKeyBuffer, doctorPubKey);
      
      // 5. Send approval
      const res3 = await fetch(`${API_BASE}/approve_access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_id: req.request_id,
          patient_id: user.username,
          encrypted_aes_key_for_doctor: doctorEncKey
        })
      });
      const data3 = await res3.json();
      
      if (data3.status === 'success') {
        setMsg({ text: `Access granted to ${req.doctor_id}`, type: 'success' });
        fetchRequests();
      } else {
        setMsg({ text: data3.message, type: 'error' });
      }
    } catch (e) {
      console.error(e);
      setMsg({ text: 'Approval failed', type: 'error' });
    }
  };

  return (
    <div className="dashboard">
      <div className="glass-panel animate-fade-in dashboard-card">
        <h2 className="section-title">Upload record</h2>
        <div className="file-upload" onClick={() => document.getElementById('file-input').click()}>
          <input 
            type="file" 
            id="file-input" 
            style={{display: 'none'}} 
            onChange={(e) => setFile(e.target.files[0])}
          />
          {file ? <p>{file.name}</p> : <p>Click to select a medical record</p>}
        </div>
        <br/>
        <button onClick={handleUpload} disabled={!file || loading} style={{width: '100%'}}>
          {loading ? 'Encrypting...' : 'Encrypt & Upload'}
        </button>
        {msg.text && <div className={`notification ${msg.type === 'error' ? 'error' : ''}`}>{msg.text}</div>}
        
        <h2 className="section-title" style={{marginTop: '2rem'}}>My encrypted vault</h2>
        <ul className="record-list">
          {records.length === 0 && <p>No records found.</p>}
          {records.map(r => (
            <li key={r.id} className="record-item">
              <span>{r.filename}</span>
              <span className="tag">ID: {r.id}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="glass-panel animate-fade-in dashboard-card" style={{animationDelay: '0.1s'}}>
        <h2 className="section-title">Pending access requests</h2>
        {requests.length === 0 ? <p>No pending requests.</p> : (
          <ul className="record-list">
            {requests.map(req => (
              <li key={req.request_id} className="record-item" style={{flexDirection: 'column', alignItems: 'flex-start'}}>
                <div style={{display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: '0.5rem'}}>
                  <strong>Dr. {req.doctor_id}</strong>
                  <span className="tag pending">Pending</span>
                </div>
                <p style={{fontSize: '0.9rem'}}>Wants access to: {req.filename} (ID: {req.record_id})</p>
                <button style={{marginTop: '0.5rem', width: '100%', padding: '0.5rem'}} onClick={() => handleApprove(req)}>
                  Approve (Re-encrypt Key)
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function DoctorDashboard({ user }) {
  const [records, setRecords] = useState([]);
  const [msg, setMsg] = useState({ text: '', type: '' });
  const [downloading, setDownloading] = useState(false);

  const fetchRecords = useCallback(async () => {
    const res = await fetch(`${API_BASE}/records?role=doctor`);
    const data = await res.json();
    if (data.status === 'success') setRecords(data.records);
  }, []);

  useEffect(() => {
    const boot = setTimeout(() => void fetchRecords(), 0);
    return () => clearTimeout(boot);
  }, [fetchRecords]);

  const handleRequestAccess = async (recordId) => {
    const res = await fetch(`${API_BASE}/request_access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doctor_id: user.username, record_id: recordId })
    });
    const data = await res.json();
    if (data.status === 'success') {
      setMsg({ text: 'Access requested. Waiting for patient approval.', type: 'success' });
    } else {
      setMsg({ text: data.message, type: 'error' });
    }
  };

  const handleDownload = async (recordId) => {
    setDownloading(true);
    setMsg({ text: 'Fetching encrypted record...', type: '' });
    
    try {
      const res = await fetch(`${API_BASE}/download_record?doctor_id=${user.username}&record_id=${recordId}`);
      const data = await res.json();
      
      if (data.status !== 'success') {
        setMsg({ text: data.message || 'Unauthorized', type: 'error' });
        setDownloading(false);
        return;
      }

      setMsg({ text: 'Decrypting locally...', type: '' });
      
      // 1. Unwrap AES key
      const privKeyStr = sessionStorage.getItem(`vault_priv_${user.username}`);
      const rawAesKeyBuffer = await crypto.unwrapKey(data.encrypted_aes_key, privKeyStr);
      
      // 2. Decrypt record
      const decryptedBuffer = await crypto.decryptDataAESGCM(data.encrypted_data, data.nonce, rawAesKeyBuffer);
      
      if (!decryptedBuffer) {
        setMsg({ text: 'Decryption failed!', type: 'error' });
        setDownloading(false);
        return;
      }
      
      // 3. Verify Signature
      const pkRes = await fetch(`${API_BASE}/public_key/${data.patient_id}`);
      const pkData = await pkRes.json();
      const isValid = await crypto.verifySignature(decryptedBuffer, data.signature, pkData.public_key);
      
      if (!isValid) {
        alert("WARNING: Digital Signature Verification Failed! Data may be tampered.");
      }
      
      // Trigger download
      const blob = new Blob([decryptedBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `decrypted_${data.filename}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setMsg({ text: `File successfully decrypted! Signature Valid: ${isValid}`, type: 'success' });
      
    } catch (e) {
      console.error(e);
      setMsg({ text: 'An error occurred during decryption', type: 'error' });
    }
    setDownloading(false);
  };

  return (
    <div className="glass-panel animate-fade-in dashboard-card">
      <h2 className="section-title">Global medical records</h2>
      <p className="section-sub doctor-hint">
        Encrypted blobs listed below — request access, then download decrypts only after approval.
      </p>
      {msg.text && <div className={`notification ${msg.type === 'error' ? 'error' : ''}`}>{msg.text}</div>}
      <br/>
      <ul className="record-list">
        {records.length === 0 && <p>No records found.</p>}
        {records.map(r => (
          <li key={r.id} className="record-item">
            <div>
              <strong>{r.filename}</strong>
              <p style={{fontSize: '0.8rem', margin: 0}}>Patient: {r.patient_id}</p>
            </div>
            <div>
              <button className="outline" style={{marginRight: '0.5rem'}} onClick={() => handleRequestAccess(r.id)}>
                Request Access
              </button>
              <button onClick={() => handleDownload(r.id)} disabled={downloading}>
                Download
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
