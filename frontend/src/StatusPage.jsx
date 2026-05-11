import { useCallback, useEffect, useMemo, useState } from 'react';

const API_BASE = '/api';

function hueFromHexFingerprint(hex) {
  const n = parseInt(hex.slice(0, 6), 16);
  return Number.isFinite(n) ? n % 360 : 210;
}

function SummaryStat({ label, value, hint }) {
  return (
    <div className="stat-card">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

function RecordCard({ record, maxCipherChars }) {
  const hue = hueFromHexFingerprint(record.ciphertext_fingerprint);
  const barPct =
    maxCipherChars > 0
      ? Math.round((record.ciphertext_storage_chars / maxCipherChars) * 100)
      : 0;
  const pending = record.access_requests?.filter((r) => r.status === 'pending').length ?? 0;
  const approved = record.access_requests?.filter((r) => r.status === 'approved').length ?? 0;

  return (
    <article
      className="vault-record-card"
      style={{
        '--record-hue': `${hue}`,
      }}
    >
      <header className="vault-record-card__head">
        <div>
          <h3 className="vault-record-card__title">{record.filename}</h3>
          <p className="vault-record-card__meta">
            Patient <strong>{record.patient_id}</strong> · ID {record.id}
          </p>
        </div>
        <span className="fingerprint-pill" title="SHA-256 fingerprint of stored ciphertext (metadata only)">
          {record.ciphertext_fingerprint}
        </span>
      </header>
      <div className="size-meter" aria-hidden>
        <div className="size-meter__fill" style={{ width: `${barPct}%` }} />
      </div>
      <p className="size-meter-caption">
        Ciphertext footprint · {record.ciphertext_storage_chars.toLocaleString()} chars stored (base64)
      </p>
      <div className="badge-row">
        <span className="badge badge-aes">AES-GCM blob</span>
        {record.nonce_present && <span className="badge badge-nonce">12-byte IV</span>}
        {record.signature_present && <span className="badge badge-sign">RSA-PSS signed</span>}
        <span className="badge badge-keys">
          {record.wrapped_key_holders?.length ?? 0} wrapped key(s)
        </span>
      </div>
      <div className="holder-chips" aria-label="Users with wrapped AES keys">
        {(record.wrapped_key_holders ?? []).map((uid) => (
          <span key={uid} className="chip">
            {uid}
          </span>
        ))}
      </div>
      {(record.access_requests?.length ?? 0) > 0 && (
        <div className="access-strip">
          <span className="access-strip__label">Access flow</span>
          <span className="access-pill pending">{pending} pending</span>
          <span className="access-pill approved">{approved} approved</span>
        </div>
      )}
    </article>
  );
}

export default function StatusPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/vault_status`);
      const json = await res.json();
      if (json.status === 'success') {
        setData(json);
        setError('');
      } else {
        setError(json.message || 'Could not load vault status');
      }
    } catch {
      setError('Network error — is the Flask API running on port 5000?');
    }
  }, []);

  useEffect(() => {
    const start = setTimeout(() => {
      void load();
    }, 0);
    const id = setInterval(() => void load(), 5000);
    return () => {
      clearTimeout(start);
      clearInterval(id);
    };
  }, [load]);

  const maxCipherChars = useMemo(() => {
    if (!data?.records?.length) return 0;
    return Math.max(...data.records.map((r) => r.ciphertext_storage_chars));
  }, [data]);

  return (
    <div className="status-page">
      <header className="status-hero animate-fade-in">
        <p className="eyebrow">Observability · ciphertext only</p>
        <h1>Vault encryption status</h1>
        <p className="lede">
          Live snapshot of what the server stores: opaque blobs, IVs, signatures, and RSA-wrapped keys.
          Plaintext never leaves the browser — this page proves it without exposing patient data.
        </p>
        <p className="sync-line" aria-live="polite">
          <span className="pulse-dot" aria-hidden />
          Live snapshot · refreshes every 5 seconds
        </p>
      </header>

      {!data && !error && (
        <div className="glass-panel status-loading animate-fade-in">
          <p>Pulling vault metadata…</p>
        </div>
      )}

      {error && (
        <div className="glass-panel notification error animate-fade-in" role="alert">
          {error}
        </div>
      )}

      {data && (
        <>
          <section className="stat-grid animate-fade-in">
            <SummaryStat
              label="Encrypted records"
              value={data.summary.total_encrypted_records}
              hint="Rows in vault"
            />
            <SummaryStat
              label="Pending requests"
              value={data.summary.pending_access_requests}
              hint="Doctor awaiting patient"
            />
            <SummaryStat
              label="Approved handoffs"
              value={data.summary.approved_access_requests}
              hint="Proxy re-encryption done"
            />
            <SummaryStat
              label="Registered users"
              value={data.summary.registered_users}
              hint="Patients & doctors"
            />
          </section>

          <section className="pipeline-section glass-panel animate-fade-in">
            <h2 className="section-title">What the server actually sees</h2>
            <p className="section-sub">
              End-to-end flow — compare this to plaintext, which never touches SQLite.
            </p>
            <ol className="pipeline" aria-label="Encryption pipeline">
              <li className="pipeline-step">
                <span className="pipeline-step__icon" aria-hidden>
                  📄
                </span>
                <span className="pipeline-step__label">Record in browser</span>
                <span className="pipeline-step__detail">Never uploaded raw</span>
              </li>
              <li className="pipeline-arrow" aria-hidden>
                →
              </li>
              <li className="pipeline-step pipeline-step--accent">
                <span className="pipeline-step__icon" aria-hidden>
                  🛡️
                </span>
                <span className="pipeline-step__label">AES-256-GCM</span>
                <span className="pipeline-step__detail">Authenticated ciphertext</span>
              </li>
              <li className="pipeline-arrow" aria-hidden>
                →
              </li>
              <li className="pipeline-step">
                <span className="pipeline-step__icon" aria-hidden>
                  🔑
                </span>
                <span className="pipeline-step__label">RSA-OAEP wrap</span>
                <span className="pipeline-step__detail">Session key for patient/doctor</span>
              </li>
              <li className="pipeline-arrow" aria-hidden>
                →
              </li>
              <li className="pipeline-step">
                <span className="pipeline-step__icon" aria-hidden>
                  🗄️
                </span>
                <span className="pipeline-step__label">SQLite vault</span>
                <span className="pipeline-step__detail">Opaque blobs only</span>
              </li>
            </ol>
          </section>

          <section className="records-section">
            <h2 className="section-title">Records in the vault</h2>
            {data.records.length === 0 ? (
              <div className="glass-panel empty-state">
                <p>No ciphertext stored yet. Upload a record as a patient to light this up.</p>
              </div>
            ) : (
              <div className="vault-record-grid">
                {data.records.map((r) => (
                  <RecordCard key={r.id} record={r} maxCipherChars={maxCipherChars} />
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
