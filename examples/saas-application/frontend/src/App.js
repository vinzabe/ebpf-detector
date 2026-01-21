import React, { useState, useEffect } from 'react';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:10092/api';

function App() {
  const [health, setHealth] = useState(null);
  const [externalIP, setExternalIP] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch health status
    fetch(`${API_URL}/health`)
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(err => console.error('Health check failed:', err));

    // Fetch external IP
    fetch(`${API_URL}/external-ip`)
      .then(res => res.json())
      .then(data => setExternalIP(data))
      .catch(err => console.error('IP fetch failed:', err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.title}>Abejar SaaS</h1>
        <p style={styles.subtitle}>Secured with Post-Quantum Cryptography</p>
      </header>

      <main style={styles.main}>
        <div style={styles.card}>
          <h2>System Status</h2>
          {loading ? (
            <p>Loading...</p>
          ) : (
            <>
              <div style={styles.statusItem}>
                <span>API Status:</span>
                <span style={health?.status === 'healthy' ? styles.healthy : styles.unhealthy}>
                  {health?.status || 'Unknown'}
                </span>
              </div>
              <div style={styles.statusItem}>
                <span>VPN IP:</span>
                <span style={styles.ip}>{externalIP?.ip || 'Unknown'}</span>
              </div>
              <div style={styles.statusItem}>
                <span>Location:</span>
                <span>{externalIP?.city}, {externalIP?.country}</span>
              </div>
              <div style={styles.statusItem}>
                <span>ISP:</span>
                <span>{externalIP?.org || 'Unknown'}</span>
              </div>
            </>
          )}
        </div>

        <div style={styles.card}>
          <h2>Security Features</h2>
          <ul style={styles.list}>
            <li>Kyber-1024 Post-Quantum Key Exchange</li>
            <li>Hybrid Mode: X25519 + Kyber</li>
            <li>WireGuard VPN Tunnel</li>
            <li>Cloudflare Tunnel with PQC TLS</li>
            <li>Zero-Trust Network Architecture</li>
          </ul>
        </div>
      </main>

      <footer style={styles.footer}>
        <p>Copyright 2024 Abejar. Contact: grant@abejar.net</p>
      </footer>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
    color: '#fff',
  },
  header: {
    textAlign: 'center',
    padding: '40px 20px',
  },
  title: {
    fontSize: '2.5rem',
    margin: 0,
    background: 'linear-gradient(90deg, #00d4ff, #7b2cbf)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
  },
  subtitle: {
    color: '#888',
    marginTop: '10px',
  },
  main: {
    maxWidth: '800px',
    margin: '0 auto',
    padding: '20px',
    display: 'grid',
    gap: '20px',
  },
  card: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: '12px',
    padding: '24px',
    backdropFilter: 'blur(10px)',
  },
  statusItem: {
    display: 'flex',
    justifyContent: 'space-between',
    padding: '10px 0',
    borderBottom: '1px solid rgba(255,255,255,0.1)',
  },
  healthy: {
    color: '#00ff88',
    fontWeight: 'bold',
  },
  unhealthy: {
    color: '#ff4444',
    fontWeight: 'bold',
  },
  ip: {
    fontFamily: 'monospace',
    color: '#00d4ff',
  },
  list: {
    lineHeight: '2',
  },
  footer: {
    textAlign: 'center',
    padding: '20px',
    color: '#666',
  },
};

export default App;
