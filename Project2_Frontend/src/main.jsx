import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = "http://127.0.0.1:8000";
const tlsOverview = [
  ["Client Hello", "Client", "Server"],
  ["Server Hello & Certificate", "Server", "Client"],
  ["Client Key Exchange", "Client", "Server"],
  ["Session Key Generation", "Both", "Both"],
  ["Finished", "Both", "Both"],
];
const sshOverview = [
  ["Protocol Version Exchange", "Client", "Server"],
  ["Key Exchange (Diffie–Hellman)", "Client", "Server"],
  ["Server Authentication", "Server", "Client"],
  ["User Authentication", "Client", "Server"],
  ["Secure Channel Established", "Both", "Both"],
];

function App() {
  const [tab, setTab] = useState("tls");
  const [session, setSession] = useState(null);
  const [step, setStep] = useState(0);
  const [event, setEvent] = useState(null);
  const [logs, setLogs] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("Hello over SecureTunnel!");
  const [messageResult, setMessageResult] = useState(null);
  const [ipsecMode, setIpsecMode] = useState("transport");
  const [ipsec, setIpsec] = useState(null);

  const isTls = tab === "tls";
  const total = isTls ? 5 : 5;
  const overview = isTls ? tlsOverview : sshOverview;

  useEffect(() => {
    fetch(`${API}/api/ipsec/${ipsecMode}`).then(r => r.json()).then(setIpsec).catch(() => setIpsec(null));
  }, [ipsecMode]);

  async function start(which = tab) {
    setBusy(true); setError(""); setEvent(null); setLogs([]); setStep(0); setSession(null); setMessageResult(null);
    try {
      const res = await fetch(`${API}/api/${which}/start`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not start simulation.");
      setSession(data.session_id);
    } catch (e) { setError(`Backend unavailable: ${e.message}. Check that the Python API is running on port 8000.`); }
    finally { setBusy(false); }
  }

  async function next() {
    if (!session) return;
    setBusy(true); setError("");
    try {
      const res = await fetch(`${API}/api/${tab}/next`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: session }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not advance.");
      if (data.event) { setEvent(data.event); setLogs(prev => [...prev, data.event]); setStep(data.step); }
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function sendMessage() {
    if (!session) return;
    setError(""); setMessageResult(null);
    try {
      const res = await fetch(`${API}/api/${tab}/message`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: session, message }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Finish the handshake first.");
      setMessageResult(data);
    } catch (e) { setError(e.message); }
  }

  function changeTab(nextTab) {
    setTab(nextTab); setSession(null); setStep(0); setEvent(null); setLogs([]); setError(""); setMessageResult(null);
  }

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand-mark">ST</div>
      <div><div className="brand">SecureTunnel</div><div className="brand-sub">NETWORK SECURITY LAB</div></div>
      <div className="top-status"><span className="status-dot"></span> EDUCATIONAL SIMULATOR</div>
    </header>

    <main>
      <section className="hero">
        <div className="eyebrow"><span className="eyebrow-line"></span> PROTOCOL EXPLORER / 01</div>
        <h1>See how secure<br/><span>connections are built.</span></h1>
        <p className="hero-copy">Step through the handshake. Follow the messages. Understand what happens before private data travels across a network.</p>
        <div className="hero-pills"><span>↗ TLS / SSL</span><span>⌘ SSH</span><span>◈ IPsec / ESP</span></div>
      </section>

      <nav className="tabs" aria-label="Protocol modules">
        <button className={tab === "tls" ? "tab active" : "tab"} onClick={() => changeTab("tls")}><span className="tab-icon">↔</span><span><b>TLS / SSL</b><small>Key exchange & handshake</small></span></button>
        <button className={tab === "ssh" ? "tab active" : "tab"} onClick={() => changeTab("ssh")}><span className="tab-icon">⌘</span><span><b>SSH</b><small>Remote access handshake</small></span></button>
        <button className={tab === "ipsec" ? "tab active" : "tab"} onClick={() => changeTab("ipsec")}><span className="tab-icon">◈</span><span><b>IPsec / ESP</b><small>Packet protection modes</small></span></button>
      </nav>

      {tab !== "ipsec" ? <section className="workspace">
        <div className="section-head">
          <div><div className="section-kicker">INTERACTIVE SIMULATION</div><h2>{isTls ? "TLS handshake" : "SSH connection"} <span className="muted">/ 0{step} of 05</span></h2></div>
          <button className="secondary-button" onClick={() => start(tab)} disabled={busy}>↻ Restart</button>
        </div>
        <div className="progress-track"><div className="progress-fill" style={{ width: `${step / total * 100}%` }} /></div>
        <div className="diagram">
          <div className={`endpoint client ${event?.from?.includes("Client") || event?.from === "Both" || event?.from?.includes("Both") ? "lit" : ""}`}>
            <div className="endpoint-symbol">▣</div><div className="endpoint-label">CLIENT</div><div className="endpoint-name">{isTls ? "Browser" : "SSH Client"}</div><div className="endpoint-meta">Your device</div>
            <div className="endpoint-lock">{step >= 4 ? "🔒 Secure" : "○ Not secured"}</div>
          </div>
          <div className="wire-area">
            <div className="wire"></div>
            <div className="wire-label">{event ? `STEP 0${event.number}` : "HANDSHAKE CHANNEL"}</div>
            <div className={`packet ${event ? "packet-active" : ""}`}><span>{event ? (event.from?.includes("Server") ? "←" : event.from === "Both" || event.from?.includes("Both") ? "↔" : "→") : "↔"}</span></div>
            <div className="wire-caption">{event ? event.title : "Messages appear here as you advance"}</div>
          </div>
          <div className={`endpoint server ${event?.from?.includes("Server") || event?.from === "Both" || event?.from?.includes("Both") ? "lit" : ""}`}>
            <div className="endpoint-symbol">▤</div><div className="endpoint-label">SERVER</div><div className="endpoint-name">{isTls ? "Web Server" : "Remote Host"}</div><div className="endpoint-meta">Destination host</div>
            <div className="endpoint-lock">{step >= 4 ? "🔒 Secure" : "○ Not secured"}</div>
          </div>
        </div>
        <div className="step-strip">{overview.map((s, i) => <div key={s[0]} className={`step-item ${step === i + 1 ? "current" : ""} ${step > i + 1 ? "done" : ""}`}><div className="step-number">{step > i + 1 ? "✓" : `0${i+1}`}</div><span>{s[0]}</span></div>)}</div>

        <div className="detail-grid">
          <section className="panel explanation">
            <div className="panel-title"><span className="tiny-icon">✳</span> STEP EXPLANATION</div>
            {event ? <>
              <div className="event-tag">STEP {String(event.number).padStart(2, "0")} / {total}</div>
              <h3>{event.title}</h3><p>{event.explanation}</p>
              {event.details?.note && <p className="note">{event.details.note}</p>}
              {event.details?.warning && <p className="note warning">{event.details.warning}</p>}
              {event.details && <details className="payload"><summary>Inspect simulated message data</summary><pre>{JSON.stringify(event.details, null, 2)}</pre></details>}
            </> : <div className="empty-state"><div className="empty-icon">↗</div><h3>Ready to establish a connection</h3><p>Start the simulation, then advance one step at a time to inspect the protocol messages and cryptographic operations.</p></div>}
            <div className="controls">
              {!session ? <button className="primary-button" onClick={() => start(tab)} disabled={busy}>{busy ? "Starting…" : "Start simulation"} <span>→</span></button> :
              <button className="primary-button" onClick={next} disabled={busy || step >= total}>{busy ? "Processing…" : step >= total ? "Handshake complete ✓" : "Next step"} <span>→</span></button>}
              <span className="control-hint">{step >= total ? "Secure channel ready" : `${total - step} step${total-step === 1 ? "" : "s"} remaining`}</span>
            </div>
          </section>
          <section className="panel log-panel">
            <div className="panel-title"><span className="tiny-icon">≋</span> HANDSHAKE LOG <span className="log-count">{logs.length}</span></div>
            {logs.length === 0 ? <div className="log-empty">Waiting for handshake events<span className="cursor">_</span></div> : <div className="log-list">{logs.map((l, i) => <div className="log-entry" key={i}><span className="log-index">{String(i+1).padStart(2, "0")}</span><div><b>{l.title}</b><small>{l.from} → {l.to}</small></div><span className="log-check">✓</span></div>)}</div>}
            {error && <div className="error-box">{error}</div>}
            <div className="log-footer"><span className={step >= total ? "green-dot" : "amber-dot"}></span>{step >= total ? "CHANNEL ESTABLISHED" : "AWAITING NEXT EVENT"}</div>
          </section>
        </div>

        <section className="panel message-panel">
          <div><div className="panel-title"><span className="tiny-icon">↗</span> TEST THE SECURE CHANNEL</div><p>After the handshake, send a sample message through AES-GCM authenticated encryption.</p></div>
          <div className="message-form"><input value={message} onChange={e => setMessage(e.target.value)} aria-label="Sample message" maxLength={500}/><button className="secondary-button" onClick={sendMessage} disabled={step < total || !session}>Encrypt & send</button></div>
          {messageResult && <div className="result-box"><b>✓ Encrypted and decrypted successfully</b><p>Nonce: <code>{messageResult.nonce}</code></p><p>Ciphertext (Base64): <code>{messageResult.ciphertext}</code></p><p>Recovered plaintext: <code>{messageResult.decrypted_message}</code></p></div>}
        </section>
      </section> : <section className="workspace">
        <div className="section-head"><div><div className="section-kicker">PACKET ENCAPSULATION</div><h2>IPsec / ESP <span className="muted">/ VISUAL GUIDE</span></h2></div></div>
        <section className="panel ipsec-panel">
          <p className="ipsec-intro">Encapsulating Security Payload (ESP) can provide confidentiality, integrity and data-origin authentication. Switch modes to see which packet parts are protected.</p>
          <div className="mode-toggle"><button className={ipsecMode === "transport" ? "mode active" : "mode"} onClick={() => setIpsecMode("transport")}>Transport mode</button><button className={ipsecMode === "tunnel" ? "mode active" : "mode"} onClick={() => setIpsecMode("tunnel")}>Tunnel mode</button></div>
          <div className="packet-stack">
            {ipsecMode === "tunnel" && <div className="packet-part outer"><small>OUTER IP HEADER · VISIBLE</small><b>New routing header</b></div>}
            {ipsecMode === "transport" && <div className="packet-part outer"><small>ORIGINAL IP HEADER · VISIBLE</small><b>Source → Destination</b></div>}
            <div className="packet-part esp"><small>ESP HEADER</small><b>SPI + Sequence Number</b></div>
            {ipsecMode === "tunnel" && <div className="packet-part encrypted"><small>ENCRYPTED ORIGINAL PACKET</small><b>Inner IP header + payload</b><span>Protected by ESP</span></div>}
            {ipsecMode === "transport" && <div className="packet-part encrypted"><small>ENCRYPTED PAYLOAD</small><b>Transport data</b><span>Original IP header remains visible</span></div>}
            <div className="packet-part trailer"><small>ESP TRAILER</small><b>Padding + Pad Length + Next Header</b></div>
            <div className="packet-part auth"><small>INTEGRITY / AUTHENTICATION DATA</small><b>Authentication tag (if negotiated)</b></div>
          </div>
          <div className="ipsec-description"><div className="tiny-icon">✳</div><div><h3>{ipsecMode === "transport" ? "Transport mode" : "Tunnel mode"}</h3><p>{ipsec?.description || "Loading description…"}</p><p><b>Encrypted:</b> {ipsec?.encrypted || "Loading…"}</p></div></div>
          <p className="disclaimer">Conceptual diagram only. Exact ESP fields and protection depend on the negotiated IPsec suite; integrity data is not always a separate trailer in every depiction.</p>
        </section>
      </section>}

      <section className="learning-row"><div><div className="section-kicker">WHAT YOU'RE LEARNING</div><h2>Three protocols. One goal.</h2></div><div className="learning-card"><span>01</span><b>Confidentiality</b><p>Encryption helps keep captured network traffic private.</p></div><div className="learning-card"><span>02</span><b>Authentication</b><p>Certificates and host keys help verify who you're talking to.</p></div><div className="learning-card"><span>03</span><b>Key exchange</b><p>Establish shared secrets to derive symmetric session keys.</p></div></section>
      <footer><div className="brand-footer">ST <b>SecureTunnel</b></div><span>LEARNING SIMULATOR · NOT A PRODUCTION SECURITY IMPLEMENTATION</span><span>API <i className="status-dot"></i> LOCAL DEMO</span></footer>
    </main>
  </div>;
}

createRoot(document.getElementById("root")).render(<App />);
