"""Interactive proof-of-concept for the pairwise identity flow."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from anon_identity.cli import load_wallet, record_service, save_wallet
from anon_identity.demo_service import validate_token
from anon_identity.provider import AuthenticationError, IdentityProvider
from anon_identity.wallet import Wallet, encode_bytes
from anon_identity.wallet_encryption import (
  decrypt_wallet_document,
  recovery_phrase_for_wallet,
)


class AuthenticationRequest(BaseModel):
    demo_session: str
    service_id: str


def _short(value: str, visible: int = 12) -> str:
    return value if len(value) <= visible * 2 else f"{value[:visible]}...{value[-visible:]}"


def _wallet_views(path: Path, recovery_phrase: str, wallet: Wallet) -> dict[str, object]:
  envelope = json.loads(path.read_text())
  document = decrypt_wallet_document(envelope, recovery_phrase)
  encrypted_view = {**envelope, "ciphertext": _short(envelope["ciphertext"], 24)}
  return {
    "revision": envelope["revision"],
    "logical": {
      "wallet_id": wallet.wallet_id,
      "services": document.get("services", {}),
      "root_secret": "[hidden]",
    },
    "encrypted": encrypted_view,
  }


def create_app(
    database_path: str | None = None,
    issuer_secret: str | None = None,
) -> FastAPI:
    resolved_database = database_path or os.getenv(
        "ANON_IDENTITY_DEMO_DATABASE", "data/web-demo.db"
    )
    resolved_secret = issuer_secret or os.getenv(
        "ANON_IDENTITY_ISSUER_SECRET",
        "development-only-secret-change-before-deployment",
    )
    provider = IdentityProvider(resolved_database, resolved_secret)
    wallet_directory = Path(resolved_database).parent / "demo-wallets"
    wallet_directory.mkdir(parents=True, exist_ok=True)
    wallets: dict[str, tuple[Path, str]] = {}
    app = FastAPI(title="Anonymous Identity Visual Demo", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return DEMO_HTML

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/demo/wallet", status_code=status.HTTP_201_CREATED)
    def create_demo_wallet() -> dict[str, object]:
        """Persist an encrypted wallet for this browser demo session."""
        wallet = Wallet.generate()
        demo_session = secrets.token_urlsafe(24)
        phrase = recovery_phrase_for_wallet(wallet)
        wallet_file = wallet_directory / f"{demo_session}.wallet.json"
        save_wallet(wallet_file, wallet, phrase)
        wallets[demo_session] = (wallet_file, phrase)
        provider.enroll(wallet.wallet_id, encode_bytes(wallet.root_public_key))
        return {
            "demo_session": demo_session,
            "wallet_id": wallet.wallet_id,
            "root_public_key": _short(encode_bytes(wallet.root_public_key)),
            "wallet_state": dict(_wallet_views(wallet_file, phrase, wallet)),
        }

    @app.post("/api/demo/authenticate")
    def authenticate(request: AuthenticationRequest) -> dict[str, object]:
        """Authenticate and persist an accepted service in the wallet."""
        stored_wallet = wallets.get(request.demo_session)
        if stored_wallet is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo wallet has expired")
        wallet_file, phrase = stored_wallet
        wallet = load_wallet(wallet_file, phrase)

        try:
            challenge = provider.create_challenge(wallet.wallet_id, request.service_id)
            proof = wallet.prove(
                challenge.challenge_id,
                challenge.challenge,
                challenge.service_id,
            )
            token = provider.verify(challenge.challenge_id, proof)
            session = validate_token(token, challenge.service_id, resolved_secret)
            record_service(
              wallet_file,
              phrase,
                session["service_id"],
                session["anonymous_subject"],
            )
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error

        return {
            "service_id": session["service_id"],
            "subject": session["anonymous_subject"],
            "pairwise_public_key": _short(proof.pairwise_public_key),
            "steps": [
                {
                    "label": "Challenge created",
                    "detail": f"One-time nonce {_short(challenge.challenge, 9)}",
                },
                {
                    "label": "Pairwise key derived",
                    "detail": f"HKDF context: {challenge.service_id}",
                },
                {
                    "label": "Proof verified",
                    "detail": "Root attestation + Ed25519 challenge signature",
                },
                {
                    "label": "Scoped token accepted",
                    "detail": f"Audience locked to {challenge.service_id}",
                },
            ],
            "proof": {
                key: _short(value) for key, value in asdict(proof).items()
            },
            "wallet_state": _wallet_views(wallet_file, phrase, wallet),
        }

    return app


DEMO_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Anonymous Identity | Protocol Demo</title>
  <style>
    :root {
      --ink: #17211d;
      --muted: #65716b;
      --paper: #f4f2ea;
      --surface: #fffefa;
      --line: #cfcec4;
      --green: #136f52;
      --green-soft: #dcece4;
      --coral: #e86645;
      --yellow: #f3c84b;
      --blue: #287bb5;
      --shadow: 0 16px 40px rgba(33, 43, 38, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background-color: var(--paper);
      background-image: linear-gradient(rgba(23,33,29,.045) 1px, transparent 1px), linear-gradient(90deg, rgba(23,33,29,.045) 1px, transparent 1px);
      background-size: 28px 28px;
      font-family: "IBM Plex Sans", "Liberation Sans", sans-serif;
      letter-spacing: 0;
    }
    button { font: inherit; }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 24px 0 48px; }
    header { display: flex; justify-content: space-between; align-items: center; padding: 8px 0 26px; border-bottom: 2px solid var(--ink); }
    .brand { display: flex; align-items: center; gap: 12px; font-family: Georgia, serif; font-weight: 700; font-size: 21px; }
    .mark { width: 30px; height: 30px; display: grid; place-items: center; background: var(--ink); color: white; border-radius: 4px; font: 700 15px/1 monospace; }
    .status { display: flex; align-items: center; gap: 8px; color: var(--green); font-size: 13px; font-weight: 700; text-transform: uppercase; }
    .status::before { content: ""; width: 9px; height: 9px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px var(--green-soft); }
    .intro { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 28px; align-items: end; padding: 44px 0 28px; }
    h1 { margin: 0; max-width: 720px; font: 700 clamp(38px, 6vw, 72px)/.98 Georgia, serif; letter-spacing: 0; }
    .eyebrow { margin-bottom: 12px; color: var(--coral); font: 700 13px/1 monospace; text-transform: uppercase; }
    .notice { max-width: 310px; padding-left: 16px; border-left: 4px solid var(--yellow); color: var(--muted); font-size: 14px; line-height: 1.5; }
    .workspace { display: grid; grid-template-columns: 350px minmax(0, 1fr); gap: 18px; align-items: stretch; }
    .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
    .wallet { padding: 24px; min-height: 360px; position: relative; overflow: hidden; }
    .wallet::after { content: ""; position: absolute; width: 130px; height: 130px; right: -45px; bottom: -45px; border: 22px solid var(--green-soft); transform: rotate(18deg); }
    .panel-label { color: var(--muted); font: 700 12px/1 monospace; text-transform: uppercase; }
    h2 { margin: 12px 0 20px; font: 700 28px/1.1 Georgia, serif; letter-spacing: 0; }
    .primary { min-height: 46px; padding: 0 18px; border: 0; border-radius: 5px; color: white; background: var(--green); font-weight: 700; cursor: pointer; }
    .primary:hover { background: #0e5941; }
    button:disabled { opacity: .45; cursor: not-allowed; }
    .facts { display: grid; gap: 16px; margin-top: 25px; }
    .fact span { display: block; margin-bottom: 6px; color: var(--muted); font-size: 12px; }
    code { font-family: "IBM Plex Mono", "Liberation Mono", monospace; overflow-wrap: anywhere; }
    .fact code { font-size: 13px; }
    .services { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; overflow: hidden; background: var(--line); }
    .service { min-width: 0; padding: 24px; background: var(--surface); }
    .service:nth-child(2) { background: #f7fbfd; }
    .service-icon { width: 44px; height: 44px; display: grid; place-items: center; border: 2px solid var(--ink); border-radius: 50%; font: 700 17px/1 Georgia, serif; }
    .service:nth-child(2) .service-icon { border-radius: 5px; border-color: var(--blue); color: var(--blue); }
    .service h3 { margin: 30px 0 6px; font: 700 23px/1.1 Georgia, serif; }
    .service p { min-height: 38px; margin: 0 0 20px; color: var(--muted); font-size: 13px; line-height: 1.45; }
    .service button { width: 100%; min-height: 42px; border: 1px solid var(--ink); border-radius: 4px; background: transparent; font-weight: 700; cursor: pointer; }
    .service button:hover:not(:disabled) { background: var(--ink); color: white; }
    .identity { min-height: 72px; margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--line); }
    .identity span { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .identity code { display: block; margin-top: 7px; color: var(--green); font-size: 12px; font-weight: 700; }
    .comparison { display: none; margin: 18px 0 0; padding: 15px 18px; border: 1px solid var(--green); background: var(--green-soft); border-radius: 6px; color: #0e5941; font-weight: 700; }
    .wallet-inspector { margin-top: 18px; overflow: hidden; }
    .inspector-head { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 22px 24px; border-bottom: 1px solid var(--line); }
    .inspector-head h2 { margin: 8px 0 0; }
    .revision { padding: 7px 10px; border-radius: 4px; color: white; background: var(--ink); font: 700 12px/1 monospace; white-space: nowrap; }
    .inspector-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--line); }
    .json-pane { min-width: 0; padding: 20px 22px 24px; background: #fbfaf5; }
    .json-pane:last-child { background: #f5f9f7; }
    .json-title { display: flex; justify-content: space-between; gap: 14px; margin-bottom: 14px; font-weight: 700; }
    .json-title small { color: var(--muted); font-weight: 400; }
    .json-lines { min-height: 230px; margin: 0; overflow: auto; color: #34423b; font: 12px/1.65 "IBM Plex Mono", "Liberation Mono", monospace; white-space: pre; }
    .json-line { width: max-content; min-width: 100%; padding: 0 5px; border-radius: 2px; transition: background-color 1.2s ease; }
    .json-line.changed { background: rgba(243, 200, 75, .45); }
    .inspector-note { margin: 0; padding: 13px 22px; border-top: 1px solid var(--line); color: var(--muted); background: var(--surface); font-size: 12px; line-height: 1.45; }
    .trace { margin-top: 18px; padding: 24px; }
    .trace-head { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
    .trace h2 { margin: 8px 0 0; }
    .trace-target { color: var(--coral); font: 700 13px/1 monospace; }
    .steps { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin-top: 26px; }
    .step { position: relative; min-height: 116px; padding: 0 18px 0 28px; border-top: 2px solid var(--line); }
    .step::before { content: ""; position: absolute; width: 12px; height: 12px; top: -7px; left: 0; border-radius: 50%; background: var(--surface); border: 2px solid var(--line); }
    .step.complete { border-color: var(--green); }
    .step.complete::before { background: var(--green); border-color: var(--green); }
    .step strong { display: block; margin: 17px 0 7px; font-size: 14px; }
    .step small { color: var(--muted); line-height: 1.4; }
    @media (max-width: 780px) {
      .shell { width: min(100% - 20px, 620px); padding-top: 12px; }
      header { padding-bottom: 16px; }
      .brand { font-size: 17px; }
      .intro { grid-template-columns: 1fr; padding-top: 30px; }
      h1 { font-size: 43px; }
      .notice { max-width: none; }
      .workspace { grid-template-columns: 1fr; }
      .wallet { min-height: 300px; }
      .services { grid-template-columns: 1fr; }
      .inspector-head { align-items: flex-start; }
      .inspector-grid { grid-template-columns: 1fr; }
      .json-lines { min-height: 190px; max-height: 330px; }
      .steps { grid-template-columns: 1fr; gap: 0; }
      .step { min-height: 86px; border-top: 0; border-left: 2px solid var(--line); padding: 0 12px 22px 24px; }
      .step::before { top: 0; left: -7px; }
      .step.complete { border-left-color: var(--green); }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div class="brand"><span class="mark">AI</span> Anonymous Identity</div>
      <div class="status">Protocol online</div>
    </header>

    <section class="intro">
      <div><div class="eyebrow">Live protocol proof</div><h1>One wallet.<br>Two unrelated identities.</h1></div>
      <div class="notice">POC boundary: the wallet runs in this demo process. A production client keeps root material encrypted on the user device.</div>
    </section>

    <section class="workspace">
      <div class="panel wallet">
        <div class="panel-label">User device</div>
        <h2>Ephemeral wallet</h2>
        <button class="primary" id="create-wallet">Create demo wallet</button>
        <div class="facts" id="wallet-facts" hidden>
          <div class="fact"><span>Wallet identifier</span><code id="wallet-id"></code></div>
          <div class="fact"><span>Root public key</span><code id="root-key"></code></div>
          <div class="fact"><span>Root secret</span><code>private / never sent</code></div>
        </div>
      </div>

      <div class="panel services">
        <article class="service">
          <div class="service-icon">F</div>
          <h3>forum.example</h3>
          <p>Community discussion account</p>
          <button data-service="forum.example" disabled>Authenticate</button>
          <div class="identity"><span>Identity received</span><code id="forum-subject">Waiting for proof</code></div>
        </article>
        <article class="service">
          <div class="service-icon">S</div>
          <h3>shop.example</h3>
          <p>Independent storefront account</p>
          <button data-service="shop.example" disabled>Authenticate</button>
          <div class="identity"><span>Identity received</span><code id="shop-subject">Waiting for proof</code></div>
        </article>
      </div>
    </section>

    <div class="comparison" id="comparison">Verified: both services received stable but different anonymous subjects.</div>

    <section class="panel wallet-inspector" id="wallet-inspector">
      <div class="inspector-head">
        <div><div class="panel-label">Wallet write monitor</div><h2>Current wallet state</h2></div>
        <div class="revision" id="wallet-revision">Not written</div>
      </div>
      <div class="inspector-grid">
        <div class="json-pane">
          <div class="json-title"><span>Logical contents</span><small>Decrypted for demo</small></div>
          <div class="json-lines" id="logical-wallet">Create a wallet to inspect its contents.</div>
        </div>
        <div class="json-pane">
          <div class="json-title"><span>Encrypted .wallet.json</span><small>Stored representation</small></div>
          <div class="json-lines" id="encrypted-wallet">No encrypted envelope written yet.</div>
        </div>
      </div>
      <p class="inspector-note">The logical view is sanitized: the root secret is never sent to or rendered by this page. Ciphertext is truncated for readability. Every write uses a fresh salt and nonce.</p>
    </section>

    <section class="panel trace">
      <div class="trace-head">
        <div><div class="panel-label">Authentication trace</div><h2>Cryptographic exchange</h2></div>
        <div class="trace-target" id="trace-target">Awaiting wallet</div>
      </div>
      <div class="steps" id="steps">
        <div class="step"><strong>Challenge</strong><small>Provider creates a fresh nonce</small></div>
        <div class="step"><strong>Derive</strong><small>Wallet derives a service-only key</small></div>
        <div class="step"><strong>Verify</strong><small>Provider checks both signatures</small></div>
        <div class="step"><strong>Session</strong><small>Service checks token audience</small></div>
      </div>
    </section>
  </main>
  <script>
    let demoSession = null;
    const subjects = {};
    const previousWalletLines = { logical: [], encrypted: [] };
    const createButton = document.querySelector('#create-wallet');
    const serviceButtons = [...document.querySelectorAll('[data-service]')];

    function renderJson(targetId, value, viewName) {
      const target = document.querySelector(`#${targetId}`);
      const lines = JSON.stringify(value, null, 2).split('\n');
      const previous = previousWalletLines[viewName];
      target.replaceChildren(...lines.map((line, index) => {
        const row = document.createElement('div');
        row.className = `json-line${previous[index] === line ? '' : ' changed'}`;
        row.textContent = line;
        return row;
      }));
      previousWalletLines[viewName] = lines;
      window.setTimeout(() => target.querySelectorAll('.changed').forEach(row => row.classList.remove('changed')), 1400);
    }

    function renderWallet(walletState) {
      document.querySelector('#wallet-revision').textContent = `Revision ${walletState.revision}`;
      renderJson('logical-wallet', walletState.logical, 'logical');
      renderJson('encrypted-wallet', walletState.encrypted, 'encrypted');
    }

    createButton.addEventListener('click', async () => {
      createButton.disabled = true;
      createButton.textContent = 'Creating...';
      try {
        const response = await fetch('/api/demo/wallet', { method: 'POST' });
        if (!response.ok) throw new Error('Wallet creation failed');
        const wallet = await response.json();
        demoSession = wallet.demo_session;
        document.querySelector('#wallet-id').textContent = wallet.wallet_id;
        document.querySelector('#root-key').textContent = wallet.root_public_key;
        document.querySelector('#wallet-facts').hidden = false;
        document.querySelector('#trace-target').textContent = 'Wallet ready';
        previousWalletLines.logical = [];
        previousWalletLines.encrypted = [];
        renderWallet(wallet.wallet_state);
        createButton.textContent = 'New wallet';
        serviceButtons.forEach(button => button.disabled = false);
      } catch (error) {
        createButton.textContent = error.message;
      } finally {
        createButton.disabled = false;
      }
    });

    serviceButtons.forEach(button => button.addEventListener('click', async () => {
      const serviceId = button.dataset.service;
      button.disabled = true;
      button.textContent = 'Signing...';
      document.querySelector('#trace-target').textContent = serviceId;
      document.querySelectorAll('.step').forEach(step => step.classList.remove('complete'));
      try {
        const response = await fetch('/api/demo/authenticate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ demo_session: demoSession, service_id: serviceId })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || 'Authentication failed');
        const steps = [...document.querySelectorAll('.step')];
        result.steps.forEach((item, index) => {
          steps[index].querySelector('strong').textContent = item.label;
          steps[index].querySelector('small').textContent = item.detail;
          window.setTimeout(() => steps[index].classList.add('complete'), index * 130);
        });
        subjects[serviceId] = result.subject;
        document.querySelector(`#${serviceId.startsWith('forum') ? 'forum' : 'shop'}-subject`).textContent = result.subject;
        renderWallet(result.wallet_state);
        if (subjects['forum.example'] && subjects['shop.example']) {
          document.querySelector('#comparison').style.display = 'block';
        }
        button.textContent = 'Authenticate again';
      } catch (error) {
        button.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    }));
  </script>
</body>
</html>
"""


app = create_app()