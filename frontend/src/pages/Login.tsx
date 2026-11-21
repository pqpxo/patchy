import { useState } from "react";
import { post } from "../api";
import { errText } from "../ui";

export default function Login({ onLogin }: { onLogin: (user: string, csrf: string) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <main className="center">
      <form className="card login" onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
          const r = await post<{ username: string; csrf_token: string }>("/api/auth/login", { username, password });
          onLogin(r.username, r.csrf_token);
        } catch (err) {
          setError(errText(err));
        } finally {
          setBusy(false);
        }
      }}>
        <h1><span className="logo" aria-hidden="true">P</span> Patchy</h1>
        <p className="muted">Home lab software inventory and vulnerability tracking.</p>
        <label className="field"><span>Username</span>
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={64} />
        </label>
        <label className="field"><span>Password</span>
          <input type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} required maxLength={256} autoFocus />
        </label>
        {error && <div className="alert bad" role="alert">{error}</div>}
        <button className="btn primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted small">No account yet? Create the administrator on the server:
          <code className="block">docker compose exec app python -m app.cli create-admin</code></p>
      </form>
    </main>
  );
}
