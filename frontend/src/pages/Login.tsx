import { useState } from "react";
import { api, ApiError, tokenStore } from "../services/api";

/** Token sign-in: the token is validated against the API and kept only in sessionStorage. */
export function Login({ onLogin }: { onLogin: () => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    tokenStore.set(token.trim());
    try {
      await api.incidents();
      onLogin();
    } catch (err) {
      tokenStore.clear();
      setError(err instanceof ApiError && err.status === 401 ? "Invalid token." : `Sign-in failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <form onSubmit={submit} className="panel w-96 space-y-4">
        <h1 className="text-xl font-bold">Aegis-Net NOC</h1>
        <p className="text-sm text-noc-muted">Enter an API token (see <code>.aegis-tokens</code> after <code>make env</code>).</p>
        <label className="block">
          <span className="label">API token</span>
          <input type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off"
                 className="mt-1 w-full rounded border border-noc-line bg-noc-bg px-2 py-1.5" aria-label="API token" />
        </label>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
        <button type="submit" className="btn-primary w-full" disabled={busy || !token.trim()}>Sign in</button>
      </form>
    </div>
  );
}
