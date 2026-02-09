import { useState } from "react";
import { useAuth } from "../hooks/useAuth";

export function Login() {
  const { login } = useAuth();
  const [token, setToken] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (token.trim()) {
      login(token.trim());
      window.location.href = "/";
    }
  }

  return (
    <div>
      <h1>ClawdStrike Cloud Login</h1>
      <form onSubmit={handleSubmit}>
        <label>
          JWT Token:
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste your JWT token"
          />
        </label>
        <button type="submit">Sign In</button>
      </form>
      <p>OIDC/SAML integration coming soon.</p>
    </div>
  );
}
