import { useAuth } from "../hooks/useAuth";

export function Settings() {
  const { logout } = useAuth();

  return (
    <div>
      <h1>Settings</h1>
      <section>
        <h2>Account</h2>
        <button onClick={logout}>Sign Out</button>
      </section>
      <section>
        <h2>API Keys</h2>
        <p>API key management coming soon.</p>
      </section>
      <section>
        <h2>Billing</h2>
        <p>Billing portal integration coming soon.</p>
      </section>
    </div>
  );
}
