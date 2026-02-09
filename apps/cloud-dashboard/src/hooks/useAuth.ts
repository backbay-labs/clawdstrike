import { useCallback, useMemo } from "react";

export function useAuth() {
  const token = useMemo(() => localStorage.getItem("token"), []);
  const isAuthenticated = token !== null;

  const login = useCallback((jwt: string) => {
    localStorage.setItem("token", jwt);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  }, []);

  return { isAuthenticated, token, login, logout };
}
