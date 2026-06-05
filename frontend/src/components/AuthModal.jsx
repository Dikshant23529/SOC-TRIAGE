import { useState, useEffect } from "react";
import { api } from "../api";

export default function AuthModal({ onAuthSuccess }) {
  const [mode, setMode] = useState("login"); // 'login' | 'register' | 'mfa'
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [tempToken, setTempToken] = useState("");
  const [hasUsers, setHasUsers] = useState(true);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Check if system has users registered
  const checkStatus = async () => {
    try {
      const res = await api.checkAuthStatus();
      setHasUsers(res.has_users);
      if (!res.has_users) {
        setMode("register");
      }
    } catch (e) {
      console.error("Failed to check auth status", e);
    }
  };

  useEffect(() => {
    checkStatus();
  }, []);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please fill in all fields.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      await api.register({ username, password });
      alert("Registration successful! Please login.");
      setUsername("");
      setPassword("");
      setConfirmPassword("");
      setHasUsers(true);
      setMode("login");
    } catch (err) {
      setError(err.message || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please enter username and password.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const res = await api.login({ username, password });
      if (res.mfa_required) {
        setTempToken(res.temp_token);
        setMode("mfa");
      } else {
        onAuthSuccess(res.access_token);
      }
    } catch (err) {
      setError(err.message || "Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async (e) => {
    e.preventDefault();
    if (!mfaCode) {
      setError("Please enter the 6-digit code.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const res = await api.verifyMfa({ temp_token: tempToken, code: mfaCode });
      onAuthSuccess(res.access_token);
    } catch (err) {
      setError(err.message || "Invalid MFA code.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>
        <div style={styles.brand}>
          <span style={styles.brandDot} />
          <span style={styles.brandTitle}>SOC TRIAGE AUTHENTICATION</span>
        </div>

        {mode === "register" && (
          <form onSubmit={handleRegister}>
            <h2 style={styles.title}>
              {!hasUsers ? "Initial Setup: Create Administrator" : "Register New Account"}
            </h2>
            <p style={styles.subtitle}>
              {!hasUsers 
                ? "There are no users registered. Create the first administrator account to configure the platform." 
                : "Create a new analyst account to log in."}
            </p>
            {error && <div style={styles.error}>{error}</div>}

            <label style={styles.label}>Username</label>
            <input
              style={styles.input}
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. admin"
            />

            <label style={styles.label}>Password</label>
            <input
              style={styles.input}
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />

            <label style={styles.label}>Confirm Password</label>
            <input
              style={styles.input}
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
            />

            <button style={styles.button} type="submit" disabled={loading}>
              {loading ? "Registering..." : "Create Account"}
            </button>

            {hasUsers && (
              <p style={styles.footerText}>
                Already have an account?{" "}
                <span style={styles.link} onClick={() => { setError(""); setMode("login"); }}>
                  Log In
                </span>
              </p>
            )}
          </form>
        )}

        {mode === "login" && (
          <form onSubmit={handleLogin}>
            <h2 style={styles.title}>Analyst Log In</h2>
            <p style={styles.subtitle}>Sign in with your credentials to access the SOC alert triage queue.</p>
            {error && <div style={styles.error}>{error}</div>}

            <label style={styles.label}>Username</label>
            <input
              style={styles.input}
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
            />

            <label style={styles.label}>Password</label>
            <input
              style={styles.input}
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
            />

            <button style={styles.button} type="submit" disabled={loading}>
              {loading ? "Signing In..." : "Log In"}
            </button>

            <p style={styles.footerText}>
              Need a new account?{" "}
              <span style={styles.link} onClick={() => { setError(""); setMode("register"); }}>
                Register
              </span>
            </p>
          </form>
        )}

        {mode === "mfa" && (
          <form onSubmit={handleVerifyMfa}>
            <h2 style={styles.title}>Multi-Factor Authentication</h2>
            <p style={styles.subtitle}>Enter the 6-digit verification code from your authenticator app.</p>
            {error && <div style={styles.error}>{error}</div>}

            <label style={styles.label}>MFA Verification Code</label>
            <input
              style={{ ...styles.input, textAlign: "center", fontSize: 24, letterSpacing: 8 }}
              type="text"
              maxLength={6}
              required
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder="000000"
            />

            <button style={styles.button} type="submit" disabled={loading}>
              {loading ? "Verifying..." : "Verify & Enter"}
            </button>

            <p style={styles.footerText}>
              Back to{" "}
              <span style={styles.link} onClick={() => { setError(""); setMode("login"); }}>
                Log In
              </span>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}

const styles = {
  overlay: {
    position: "fixed",
    top: 0, left: 0, right: 0, bottom: 0,
    backgroundColor: "rgba(3, 7, 18, 0.95)",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    zIndex: 9999,
  },
  modal: {
    width: "100%",
    maxWidth: 420,
    backgroundColor: "#0a1628",
    border: "1px solid #1e3a5f",
    borderRadius: 8,
    padding: 32,
    boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)",
  },
  brand: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    borderBottom: "1px solid #1e3a5f",
    paddingBottom: 16,
    marginBottom: 24,
  },
  brandDot: {
    width: 8, height: 8,
    borderRadius: "50%",
    backgroundColor: "#ef4444",
    boxShadow: "0 0 8px #ef4444",
  },
  brandTitle: {
    fontFamily: "Syne, sans-serif",
    fontWeight: 800,
    fontSize: 12,
    letterSpacing: "0.1em",
    color: "#e2e8f0",
  },
  title: {
    fontSize: 18,
    fontWeight: 700,
    color: "#f1f5f9",
    marginBottom: 6,
    fontFamily: "Syne, sans-serif",
  },
  subtitle: {
    fontSize: 12,
    color: "#64748b",
    marginBottom: 20,
    lineHeight: 1.5,
  },
  label: {
    fontSize: 10,
    fontWeight: 600,
    letterSpacing: "0.12em",
    textTransform: "uppercase",
    color: "#475569",
    marginBottom: 6,
    display: "block",
  },
  input: {
    width: "100%",
    backgroundColor: "#0d1928",
    border: "1px solid #1e3a5f",
    borderRadius: 4,
    color: "#e2e8f0",
    padding: "10px 14px",
    fontSize: 14,
    fontFamily: "inherit",
    outline: "none",
    marginBottom: 16,
  },
  button: {
    width: "100%",
    backgroundColor: "#0ea5e9",
    color: "#fff",
    border: "none",
    borderRadius: 4,
    padding: "12px",
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: "pointer",
    fontFamily: "inherit",
    marginTop: 8,
  },
  error: {
    backgroundColor: "#451a03",
    border: "1px solid #92400e",
    color: "#fca5a5",
    padding: "10px 12px",
    borderRadius: 4,
    fontSize: 12,
    marginBottom: 16,
  },
  footerText: {
    fontSize: 12,
    color: "#64748b",
    marginTop: 16,
    textAlign: "center",
  },
  link: {
    color: "#38bdf8",
    cursor: "pointer",
    fontWeight: 600,
    textDecoration: "underline",
  },
};
