import axios from "axios";
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

function uuidv4() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

async function sha256Hex(str: string) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getOrCreateDeviceId() {
  if (typeof window === "undefined") return "dev-ssr";
  let did = localStorage.getItem("deviceId");
  if (!did) {
    did = uuidv4();
    localStorage.setItem("deviceId", did);
  }
  return did;
}

async function generateFingerprint() {
  if (typeof navigator === "undefined") return "fp-ssr";
  const ua = navigator.userAgent || "";
  const platform = navigator.platform || "";
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  const raw = `${ua}|${platform}|${tz}`;
  return await sha256Hex(raw);
}

function getOrCreateCSRF() {
  if (typeof window === "undefined") return "csrf-ssr";
  let t = localStorage.getItem("csrfToken");
  if (!t) {
    t = uuidv4();
    localStorage.setItem("csrfToken", t);
  }
  return t;
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || "http://localhost:5000",
  withCredentials: true,
});

let inMemoryAccessToken: string | null = null;
let refreshPromise: Promise<string> | null = null; 

async function refreshAccessToken(deviceId: string, fingerprint: string) {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const csrf = getOrCreateCSRF();
      const res = await api.post("/token", { fingerprint, deviceId, csrf }, { headers: { "x-csrf-token": csrf } });
      const { accessToken } = res.data;
      inMemoryAccessToken = accessToken;
      return accessToken;
    } catch (err) {
      // failed to refresh -> clear token
      inMemoryAccessToken = null;
      throw err;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

api.interceptors.request.use(async (config) => {
  if (inMemoryAccessToken) {
    config.headers = config.headers || {};
    (config.headers as any)["Authorization"] = `Bearer ${inMemoryAccessToken}`;
  }

  const csrf = localStorage.getItem("csrfToken");
  if (csrf) {
    config.headers = config.headers || {};
    (config.headers as any)["x-csrf-token"] = csrf;
  }

  return config;
});

api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config;
    if (!original) return Promise.reject(error);

    if ((original as any)._retry) return Promise.reject(error);

    if (error.response && error.response.status === 401) {
      (original as any)._retry = true;
      try {
        const deviceId = getOrCreateDeviceId();
        const fp = await generateFingerprint();
        const newToken = await refreshAccessToken(deviceId, fp);

        original.headers = original.headers || {};
        original.headers["Authorization"] = `Bearer ${newToken}`;
        return api(original);
      } catch (e) {
        return Promise.reject(e);
      }
    }

    return Promise.reject(error);
  }
);

interface AuthContextValue {
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuth, setIsAuth] = useState<boolean>(() => !!inMemoryAccessToken);

  useEffect(() => {
    (async () => {
      try {
        const deviceId = getOrCreateDeviceId();
        const fp = await generateFingerprint();
        await refreshAccessToken(deviceId, fp);
        setIsAuth(!!inMemoryAccessToken);
      } catch {
        setIsAuth(false);
      }
    })();
  }, []);

  const login = async (username: string, password: string) => {
    const deviceId = getOrCreateDeviceId();
    const fingerprint = await generateFingerprint();
    const csrf = getOrCreateCSRF();

    const res = await api.post(
      "/login",
      { username, password, fingerprint, deviceId, csrf },
      { headers: { "x-csrf-token": csrf } }
    );

    const { accessToken } = res.data;
    inMemoryAccessToken = accessToken;
    setIsAuth(true);
  };

  const logout = async () => {
    try {
      const csrf = getOrCreateCSRF();
      await api.post("/logout", { csrf }, { headers: { "x-csrf-token": csrf } });
    } catch (e) {
    }
    inMemoryAccessToken = null;
    localStorage.removeItem("csrfToken");
    setIsAuth(false);
  };

  const value = useMemo(
    () => ({ login, logout, getAccessToken: () => inMemoryAccessToken, isAuthenticated: isAuth }),
    [isAuth]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};


export const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setErr(null);
    try {
      await login(u, p);
    } catch (e: any) {
      setErr(e?.response?.data?.error || e.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <input value={u} onChange={(e) => setU(e.target.value)} placeholder="username" />
      <input value={p} onChange={(e) => setP(e.target.value)} placeholder="password" type="password" />
      <button disabled={loading} type="submit">
        Login
      </button>
      {err && <div style={{ color: "red" }}>{err}</div>}
    </form>
  );
};

export const ProfileButton: React.FC = () => {
  const [profile, setProfile] = useState<any>(null);

  const fetchProfile = async () => {
    try {
      const res = await api.get("/profile");
      setProfile(res.data);
    } catch (e: any) {
      console.error(e);
      setProfile({ error: e?.response?.status });
    }
  };

  return (
    <div>
      <button onClick={fetchProfile}>Get Profile</button>
      <pre>{profile ? JSON.stringify(profile, null, 2) : "no data"}</pre>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <div style={{ padding: 20 }}>
        <h3>Auth demo</h3>
        <LoginForm />
        <ProfileButton />
      </div>
    </AuthProvider>
  );
};
