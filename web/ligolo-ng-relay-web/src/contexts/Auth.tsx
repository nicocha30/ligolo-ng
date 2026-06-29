import * as React from "react";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { SessionExpiredError, SessionParseFailedError } from "@/errors/login.ts";
import { AppError, UnknownHttpError } from "@/errors";
import ErrorContext from "@/contexts/Error.tsx";
import { useApi } from "@/hooks/useApi.ts";
import { Session, sessionSchema } from "@/schemas/session.ts";
import { validate } from "@/schemas";
import { AuthResponse, authResponseSchema } from "@/schemas/api/auth.ts";
import { pingResponseSchema } from "@/schemas/api/ping.ts";

const defaultApiUrl = import.meta.env["VITE_DEFAULT_API_URL"];
const sessionStorageKey = "ligolo-session";

interface IAuthContext {
  session: Session | null;
  authLoaded: boolean;
  logOut: () => void;
  login: (apiUrl: string, username: string, password: string) => Promise<void>;
}

const storedSession = localStorage.getItem(sessionStorageKey) ?? null;
const defaultAuthContext: IAuthContext = {
  session: null,
  authLoaded: false,
  logOut: () => undefined,
  login: async () => undefined
};

export const AuthContext = createContext<IAuthContext>(defaultAuthContext);
const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [session, setSession] = useState<IAuthContext["session"]>(null);
  const { setError } = useContext(ErrorContext);
  const { post, get } = useApi(defaultApiUrl);
  const [authLoaded, setAuthLoaded] = useState<boolean>(false);

  const logOut = useCallback(() => {
    localStorage.removeItem(sessionStorageKey);
    setSession(null);
  }, []);

  useEffect(() => {
    if (!storedSession) return;
    try {
      const sessionData = JSON.parse(storedSession);
      const session: Session = validate(sessionData, sessionSchema);

      setSession(session);
    } catch (error) {
      setError(new SessionParseFailedError("Unable to parse session data"));
      localStorage.removeItem(sessionStorageKey);
      console.error(error);
    }
  }, []);

  useEffect(() => {
    (async () => {
      if (!session) return setAuthLoaded(true);

      try {
        const { message } = validate(await get("api/v1/ping"), pingResponseSchema);
        if (message === "pong") return setAuthLoaded(true);

        throw new SessionExpiredError();
      } catch (error) {
        logOut();

        setError(
          error instanceof AppError
            ? error
            : new SessionParseFailedError("Unable to parse session data")
        );
      }
    })();
  }, [get]);

  const login = useCallback(
    async (apiUrl: string, username: string, password: string) => {
      try {
        const response: AuthResponse = validate(
          await post("api/auth", { username, password }, { apiUrl }),
          authResponseSchema
        );

        const newSession = {
          apiUrl,
          authToken: response.token
        };

        setSession(newSession);
        localStorage.setItem(sessionStorageKey, JSON.stringify(newSession));
      } catch (error) {
        if (error instanceof AppError) setError(new SessionExpiredError());

        throw UnknownHttpError.fromError(error);
      }
    },
    [post]
  );

  return (
    <AuthContext.Provider value={{ session, login, logOut, authLoaded }}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthProvider;
