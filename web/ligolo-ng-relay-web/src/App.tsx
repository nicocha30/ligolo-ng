import { useContext, useEffect, useState } from "react";
import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import InterfacesPage from "@/pages/interfaces/index.tsx";
import ListenersPage from "@/pages/listeners/index.tsx";
import LoginPage from "@/pages/login.tsx";
import AgentPage from "@/pages/agents/index.tsx";
import RelayPage from "@/pages/relay/index.tsx";
import ErrorPage from "@/pages/error.tsx";
import { PageNotFoundError } from "@/errors/pages.ts";
import LoadingPage from "@/pages/loading.tsx";
import { AuthContext } from "@/contexts/Auth.tsx";
import DefaultLayout from "@/layouts/default.tsx";
import ErrorContext from "@/contexts/Error.tsx";
import { AccessDeniedError } from "@/errors/login.ts";

const PrivateRoute = () => {
  const { setError } = useContext(ErrorContext);
  const { authLoaded, session } = useContext(AuthContext);

  useEffect(() => {
    if (!authLoaded) return;
    if (!session) setError(new AccessDeniedError());
  }, [session, authLoaded]);

  if (!session) return <Navigate to="/login" />;

  return (
    <DefaultLayout>
      <Outlet />
    </DefaultLayout>
  );
};

function App() {
  const [isLoading, setIsLoading] = useState(true);
  const { authLoaded, session } = useContext(AuthContext);

  useEffect(() => {
    setTimeout(() => setIsLoading(false), 800);
  }, []);

  if (isLoading && !authLoaded) return <LoadingPage />;

  return (
    <Routes>
      <Route element={<LoginPage />} path="/login" />
      <Route element={<PrivateRoute />}>
        <Route element={<AgentPage />} path="/agents" />
        <Route element={<RelayPage />} path="/relay" />
        <Route element={<InterfacesPage />} path="/interfaces" />
        <Route element={<ListenersPage />} path="/listeners" />
      </Route>
      <Route
        element={<Navigate to={session ? "/agents" : "/login"} />}
        path="/"
      />
      <Route element={<ErrorPage error={new PageNotFoundError()} />} path="*" />
    </Routes>
  );
}

export default App;
