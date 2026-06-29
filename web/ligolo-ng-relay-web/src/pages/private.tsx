import { Outlet } from "react-router-dom";
import { AuthContext } from "@/contexts/Auth.tsx";
import LoginPage from "@/pages/login.tsx";
import { useContext } from "react";
import DefaultLayout from "@/layouts/default.tsx";

const PrivateRoute = () => {
  const { session } = useContext(AuthContext);

  return !session ? (
    <LoginPage />
  ) : (
    <DefaultLayout>
      <Outlet />
    </DefaultLayout>
  );
};

export default PrivateRoute;
