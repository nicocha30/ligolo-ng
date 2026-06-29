import * as React from "react";
import { useCallback, useContext, useState } from "react";
import { Logo } from "@/assets/icons/logo.tsx";
import { ThemeSwitch } from "@/components/theme-switch.tsx";
import { AuthContext } from "@/contexts/Auth.tsx";
import ErrorContext from "@/contexts/Error.tsx";
import { InvalidApiUrlError } from "@/errors/login.ts";
import {
  Alert,
  Button,
  Card,
  CircularProgress,
  Form,
  Input,
} from "@heroui/react";
import { useNavigate } from "react-router-dom";

const savedApiUrlKey = "ligolo-saved-api-url";
const defaultApiUrl: string | undefined =
  localStorage.getItem(savedApiUrlKey) ||
  import.meta.env["VITE_DEFAULT_API_URL"];

export default function LoginPage() {
  const [apiUrl, setApiUrl] = useState(defaultApiUrl);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const { login } = useContext(AuthContext);
  const [loading, setLoading] = useState(false);

  const { setError } = useContext(ErrorContext);

  const navigate = useNavigate();

  const handleSubmit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!apiUrl) throw new InvalidApiUrlError();

      setLoading(true);
      try {
        await login(apiUrl.replace(/\/+$/, ""), username, password);
        localStorage.setItem(savedApiUrlKey, apiUrl.replace(/\/+$/, ""));
        navigate("/agents");
      } catch (error) {
        setError(error);
      }

      setLoading(false);
    },
    [login, apiUrl, username, password, setError],
  );

  return (
    <div className="h-[100vh] flex items-center">
      <div className="absolute top-0 right-0 p-4">
        <ThemeSwitch />
      </div>
      <div className="flex flex-col w-full justify-center">
        <div className="inline-flex  text-default-foreground items-center gap-1 justify-center mb-2 select-none">
          <Logo size={50} />
          <p className="font-bold font-[500] text-xl tracking-wider flex items-center gap-[1px] opacity-90 hover:opacity-100 cursor-pointer">
            Ligolo-ng Relay
          </p>
        </div>
        <div className="w-[600px] mx-auto my-4 flex items-center justify-center px-2">
          <Alert variant="flat" title="Log in to your account to continue" />
        </div>
        <Card className="w-[600px] flex m-auto p-6">
          <Form validationBehavior="native" onSubmit={handleSubmit}>
            <Input
              size="sm"
              placeholder="API URL"
              labelPlacement="outside"
              isRequired
              value={apiUrl}
              onValueChange={setApiUrl}
              name="api_url"
            />
            <Input
              size="sm"
              placeholder="Username"
              name="username"
              labelPlacement="outside"
              isRequired
              value={username}
              onValueChange={setUsername}
            />
            <Input
              size="sm"
              labelPlacement="outside"
              isRequired
              placeholder="Enter your password"
              value={password}
              type="password"
              onValueChange={setPassword}
            />
            <Button
              className="mt-2 w-full gap-0 text-opacity-50"
              size="sm"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <CircularProgress className="scale-50" color="default" />
                  Authenticating
                </>
              ) : (
                "Authenticate"
              )}
            </Button>
          </Form>
        </Card>
      </div>
    </div>
  );
}
