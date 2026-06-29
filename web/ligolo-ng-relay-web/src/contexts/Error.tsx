import {
  Component,
  createContext,
  Dispatch,
  ReactNode,
  useEffect,
  useState,
} from "react";
import { AppError, UnknownAppError } from "@/errors";
import ErrorPage from "@/pages/error.tsx";
import AuthProvider from "@/contexts/Auth.tsx";

export interface IErrorContext {
  error?: AppError | unknown;
  setError: Dispatch<IErrorContext["error"]>;
}

const ErrorContext = createContext<IErrorContext>({
  error: undefined,
  setError: () => undefined,
});

interface IErrorBoundaryProps {
  children: ReactNode;
}
export class ErrorBoundary extends Component<
  IErrorBoundaryProps,
  { error?: IErrorContext["error"] }
> {
  constructor(props: IErrorBoundaryProps) {
    super(props);
    this.state = { error: undefined };
  }

  static getDerivedStateFromError(error?: IErrorContext["error"]) {
    return { error };
  }

  render() {
    return this.state.error ? (
      <ErrorPage
        error={
          this.state.error instanceof AppError
            ? this.state.error
            : UnknownAppError.fromError(this.state.error)
        }
      />
    ) : (
      this.props.children
    );
  }
}

interface IErrorWrapperProps {
  children: ReactNode;
}

export const ErrorWrapper = ({ children }: IErrorWrapperProps) => {
  const [error, setError] = useState<IErrorContext["error"]>();

  useEffect(() => {
    if (!error) return;

    if (error instanceof AppError) error.toast();
    setError(undefined);
  }, [error, setError]);

  return (
    <AuthProvider>
      <ErrorBoundary>
        <ErrorContext.Provider value={{ error, setError }}>
          {children}
        </ErrorContext.Provider>
      </ErrorBoundary>
    </AuthProvider>
  );
};

export default ErrorContext;
