import { useCallback, useContext, useMemo } from "react";
import useSWR, { SWRResponse } from "swr";
import { AuthContext } from "@/contexts/Auth.tsx";
import { UnknownHttpError } from "@/errors";

interface IApiOptions {
  apiUrl: string;
}

export const useApi = (_apiUrl?: string) => {
  const { session } = useContext(AuthContext);
  const apiUrl = useMemo(() => _apiUrl || session?.apiUrl, [session, _apiUrl]);

  const swrCallback = useCallback(
    async (endpoint: string) => {
      if (!session)
        return console.info(
          `[SWR:${endpoint}] Skipped because no session exists`
        );

      const res = await fetch(endpoint, {
        headers: {
          "Content-Type": "application/json",
          Authorization: session.authToken
        }
      });

      return await res.json();
    },
    [session]
  );

  const post = useCallback(
    async (
      endpoint: string,
      body: Record<string, unknown>,
      opt?: IApiOptions
    ): Promise<Record<string, unknown>> => {
      const authInjection = session
        ? { Authorization: session.authToken }
        : null;

      const response = await fetch(`${opt?.apiUrl ?? apiUrl}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authInjection },
        body: JSON.stringify(body)
      });

      const jsonResp = await response.json();

      if (jsonResp.error) throw UnknownHttpError.fromResponse(jsonResp);

      return jsonResp;
    },
    [session]
  );

  const get = useCallback(
    async (endpoint: string, opt?: IApiOptions) => {
      // TODO implement query params
      const authInjection = session
        ? { Authorization: session.authToken }
        : null;

      const response = await fetch(`${opt?.apiUrl ?? apiUrl}/${endpoint}`, {
        headers: {
          "Content-Type": "application/json",
          ...authInjection
        }
      });

      const jsonResp = await response.json();

      if (jsonResp.error) throw UnknownHttpError.fromResponse(jsonResp);

      return jsonResp;
    },
    [session]
  );

  const del = useCallback(
    async (
      endpoint: string,
      body?: Record<string, unknown>,
      opt?: IApiOptions
    ) => {
      const authInjection = session
        ? { Authorization: session.authToken }
        : null;

      const response = await fetch(`${opt?.apiUrl ?? apiUrl}/${endpoint}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          ...authInjection
        },
        body: JSON.stringify(body)
      });

      try {
        const jsonResp = await response.json();

        if (jsonResp.error) throw UnknownHttpError.fromResponse(jsonResp);

        return jsonResp;
      } catch (_err) {
        console.log("warn - catched error:" + _err);
        return;
      }
    },
    [session]
  );

  const swr: <Data>(endpoint: string) => SWRResponse<Data> = useCallback(
    (endpoint: string) => {
      return useSWR(
        `${session?.apiUrl}/${endpoint}`,
        (url: string) => swrCallback(url),
        { keepPreviousData: true, refreshInterval: 2000 }
      );
    },
    [session]
  );

  return { post, get, swr, del };
};
