import { useEffect, useRef, useCallback } from "react";

type WsEventHandler = (event: string, data: unknown) => void;

interface UseWebSocketOptions {
  url: string;
  enabled?: boolean;
  reconnectIntervalMs?: number;
}

export function useWebSocket({ url, enabled = true, reconnectIntervalMs = 3000 }: UseWebSocketOptions) {
  const handlerRef = useRef<WsEventHandler | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const onEvent = useCallback((handler: WsEventHandler) => {
    handlerRef.current = handler;
  }, []);

  const send = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    if (!enabled || !url) return;

    function connect() {
      if (!mountedRef.current) return;
      if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) return;

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        // Start keepalive pings
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 45_000);

        ws.addEventListener("close", () => clearInterval(pingInterval), { once: true });
      };

      ws.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data as string) as { event: string; data: unknown };
          handlerRef.current?.(payload.event, payload.data);
        } catch {
          // non-JSON message (e.g. "pong") — ignore
        }
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (!mountedRef.current) return;
        // Reconnect after delay
        reconnectTimerRef.current = setTimeout(connect, reconnectIntervalMs);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [url, enabled, reconnectIntervalMs]);

  return { onEvent, send };
}
