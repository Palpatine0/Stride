"""Verify the configured public TLS/WebSocket route without sending a credential."""
import base64
import hashlib
import http.client
import os
import ssl
import time


def check_route():
    host = os.environ["VPN_HOST"]
    port = int(os.environ.get("VPN_PORT", "443"))
    path = os.environ["VPN_WS_PATH"]
    if not path.startswith("/"):
        raise ValueError("VPN_WS_PATH must start with /")
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected = base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    ).digest()).decode("ascii")
    connection = http.client.HTTPSConnection(host, port, timeout=8, context=context)
    try:
        connection.request("GET", path, headers={
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": key,
        })
        response = connection.getresponse()
        if response.status != 101:
            raise RuntimeError(
                f"public VPN endpoint returned HTTP {response.status}; expected WebSocket 101"
            )
        if (response.getheader("Upgrade", "").lower() != "websocket"
                or "upgrade" not in [part.strip().lower() for part in
                    response.getheader("Connection", "").split(",")]
                or response.getheader("Sec-WebSocket-Accept") != expected):
            raise RuntimeError("public VPN endpoint returned an invalid WebSocket handshake")
    finally:
        connection.close()


if __name__ == "__main__":
    for attempt in range(6):
        try:
            check_route()
        except (OSError, ValueError, KeyError, http.client.HTTPException, RuntimeError) as error:
            # Do not print exception details: URLs/configuration may contain secrets.
            detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            if attempt == 5:
                raise SystemExit("Public VPN route failed: " + detail
                                 + ". Check tunnel ingress and Xray network reachability.")
            time.sleep(2)
        else:
            print("Public VPN TLS/WebSocket handshake verified (101).")
            print("Authenticated internet access and the user's phone still need separate checks.")
            break
