import os
import secrets
import time
from contextvars import ContextVar
from urllib.parse import urlencode, urlparse

import httpx
import uvicorn
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP as MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# ---------------------------------------------------------------------------
# Configuration — set these as environment variables on your server
# ---------------------------------------------------------------------------
SPLITWISE_BASE_URL = "https://secure.splitwise.com/api/v3.0"
SPLITWISE_AUTHORIZE_URL = "https://secure.splitwise.com/oauth/authorize"
SPLITWISE_TOKEN_URL = "https://secure.splitwise.com/oauth/token"

CLIENT_ID = os.environ.get("SPLITWISE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SPLITWISE_CLIENT_SECRET", "")
# Public base URL of your hosted server, no trailing slash.
# e.g. https://splitwise.example.com
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8000")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

SPLITWISE_CALLBACK_URL = f"{SERVER_URL}/auth/callback"
SERVER_HOST = urlparse(SERVER_URL).netloc  # e.g. "web-production-22fff.up.railway.app"

# ContextVar lets the ASGI middleware pass each user's Splitwise token
# into synchronous tool handlers without threading issues.
_splitwise_token: ContextVar[str | None] = ContextVar("_splitwise_token", default=None)


# ---------------------------------------------------------------------------
# OAuth provider
# ---------------------------------------------------------------------------
class SplitwiseOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """
    OAuth provider that proxies Claude.ai authentication through Splitwise.

    Flow:
      1. Claude.ai  →  GET /authorize  →  redirect to Splitwise
      2. User authorises on Splitwise
      3. Splitwise  →  GET /auth/callback  →  we issue an MCP auth code
                                            →  redirect back to Claude.ai
      4. Claude.ai  →  POST /token  →  we exchange for an MCP access token
      5. Claude.ai  →  POST /mcp (Bearer <mcp_token>)
                    →  middleware resolves mcp_token → splitwise_token → ContextVar
                    →  tools call Splitwise API on the user's behalf
    """

    def __init__(self) -> None:
        # Registered MCP clients (Claude.ai performs dynamic client registration)
        self.clients: dict[str, OAuthClientInformationFull] = {}
        # Splitwise state → saved MCP client params (pending OAuth round-trip)
        self.pending_auths: dict[str, dict] = {}
        # MCP auth code → AuthorizationCode object
        self.auth_codes: dict[str, AuthorizationCode] = {}
        # key (auth code or mcp token) → Splitwise access token
        self.splitwise_tokens: dict[str, str] = {}
        # MCP access token → AccessToken object
        self.access_tokens: dict[str, AccessToken] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Redirect to Splitwise, saving MCP client params under a fresh state."""
        state = secrets.token_urlsafe(32)
        self.pending_auths[state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "mcp_state": params.state,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes or [],
            "resource": params.resource,
        }
        query = urlencode(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": SPLITWISE_CALLBACK_URL,
                "response_type": "code",
                "state": state,
            }
        )
        return f"{SPLITWISE_AUTHORIZE_URL}?{query}"

    async def handle_splitwise_callback(self, code: str, state: str) -> str:
        """
        Called from GET /auth/callback when Splitwise redirects back.
        Exchanges the Splitwise code, creates an MCP auth code, and returns
        the URL to redirect Claude.ai to.
        """
        pending = self.pending_auths.pop(state, None)
        if not pending:
            raise ValueError("Invalid or expired OAuth state.")

        async with httpx.AsyncClient() as http:
            resp = await http.post(
                SPLITWISE_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "redirect_uri": SPLITWISE_CALLBACK_URL,
                    "code": code,
                },
            )
        if resp.is_error:
            raise ValueError(f"Splitwise token exchange failed: {resp.text}")

        splitwise_access_token = resp.json().get("access_token", "")
        if not splitwise_access_token:
            raise ValueError("No access_token in Splitwise response.")

        # Create MCP authorization code
        mcp_code = f"mcp_{secrets.token_hex(16)}"
        self.auth_codes[mcp_code] = AuthorizationCode(
            code=mcp_code,
            client_id=pending["client_id"],
            redirect_uri=AnyHttpUrl(pending["redirect_uri"]),
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            code_challenge=pending["code_challenge"],
            scopes=pending["scopes"],
            expires_at=time.time() + 300,
            resource=pending.get("resource"),
        )
        # Stash Splitwise token under the code; moved to mcp_token in exchange step
        self.splitwise_tokens[mcp_code] = splitwise_access_token

        return construct_redirect_uri(
            pending["redirect_uri"],
            code=mcp_code,
            state=pending.get("mcp_state"),
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Issue an MCP access token, binding it to the Splitwise token."""
        self.auth_codes.pop(authorization_code.code, None)
        splitwise_token = self.splitwise_tokens.pop(authorization_code.code, None)
        if not splitwise_token:
            raise ValueError("Authorization code not found or already used.")

        mcp_token = f"mcp_{secrets.token_hex(32)}"
        self.access_tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,
        )
        # Key used by SplitwiseTokenMiddleware to resolve Bearer → Splitwise token
        self.splitwise_tokens[mcp_token] = splitwise_token

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self.access_tokens.get(token)
        if not access_token:
            return None
        if access_token.expires_at and access_token.expires_at < time.time():
            self.access_tokens.pop(token, None)
            self.splitwise_tokens.pop(token, None)
            return None
        return access_token

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None  # Not supported

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise NotImplementedError("Refresh tokens not supported.")

    async def revoke_token(  # type: ignore[override]
        self, token: str, token_type_hint: str | None = None
    ) -> None:
        self.access_tokens.pop(token, None)
        self.splitwise_tokens.pop(token, None)


# ---------------------------------------------------------------------------
# ASGI middleware
# Reads the MCP Bearer token from each request's Authorization header,
# resolves it to the user's Splitwise access token via the provider, and
# injects it into the current async context via a ContextVar.
# Using pure ASGI (not BaseHTTPMiddleware) avoids buffering SSE streams.
# ---------------------------------------------------------------------------
class SplitwiseTokenMiddleware:
    def __init__(self, app: ASGIApp, provider: SplitwiseOAuthProvider) -> None:
        self.app = app
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth = headers.get(b"authorization", b"").decode("latin1")
            token: str | None = None
            if auth.startswith("Bearer "):
                mcp_token = auth[7:]
                token = self.provider.splitwise_tokens.get(mcp_token)
            var = _splitwise_token.set(token)
            try:
                await self.app(scope, receive, send)
            finally:
                _splitwise_token.reset(var)
        else:
            await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
provider = SplitwiseOAuthProvider()

mcp = MCPServer(
    name="splitwise",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(SERVER_URL),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["splitwise"],
            default_scopes=["splitwise"],
        ),
        required_scopes=["splitwise"],
        resource_server_url=None,  # Combined AS + RS (legacy mode)
    ),
    transport_security=TransportSecuritySettings(
        allowed_hosts=[SERVER_HOST, "localhost", "127.0.0.1"],
    ),
)


@mcp.custom_route("/auth/callback", methods=["GET"])
async def splitwise_callback(request: Request) -> Response:
    """Handle Splitwise's OAuth redirect and forward Claude.ai to the MCP auth code."""
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    try:
        redirect_url = await provider.handle_splitwise_callback(code, state)
        return RedirectResponse(redirect_url, status_code=302)
    except ValueError as exc:
        return HTMLResponse(f"OAuth error: {exc}", status_code=400)


def _get_client() -> httpx.Client:
    token = _splitwise_token.get()
    if not token:
        raise ValueError(
            "Not authenticated with Splitwise. "
            "Connect Claude to this MCP server and complete the OAuth flow."
        )
    return httpx.Client(
        base_url=SPLITWISE_BASE_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30.0,
    )


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_error:
        raise RuntimeError(
            f"Splitwise API error {response.status_code}: {response.text}"
        )


@mcp.tool()
def get_current_user() -> dict:
    """Get the currently authenticated Splitwise user."""
    with _get_client() as client:
        response = client.get("/get_current_user")
        _raise_for_status(response)
        user = response.json()["user"]
        return {
            "id": user["id"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "email": user["email"],
            "default_currency": user.get("default_currency", "USD"),
        }


@mcp.tool()
def list_groups() -> list[dict]:
    """List all Splitwise groups the current user belongs to, including their members."""
    with _get_client() as client:
        response = client.get("/get_groups")
        _raise_for_status(response)
        groups = response.json()["groups"]

    result = []
    for group in groups:
        members = [
            {
                "id": m["id"],
                "name": f"{m['first_name']} {m.get('last_name', '')}".strip(),
                "email": m.get("email", ""),
            }
            for m in group.get("members", [])
        ]
        result.append(
            {
                "id": group["id"],
                "name": group["name"],
                "group_type": group.get("group_type", "other"),
                "members": members,
            }
        )
    return result


@mcp.tool()
def list_friends() -> list[dict]:
    """List all Splitwise friends of the current user with their balances."""
    with _get_client() as client:
        response = client.get("/get_friends")
        _raise_for_status(response)
        friends = response.json()["friends"]

    result = []
    for f in friends:
        balances = [
            {"currency": b["currency_code"], "amount": b["amount"]}
            for b in f.get("balance", [])
        ]
        result.append(
            {
                "id": f["id"],
                "name": f"{f['first_name']} {f.get('last_name', '')}".strip(),
                "email": f.get("email", ""),
                "balances": balances,
            }
        )
    return result


@mcp.tool()
def add_expense(
    description: str,
    amount: float,
    group_id: int,
    paid_by_user_id: int,
    split_user_ids: list[int],
    currency_code: str = "USD",
    date: str | None = None,
) -> dict:
    """
    Add an expense to a Splitwise group, split equally among the specified users.

    Args:
        description: What the expense is for (e.g. "Dinner", "Groceries").
        amount: Total cost of the expense.
        group_id: The ID of the group to add the expense to.
        paid_by_user_id: The user ID of the person who paid.
        split_user_ids: List of user IDs to split the expense among (must include paid_by_user_id).
        currency_code: Currency code, e.g. "USD", "EUR". Defaults to "USD".
        date: Optional ISO 8601 date string (e.g. "2024-03-22T18:00:00Z"). Defaults to now.
    """
    if paid_by_user_id not in split_user_ids:
        split_user_ids = [paid_by_user_id] + list(split_user_ids)

    num_users = len(split_user_ids)
    base_share = round(amount / num_users, 2)
    remainder = round(amount - base_share * num_users, 2)

    payload: dict = {
        "cost": f"{amount:.2f}",
        "description": description,
        "currency_code": currency_code,
        "group_id": group_id,
        "payment": False,
    }

    if date:
        payload["date"] = date

    for i, user_id in enumerate(split_user_ids):
        owed = base_share + (remainder if i == 0 else 0)
        paid = f"{amount:.2f}" if user_id == paid_by_user_id else "0.00"
        payload[f"users__{i}__user_id"] = user_id
        payload[f"users__{i}__paid_share"] = paid
        payload[f"users__{i}__owed_share"] = f"{owed:.2f}"

    with _get_client() as client:
        response = client.post("/create_expense", data=payload)
        _raise_for_status(response)
        data = response.json()

    errors = data.get("errors", {})
    if errors and any(errors.values()):
        raise RuntimeError(f"Splitwise returned errors: {errors}")

    expense = data["expenses"][0]
    return {
        "id": expense["id"],
        "description": expense["description"],
        "cost": expense["cost"],
        "currency_code": expense["currency_code"],
        "group_id": expense["group_id"],
        "date": expense["date"],
        "created_at": expense["created_at"],
        "splits": [
            {
                "user_id": u["user"]["id"],
                "name": f"{u['user']['first_name']} {u['user'].get('last_name', '')}".strip(),
                "paid_share": u["paid_share"],
                "owed_share": u["owed_share"],
                "net_balance": u["net_balance"],
            }
            for u in expense.get("users", [])
        ],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    # streamable_http_app() builds the full Starlette app:
    #   POST /mcp          — MCP protocol (Streamable HTTP)
    #   GET  /.well-known/oauth-authorization-server  — OAuth discovery
    #   GET  /authorize    — start OAuth (calls provider.authorize → Splitwise)
    #   POST /token        — exchange auth code for access token
    #   POST /register     — dynamic client registration (Claude.ai uses this)
    #   GET  /auth/callback — our custom route; handles Splitwise redirect
    starlette_app = mcp.streamable_http_app()
    wrapped = SplitwiseTokenMiddleware(starlette_app, provider)
    uvicorn.run(wrapped, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
