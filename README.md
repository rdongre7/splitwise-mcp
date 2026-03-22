# splitwise-mcp

A hosted MCP server for interacting with [Splitwise](https://www.splitwise.com/), focused on adding expenses among friends in groups.

Authentication uses the MCP OAuth 2.0 spec — Claude.ai handles the entire OAuth flow automatically when a user connects. No manual token management required.

## How it works

```
Claude.ai  ──→  GET /authorize  ──→  Splitwise OAuth (user logs in)
Splitwise  ──→  GET /auth/callback  ──→  server issues MCP auth code  ──→  Claude.ai
Claude.ai  ──→  POST /token  ──→  server issues MCP access token
Claude.ai  ──→  POST /mcp (Bearer <token>)  ──→  tools call Splitwise API
```

The server acts as both the MCP Authorization Server and the MCP Resource Server, proxying auth through Splitwise.

## Server setup

### 1. Create a Splitwise OAuth app

Go to [https://secure.splitwise.com/oauth_clients](https://secure.splitwise.com/oauth_clients) and create a new application. Set the **Callback URL** to:

```
https://your-server.com/auth/callback
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env with your credentials
```

| Variable | Description |
|----------|-------------|
| `SPLITWISE_CLIENT_ID` | From your Splitwise OAuth app |
| `SPLITWISE_CLIENT_SECRET` | From your Splitwise OAuth app |
| `SERVER_URL` | Public base URL of this server, e.g. `https://splitwise.example.com` |
| `HOST` | Bind address (default `0.0.0.0`) |
| `PORT` | Port (default `8000`) |

### 3. Install and run

```bash
pip install -e .
python server.py
# or: splitwise-mcp
```

---

## Connecting Claude.ai

In Claude.ai settings, add a new custom integration with:

- **URL**: `https://your-server.com/mcp`

Claude.ai will automatically discover the OAuth endpoints, redirect you to log in with Splitwise, and handle token management. No manual token copying required.

---

## Available tools

| Tool | Description |
|------|-------------|
| `get_current_user` | Get the authenticated user's info |
| `list_groups` | List all groups with their members |
| `list_friends` | List all friends with balances |
| `add_expense` | Add an expense to a group, split equally |

## Example usage

```
List my Splitwise groups
→ Returns group IDs, names, and member info

Add a $60 dinner expense to group 12345, paid by user 111, split with users 111, 222, 333
→ Creates expense split equally ($20 each)
```

## Production notes

- The server stores OAuth tokens in memory. Tokens are lost on restart; users will need to re-authenticate. For persistence, replace the `dict` stores in `SplitwiseOAuthProvider` with a database.
- Access tokens expire after 1 hour.
- Run behind a reverse proxy (nginx, Caddy) with TLS for production.
