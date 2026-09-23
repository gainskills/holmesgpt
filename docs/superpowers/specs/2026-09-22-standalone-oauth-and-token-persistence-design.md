# Standalone OAuth, Token Persistence, and Security Architecture

## 1. Problem Statement & Context

HolmesGPT introduces Model Context Protocol (MCP) OAuth support in Holmes 0.25.0 ([PR #1900](https://github.com/HolmesGPT/holmesgpt/pull/1900)). However, the implementation was coupled to two specific environments:
1. **Local CLI (`holmes ask`)**: Spawns an ephemeral Python HTTP server on `127.0.0.1:8888` and writes tokens to `~/.holmes/auth/mcp_tokens.json`.
2. **Robusta SaaS Platform (`platform.robusta.dev`)**: Relies on Robusta's hosted web frontend to intercept browser redirects and send a `POST /api/oauth/callback` JSON request to Holmes, storing tokens in Supabase DB (`DalTokenStore`).

When Holmes runs as an independent server in a Kubernetes cluster without Robusta SaaS:
- **No HTTP GET Callback Receiver**: Identity Providers (IdPs) redirect browsers via HTTP `GET` (`GET <redirect_uri>?code=...&state=...`). `server.py` only exposes `POST /api/oauth/callback`, returning `405 Method Not Allowed`.
- **No Token Persistence**: In server mode without Robusta SaaS (`dal.enabled == False`), `OAuthTokenManager` leaves `self._store = None`. Tokens exist only in pod memory (`OAuthTokenCache`). Any pod restart, crash, or rolling deployment wipes memory, forcing users to re-authenticate repeatedly.
- **Read-Only Filesystem**: Production Helm charts enforce `readOnlyRootFilesystem: true`, causing disk-based storage (`DiskTokenStore`) to fail with `OSError`.
- **No Headless / Machine-to-Machine Flow**: Automated operations (e.g. AlertManager alert investigations) have no human present to log in via browser; they require standard OAuth 2.0 Client Credentials.
- **Security & Rate Limiting Gaps**: `server.py` lacks HTTP rate limiting, and static `HOLMES_API_KEY` middleware blocks browser redirects.
- **Silent Timeouts**: Neither server nor CLI clearly notifies users when authentication sessions or network calls time out.

---

## 2. Architecture & Design Goals

1. **Dual OAuth Modes**:
   - **Interactive Authorization Code Flow**: Native `GET /api/oauth/callback` (and alias `/callback`) in `server.py` to handle browser redirects seamlessly via `kubectl port-forward` or Ingress.
   - **Headless Client Credentials Flow**: Direct machine-to-machine exchange for unattended Kubernetes workloads.
2. **Zero-Reauth Persistence via Kubernetes Secret**:
   - `K8sSecretTokenStore` persists tokens to `Secret/holmes-mcp-tokens` in the pod's namespace.
   - Compatible with `readOnlyRootFilesystem: true`.
   - On pod startup/upgrade, tokens are preloaded into memory; expiring tokens are refreshed automatically in the background using refresh tokens.
3. **Strict Non-Breaking Isolation**:
   - CLI mode continues using `DiskTokenStore` (`~/.holmes/auth/mcp_tokens.json`).
   - Robusta SaaS mode continues using `DalTokenStore` (`oauth_tokens` Supabase table).
   - Standalone K8s mode activates `K8sSecretTokenStore` only when `dal.enabled == False`.
   - Fallback `DEFAULT_CLUSTER_USER = "cluster_user"` prevents dropping tokens when `user_id` is omitted in requests.
4. **Defense-in-Depth Security**:
   - Cryptographic `state` nonce validation and PKCE (`code_verifier`).
   - Sliding-window rate limiter on callback endpoints (10 req/min per IP).
   - `/api/oauth/callback` and `/callback` added to `AUTH_EXEMPT_PATHS`.
5. **Comprehensive Timeout & Error Handling**:
   - Server: 10-minute TTL on pending exchanges with dedicated "Session Expired" and "Gateway Timeout (504)" HTML pages.
   - CLI: Explicit terminal progress and timeout notices with dynamic MCP server names (`{server_name}`).

---

## 3. Component Design

### 3.1. Server Callback Endpoints (`server.py`)

In `server.py`, add the HTTP `GET` handler:

```python
@app.get("/api/oauth/callback", response_class=HTMLResponse)
@app.get("/callback", response_class=HTMLResponse)
async def oauth_callback_get(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    ...
```

#### Workflow:
1. **Rate Limiting**: Check client IP against the sliding-window limiter (10 requests/min). Exceeding returns `HTTP 429`.
2. **IdP Error Check**: If `error` is present (e.g. `access_denied`), render an error HTML page explaining the user or IdP rejected authentication.
3. **State & Session Validation**:
   - Look up pending exchange by `state`.
   - If not found or expired (`now - created_at > 600`), render the "Session Expired" HTML page (`HTTP 400`).
4. **Token Exchange**:
   - Call `exchange_code_for_tokens()` with `code`, `code_verifier`, and `redirect_uri`.
   - On `httpx.TimeoutException`: Render "Gateway Timeout" HTML (`HTTP 504`) with egress network check advice.
   - On `OAuthTokenExchangeError`: Render "Exchange Failed" HTML (`HTTP 502`).
5. **Token Storage**:
   - Call `token_manager.store_token(oauth_config, token_data, request_context)`.
   - If `request_context` has no `user_id`, use `DEFAULT_CLUSTER_USER`.
6. **Success Response**:
   - Render responsive, self-contained HTML (green checkmark, instructions to close tab).

#### Preserving Existing POST Endpoint:
The existing `@app.post("/api/oauth/callback")` taking `OAuthCallbackRequest` remains completely untouched for backwards compatibility with Robusta SaaS UI.

---

### 3.2. Headless Client Credentials (`holmes/core/oauth_config.py` & `toolset_mcp.py`)

1. **Schema Extension (`MCPOAuthConfig`)**:
   ```python
   class MCPOAuthConfig(BaseModel):
       enabled: bool = False
       grant_type: Literal["authorization_code", "client_credentials"] = "authorization_code"
       token_url: Optional[str] = None
       client_id: Optional[str] = None
       client_secret: Optional[str] = None
       scopes: Optional[List[str]] = None
       resource: Optional[str] = None
       authorization_url: Optional[str] = None
       registration_endpoint: Optional[str] = None
   ```
2. **Direct Exchange (`exchange_client_credentials_for_tokens`)**:
   - POSTs to `token_url` with `grant_type=client_credentials`, `client_id`, `client_secret`, and `scope`.
   - Supports HTTP Basic Auth and POST body credentials.
3. **Execution Integration**:
   - In `RemoteMCPTool.requires_approval()`, if `grant_type == "client_credentials"`, skip browser approval prompts.
   - Fetch token directly via `token_manager`, cache it, and proceed with tool execution.
   - Before token expiry, the background sweep refreshes the token using `client_id` + `client_secret`.

---

### 3.3. Kubernetes Secret Token Store (`K8sSecretTokenStore`)

Located in `holmes/plugins/toolsets/mcp/oauth_token_store.py`:

```python
class K8sSecretTokenStore(TokenStore):
    """Persists OAuth tokens into a Kubernetes Secret (holmes-mcp-tokens)."""

    def __init__(self, secret_name: str = "holmes-mcp-tokens", namespace: Optional[str] = None):
        self._secret_name = secret_name
        self._namespace = namespace or self._detect_namespace()
        self._core_api = None  # Lazy-initialized CoreV1Api
```

- **Namespace Detection**: Reads `/var/run/secrets/kubernetes.io/serviceaccount/namespace` or falls back to `POD_NAMESPACE` / `"default"`.
- **Key Format**: `{toolset_name}__{user_id or DEFAULT_CLUSTER_USER}`.
- **Payload**: JSON string with `access_token`, `refresh_token`, `token_expiry`, `token_url`, `client_id`, `grant_type`, `resource`.
- **Operations**:
  - `store_token(...)`: Reads secret, updates key, calls `create_namespaced_secret` or `patch_namespaced_secret`.
  - `get_token(...)`: Reads secret, extracts key, computes remaining TTL from `token_expiry`.
  - `get_all_for_preload()`: Returns all valid tokens to warm up `OAuthTokenCache` on pod startup.
  - `delete_token(...)`: Removes key from secret.

---

### 3.4. Token Store Selection Hierarchy (`oauth_token_manager.py`)

```python
def _init_store(self, dal: Any) -> None:
    if self._store is not None:
        return
    if dal and getattr(dal, "enabled", False):
        self._store = DalTokenStore(dal)
        logger.info("OAuthTokenManager: using DalTokenStore (Robusta SaaS)")
    elif _is_running_in_k8s():
        self._store = K8sSecretTokenStore()
        logger.info("OAuthTokenManager: using K8sSecretTokenStore (Standalone K8s)")
    else:
        self._store = DiskTokenStore()
        logger.info("OAuthTokenManager: using DiskTokenStore (CLI)")
```

- `DEFAULT_CLUSTER_USER = "cluster_user"`: Used when `request_context` has no `user_id`, ensuring tokens are never dropped.

---

### 3.5. Timeout & Feedback Improvements

#### Server Mode:
1. `_PendingOAuthExchange`: Add `created_at = time.monotonic()` with 10-minute TTL.
2. Expired sessions produce an explicit `HTTP 400` / `408` HTML response.
3. Network timeouts to `token_url` produce an `HTTP 504` HTML response explaining egress connectivity.
4. Expired/revoked refresh tokens (`invalid_grant`) trigger automatic eviction from cache and Secret.

#### CLI Mode (`holmes ask`):
In `cli_oauth_flow()` in `holmes/core/oauth_utils.py`:
1. Use dynamic `{server_name}` (never hardcoded):
   ```text
   For OAuth authentication to {server_name}, visit: {auth_url}

   ⏳ Waiting up to {timeout_minutes} minutes for authentication to complete (press Ctrl+C to cancel)...
   ```
2. On timeout (`callback_event.wait()` expires):
   ```text
   ❌ Authentication timed out after {timeout_minutes} minutes for {server_name}.
   No authorization response was received from the browser.
   ```
3. On IdP rejection:
   ```text
   ❌ Authentication was rejected by {server_name}: {error} - {error_description}
   ```
4. Configurable via `HOLMES_OAUTH_TIMEOUT_SECONDS` (default: 300).

---

## 4. Helm & RBAC Manifests

### 4.1. Scoped Role & RoleBinding (`helm/holmes/templates/oauth-rbac.yaml`)

```yaml
{{- if and .Values.createServiceAccount (not .Values.robusta.enabled) }}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "holmes.fullname" . }}-oauth-secret-role
  namespace: {{ .Release.Namespace }}
  labels:
    app.kubernetes.io/name: {{ include "holmes.name" . }}
    app.kubernetes.io/instance: {{ .Release.Name }}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["holmes-mcp-tokens"]
    verbs: ["get", "create", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "holmes.fullname" . }}-oauth-secret-rolebinding
  namespace: {{ .Release.Namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "holmes.fullname" . }}-oauth-secret-role
subjects:
  - kind: ServiceAccount
    name: {{ include "holmes.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
```

Ensure `automountServiceAccountToken: true` is configured when the ServiceAccount needs Kubernetes API access.

---

## 5. Testing Strategy

1. **Server Endpoints (`tests/test_server_endpoints.py`)**:
   - `test_oauth_callback_get_success`: Verify `GET /api/oauth/callback` exchanges code, stores token, and returns 200 HTML.
   - `test_oauth_callback_alias`: Verify `GET /callback` works identically.
   - `test_oauth_callback_timeout`: Verify expired session returns session-expired HTML.
   - `test_oauth_callback_idp_error`: Verify `error=access_denied` renders clean error HTML.
   - `test_oauth_callback_rate_limit`: Verify >10 req/min returns 429.
   - `test_api_key_auth_exemption`: Verify endpoint is reachable when `HOLMES_API_KEY` is set.
2. **K8s Secret Store (`tests/test_mcp_oauth.py`)**:
   - Mock Kubernetes API to test `store_token`, `get_token`, `delete_token`, and `get_all_for_preload`.
3. **Client Credentials Flow (`tests/test_mcp_oauth.py`)**:
   - Test `grant_type: client_credentials` token request, caching, and refresh.
4. **CLI Timeout Feedback (`tests/test_mcp_oauth.py`)**:
   - Verify terminal messages show dynamic `{server_name}` on timeout and error.
5. **Regression Verification**:
   - Ensure existing `DiskTokenStore` and `DalTokenStore` unit tests remain 100% passing.

---

## 6. Documentation Updates

Update `docs/data-sources/oauth-mcp-servers.md`:
1. Add **"Standalone Kubernetes (without Robusta Platform)"** setup guide.
2. Document **Flow 1 (Interactive via Port-Forward / Ingress)** with redirect URI configuration.
3. Document **Flow 2 (Client Credentials)** for headless Kubernetes deployments.
4. Document **Token Persistence** via `Secret/holmes-mcp-tokens`.
