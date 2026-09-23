"""OAuth token storage: in-memory cache, disk store, and DB store."""

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from holmes.common.env_vars import DEFAULT_CLI_USER
from holmes.core.config import config_path_dir

logger = logging.getLogger(__name__)


# ── In-memory cache ───────────────────────────────────────────────────────


class _CachedToken:
    """Holds an access token, its expiry, and an optional refresh token."""

    def __init__(
        self,
        access_token: str,
        expires_at: float,
        refresh_token: Optional[str] = None,
        refresh_expires_at: Optional[float] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        authorization_url: Optional[str] = None,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> None:
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.refresh_expires_at = refresh_expires_at
        # Metadata for background refresh sweep
        self.token_url = token_url
        self.client_id = client_id
        self.authorization_url = authorization_url
        self.user_id = user_id
        self.resource = resource

    @property
    def access_expired(self) -> bool:
        return time.monotonic() >= self.expires_at

    @property
    def refresh_expired(self) -> bool:
        if self.refresh_token is None or self.refresh_expires_at is None:
            return True
        return time.monotonic() >= self.refresh_expires_at


class OAuthTokenCache:
    """TTL cache for OAuth tokens keyed by conversation ID, with refresh token support."""

    def __init__(self) -> None:
        self._cache: Dict[str, _CachedToken] = {}
        self._lock = threading.Lock()

    def get_valid_access_token(self, key: str) -> Optional[str]:
        """Return a valid (non-expired) access token, or None if expired or missing."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if not entry.access_expired:
                return entry.access_token
            # Access expired — keep entry if refresh token exists (caller should try refresh)
            if entry.refresh_token:
                return None
            # No refresh token, evict
            del self._cache[key]
            return None

    def get_refresh_token(self, key: str) -> Optional[str]:
        """Return the refresh token even if expired — some IdPs accept expired refresh tokens to issue new ones."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            return entry.refresh_token

    def get_resource(self, key: str) -> Optional[str]:
        """Return the RFC 8707 resource the cached token was issued for, if any."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            return entry.resource

    def set(
        self,
        key: str,
        access_token: str,
        expires_in: int = 300,
        refresh_token: Optional[str] = None,
        refresh_expires_in: Optional[int] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        authorization_url: Optional[str] = None,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> None:
        now = time.monotonic()
        # Subtract a small buffer so we refresh before actual expiry
        access_expires_at = now + max(expires_in - 30, 10)
        refresh_expires_at = None
        if refresh_token:
            # Default to 24 hours if IdP doesn't return refresh_expires_in (not all do)
            refresh_ttl = refresh_expires_in if refresh_expires_in else 86400
            refresh_expires_at = now + max(refresh_ttl - 30, 10)
        with self._lock:
            self._cache[key] = _CachedToken(
                access_token, access_expires_at, refresh_token, refresh_expires_at,
                token_url=token_url, client_id=client_id,
                authorization_url=authorization_url, user_id=user_id,
                resource=resource,
            )

    def evict(self, key: str) -> None:
        """Remove an entry from the cache (e.g. after a failed refresh)."""
        with self._lock:
            self._cache.pop(key, None)

    def get_expiring_entries(self, within_seconds: int) -> list[tuple[str, "_CachedToken"]]:
        """Return (key, entry) pairs for tokens whose access expires within the given window."""
        threshold = time.monotonic() + within_seconds
        with self._lock:
            return [
                (key, entry) for key, entry in self._cache.items()
                if entry.expires_at <= threshold
            ]

    def has_token_or_refresh(self, key: str) -> bool:
        """True if there is a valid access token or any refresh token (even expired — IdP decides validity)."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if not entry.access_expired:
                return True
            if entry.refresh_token:
                return True
            del self._cache[key]
            return False


# ── Persistent token store interface ──────────────────────────────────────


class TokenStore(ABC):
    """Abstract persistent OAuth token storage — either DB or disk."""

    @abstractmethod
    def get_token(
        self,
        provider_name: str,
        user_id: Optional[str] = None,
        provider_aliases: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Load a token by provider and user. Returns decrypted token data or None."""

    @abstractmethod
    def store_token(
        self,
        provider_name: str,
        token_data: Dict[str, Any],
        user_id: Optional[str] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> bool:
        """Store a token. Returns True on success."""

    @abstractmethod
    def delete_token(self, provider_name: str, user_id: Optional[str] = None) -> bool:
        """Delete a token by provider and user. Returns True if deleted."""

    @abstractmethod
    def get_all_for_preload(self) -> List[Dict[str, Any]]:
        """Get all tokens for preloading into cache at startup.

        Returns list of dicts with keys: provider_name, user_id, token_data,
        token_expiry (optional).
        """



# ── DB-backed token store ─────────────────────────────────────────────────


class DalTokenStore(TokenStore):
    """Persists OAuth tokens in the Supabase DB with Fernet encryption."""

    def __init__(self, dal: Any) -> None:
        self._dal = dal

    def get_token(
        self,
        provider_name: str,
        user_id: Optional[str] = None,
        provider_aliases: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not user_id:
            return None

        signing_key_hash = self._get_signing_key_hash()
        if not signing_key_hash:
            return None

        providers_to_try: List[str] = []
        if provider_name:
            providers_to_try.append(provider_name)
        if provider_aliases:
            providers_to_try.extend(provider_aliases)
        if not providers_to_try:
            providers_to_try.append("unknown")

        for provider in providers_to_try:
            db_record = self._dal.get_oauth_token(provider, user_id=user_id, signing_key_hash=signing_key_hash)
            if not db_record:
                continue

            token_data = self._decrypt_token(db_record["encrypted_token"])
            if token_data:
                # Compute remaining TTL from stored token_expiry
                token_expiry_str = db_record.get("token_expiry")
                if token_expiry_str:
                    try:
                        token_expiry = datetime.fromisoformat(token_expiry_str)
                        remaining = (token_expiry - datetime.now(timezone.utc)).total_seconds()
                        token_data["_remaining_ttl"] = max(int(remaining), 1)
                    except (ValueError, TypeError):
                        pass
            return token_data

        return None

    def store_token(
        self,
        provider_name: str,
        token_data: Dict[str, Any],
        user_id: Optional[str] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> bool:
        signing_key_hash = self._get_signing_key_hash()
        if not signing_key_hash:
            return False

        try:
            # Include metadata needed for refresh after DB round-trip
            enriched = dict(token_data)
            if token_url:
                enriched["token_url"] = token_url
            if client_id:
                enriched["client_id"] = client_id
            if resource is not None:
                enriched["resource"] = resource
            encrypted = self._encrypt_token(enriched)
            if not encrypted:
                logger.warning("Cannot encrypt token (no signing key)")
                return False

            # Store access token expiry so preload can compute remaining TTL
            expiry = None
            if token_data.get("expires_in"):
                expiry = (datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])).isoformat()

            self._dal.upsert_oauth_token(
                provider_name=provider_name or "unknown",
                encrypted_token=encrypted,
                signing_key_hash=signing_key_hash,
                token_expiry=expiry,
                user_id=user_id,
            )
            logger.debug("Token stored to DB (provider=%s, user_id=%s)", provider_name, user_id)
            return True
        except Exception:
            logger.warning("Failed to store token to DB", exc_info=True)
            return False

    def delete_token(self, provider_name: str, user_id: Optional[str] = None) -> bool:
        if not user_id:
            return False
        signing_key_hash = self._get_signing_key_hash()
        if not signing_key_hash:
            return False
        try:
            self._dal.delete_oauth_token(provider_name, user_id, signing_key_hash)
            return True
        except Exception:
            logger.warning("Failed to delete token from DB (provider=%s)", provider_name, exc_info=True)
            return False

    def get_all_for_preload(self) -> List[Dict[str, Any]]:
        signing_key_hash = self._get_signing_key_hash()
        if not signing_key_hash:
            return []

        db_tokens = self._dal.get_all_oauth_tokens_for_cluster(signing_key_hash)
        if not db_tokens:
            return []

        results = []
        for row in db_tokens:
            token_data = self._decrypt_token(row["encrypted_token"])
            if not token_data or not token_data.get("access_token"):
                continue
            results.append({
                "provider_name": row.get("provider_name", ""),
                "user_id": row.get("user_id"),
                "token_data": token_data,
                "token_expiry": row.get("token_expiry"),
            })
        return results

    # ── Encryption helpers ─────────────────────────────────────────────

    @staticmethod
    def _get_signing_key() -> Optional[str]:
        from holmes.config import Config
        return Config.get_robusta_global_config_value("signing_key")

    def _get_signing_key_hash(self) -> Optional[str]:
        key = self._get_signing_key()
        if not key:
            return None
        return hashlib.sha256(key.encode()).hexdigest()

    @staticmethod
    def _derive_fernet_key(signing_key: str) -> bytes:
        return base64.urlsafe_b64encode(
            HKDF(algorithm=SHA256(), length=32, salt=b"holmesgpt-oauth-db-token", info=b"token-encryption")
            .derive(signing_key.encode())
        )

    def _encrypt_token(self, token_data: Dict[str, Any]) -> Optional[str]:
        signing_key = self._get_signing_key()
        if not signing_key:
            return None
        return Fernet(self._derive_fernet_key(signing_key)).encrypt(json.dumps(token_data).encode()).decode()

    def _decrypt_token(self, encrypted: str) -> Optional[Dict[str, Any]]:
        signing_key = self._get_signing_key()
        if not signing_key:
            return None
        try:
            decrypted = Fernet(self._derive_fernet_key(signing_key)).decrypt(encrypted.encode())
            return json.loads(decrypted)
        except Exception:
            logger.warning("Failed to decrypt token from DB (signing_key mismatch?)")
            return None


# ── Disk-backed token store ───────────────────────────────────────────────


class DiskTokenStore(TokenStore):
    """Persists OAuth tokens to ~/.holmes/auth/mcp_tokens.json for CLI usage."""

    def __init__(self, enabled: bool = True) -> None:
        self._path = Path(config_path_dir) / "auth" / "mcp_tokens.json"
        self._enabled = enabled
        self._lock = threading.Lock()
        if not self._enabled:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._enabled = False
            logger.info("OAuth disk token store disabled (read-only filesystem)")

    def get_token(
        self,
        provider_name: str,
        user_id: Optional[str] = None,
        provider_aliases: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self._enabled:
            return None
        with self._lock:
            data = self._load()
            token = data.get(provider_name)
            if token and token.get("expires_at", float("inf")) > time.time():
                return token
            return None

    def store_token(
        self,
        provider_name: str,
        token_data: Dict[str, Any],
        user_id: Optional[str] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            data = self._load()
            # Include metadata needed for refresh after a process restart
            # (mirrors DalTokenStore's enrichment)
            enriched = dict(token_data)
            if token_url:
                enriched["token_url"] = token_url
            if client_id:
                enriched["client_id"] = client_id
            if resource is not None:
                enriched["resource"] = resource
            data[provider_name] = enriched
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
        return True

    def delete_token(self, provider_name: str, user_id: Optional[str] = None) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            data = self._load()
            if provider_name not in data:
                return False
            del data[provider_name]
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
        return True

    def get_all_for_preload(self) -> List[Dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock:
            data = self._load()
        results = []
        now = time.time()
        for key, token_data in data.items():
            if token_data.get("expires_at", float("inf")) > now and token_data.get("access_token"):
                results.append({
                    "provider_name": key,
                    "user_id": DEFAULT_CLI_USER,
                    "token_data": token_data,
                    "token_expiry": None,
                })
        return results

    def _load(self) -> Dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            with open(self._path) as f:
                return json.load(f)
        except Exception:
            return {}


# ── Kubernetes Secret token store ─────────────────────────────────────────


class K8sSecretTokenStore(TokenStore):
    """Persists OAuth tokens into a Kubernetes Secret (holmes-mcp-tokens)."""

    def __init__(self, secret_name: str = "holmes-mcp-tokens", namespace: Optional[str] = None) -> None:
        self._secret_name = secret_name
        self._namespace = namespace or self._detect_namespace()
        self._api_client: Optional[Any] = None
        self._lock = threading.Lock()

    @staticmethod
    def _detect_namespace() -> str:
        ns_file = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        if ns_file.exists():
            try:
                return ns_file.read_text().strip()
            except Exception:
                pass
        return os.environ.get("POD_NAMESPACE", "default")

    def _get_api(self) -> Any:
        if self._api_client is None:
            with self._lock:
                if self._api_client is None:
                    try:
                        config.load_incluster_config()
                    except Exception:
                        try:
                            config.load_kube_config()
                        except Exception:
                            pass
                    self._api_client = client.CoreV1Api()
        return self._api_client

    def _format_key(self, provider_name: str, user_id: Optional[str] = None) -> str:
        raw = f"{provider_name}__{user_id or 'default'}"
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw)

    @staticmethod
    def _decode_token_value(val: Any) -> Optional[Dict[str, Any]]:
        if not val:
            return None
        if isinstance(val, dict):
            return val
        if isinstance(val, bytes):
            val = val.decode("utf-8")
        if not isinstance(val, str):
            return None
        val = val.strip()

        parsed: Any = None
        if val.startswith("{"):
            try:
                parsed = json.loads(val)
            except Exception:
                pass
        if parsed is None:
            try:
                decoded = base64.b64decode(val.encode("utf-8")).decode("utf-8")
                parsed = json.loads(decoded)
            except Exception:
                pass
        if parsed is None:
            try:
                parsed = json.loads(val)
            except Exception:
                pass

        if isinstance(parsed, dict):
            return parsed
        return None

    def get_token(
        self,
        provider_name: str,
        user_id: Optional[str] = None,
        provider_aliases: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        api = self._get_api()
        try:
            try:
                secret = api.read_namespaced_secret(self._secret_name, self._namespace)
            except ApiException as e:
                if e.status == 404:
                    return None
                raise
        except Exception:
            logger.warning("Failed to read K8s Secret %s in namespace %s", self._secret_name, self._namespace, exc_info=True)
            return None

        secret_dict: Dict[str, Any] = {}
        if getattr(secret, "data", None):
            secret_dict.update(secret.data)
        if getattr(secret, "string_data", None):
            secret_dict.update(secret.string_data)

        providers_to_try: List[str] = []
        if provider_name:
            providers_to_try.append(provider_name)
        if provider_aliases:
            providers_to_try.extend(provider_aliases)
        if not providers_to_try:
            providers_to_try.append("unknown")

        for prov in providers_to_try:
            key = self._format_key(prov, user_id)
            raw_val = secret_dict.get(key)
            if not raw_val:
                continue
            token_data = self._decode_token_value(raw_val)
            if not token_data or not token_data.get("access_token"):
                continue

            token_expiry_str = token_data.get("token_expiry")
            if token_expiry_str:
                try:
                    token_expiry = datetime.fromisoformat(token_expiry_str)
                    remaining = (token_expiry - datetime.now(timezone.utc)).total_seconds()
                    token_data["_remaining_ttl"] = max(int(remaining), 1)
                except (ValueError, TypeError):
                    pass
            return token_data

        return None

    def store_token(
        self,
        provider_name: str,
        token_data: Dict[str, Any],
        user_id: Optional[str] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> bool:
        enriched = dict(token_data)
        if token_url:
            enriched["token_url"] = token_url
        if client_id:
            enriched["client_id"] = client_id
        if resource is not None:
            enriched["resource"] = resource
        if provider_name:
            enriched["provider_name"] = provider_name
        if user_id:
            enriched["user_id"] = user_id

        if token_data.get("expires_in") and "token_expiry" not in enriched:
            enriched["token_expiry"] = (datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])).isoformat()

        key = self._format_key(provider_name, user_id)
        json_str = json.dumps(enriched)

        api = self._get_api()
        with self._lock:
            try:
                secret_exists = True
                try:
                    api.read_namespaced_secret(self._secret_name, self._namespace)
                except ApiException as e:
                    if e.status == 404:
                        secret_exists = False
                    else:
                        raise

                if not secret_exists:
                    secret_body = client.V1Secret(
                        metadata=client.V1ObjectMeta(name=self._secret_name, namespace=self._namespace),
                        string_data={key: json_str},
                    )
                    try:
                        api.create_namespaced_secret(namespace=self._namespace, body=secret_body)
                    except ApiException as e:
                        if e.status == 409:
                            patch_body = client.V1Secret(string_data={key: json_str})
                            api.patch_namespaced_secret(name=self._secret_name, namespace=self._namespace, body=patch_body)
                        else:
                            raise
                else:
                    patch_body = client.V1Secret(string_data={key: json_str})
                    api.patch_namespaced_secret(name=self._secret_name, namespace=self._namespace, body=patch_body)

                logger.debug("Token stored to K8s Secret %s (provider=%s, user_id=%s)", self._secret_name, provider_name, user_id)
                return True
            except Exception:
                logger.warning("Failed to store token in K8s Secret %s", self._secret_name, exc_info=True)
                return False

    def delete_token(self, provider_name: str, user_id: Optional[str] = None) -> bool:
        key = self._format_key(provider_name, user_id)
        api = self._get_api()
        with self._lock:
            try:
                try:
                    secret = api.read_namespaced_secret(self._secret_name, self._namespace)
                except ApiException as e:
                    if e.status == 404:
                        return False
                    raise

                data = secret.data or {}
                string_data = secret.string_data or {}
                if key not in data and key not in string_data:
                    return False

                if key in data:
                    del data[key]
                if key in string_data:
                    del string_data[key]
                secret.data = data
                secret.string_data = string_data
                api.replace_namespaced_secret(name=self._secret_name, namespace=self._namespace, body=secret)
                return True
            except Exception:
                logger.warning("Failed to delete token from K8s Secret %s", self._secret_name, exc_info=True)
                return False

    def get_all_for_preload(self) -> List[Dict[str, Any]]:
        api = self._get_api()
        try:
            try:
                secret = api.read_namespaced_secret(self._secret_name, self._namespace)
            except ApiException as e:
                if e.status == 404:
                    return []
                raise
        except Exception:
            logger.warning("Failed to read K8s Secret %s for preload", self._secret_name, exc_info=True)
            return []

        secret_dict: Dict[str, Any] = {}
        if getattr(secret, "data", None):
            secret_dict.update(secret.data)
        if getattr(secret, "string_data", None):
            secret_dict.update(secret.string_data)

        results: List[Dict[str, Any]] = []
        for key, raw_val in secret_dict.items():
            token_data = self._decode_token_value(raw_val)
            if not token_data or not token_data.get("access_token"):
                continue

            provider_name = token_data.get("provider_name")
            user_id = token_data.get("user_id")
            if not provider_name:
                parts = key.split("__", 1)
                provider_name = parts[0]
                if not user_id and len(parts) > 1:
                    user_id = parts[1]

            results.append({
                "provider_name": provider_name or "",
                "user_id": user_id,
                "token_data": token_data,
                "token_expiry": token_data.get("token_expiry"),
            })
        return results

