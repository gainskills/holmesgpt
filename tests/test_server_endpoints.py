import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from holmes.core.tool_calling_llm import RelayRefusal
from server import app, extract_passthrough_headers


@pytest.fixture
def client():
    return TestClient(app)


DISABLED_MESSAGE = (
    "Robusta-hosted models are disabled for this account. Configure a model on "
    "the cluster, or enable Robusta-hosted models in Settings > LLM Models."
)


@pytest.mark.parametrize(
    "status_code, message",
    [
        (403, DISABLED_MESSAGE),
        (401, "Your session has expired. Reconnect the cluster to the platform."),
    ],
)
@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_answers_a_relay_refusal_with_its_own_status(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
    status_code,
    message,
):
    """Relay refusing the call on a Robusta-hosted model is the platform
    talking to the user: /api/chat passes its status and sentence through
    rather than turning them into a 500 (ROB-1389)."""
    mock_get_global_instructions.return_value = []
    mock_ai = MagicMock()
    mock_ai.call.side_effect = RelayRefusal(message, status_code)
    mock_create_toolcalling_llm.return_value = mock_ai

    response = client.post("/api/chat", json={"ask": "what is wrong?"})

    assert response.status_code == status_code
    assert response.json()["detail"] == message


@pytest.mark.parametrize("status_code", [401, 403])
@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_stream_carries_a_relay_refusal_in_the_error_event(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
    status_code,
):
    """A stream has committed HTTP 200 before the LLM call runs, so the
    refusal rides the SSE error event: relay's sentence as the text and a code
    per status the client can key on (ROB-1389)."""
    from holmes.core.relay_refusal import RELAY_REFUSAL_ERROR_CODES

    mock_get_global_instructions.return_value = []
    message = "Robusta-hosted models are disabled for this account."

    def refused_stream(*args, **kwargs):
        raise RelayRefusal(message, status_code)
        yield  # a generator, like the real call_stream

    mock_ai = MagicMock()
    mock_ai.call_stream.return_value = refused_stream()
    mock_create_toolcalling_llm.return_value = mock_ai

    response = client.post("/api/chat", json={"ask": "what is wrong?", "stream": True})

    assert response.status_code == 200
    events = [
        json.loads(line[len("data: ") :])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    assert events == [
        {
            "description": message,
            "error_code": RELAY_REFUSAL_ERROR_CODES[status_code],
            "msg": message,
            "success": False,
        }
    ]


@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_all_fields(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
):
    mock_ai = MagicMock()
    mock_ai.call.return_value = MagicMock(
        result="This is a mock analysis with tools and follow-up actions.",
        tool_calls=[
            {
                "tool_call_id": "1",
                "tool_name": "log_fetcher",
                "description": "Fetches logs",
                "result": {"status": "success", "data": "Log data"},
            }
        ],
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What can you do?"},
        ],
        metadata={},
        num_llm_calls=1,
    )
    mock_create_toolcalling_llm.return_value = mock_ai

    mock_get_global_instructions.return_value = []

    payload = {
        "ask": "What can you do?",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "model": "gpt-4.1",
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "analysis" in data
    assert "conversation_history" in data
    assert "tool_calls" in data
    assert "follow_up_actions" in data

    assert isinstance(data["analysis"], str)
    assert isinstance(data["conversation_history"], list)
    assert isinstance(data["tool_calls"], list)
    assert isinstance(data["follow_up_actions"], list)

    assert any(msg.get("role") == "user" for msg in data["conversation_history"])

    if data["tool_calls"]:
        tool_call = data["tool_calls"][0]
        assert "tool_call_id" in tool_call
        assert "tool_name" in tool_call
        assert "description" in tool_call
        assert "result" in tool_call

    if data["follow_up_actions"]:
        action = data["follow_up_actions"][0]
        assert "id" in action
        assert "action_label" in action
        assert "prompt" in action
        assert "pre_action_notification_text" in action


@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_with_images(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
):
    """Test /api/chat endpoint with image analysis support."""
    mock_ai = MagicMock()

    # Capture the messages passed to the LLM
    captured_messages = []

    def capture_messages(messages, **kwargs):
        captured_messages.append(messages)
        return MagicMock(
            result="This is an analysis of the provided image.",
            tool_calls=[],
            messages=messages,
            metadata={},
            num_llm_calls=1,
        )

    mock_ai.call.side_effect = capture_messages
    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    payload = {
        "ask": "What's in this image?",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "model": "gpt-4-vision-preview",
        "images": [
            "https://example.com/image1.png",
            "https://example.com/image2.jpg",
        ],
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify response structure
    assert "analysis" in data
    assert "conversation_history" in data
    assert "tool_calls" in data
    assert "follow_up_actions" in data

    # Verify the messages were captured
    assert len(captured_messages) == 1
    messages = captured_messages[0]

    # Find the user message with images
    user_message = next((m for m in messages if m["role"] == "user"), None)
    assert user_message is not None

    # Verify the content is an array with text and images
    content = user_message["content"]
    assert isinstance(content, list)
    assert len(content) == 3  # 1 text + 2 images

    # Verify text content
    text_item = content[0]
    assert text_item["type"] == "text"
    assert "What's in this image?" in text_item["text"]

    # Verify image contents
    image_items = content[1:]
    assert len(image_items) == 2
    for i, image_item in enumerate(image_items):
        assert image_item["type"] == "image_url"
        assert "image_url" in image_item
        assert image_item["image_url"]["url"] == payload["images"][i]


@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_with_images_advanced_format(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
):
    """Test /api/chat endpoint with advanced image format (dict with detail and format)."""
    mock_ai = MagicMock()

    # Capture the messages passed to the LLM
    captured_messages = []

    def capture_messages(messages, **kwargs):
        captured_messages.append(messages)
        return MagicMock(
            result="Detailed analysis of high-resolution image.",
            tool_calls=[],
            messages=messages,
            metadata={},
            num_llm_calls=1,
        )

    mock_ai.call.side_effect = capture_messages
    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    payload = {
        "ask": "Analyze this screenshot in detail",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "model": "gpt-4o",
        "images": [
            # Mix of simple strings and advanced dict format
            "https://example.com/simple-url.png",
            {
                "url": "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
                "detail": "high",
            },
            {
                "url": "https://example.com/image-with-format.webp",
                "detail": "low",
                "format": "image/webp",
            },
        ],
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify response structure
    assert "analysis" in data
    assert "conversation_history" in data

    # Verify the messages were captured
    assert len(captured_messages) == 1
    messages = captured_messages[0]

    # Find the user message with images
    user_message = next((m for m in messages if m["role"] == "user"), None)
    assert user_message is not None

    # Verify the content is an array
    content = user_message["content"]
    assert isinstance(content, list)
    assert len(content) == 4  # 1 text + 3 images

    # Verify text content
    text_item = content[0]
    assert text_item["type"] == "text"
    assert "Analyze this screenshot in detail" in text_item["text"]

    # Verify first image (simple string URL)
    image1 = content[1]
    assert image1["type"] == "image_url"
    assert image1["image_url"]["url"] == "https://example.com/simple-url.png"
    assert "detail" not in image1["image_url"]
    assert "format" not in image1["image_url"]

    # Verify second image (base64 with detail)
    image2 = content[2]
    assert image2["type"] == "image_url"
    assert image2["image_url"]["url"] == "data:image/jpeg;base64,/9j/4AAQSkZJRg=="
    assert image2["image_url"]["detail"] == "high"
    assert "format" not in image2["image_url"]

    # Verify third image (URL with detail and format)
    image3 = content[3]
    assert image3["type"] == "image_url"
    assert image3["image_url"]["url"] == "https://example.com/image-with-format.webp"
    assert image3["image_url"]["detail"] == "low"
    assert image3["image_url"]["format"] == "image/webp"


@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_with_images_missing_url_key(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
):
    """Test /api/chat endpoint raises error when image dict missing 'url' key."""
    mock_ai = MagicMock()
    mock_ai.call.return_value = MagicMock(
        result="This should not be reached.",
        tool_calls=[],
        messages=[],
        metadata={},
        num_llm_calls=1,
    )
    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    payload = {
        "ask": "Analyze this",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "model": "gpt-4o",
        "images": [
            # Dict missing required "url" key
            {"detail": "high", "format": "image/jpeg"}
        ],
    }
    response = client.post("/api/chat", json=payload)

    # Should return 500 error with clear message
    assert response.status_code == 500
    data = response.json()
    assert "Image dict must contain a 'url' key" in data["detail"]


@patch("server.tool_result_storage")
@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_frontend_tool_collision_returns_400(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    mock_tool_result_storage,
    client,
):
    mock_ai = MagicMock()
    mock_ai.tool_executor.tools_by_name = {"existing_tool": MagicMock()}
    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    storage_cm = MagicMock()
    storage_cm.__enter__.return_value = "/tmp/test"
    mock_tool_result_storage.return_value = storage_cm

    payload = {
        "ask": "anything",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "frontend_tools": [
            {
                "name": "existing_tool",
                "description": "intentional collision",
                "parameters": {"type": "object", "properties": {}},
                "mode": "pause",
            }
        ],
        "stream": True,
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 400, response.text
    assert "existing_tool" in response.json()["detail"]
    storage_cm.__exit__.assert_called_once()


@patch("server.tool_result_storage")
@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_pause_mode_without_streaming_cleans_up_storage(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    mock_tool_result_storage,
    client,
):
    mock_ai = MagicMock()
    mock_ai.tool_executor.tools_by_name = {}
    cloned_executor = MagicMock()
    mock_ai.tool_executor.clone_with_extra_tools.return_value = cloned_executor
    mock_ai.with_executor.return_value = MagicMock()
    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    storage_cm = MagicMock()
    storage_cm.__enter__.return_value = "/tmp/test"
    mock_tool_result_storage.return_value = storage_cm

    payload = {
        "ask": "anything",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "frontend_tools": [
            {
                "name": "create_dashboard",
                "description": "needs streaming",
                "parameters": {"type": "object", "properties": {}},
                "mode": "pause",
            }
        ],
        "stream": False,
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 400, response.text
    assert "stream=true" in response.json()["detail"]
    storage_cm.__exit__.assert_called_once()


@patch("holmes.config.Config.create_toolcalling_llm")
@patch("holmes.core.supabase_dal.SupabaseDal.get_global_instructions_for_account")
def test_api_chat_noop_frontend_tool_uses_cloned_ai_in_non_streaming(
    mock_get_global_instructions,
    mock_create_toolcalling_llm,
    client,
):
    mock_ai = MagicMock()
    mock_ai.tool_executor.tools_by_name = {"existing_tool": MagicMock()}

    cloned_executor = MagicMock(name="cloned_executor")
    mock_ai.tool_executor.clone_with_extra_tools.return_value = cloned_executor

    cloned_ai = MagicMock(name="cloned_ai")
    cloned_ai.call.return_value = MagicMock(
        result="answer-from-cloned-ai",
        tool_calls=[],
        messages=[
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
        ],
        metadata={},
        num_llm_calls=1,
    )
    # Distinguishable so the test fails clearly if request_ai isn't used.
    mock_ai.call.return_value = MagicMock(
        result="answer-from-original-ai-WRONG",
        tool_calls=[],
        messages=[],
        metadata={},
        num_llm_calls=1,
    )
    mock_ai.with_executor.return_value = cloned_ai

    mock_create_toolcalling_llm.return_value = mock_ai
    mock_get_global_instructions.return_value = []

    payload = {
        "ask": "log this",
        "conversation_history": [
            {"role": "system", "content": "You are a helpful assistant."}
        ],
        "frontend_tools": [
            {
                "name": "emit_telemetry",
                "description": "Fire-and-forget telemetry",
                "parameters": {"type": "object", "properties": {}},
                "mode": "noop",
                "noop_response": "ack",
            }
        ],
        "stream": False,
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["analysis"] == "answer-from-cloned-ai"

    cloned_ai.call.assert_called_once()
    mock_ai.call.assert_not_called()
    mock_ai.tool_executor.clone_with_extra_tools.assert_called_once()
    mock_ai.with_executor.assert_called_once_with(cloned_executor)


class TestExtractPassthroughHeaders:
    def test_extract_normal_headers(self):
        scope = {
            "type": "http",
            "headers": [
                (b"x-tenant-id", b"tenant-123"),
                (b"x-custom-header", b"custom-value"),
                (b"content-type", b"application/json"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {
            "headers": {
                "x-tenant-id": "tenant-123",
                "x-custom-header": "custom-value",
                "content-type": "application/json",
            }
        }

    def test_blocks_authorization_header(self):
        scope = {
            "type": "http",
            "headers": [
                (b"authorization", b"Bearer secret-token"),
                (b"x-tenant-id", b"tenant-123"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {"headers": {"x-tenant-id": "tenant-123"}}
        assert "authorization" not in result["headers"]

    def test_blocks_cookie_headers(self):
        scope = {
            "type": "http",
            "headers": [
                (b"cookie", b"session=abc123"),
                (b"set-cookie", b"session=abc123; Path=/"),
                (b"x-tenant-id", b"tenant-123"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {"headers": {"x-tenant-id": "tenant-123"}}
        assert "cookie" not in result["headers"]
        assert "set-cookie" not in result["headers"]

    def test_case_insensitive_blocking(self):
        scope = {
            "type": "http",
            "headers": [
                (b"Authorization", b"Bearer secret"),
                (b"COOKIE", b"session=abc"),
                (b"Set-Cookie", b"session=abc; Path=/"),
                (b"x-tenant-id", b"tenant-123"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {"headers": {"x-tenant-id": "tenant-123"}}
        assert "Authorization" not in result["headers"]
        assert "COOKIE" not in result["headers"]
        assert "Set-Cookie" not in result["headers"]

    def test_empty_headers(self):
        scope = {"type": "http", "headers": []}
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {}

    def test_all_blocked_headers(self):
        scope = {
            "type": "http",
            "headers": [
                (b"authorization", b"Bearer secret"),
                (b"cookie", b"session=abc"),
                (b"set-cookie", b"session=abc; Path=/"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert result == {}

    def test_preserves_header_case(self):
        scope = {
            "type": "http",
            "headers": [
                (b"X-Tenant-ID", b"tenant-123"),
                (b"X-Custom-Header", b"value"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        assert "X-Tenant-ID" in result["headers"]
        assert "X-Custom-Header" in result["headers"]
        assert result["headers"]["X-Tenant-ID"] == "tenant-123"
        assert result["headers"]["X-Custom-Header"] == "value"

    def test_custom_blocked_headers_via_env(self, monkeypatch):
        """Test that HOLMES_PASSTHROUGH_BLOCKED_HEADERS env var works"""
        # Set custom blocked headers via environment variable
        monkeypatch.setenv(
            "HOLMES_PASSTHROUGH_BLOCKED_HEADERS", "x-internal-token,x-secret"
        )

        scope = {
            "type": "http",
            "headers": [
                (b"x-internal-token", b"secret-value"),
                (b"x-secret", b"another-secret"),
                (b"authorization", b"Bearer token"),  # Not in custom list, should pass
                (b"x-tenant-id", b"tenant-123"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        # Custom blocked headers should be filtered
        assert "x-internal-token" not in result["headers"]
        assert "x-secret" not in result["headers"]
        # Authorization is not in custom list, so it should pass through
        assert "authorization" in result["headers"]
        assert result["headers"]["authorization"] == "Bearer token"
        # Regular headers should pass
        assert result["headers"]["x-tenant-id"] == "tenant-123"

    def test_empty_blocked_headers_env(self, monkeypatch):
        """Test that empty HOLMES_PASSTHROUGH_BLOCKED_HEADERS allows all headers"""
        monkeypatch.setenv("HOLMES_PASSTHROUGH_BLOCKED_HEADERS", "")

        scope = {
            "type": "http",
            "headers": [
                (b"authorization", b"Bearer token"),
                (b"cookie", b"session=abc"),
                (b"x-tenant-id", b"tenant-123"),
            ],
        }
        request = Request(scope)
        result = extract_passthrough_headers(request)

        # With empty blocklist, all headers should pass through
        assert "authorization" in result["headers"]
        assert "cookie" in result["headers"]
        assert "x-tenant-id" in result["headers"]


# ── Native OAuth Callback (GET) Tests ─────────────────────────────────────


def test_oauth_callback_get_success(client, monkeypatch):
    from holmes.core.oauth_config import _get_exchange_manager, MCPOAuthConfig

    tool_call_id = "tc-get-test"
    _get_exchange_manager().register_pending(
        tool_call_id=tool_call_id,
        code_verifier="verifier-123",
        oauth_config=MCPOAuthConfig(token_url="http://mock/token", client_id="cid"),
        redirect_uri="http://localhost:8080/api/oauth/callback",
    )
    with monkeypatch.context() as m:
        m.setattr(
            "holmes.core.oauth_server_callbacks.exchange_code_for_tokens",
            lambda **kwargs: {"access_token": "at-123"},
        )
        response = client.get(f"/api/oauth/callback?code=code-123&state={tool_call_id}")
        assert response.status_code == 200
        assert "Authentication Successful" in response.text


def test_oauth_callback_alias_path(client, monkeypatch):
    response = client.get("/callback?error=access_denied&error_description=User+cancelled")
    assert response.status_code == 400
    assert "access_denied" in response.text


def test_oauth_callback_session_expired(client):
    import time
    from holmes.core.oauth_config import _get_exchange_manager, MCPOAuthConfig

    # Case 1: Unknown state
    response = client.get("/api/oauth/callback?code=code-123&state=nonexistent-state")
    assert response.status_code == 400
    assert "Session Expired" in response.text

    # Case 2: Expired state (> 600s)
    tool_call_id = "tc-expired-test"
    mgr = _get_exchange_manager()
    mgr.register_pending(
        tool_call_id=tool_call_id,
        code_verifier="verifier-123",
        oauth_config=MCPOAuthConfig(token_url="http://mock/token", client_id="cid"),
        redirect_uri="http://localhost:8080/api/oauth/callback",
    )
    with mgr._lock:
        mgr._pending[tool_call_id].created_at = time.monotonic() - 601

    response = client.get(f"/api/oauth/callback?code=code-123&state={tool_call_id}")
    assert response.status_code == 400
    assert "Session Expired" in response.text


def test_oauth_callback_rate_limit(client):
    import server

    # Reset IP history to avoid test pollution
    if hasattr(server, "_callback_ip_history"):
        with server._callback_ip_lock:
            server._callback_ip_history.clear()

    try:
        # 10 requests allowed
        for _ in range(10):
            resp = client.get("/callback?error=access_denied&error_description=cancelled")
            assert resp.status_code == 400

        # 11th request rejected with 429
        resp = client.get("/callback?error=access_denied&error_description=cancelled")
        assert resp.status_code == 429
        assert "Too Many Requests" in resp.text or "Rate Limited" in resp.text
    finally:
        if hasattr(server, "_callback_ip_history"):
            with server._callback_ip_lock:
                server._callback_ip_history.clear()


def test_callback_rate_limiter_prunes_expired_ips():
    import time
    from fastapi import Request
    import server

    with server._callback_ip_lock:
        server._callback_ip_history.clear()
        # Add an expired IP entry
        server._callback_ip_history["expired-ip"] = [time.time() - 120.0]

    try:
        req = Request(
            {
                "type": "http",
                "headers": [(b"x-forwarded-for", b"active-ip")],
                "client": ("127.0.0.1", 12345),
            }
        )
        is_limited = server._is_callback_rate_limited(req)
        assert not is_limited

        with server._callback_ip_lock:
            assert "expired-ip" not in server._callback_ip_history
            assert "active-ip" in server._callback_ip_history
    finally:
        with server._callback_ip_lock:
            server._callback_ip_history.clear()


def test_oauth_callback_timeout_504(client, monkeypatch):
    import httpx
    from holmes.core.oauth_config import _get_exchange_manager, MCPOAuthConfig

    tool_call_id = "tc-timeout-test"
    _get_exchange_manager().register_pending(
        tool_call_id=tool_call_id,
        code_verifier="verifier-123",
        oauth_config=MCPOAuthConfig(token_url="http://mock/token", client_id="cid"),
        redirect_uri="http://localhost:8080/api/oauth/callback",
    )
    with monkeypatch.context() as m:
        m.setattr(
            "holmes.core.oauth_server_callbacks.exchange_code_for_tokens",
            MagicMock(side_effect=httpx.ConnectTimeout("Connection timed out")),
        )
        response = client.get(f"/api/oauth/callback?code=code-123&state={tool_call_id}")
        assert response.status_code == 504
        assert "Gateway Timeout" in response.text


def test_oauth_callback_exchange_error_502(client, monkeypatch):
    from holmes.core.oauth_config import _get_exchange_manager, MCPOAuthConfig, OAuthTokenExchangeError

    tool_call_id = "tc-error-test"
    _get_exchange_manager().register_pending(
        tool_call_id=tool_call_id,
        code_verifier="verifier-123",
        oauth_config=MCPOAuthConfig(token_url="http://mock/token", client_id="cid"),
        redirect_uri="http://localhost:8080/api/oauth/callback",
    )
    with monkeypatch.context() as m:
        m.setattr(
            "holmes.core.oauth_server_callbacks.exchange_code_for_tokens",
            MagicMock(side_effect=OAuthTokenExchangeError(400, "invalid_grant: code expired")),
        )
        response = client.get(f"/api/oauth/callback?code=code-123&state={tool_call_id}")
        assert response.status_code == 502
        assert "Token Exchange Failed" in response.text


def test_oauth_callback_auth_exemption():
    from holmes.utils.auth import AUTH_EXEMPT_PATHS
    assert "/api/oauth/callback" in AUTH_EXEMPT_PATHS
    assert "/callback" in AUTH_EXEMPT_PATHS

