import os
import json
import time
import uuid
import pytest
from starlette.testclient import TestClient
from server import app
from engine import security

client = TestClient(app)


def generate_auth_headers(client_id: str, secret: str, method: str, path: str, body: bytes = b"") -> dict:
    ts = str(time.time())
    nonce = uuid.uuid4().hex
    sig = security.compute_request_signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=ts,
        nonce=nonce,
        body_bytes=body
    )
    return {
        "x-wakex-client-id": client_id,
        "x-wakex-timestamp": ts,
        "x-wakex-nonce": nonce,
        "x-wakex-signature": sig,
        "content-type": "application/json"
    }


def test_scenes_lifecycle_and_apply():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    security.reset_all_auth_state()

    ctrl_client = security.register_paired_client("Controller", "client_ctrl", permission="control")

    # 1. List scenes
    headers_get = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "GET", "/api/scenes")
    resp = client.get("/api/scenes", headers=headers_get)
    assert resp.status_code == 200
    scenes = resp.json()["scenes"]
    assert len(scenes) >= 4
    scene_ids = [s["id"] for s in scenes]
    assert "scene_game" in scene_ids
    assert "scene_quiet" in scene_ids

    # 2. Apply Game scene
    headers_apply = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/scenes/scene_game/apply")
    resp = client.post("/api/scenes/scene_game/apply", headers=headers_apply)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["scene_id"] == "scene_game"
    assert "operating_mode" in data["results"]

    # 3. Create custom scene
    custom_dict = {"name": "Night Movie", "icon": "film", "actions": {"operating_mode": "silent", "brightness": 20}}
    custom_payload = json.dumps(custom_dict).encode("utf-8")
    headers_create = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/scenes", body=custom_payload)
    resp = client.post("/api/scenes", headers=headers_create, content=custom_payload)
    assert resp.status_code == 200
    created = resp.json()
    assert created["name"] == "Night Movie"
    new_id = created["id"]

    # 4. Delete custom scene
    headers_del = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "DELETE", f"/api/scenes/{new_id}")
    resp = client.delete(f"/api/scenes/{new_id}", headers=headers_del)
    assert resp.status_code == 200

    # 5. Cannot delete built-in scene
    headers_del_builtin = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "DELETE", "/api/scenes/scene_game")
    resp = client.delete("/api/scenes/scene_game", headers=headers_del_builtin)
    assert resp.status_code == 400
