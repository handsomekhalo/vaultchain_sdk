import hmac
import hashlib
import time
import json
import urllib.request
import urllib.error


class VaultChainError(Exception):
    pass


class VaultChainClient:
    def __init__(self, base_url: str, api_key: str, secret: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.secret = secret

    def _sign(self, method: str, path: str, body_str: str, timestamp: str) -> str:
        message = f"{method}\n{path}\n{body_str}\n{timestamp}"
        return hmac.new(self.secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    def _request(self, method: str, path: str, body_dict: dict | None = None):
        body_str = json.dumps(body_dict) if body_dict is not None else ""
        timestamp = str(time.time())
        signature = self._sign(method, path, body_str, timestamp)

        headers = {
            "X-Api-Key": self.api_key,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "Content-Type": "application/json",
        }

        url = f"{self.base_url}{path}"
        data = body_str.encode() if body_dict is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise VaultChainError(f"{e.code}: {e.read().decode()}")

    def create_inference(self, *, user_ref, model_version, provider, input_payload,
                          output_payload, latency_ms, token_count=None, cost_usd=None):
        body = {
            "user_ref": user_ref,
            "model_version": model_version,
            "provider": provider,
            "input_payload": input_payload,
            "output_payload": output_payload,
            "latency_ms": latency_ms,
            "token_count": token_count,
            "cost_usd": cost_usd,
        }
        return self._request("POST", "/audit_api/create_inference_api/", body)

    def get_inference(self, record_id: str):
        return self._request("GET", f"/audit_api/get_inference_api/{record_id}/")

    def verify_chain(self):
        return self._request("GET", "/tenants_api/verify_tenant_chain_api/")