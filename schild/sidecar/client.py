"""
SCHILD Sidecar Client
Dipanggil dari SCHILD backend untuk mengirim perintah ke sidecar server
yang berjalan di remote host.
"""

# DONE: TASK-11.4

import logging
from typing import Optional
import requests

from schild.core.config import SIDECAR_TIMEOUT

logger = logging.getLogger("schild.sidecar.client")


class SidecarClient:
    """
    HTTP client untuk berkomunikasi dengan sidecar server di remote host.
    Satu instance per remote host.
    """

    def __init__(self, base_url: str, secret: str, timeout: int = SIDECAR_TIMEOUT):
        """
        Args:
            base_url: URL sidecar, misal "http://dvwa-vm:8421"
            secret:   Shared secret (SCHILD_SIDECAR_SECRET)
            timeout:  Request timeout dalam detik
        """
        self.base_url = base_url.rstrip("/")
        self.secret   = secret
        self.timeout  = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "x-schild-token": self.secret,
        })

    def is_alive(self) -> bool:
        """Cek apakah sidecar server bisa diakses."""
        try:
            resp = self._session.get(f"{self.base_url}/health", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def execute(self, action: str, params: dict = None) -> dict:
        """
        Kirim perintah mitigasi ke sidecar.

        Returns:
            dict dengan keys: action, success (bool), output (str), timestamp (str)
            Jika koneksi gagal: {"action": action, "success": False, "output": "<error>"}
        """
        try:
            resp = self._session.post(
                f"{self.base_url}/mitigate",
                json={"action": action, "params": params or {}},
                timeout=self.timeout,
            )
            if resp.status_code == 403:
                return {"action": action, "success": False, "output": "Auth failed — wrong secret."}
            if resp.status_code == 400:
                detail = resp.json().get("detail", "Bad request")
                return {"action": action, "success": False, "output": f"Bad request: {detail}"}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            msg = f"Cannot reach sidecar at {self.base_url} — is it running?"
            logger.error(msg)
            return {"action": action, "success": False, "output": msg}
        except requests.exceptions.Timeout:
            msg = f"Sidecar request timed out after {self.timeout}s"
            logger.error(msg)
            return {"action": action, "success": False, "output": msg}
        except Exception as e:
            msg = f"Sidecar client error: {e}"
            logger.error(msg)
            return {"action": action, "success": False, "output": msg}


class SidecarRegistry:
    """
    Mengelola kumpulan sidecar client (satu per remote host).
    Satu SCHILD instance bisa manage banyak remote host.
    """

    def __init__(self):
        self._clients: dict[str, SidecarClient] = {}

    def register(self, name: str, base_url: str, secret: str) -> SidecarClient:
        """
        Register remote host.

        Args:
            name:     Nama host, misal "dvwa", "webserver-1"
            base_url: URL sidecar, misal "http://10.0.0.5:8421"
            secret:   Shared secret

        Returns:
            SidecarClient yang sudah diregister
        """
        client = SidecarClient(base_url=base_url, secret=secret)
        self._clients[name] = client
        return client

    def get(self, name: str) -> Optional[SidecarClient]:
        return self._clients.get(name)

    def list_hosts(self) -> list[str]:
        return list(self._clients.keys())

    def ping_all(self) -> dict[str, bool]:
        """Ping semua registered sidecar — berguna untuk health check."""
        return {name: client.is_alive() for name, client in self._clients.items()}
