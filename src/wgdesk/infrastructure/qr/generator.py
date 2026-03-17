from __future__ import annotations

from pathlib import Path

from wgdesk.application.errors import WGDeskError

try:
    import qrcode
except ImportError:  # pragma: no cover - runtime dependency
    qrcode = None


class QRCodeGenerator:
    def __init__(self, export_dir: Path) -> None:
        self.export_dir = export_dir
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def generate_png(self, client_id: str, config_text: str) -> Path:
        if qrcode is None:
            raise WGDeskError("qrcode is not installed")

        image = qrcode.make(config_text)
        output_path = self.export_dir / f"{client_id}.png"
        image.save(output_path)
        output_path.chmod(0o600)
        return output_path

