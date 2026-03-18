from __future__ import annotations

from pathlib import Path

from src.models import VPNManagerError

try:
    import qrcode
except ImportError:  # pragma: no cover - runtime dependency
    qrcode = None


def generate_qr_code(config_text: str, output_path: Path) -> Path:
    """Generate a PNG QR code for a WireGuard client configuration."""

    if qrcode is None:
        raise VPNManagerError(
            "QR export requires the 'qrcode' package. Install dependencies from requirements.txt."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(config_text)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    image.save(output_path)
    return output_path
