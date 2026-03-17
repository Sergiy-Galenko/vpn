from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from wgdesk.bootstrap import bootstrap
from wgdesk.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    context = bootstrap()
    app.setApplicationName(context.config.app_name)
    app.setOrganizationName(context.config.organization_name)

    theme_path = context.config.qss_dir / "theme.qss"
    if theme_path.exists():
        app.setStyleSheet(theme_path.read_text(encoding="utf-8"))
    icon_path = context.config.assets_dir / "wireguard_control_room_logo.svg"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow(context)
    window.show()
    QTimer.singleShot(0, window.show_initial_setup_if_needed)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
