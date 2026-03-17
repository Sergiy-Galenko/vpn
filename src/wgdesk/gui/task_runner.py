from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)


@dataclass(slots=True)
class TaskSpec:
    callback: Callable[[], Any]
    on_success: Callable[[Any], None] | None = None
    on_error: Callable[[str], None] | None = None


class TaskRunnable(QRunnable):
    def __init__(self, spec: TaskSpec) -> None:
        super().__init__()
        self.spec = spec
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            result = self.spec.callback()
        except Exception as exc:  # pragma: no cover - Qt thread boundary
            self.signals.failed.emit(str(exc))
        else:
            self.signals.finished.emit(result)


class TaskRunner(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.pool = QThreadPool.globalInstance()

    def submit(self, spec: TaskSpec) -> None:
        runnable = TaskRunnable(spec)
        if spec.on_success is not None:
            runnable.signals.finished.connect(spec.on_success)
        if spec.on_error is not None:
            runnable.signals.failed.connect(spec.on_error)
        self.pool.start(runnable)
