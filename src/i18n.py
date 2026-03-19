from __future__ import annotations

DEFAULT_LANGUAGE = "uk"
SUPPORTED_LANGUAGES = ("uk", "en")
LANGUAGE_LABELS = {
    "uk": "Українська",
    "en": "English",
}


def normalize_language(value: str | None) -> str:
    """Normalize arbitrary language input to a supported UI language."""

    normalized = (value or "").strip().lower()
    if normalized in {"ua", "ukr", "ukrainian", "українська"}:
        return "uk"
    if normalized in {"en", "eng", "english"}:
        return "en"
    return DEFAULT_LANGUAGE


def translate(language: str, en: str, uk: str) -> str:
    """Return the localized version of a string."""

    return en if normalize_language(language) == "en" else uk
