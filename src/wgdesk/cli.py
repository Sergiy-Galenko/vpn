from __future__ import annotations

import argparse

from wgdesk.bootstrap import bootstrap


def main() -> int:
    parser = argparse.ArgumentParser(description="WGDesk CLI")
    parser.add_argument("command", choices=["profiles", "audit"])
    args = parser.parse_args()

    context = bootstrap()
    if args.command == "profiles":
        for profile in context.services.session.list_profiles():
            print(f"{profile.id} | {profile.name} | {profile.mode.value} | {profile.host or 'local'}")
        return 0
    if args.command == "audit":
        for entry in context.services.audit.recent(20):
            print(f"{entry.timestamp} | {entry.action} | {entry.result.value} | {entry.message}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
