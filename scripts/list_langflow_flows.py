from __future__ import annotations

import json

from guardian.clients.langflow import LangflowClient
from guardian.config import AppSettings, load_run_config


def main() -> None:
    settings = AppSettings()
    config = load_run_config(settings.config_path)
    client = LangflowClient(settings, config.execution)
    try:
        print(json.dumps(client.list_flows(), ensure_ascii=False, indent=2))
    finally:
        client.close()


if __name__ == "__main__":
    main()
