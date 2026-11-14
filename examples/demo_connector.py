"""Source-checkout entry point for the packaged, synthetic notes connector."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent_gateway.demo_connector import build_server, main  # noqa: E402,F401

if __name__ == "__main__":
    main()
