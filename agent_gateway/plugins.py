"""Host-installed connector manifests. Web admins select these; they cannot install commands."""
from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .config import ENV_NAME, NAME

_logger = logging.getLogger("agent_gateway")
MANIFEST_ENV = "AGW_CLI_MANIFEST"
IMAGE_PLUGINS_ENV = "AGW_IMAGE_PLUGINS_DIR"
SPEC = {"label": "Local connector / 本地连接器", "fields": ["plugin"], "secrets": [],
        "tools": [], "probe": (None, {})}


class ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Option(ManifestModel):
    flag: str = Field(pattern=r"^--[a-zA-Z][a-zA-Z0-9_-]{0,63}$")
    description: str = Field(default="", max_length=600)
    type: Literal["string", "integer", "boolean"] = "string"
    required: bool = False

    def schema(self):
        out = {"type": self.type, "description": self.description}
        if self.type == "string":
            out.update(maxLength=2048, pattern=r"^[^\x00-\x1f\x7f]*$")
        if self.type == "integer":
            out.update(minimum=-1_000_000_000, maximum=1_000_000_000)
        return out


class Action(ManifestModel):
    description: str = Field(min_length=1, max_length=1000)
    argv: list[str] = Field(default_factory=list, max_length=32)
    options: dict[str, Option] = Field(default_factory=dict, max_length=24)
    access: Literal["read", "write"] = "write"
    output: Literal["text", "json"] = "text"
    timeout_seconds: int = Field(15, ge=1, le=45)

    @model_validator(mode="after")
    def _check(self):
        if any(not re.fullmatch(NAME, key) for key in self.options):
            raise ValueError("option keys must be valid names")
        if len({option.flag for option in self.options.values()}) != len(self.options):
            raise ValueError("option flags must be unique")
        _check_argv(self.argv)
        return self


def _check_argv(argv):
    if any(len(arg) > 4096 or "\0" in arg for arg in argv):
        raise ValueError("invalid argument")


class Plugin(ManifestModel):
    version: Literal[1] = 1
    id: str = Field(pattern=NAME)
    label: str = Field(min_length=1, max_length=80)
    kind: Literal["stdio", "cli", "web"]
    command: list[str] = Field(default_factory=list, max_length=32)
    env: dict[str, str] = Field(default_factory=dict, max_length=24)
    credentials: dict[str, str] = Field(default_factory=dict, max_length=12)
    tools: dict[str, Action] = Field(default_factory=dict, max_length=40)
    socket: str | None = None  # a sidecar's Unix socket; see sidecar.py

    web: dict | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.socket is not None and (self.kind != "stdio" or not Path(self.socket).is_absolute()):
            raise ValueError("a sidecar socket needs a stdio connector and an absolute path")
        if self.kind == "web":
            from .web_profiles import WebProfile
            if self.command or self.env or self.credentials or self.tools or self.web is None:
                raise ValueError("Web profiles configure only the web field")
            WebProfile.model_validate(self.web)
            return self
        if self.web is not None or not self.command or not Path(self.command[0]).is_absolute():
            raise ValueError("command must use an absolute executable path")
        _check_argv(self.command)
        if (bool(self.tools) != (self.kind == "cli")
                or any(not re.fullmatch(NAME, key) for key in self.tools)):
            raise ValueError("declare named tools for CLI plugins only")
        if set(self.credentials) & self.env.keys() or {MANIFEST_ENV, "AGW_WEB_PROFILE", "AGW_WEB_SESSION"} & self.env.keys():
            raise ValueError("overlapping environment settings")
        for key, value in (self.env | self.credentials).items():
            if not re.fullmatch(ENV_NAME, key) or len(value) > 2048 or "\0" in value:
                raise ValueError("invalid environment field")
        for key in self.credentials:
            if (not re.fullmatch(r"(?:[A-Z0-9]+_)*(?:TOKEN|PASSWORD|SECRET|KEY|ACCESS_KEY_ID|CREDENTIAL)", key)
                    or key.startswith(("LD_", "DYLD_", "PYTHON", "GIT_CONFIG", "AGW_"))):
                raise ValueError("unsafe credential environment variable")
        return self

    def credential_slots(self):
        if self.kind == "web":
            from .web_profiles import SESSION_ENV
            return {SESSION_ENV: "Browser session JSON"}
        return self.credentials

    def connection(self):
        if self.kind == "web":
            from .web_profiles import PROFILE_ENV, WebProfile
            profile = WebProfile.model_validate(self.web)
            return [sys.executable, "-m", "agent_gateway.connectors.web"], {PROFILE_ENV: profile.model_dump_json()}
        if self.kind == "stdio":
            return self.command, self.env
        return [sys.executable, "-m", "agent_gateway.connectors.local_cli"], {**self.env, MANIFEST_ENV: self.model_dump_json()}

    def public(self):
        value = {"id": self.id, "label": self.label, "kind": self.kind, "credentials": self.credential_slots()}
        if self.kind == "web":
            value.update(origin=self.web["origin"], experimental=self.web.get("experimental", False))
        return value


def load_plugins(directory: Path | None):
    plugins = {}
    if directory is None or not directory.is_dir():
        return plugins
    for path in sorted(directory.glob("*.json"))[:100]:
        try:
            if not path.is_file():
                continue
            with path.open("rb") as file:
                spec = file.read(65537)
            if len(spec) > 65536:
                raise ValueError("manifest too large")
            plugin = Plugin.model_validate_json(spec)
            if path.stem != plugin.id:
                raise ValueError("manifest filename must match its ID")
            plugins[plugin.id] = plugin
        except (OSError, ValueError):
            _logger.warning("Invalid local connector manifest ignored")
    return plugins


def connector_plugins(directory: Path | None):
    from .web_profiles import bundled_profiles
    bundled = {key: Plugin(id=key, label=label, kind="web", web=profile.model_dump())
               for key, (label, profile) in bundled_profiles().items()}
    # An image can ship manifests for connectors it installs; the host's manifests override them by ID.
    image = os.environ.get(IMAGE_PLUGINS_ENV)
    plugins = load_plugins(Path(image) if image else None) | load_plugins(directory)
    # A sidecar connector is offered only where its sidecar is running.
    return {key: plugin for key, plugin in plugins.items()
            if plugin.socket is None or Path(plugin.socket).exists()} | bundled
