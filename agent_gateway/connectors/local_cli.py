"""Run a bounded CLI action from a trusted manifest, without a shell."""
import json
import os
import select
import signal
import subprocess
import time

from ..plugins import MANIFEST_ENV, Plugin
from ._base import ConnectorError, Tool, serve, setting

MAX_OUTPUT = 512 * 1024


def _run(command, env, timeout):
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        raise ConnectorError("The plugin executable could not start.", "local_cli_start_failed") from None
    output = bytearray()
    try:
        while True:
            now = time.monotonic()
            if now >= deadline or not select.select([proc.stdout], [], [], deadline - now)[0]:
                raise subprocess.TimeoutExpired(command, timeout)
            chunk = os.read(proc.stdout.fileno(), 16384)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                raise ConnectorError("The plugin exceeded its output limit.", "local_cli_output_limit")
        if proc.wait(timeout=max(0, deadline - time.monotonic())) != 0:
            raise ConnectorError("The plugin command failed.", "local_cli_failed")
    except subprocess.TimeoutExpired:
        raise ConnectorError("The plugin command timed out.", "local_cli_timeout") from None
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.stdout.close()
        proc.wait()
    return output.decode("utf-8", errors="replace")


def build_tools(plugin):
    env = {key: os.environ[key] for key in ("PATH", "LANG", *plugin.credentials) if key in os.environ}
    env.update(plugin.env)

    def execute(action, supplied):
        # A value cannot add an option, alter the command, or become shell code.
        argv = [*plugin.command, *action.argv]
        for key, option in action.options.items():
            if key in supplied:
                val = str(supplied[key]).lower() if option.type == "boolean" else str(supplied[key])
                argv.append(f"{option.flag}={val}")
        stdout = _run(argv, env, action.timeout_seconds)
        if action.output == "text":
            return stdout
        try:
            return json.loads(stdout)
        except ValueError:
            raise ConnectorError("The plugin did not return valid JSON.", "local_cli_invalid_output") from None

    return [Tool(name, action.description, lambda args, action=action: execute(action, args),
                 {key: val.schema() for key, val in action.options.items()},
                 tuple(key for key, val in action.options.items() if val.required), action.access == "read")
            for name, action in plugin.tools.items()]


def main():
    plugin = Plugin.model_validate_json(setting(MANIFEST_ENV))
    serve(plugin.id, build_tools(plugin))


if __name__ == "__main__":
    main()
