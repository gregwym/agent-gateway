"""Run a test-only localhost service without reverse DNS for its display name.

macOS hosted runners can stall in socket.getfqdn() before HTTPServer.listen():
https://github.com/actions/runner-images/issues/14409
All services launched here bind to loopback and use synthetic accounts. Their
hostname is known; protocol handling, address resolution and TLS stay unchanged.
This wrapper is never installed or used by production connector commands.
"""

import runpy
import socket
import sys

socket.getfqdn = lambda name="": "localhost"
sys.argv = sys.argv[1:]
runpy.run_module(sys.argv[0], run_name="__main__", alter_sys=True)
