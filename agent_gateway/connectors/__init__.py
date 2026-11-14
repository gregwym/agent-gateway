"""Connectors that ship with the gateway: small MCP servers, one process per account.

The gateway starts each one as a stdio child (`python -m agent_gateway.connectors.<name>`)
and hands it that account's credential in environment variables. No tool takes an
account, user or credential argument, and no tool sends a write to the service.

What a credential could do if misused is a property of the service, not of these
modules: see "只读的真实含义" in docs/design.md.
"""
