"""Engine interfaces: thin wrappers over `pqc_scanner.core`.

Each interface (CLI, MCP, skill, hosted service) is another face of the same
engine and must NOT contain its own detection logic: it only calls `scan()` and
presents the result.
"""
