"""Outputs: outbound adapters that serialize `Finding`s to external formats.

Currently the CycloneDX CBOM (``cbom``). The colored terminal summary lives with
the CLI in ``interfaces`` because it is presentation, not a reusable artifact.
Outputs depend inward on the domain only.
"""
