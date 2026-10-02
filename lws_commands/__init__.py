"""
LWS Commands Module (placeholder, not implemented)

The intent was to split the ~61 CLI commands in lws.py out into one file
per command group (conf, lxc, px, app, sec), the way lws_core/ already
split out config/SSH/Proxmox/utility helpers. That split was never done:
this package is empty, nothing in the project imports it, and lws.py
still defines every command directly.
"""

__all__ = []
