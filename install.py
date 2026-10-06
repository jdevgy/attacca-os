#!/usr/bin/env python3
"""Install this local Attacca source using the universal client installer.

The archive comes from this checkout, never from the configured server.  Keep
the actual native-plugin/configuration work in one installer implementation.
"""

import argparse
from email.message import Message
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit

import attacca


def server_origin(value):
    """Apply the hosted installer's shell-safe origin validation locally."""
    if not value or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127
                        for ch in value):
        raise ValueError("server URL must be an HTTP(S) origin without spaces")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc \
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment \
            or parsed.username is not None or parsed.password is not None:
        raise ValueError("server URL must be an HTTP(S) origin, without a path or credentials")
    headers = Message()
    headers["Host"] = parsed.netloc
    headers["X-Forwarded-Proto"] = parsed.scheme
    try:
        return attacca._distribution_base_url(SimpleNamespace(
            headers=headers, request_version="HTTP/1.1"))
    except attacca.AttaccaError as error:
        raise ValueError(str(error)) from None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Install this local Attacca checkout into detected coding tools (no curl or download).")
    parser.add_argument("--url", default=None,
                        help="Attacca server origin (default: http://127.0.0.1:4173; "
                             "--runtime-only preserves an existing machine origin)")
    parser.add_argument("--runtime-only", action="store_true",
                        help="install the stable runtime and CLI for native marketplaces, "
                             "without registering coding tools or restarting the watcher")
    args = parser.parse_args(argv)
    try:
        if args.runtime_only:
            # Validate before replacing runtime bytes. The shell re-reads the
            # config under its normal lock before the single origin update.
            attacca._read_machine_config()
        base_url = server_origin(args.url if args.url is not None else
                                 (attacca.configured_server_url()
                                  if args.runtime_only else "http://127.0.0.1:4173"))
    except (ValueError, attacca.AttaccaError) as error:
        parser.error(str(error))
    shell = shutil.which("sh")
    if not shell:
        parser.error("a POSIX shell (sh) is required; use Linux, macOS, or WSL")
    try:
        snapshot = attacca._capture_distribution_snapshot()
        archive = attacca.build_plugin_zip(
            base_url, source_snapshot=snapshot["plugin_sources"],
            plugin_files=snapshot["plugin_files"],
            mcp_config_files=snapshot["plugin_mcp_config_files"],
            zip_date_time=snapshot["plugin_zip_date_time"])
        script = snapshot["install_template"].format(
            base=base_url, version=snapshot["version"],
            required_files=repr(list(snapshot["plugin_files"])))
        # Use a neutral cwd: native installers reconcile the current checkout's
        # old MCP registration, which must not alter the source repository.
        with tempfile.TemporaryDirectory(prefix="attacca-local-install-") as directory:
            payload = Path(directory) / "plugin.zip"
            payload.write_bytes(archive)
            env = os.environ.copy()
            env["ATTACCA_INSTALL_ARCHIVE"] = str(payload)
            # This mode is an explicit command-line choice, never inherited
            # accidentally by a later ordinary installation.
            env.pop("ATTACCA_INSTALL_RUNTIME_ONLY", None)
            if args.runtime_only:
                env["ATTACCA_INSTALL_RUNTIME_ONLY"] = "1"
            print("Installing local Attacca %s; clients will connect to %s" %
                  (snapshot["version"], base_url), flush=True)
            result = subprocess.run([shell], input=script, text=True,
                                    cwd=directory, env=env)
            return result.returncode
    except (attacca.AttaccaError, OSError, ValueError) as error:
        print("Attacca installation failed: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
