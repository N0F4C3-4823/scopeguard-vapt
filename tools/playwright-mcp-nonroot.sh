#!/bin/sh
set -eu

# The Codex MCP parent is root-owned in this WSL session. Run only the
# Playwright MCP child as the dedicated unprivileged browser user so Chromium
# can retain its normal sandbox. The working directory is intentionally outside
# /root because the browser user cannot traverse root's private home directory.
cd /tmp
exec sudo -u noface -H env HOME=/home/noface XDG_CACHE_HOME=/home/noface/.cache \
  npx --yes @playwright/mcp@latest --headless "$@"
