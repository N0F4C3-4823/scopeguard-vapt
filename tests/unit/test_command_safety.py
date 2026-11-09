import sys
from pathlib import Path

import pytest

from app.commands import CommandRejected, run_command


def test_command_runner_rejects_shell_injection_and_preserves_argv(tmp_path):
    with pytest.raises(CommandRejected):
        run_command(["sh", "-c", "echo unsafe"], timeout_seconds=1, cwd=tmp_path)
    result = run_command([sys.executable, "-c", "print('safe')"], timeout_seconds=1, cwd=Path.cwd())
    assert result.exit_code == 0
    assert result.stdout == b"safe\n"
    assert result.argv[-1] == "print('safe')"
