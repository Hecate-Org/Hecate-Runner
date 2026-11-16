"""Exercise outbox startup against a real unprivileged Linux syscall filter."""

import ctypes.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp contract")
def test_outboxes_initialize_when_privileged_mode_syscalls_are_denied(tmp_path):
    library = ctypes.util.find_library("seccomp")
    if not library:
        pytest.skip("libseccomp is unavailable")
    workspace = tmp_path / "shared"
    workspace.mkdir()
    workspace.chmod(0o2770)
    program = r"""
import ctypes, json, os, stat, sys
from pathlib import Path
from hecate_runner import private_data
from hecate_runner.config import Settings
from hecate_runner.github_publisher import PromotionOutbox
from hecate_runner.misp_publisher import _connect

class Comparison(ctypes.Structure):
    _fields_ = [('arg',ctypes.c_uint32),('op',ctypes.c_int),('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
lib=ctypes.CDLL(sys.argv[1],use_errno=True)
lib.seccomp_init.argtypes=[ctypes.c_uint32]; lib.seccomp_init.restype=ctypes.c_void_p
lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]; lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Comparison)]
lib.seccomp_load.argtypes=[ctypes.c_void_p]
lib.seccomp_release.argtypes=[ctypes.c_void_p]; lib.seccomp_release.restype=None
context=lib.seccomp_init(0x7fff0000)  # allow ordinary operations
assert context
try:
    for name,index in [('mkdir',1),('mkdirat',2),('chmod',1),('fchmod',1),('fchmodat',2),('fchmodat2',2)]:
        number=lib.seccomp_syscall_resolve_name(name.encode())
        if number<0:
            continue
        for bit in (0o2000,0o4000):
            comparison=Comparison(index,7,bit,bit)  # masked equality
            assert lib.seccomp_rule_add_array(context,0x00050001,number,1,ctypes.byref(comparison))==0
    assert lib.seccomp_load(context)==0
finally:
    lib.seccomp_release(context)

workspace=Path(sys.argv[2])
try:
    (workspace/'forbidden-control').mkdir(mode=0o2770)
except PermissionError:
    pass
else:
    raise AssertionError('control did not activate the syscall filter')
os.umask(0o007)
private_data._shared_gid=os.getgid
github=workspace/'.hecate/publisher/promotion-outbox.sqlite3'
assert PromotionOutbox(github).summary()==[]
assert PromotionOutbox(github).summary()==[]  # already-existing directory
with _connect(Settings(hecate_workspace=workspace)) as database:
    assert database.execute('SELECT count(*) FROM exports').fetchone()[0]==0
assert stat.S_IMODE(github.parent.stat().st_mode)==0o2770
assert stat.S_IMODE(github.stat().st_mode)==0o660
print(json.dumps({'filter_control':True,'new_and_existing_outboxes':True}))
"""
    result = subprocess.run(
        [sys.executable, "-c", program, library, str(workspace)],
        env={
            "PATH": os.defpath,
            "HOME": str(tmp_path),
            "HECATE_SERVICE_ISOLATED": "1",
            "PYTHON_DOTENV_DISABLED": "1",
            "LITELLM_LOCAL_MODEL_COST_MAP": "true",
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"filter_control": true' in result.stdout
