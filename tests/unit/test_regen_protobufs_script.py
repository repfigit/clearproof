"""Acceptance tests for the real Bash regeneration/check workflow in private copies."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ["trisa_api_pb2.py", "trisa_api_pb2_grpc.py", "trisa_errors_pb2.py", "trisa_errors_pb2_grpc.py"]


@pytest.fixture
def proto_tree(tmp_path):
    root = tmp_path / "project"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/regen_protobufs.sh", root / "scripts/regen_protobufs.sh")
    shutil.copytree(ROOT / "protos", root / "protos")
    output = root / "src/protocol/bridges"
    output.mkdir(parents=True)
    for name in FILES:
        shutil.copyfile(ROOT / "src/protocol/bridges" / name, output / name)
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    env = {**os.environ, "TMPDIR": str(temporary)}

    def run(check=False):
        result = subprocess.run(
            ["bash", str(root / "scripts/regen_protobufs.sh"), *(["--check"] if check else [])],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=90,
        )
        assert list(temporary.iterdir()) == [], "generation must clean temporary output even on failure"
        return result

    return root, output, env, run


def snapshot(output):
    return {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in output.iterdir()}


def test_real_protobuf_write_and_check_reproduce_all_committed_stubs(proto_tree):
    _, output, _, run = proto_tree
    expected = {name: (output / name).read_bytes() for name in FILES}
    for path in output.iterdir():
        path.unlink()
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count(">> wrote ") == 4
    assert {name: (output / name).read_bytes() for name in FILES} == expected
    before = snapshot(output)
    result = run(check=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "in sync with protos/" in result.stdout
    assert snapshot(output) == before


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("missing", [False, True])
def test_real_protobuf_check_detects_each_stale_or_missing_file_without_writing(proto_tree, name, missing):
    _, output, _, run = proto_tree
    if missing:
        (output / name).unlink()
    else:
        (output / name).write_text("# synthetic stale sentinel\n")
    before = snapshot(output)
    result = run(check=True)
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"::error file=src/protocol/bridges/{name}::" in result.stdout
    assert result.stdout.count("::error file=") == 1
    assert snapshot(output) == before


def install_compiler_fixture(root, env, *, warnings=True, remove=None, code=0):
    """Model compiler-format changes without touching repository-generated files."""
    stub = (
        "import grpc\n" + ("import warnings\n" if warnings else "")
        + "import trisa_api_pb2 as trisa__api__pb2\n"
        + "if True:\n    raise RuntimeError(\n"
        + "        'version mismatch'\n"
        + "        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'\n    )\n"
    )
    files = {
        "trisa_api_pb2.py": "import trisa_errors_pb2 as trisa__errors__pb2\n",
        "trisa_api_pb2_grpc.py": stub,
        "trisa_errors_pb2.py": "# synthetic errors fixture\n",
        "trisa_errors_pb2_grpc.py": "# synthetic errors grpc fixture\n",
    }
    if remove:
        for name in files:
            files[name] = files[name].replace(remove, "# changed compiler output\n")
    commands = root / "bin"
    commands.mkdir()
    compiler = commands / "uv"
    compiler.write_text(
        f"#!{sys.executable}\nimport pathlib, sys\n"
        "assert sys.argv[1:9] == ['run', '--quiet', '--with', 'grpcio-tools==1.80.0', "
        "'python', '-m', 'grpc_tools.protoc', '-Iprotos']\n"
        "assert sys.argv[-2:] == ['protos/trisa_api.proto', 'protos/trisa_errors.proto']\n"
        f"if {code}: sys.exit({code})\n"
        "out = pathlib.Path(next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--python_out=')))\n"
        f"for name, contents in {files!r}.items(): (out / name).write_text(contents)\n"
    )
    compiler.chmod(0o755)
    env["PATH"] = f"{commands}:{env['PATH']}"


@pytest.mark.parametrize("warnings", [False, True])
def test_postprocessing_handles_compilers_with_or_without_warnings_import(proto_tree, warnings):
    root, output, env, run = proto_tree
    install_compiler_fixture(root, env, warnings=warnings)
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / FILES[0]).read_text().startswith("from . import trisa_errors_pb2 as")
    grpc = (output / FILES[1]).read_text()
    assert "from . import trisa_api_pb2 as" in grpc
    assert grpc.count("import warnings\n") == 1
    assert "raise RuntimeError" not in grpc
    assert "warnings.warn(" in grpc
    assert "RuntimeWarning," in grpc
    assert "stacklevel=2," in grpc


@pytest.mark.parametrize("pattern", [
    "import trisa_errors_pb2 as", "import trisa_api_pb2 as", "import grpc\n",
    "    raise RuntimeError(\n",
    "        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'\n    )\n",
])
def test_postprocessing_rejects_changed_compiler_format_without_publishing(proto_tree, pattern):
    root, output, env, run = proto_tree
    install_compiler_fixture(root, env, warnings=False, remove=pattern)
    before = snapshot(output)
    result = run()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "post-process failed: pattern not found" in result.stderr
    assert snapshot(output) == before


def test_compiler_failure_preserves_existing_stubs_and_exit_code(proto_tree):
    root, output, env, run = proto_tree
    install_compiler_fixture(root, env, code=9)
    before = snapshot(output)
    result = run()
    assert result.returncode == 9
    assert "Post-processing" not in result.stdout
    assert snapshot(output) == before
