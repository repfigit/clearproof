"""Local commands accept bounded regular files without following symlinks."""

import os

import pytest

from src.protocol.file_input import read_bounded


@pytest.mark.parametrize("size", [0, 9, 10, 11])
def test_regular_file_exact_byte_limit(tmp_path, size):
    path = tmp_path / "synthetic-input"
    content = b"x" * size
    path.write_bytes(content)
    if size <= 10:
        assert read_bounded(path, 10) == content
    else:
        with pytest.raises(ValueError, match="^Input size limit$"):
            read_bounded(path, 10)
    assert path.read_bytes() == content


def test_fifo_is_rejected_without_waiting_for_writer(tmp_path):
    path = tmp_path / "synthetic-pipe"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="^Expected a regular input file$"):
        read_bounded(path, 10)


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "synthetic-target"
    target.write_bytes(b"synthetic-private-bytes")
    link = tmp_path / "synthetic-link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        read_bounded(link, 100)
    assert target.read_bytes() == b"synthetic-private-bytes"


def test_missing_file_fails_without_creation(tmp_path):
    path = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        read_bounded(path, 10)
    assert not path.exists()
