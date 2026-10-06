"""Load an operator-owned proving target factory for API and separate workers."""

import importlib
import inspect
import os
import re

from src.services.proof_jobs import ProvingTarget
from src.storage.pilot import _identifier


async def load_proving_targets(db, cipher):
    """The environment is operator configuration; request data never reaches imports.

    The callable accepts (Database, RecordCipher) and returns an immutable-record
    target mapping, optionally asynchronously. It must independently pin keys,
    artifacts and runtime; local-development self-pins are not production trust.
    """
    factory = os.getenv("PILOT_PROVING_FACTORY", "")
    if not factory:
        return {}
    if db is None or not re.fullmatch(r"[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*:[a-zA-Z_]\w*", factory):
        raise RuntimeError("Invalid operator proving factory configuration")
    try:
        module, name = factory.split(":")
        targets = getattr(importlib.import_module(module), name)(db, cipher)
        if inspect.isawaitable(targets):
            targets = await targets
        if type(targets) is not dict or not 1 <= len(targets) <= 256:
            raise ValueError("mapping")
        for key, target in targets.items():
            if type(key) is not tuple or len(key) != 2 or not isinstance(target, ProvingTarget):
                raise ValueError("target")
            for part in key:
                _identifier(part)
            if target.configuration.context.tenant_id != key[0] or target.configuration.transfer.tenant_id != key[0]:
                raise ValueError("scope")
            target.prover.verifier.artifacts.check_artifact_context(target.configuration.context)
            if target.sanctions.root != target.configuration.sanctions.snapshot.root:
                raise ValueError("sanctions")
        return targets
    except Exception:
        raise RuntimeError("Operator proving configuration could not be loaded") from None
