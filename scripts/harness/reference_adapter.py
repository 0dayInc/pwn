"""Optional external Python agent API boundary, never used by offline runs.

PWN-owned evaluation and supervision remain Ruby. This file uses Python solely
because the pinned reference exposes a Python API. No CLI flags are invented.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def locked(path):
    path = Path(path)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != Path(str(path) + ".sha256").read_text().strip():
        raise ValueError(f"lock mismatch: {path}")
    return json.loads(raw)


def inspect_source(source, metadata):
    source = Path(source).resolve(strict=True)
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != metadata["reference_revision"]:
        raise ValueError("reference revision mismatch")
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True).strip():
        raise ValueError("reference tracked source is dirty")
    for relative, expected in metadata["inspected_reference_sources"].items():
        if hashlib.sha256((source / relative).read_bytes()).hexdigest() != expected:
            raise ValueError(f"reference source drift: {relative}")
    tree = ast.parse((source / "run_agent.py").read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AIAgent")
    init = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    fields = {arg.arg for arg in init.args.args + init.args.kwonlyargs}
    if not set(metadata["reference_agent"]["constructor_fields"]).issubset(fields):
        raise ValueError("reference constructor API drift")
    facade = ast.parse((source / "agent/turn_facade.py").read_text())
    run = next(node for node in ast.walk(facade) if isinstance(node, ast.FunctionDef) and node.name == "run_conversation")
    if not {"user_message", "conversation_history"}.issubset({arg.arg for arg in run.args.args}):
        raise ValueError("reference invocation API drift")
    return source, sorted(fields - {"self"})


def parity(manifest):
    fields = ("provider", "model", "revision", "endpoint", "reasoning", "temperature",
              "max_iterations", "max_tokens", "wall_seconds", "tool_capabilities", "network")
    left, right = manifest["pwn"], manifest["reference"]
    for key in fields:
        for config in (left, right):
            value = config.get(key)
            if value is None or str(value).strip().lower() in ("", "unknown", "unselected", "latest"):
                raise ValueError(f"unknown comparison field: {key}")
        if left[key] != right[key]:
            raise ValueError(f"comparison mismatch: {key}")
    if not manifest.get("parity_reviewed") or not manifest.get("provider_hard_cost_cap_confirmed"):
        raise ValueError("tool/sandbox parity and provider hard cost cap require explicit review")
    if not isinstance(manifest.get("approved_cost_usd"), (int, float)) or manifest["approved_cost_usd"] <= 0:
        raise ValueError("positive approved cost budget required")
    for key in ("max_iterations", "max_tokens", "wall_seconds"):
        if not isinstance(right[key], (int, float)) or right[key] <= 0:
            raise ValueError(f"positive budget required: {key}")
    return right


def constructor(config, cwd, api_key):
    return dict(base_url=config["endpoint"], api_key=api_key,
                provider=config["provider"], requested_provider=config["provider"],
                api_mode=config["api_mode"], model=config["model"],
                max_iterations=config["max_iterations"], enabled_toolsets=config["toolsets"],
                max_tokens=config["max_tokens"], reasoning_config=config["reasoning"],
                request_overrides={"temperature": config["temperature"]},
                run_budget_seconds=config["wall_seconds"], cwd=str(cwd),
                skip_context_files=True, load_soul_identity=False, skip_memory=True,
                skip_background_review=True, save_trajectories=False, quiet_mode=True,
                fallback_model=None, checkpoints_enabled=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--approve-live", action="store_true")
    parser.add_argument("--inspect-source")
    parser.add_argument("--source")
    parser.add_argument("--manifest")
    parser.add_argument("--prompt-file")
    parser.add_argument("--output")
    args = parser.parse_args()
    if not args.approve_live and not args.inspect_source:
        parser.error("explicit --approve-live required; no agent imported or credentials read")
    metadata = locked(Path(__file__).with_name("adapters.json"))
    source, fields = inspect_source(args.inspect_source or args.source, metadata)
    if args.inspect_source:
        print(json.dumps({"status": "STATIC_API_VERIFIED", "model_quality": "NOT_RUN", "constructor_fields": fields}))
        return
    config = parity(locked(args.manifest))
    home, cwd = Path.home().resolve(), Path.cwd().resolve()
    if not str(home).startswith("/tmp/") or not str(cwd).startswith("/tmp/"):
        raise ValueError("isolated temporary HOME and task cwd required")
    private_home = home / "reference-state"
    private_home.mkdir(mode=0o700, exist_ok=False)
    os.environ["HERMES_HOME"] = str(private_home)
    api_key = os.environ.pop("PWN_EVAL_API_KEY", None)
    if not api_key:
        raise ValueError("explicit PWN_EVAL_API_KEY required; no credential discovery permitted")
    if (source / ".env").exists():
        raise ValueError("reference checkout .env is not permitted; use a credential-free source copy")
    path = os.environ.get("PATH", "/usr/bin:/bin")
    os.environ.clear()
    os.environ.update(HOME=str(home), HERMES_HOME=str(private_home), PATH=path,
                      LANG="C.UTF-8", TERMINAL_ENV="local")
    kwargs = constructor(config, cwd, api_key)
    if not set(kwargs).issubset(fields):
        raise ValueError("unsupported constructor options")
    sys.path.insert(0, str(source))
    from run_agent import AIAgent

    agent = AIAgent(**kwargs)
    response = agent.run_conversation(user_message=Path(args.prompt_file).read_text(), conversation_history=[])
    Path(args.output).write_text(json.dumps({"outcome": "UNVERIFIED", "response": response,
                                           "tokens": None, "cost": None,
                                           "note": "Raw response retained. Host artifact checker must grade; unobserved aggregate usage remains unknown."}, default=str))


if __name__ == "__main__":
    main()
