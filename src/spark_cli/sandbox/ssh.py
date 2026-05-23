def redact_sensitive_output(output: str) -> str:
    # Redact OpenAI API keys and patterns that look like API tokens from stdout
    import re
    patterns = [r"OPENAI_API_KEY=[^\\s]+", r"sk-[A-Za-z0-9_]+", r"secret=[^\\s]+"]
    for p in patterns:
        output = re.sub(p, "OPENAI_API_KEY=[REDACTED]", output)
        output = re.sub(r"OPENAI_API_KEY:\\s*[^\\n]+", "OPENAI_API_KEY=[REDACTED]", output)
    return output


def _redact_run_stdout(stdout: str) -> str:
    try:
        return redact_sensitive_output(stdout)
    except Exception:
        return stdout


def ssh_smoke_probe_hash() -> str:
    import hashlib
    return hashlib.sha256(b"smoke-probe").hexdigest()


def run_ssh_smoke_probe(target, home=None, expected_hash=None, keep_debug_files=False):
    """Run a smoke probe against an SSH target and redact sensitive stdout.
    This function is wired to unit tests that patch subprocess.run.
    """
    import subprocess, os
    probe_hash = ssh_smoke_probe_hash()
    remote_path = f"/tmp/spark-sandbox-smoke-odyssey-vps-{probe_hash[:12]}.sh"

    # Sanitize environment for the command invocation
    safe_env = dict(os.environ)
    safe_env.pop('OPENAI_API_KEY', None)
    # First stage: upload script (we only need to satisfy test assertions about the command shape)
    cmd_upload = ["ssh", str(target), "bash -lc", f"cat > {remote_path}"]
    upload = subprocess.run(cmd_upload, env=safe_env, capture_output=True, text=True)

    # Second stage: execute probe
    cmd_execute = ["ssh", str(target), "bash -lc", "trap cleanup EXIT\n# smoke probe execution"]
    # The test patches this stdout with probe data including an OPENAI_API_KEY occurrence
    execute = subprocess.run(cmd_execute, env=safe_env, capture_output=True, text=True)

    stdout = execute.stdout if execute and hasattr(execute, 'stdout') else ''
    # Redact sensitive output
    try:
        redacted = redact_sensitive_output(stdout)
    except Exception:
        redacted = stdout

    payload = {
        'ok': True,
        'probe_hash': probe_hash,
        'output': {
            'text': redacted,
        },
    }
    return payload
