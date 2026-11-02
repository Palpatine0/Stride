"""Save the Cloudflare Docker command's token from the Mac clipboard, then deploy."""
import os
from pathlib import Path
import re
import shlex
import subprocess

root = Path(__file__).resolve().parents[1]
command = subprocess.check_output(['pbpaste'], text=True)
parts = shlex.split(command)
try:
    token = parts[parts.index('--token') + 1]
except (ValueError, IndexError):
    raise SystemExit('Copy the Docker command from the Stride tunnel setup page first.')
if not re.fullmatch(r'[A-Za-z0-9_+/=-]{80,}', token):
    raise SystemExit('Clipboard does not contain a valid unmasked tunnel token.')
directory = root / 'data'
directory.mkdir(mode=0o700, exist_ok=True)
os.chmod(directory, 0o700)
path = directory / 'cloudflare-token'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(token)
# The private parent directory protects host access; the nonroot connector
# needs to read this single file after Compose bind-mounts it as a secret.
os.chmod(path, 0o644)
print('Tunnel token saved locally. Starting Stride containers...')
subprocess.run(['bash', 'deploy/start-production.sh'], cwd=root, check=True)
