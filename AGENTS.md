# Repository Guidelines

## Project Structure & Module Organization
The repository is intentionally compact: `scripts/xray_onekey.sh` contains the Bash installer that provisions the Xray VLESS Reality + SOCKS5 stack, `Makefile` wraps the same actions for convenience, and `README.md` offers operator-facing instructions. Runtime artifacts are generated on the target host under `/etc/xray/` (configuration, identity env file) and `/var/log/xray/` (logs); mock these paths or bind-mount them when validating changes locally.

## Build, Test, and Development Commands
Use the Makefile targets when iterating with sudo:
```bash
make install   # run ./scripts/xray_onekey.sh install
make status    # inspect container state and listeners
make uninstall # remove the docker container, keep configs
```
During development run `shellcheck scripts/xray_onekey.sh` and `bash -n scripts/xray_onekey.sh` for linting and syntax checks. For dry runs on non-root shells, combine `SKIP_ROOT_CHECK=1` with a container or VM snapshot before exercising `./scripts/xray_onekey.sh status`.

## Coding Style & Naming Conventions
Keep Bash files POSIX-compatible where feasible, but rely on Bash features intentionally. Retain `set -euo pipefail`, two-space indentation, and local variables declared with `local` inside functions. Continue the existing naming scheme: lowercase snake_case for functions, uppercase for exported or overridable environment variables (`CONFIG_DIR`, `XRAY_IMAGE`). Guard `shellcheck disable` directives with inline comments that justify the exception, and prefer the existing `info/warn/error` helpers for user-facing logs.

## Testing Guidelines
Before opening a PR, lint and syntax-check the script, then validate the deployment path on a disposable Rocky Linux 9 VM (preferred) or Debian/Ubuntu snapshot. Exercise the full lifecycle: `sudo ./scripts/xray_onekey.sh install`, `status`, and `uninstall`. Capture `sudo docker logs --tail=80 xray-reality` and `ss -ltnp | egrep ':(8443|1080)\b'` output to confirm listeners. If you change connection defaults, verify the generated `/etc/xray/config.json` and backup rotation behaviour.

## Commit & Pull Request Guidelines
This branch has no historical commits yet; adopt Conventional Commit prefixes (for example `feat: add debian firewall hint`) and write messages in the imperative mood. Open PRs with a short summary, environment matrix (OS, Docker version), and evidence of lint/test runs. Link related issues or deployments, and exclude secrets—`reality.env`, private keys, and UUIDs must stay off the repo even in logs or screenshots.

## Security & Configuration Tips
Never commit credentials or sample keys; rely on `.gitignore` to keep `reality.env` out of version control and redact secrets from shared logs. When proposing new defaults, document the security impact in the PR and ensure firewall guidance stays current for Rocky, Ubuntu, and Debian targets.
