#!/usr/bin/env bash
# Deploy (or update) Firewall Backups on a Docker host over SSH.
#   ./deploy.sh user@your-server [remote_dir]     (default: ~/fwbackup on the server)
# First run creates <remote_dir>/.env on the server and asks for the Sophos credential
# and email settings. Later runs update the code and keep .env and data/ untouched.
set -euo pipefail

TARGET="${1:?Usage: ./deploy.sh user@host [remote_dir]}"
REMOTE_DIR="${2:-fwbackup}"   # relative paths are under the SSH user's home folder
HOST="${TARGET#*@}"
cd "$(dirname "$0")"

echo "==> Checking Docker on $TARGET"
if ! ssh "$TARGET" "docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1"; then
  echo "Docker Compose isn't available on $HOST for this user."
  echo "If Docker is installed, add the user to the docker group once:  ssh -t $TARGET 'sudo usermod -aG docker \$USER'"
  echo "then sign out and back in (or reboot) and run this script again."
  exit 1
fi
if ! ssh "$TARGET" "docker info >/dev/null 2>&1"; then
  echo "This user can't talk to Docker on $HOST (permission denied on the Docker socket)."
  echo "Fix once:  ssh -t $TARGET 'sudo usermod -aG docker \$USER'   then run this script again."
  exit 1
fi

echo "==> Copying app to $TARGET:$REMOTE_DIR"
if ! ssh "$TARGET" "mkdir -p '$REMOTE_DIR/data'" 2>/dev/null; then
  echo "    $REMOTE_DIR isn't writable by this user; creating it with sudo (you may be asked for your password)"
  ssh -t "$TARGET" "sudo mkdir -p '$REMOTE_DIR/data' && sudo chown -R \$(id -u):\$(id -g) '$REMOTE_DIR'"
fi
tar czf - --exclude='./data' --exclude='./.env' --exclude='__pycache__' --exclude='./sample_report.html' . \
  | ssh "$TARGET" "tar xzf - -C '$REMOTE_DIR'"

if ! ssh "$TARGET" "test -f '$REMOTE_DIR/.env'"; then
  echo "==> First install: creating .env on the server"
  read -rp  "Sophos Fusion API client ID: " SCID
  read -rsp "Sophos Fusion API client secret: " SCSEC; echo
  read -rp  "Web app admin password (blank = generate one): " ADMINPW
  [ -z "$ADMINPW" ] && ADMINPW="$(openssl rand -base64 18 | tr -d '/+=')" && GEN=1
  read -rp  "Report 'from' address (blank = set later): " MFROM
  SECRET="$(openssl rand -hex 32)"
  sed -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$ADMINPW|" \
      -e "s|^APP_SECRET_KEY=.*|APP_SECRET_KEY=$SECRET|" \
      -e "s|^APP_BASE_URL=.*|APP_BASE_URL=http://$HOST:8080|" \
      -e "s|^SOPHOS_CLIENT_ID=.*|SOPHOS_CLIENT_ID=$SCID|" \
      -e "s|^SOPHOS_CLIENT_SECRET=.*|SOPHOS_CLIENT_SECRET=$SCSEC|" \
      -e "s|^MAIL_FROM=.*|MAIL_FROM=$MFROM|" .env.example \
    | ssh "$TARGET" "umask 077 && cat > '$REMOTE_DIR/.env'"
  [ "${GEN:-}" = 1 ] && echo "    Generated admin password: $ADMINPW"
  echo "    Edit ~/$REMOTE_DIR/.env on the server later to add email (SMTP or Graph) settings."
fi

echo "==> Building and starting the container"
ssh "$TARGET" "cd '$REMOTE_DIR' && (docker compose up -d --build || docker-compose up -d --build)"
sleep 5
if ssh "$TARGET" "curl -fsS http://localhost:8080/healthz >/dev/null 2>&1 || wget -qO- http://localhost:8080/healthz >/dev/null 2>&1"; then
  echo "==> Running: http://$HOST:8080"
else
  echo "==> Container started, but the health check didn't answer yet. Check: ssh $TARGET 'cd $REMOTE_DIR && docker compose logs --tail 50'"
fi
