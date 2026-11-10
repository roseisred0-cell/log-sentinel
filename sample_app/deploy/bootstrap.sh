#!/bin/bash
# Dung may chu web LogSentinel. Chay boi EC2 UserData voi INCIDENT_TABLE va AWS_REGION.
# Idempotent: chay lai khong sinh lai mat khau / TOTP da co.
set -euo pipefail
: "${INCIDENT_TABLE:?can INCIDENT_TABLE}" "${AWS_REGION:?can AWS_REGION}"

APP_DIR=/opt/logsentinel/app
DEPLOY="$APP_DIR/deploy"
ENV_DIR=/etc/logsentinel

dnf install -y nginx python3-pip amazon-cloudwatch-agent openssl

id webapp >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin webapp

python3 -m venv /opt/logsentinel/venv
/opt/logsentinel/venv/bin/pip install --quiet --upgrade pip
/opt/logsentinel/venv/bin/pip install --quiet -r "$APP_DIR/requirements.txt"

# Log ung dung: webapp ghi, CloudWatch Agent doc. Khong chua mat khau/OTP nen 0644 la du.
install -d -o webapp -g webapp -m 0755 /var/log/webapp
touch /var/log/webapp/access.log
chown webapp:webapp /var/log/webapp/access.log
chmod 0644 /var/log/webapp/access.log

# Bi mat sinh ngau nhien TAI CHO -> khong nam trong Git, CloudFormation template hay UserData.
# Lay ra bang SSM Session Manager:  sudo cat /etc/logsentinel/webapp.env
install -d -o root -g webapp -m 0750 "$ENV_DIR"
if [ ! -s "$ENV_DIR/webapp.env" ]; then
  ( umask 077
    python3 - > "$ENV_DIR/webapp.env" <<'PY'
import base64, secrets
print("APP_ADMIN_USER=admin")
print("APP_ADMIN_PASSWORD=" + secrets.token_urlsafe(18))
print("APP_TOTP_SECRET=" + base64.b32encode(secrets.token_bytes(20)).decode())
print("APP_SETUP_TOKEN=" + secrets.token_urlsafe(32))
PY
  )
fi
cat > "$ENV_DIR/runtime.env" <<RT
INCIDENT_TABLE=$INCIDENT_TABLE
AWS_DEFAULT_REGION=$AWS_REGION
TRUST_PROXY=true
APP_LOG_PATH=/var/log/webapp/access.log
RT
chown root:webapp "$ENV_DIR"/*.env
chmod 0640 "$ENV_DIR"/*.env

# TLS tu ky (demo). Production: dung ACM + ALB hoac Let's Encrypt voi domain that.
install -d -m 0755 /etc/pki/nginx
install -d -m 0700 /etc/pki/nginx/private
if [ ! -s /etc/pki/nginx/logsentinel.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=logsentinel.local" \
    -keyout /etc/pki/nginx/private/logsentinel.key -out /etc/pki/nginx/logsentinel.crt
  chmod 0600 /etc/pki/nginx/private/logsentinel.key
fi

install -m 0644 "$DEPLOY/nginx.conf" /etc/nginx/nginx.conf
nginx -t

install -m 0644 "$DEPLOY/webapp.service" /etc/systemd/system/webapp.service
systemctl daemon-reload
systemctl enable --now webapp.service
systemctl enable --now nginx
systemctl restart webapp.service nginx

install -m 0644 "$DEPLOY/cwagent.json" /opt/aws/amazon-cloudwatch-agent/etc/logsentinel.json
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/logsentinel.json

echo "[LogSentinel] bootstrap OK"
