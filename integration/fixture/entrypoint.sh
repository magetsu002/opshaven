#!/bin/sh
set -eu

: "${OPSHAVEN_AUTHORIZED_KEY:?OPSHAVEN_AUTHORIZED_KEY is required}"
printf 'restrict,command="/usr/local/bin/opshaven-dispatch" %s opshaven-integration\n' "$OPSHAVEN_AUTHORIZED_KEY" \
  > /var/lib/opshaven/.ssh/authorized_keys
chown opshaven:nogroup /var/lib/opshaven/.ssh/authorized_keys
chmod 0600 /var/lib/opshaven/.ssh/authorized_keys

printf 'NODE_ENV=integration\nSECRET_TOKEN=PLANTED-SECRET-MUST-NOT-CROSS-SSH\n' > /etc/opshaven/fixture.env
chown root:nogroup /etc/opshaven/fixture.env
chmod 0640 /etc/opshaven/fixture.env

mkdir -p /srv/opshaven-fixture/repository /srv/opshaven-fixture/releases /var/lib/opshaven/approvals
if [ ! -d /srv/opshaven-fixture/repository/.git ]; then
  git -C /srv/opshaven-fixture/repository init --initial-branch=main >/dev/null
  git -C /srv/opshaven-fixture/repository config user.name "OpsHaven Fixture"
  git -C /srv/opshaven-fixture/repository config user.email "fixture@example.invalid"
  printf 'generic fixture\n' > /srv/opshaven-fixture/repository/README.txt
  git -C /srv/opshaven-fixture/repository add README.txt
  git -C /srv/opshaven-fixture/repository commit -m "fixture: initialize" >/dev/null
fi
commit="$(git -C /srv/opshaven-fixture/repository rev-parse HEAD)"
mkdir -p "/srv/opshaven-fixture/releases/$commit"
ln -sfn "/srv/opshaven-fixture/releases/$commit" /srv/opshaven-fixture/current
chown -R opshaven:nogroup /srv/opshaven-fixture /var/lib/opshaven

ssh-keygen -A >/dev/null
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
