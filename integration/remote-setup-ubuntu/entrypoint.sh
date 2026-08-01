#!/bin/sh
set -eu

create_application_fixture() {
  name="$1"
  port="$2"
  base="/srv/opshaven-fixtures/$name"
  repository="$base/repository"
  releases="$base/releases"
  install -d -m 755 "$repository" "$releases"
  git -C "$repository" init -q -b main
  git -C "$repository" config user.name "OpsHaven Synthetic Fixture"
  git -C "$repository" config user.email "fixture@example.invalid"
  cat > "$repository/package.json" <<EOF
{"name":"$name","version":"1.0.0","private":true,"scripts":{"build":"node -e \"require('node:fs').writeFileSync('build.txt','built\\n')\""}}
EOF
  cat > "$repository/package-lock.json" <<EOF
{"name":"$name","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"$name","version":"1.0.0"}}}
EOF
  printf '%s\n' "current $name" > "$repository/REVISION.txt"
  git -C "$repository" add package.json package-lock.json REVISION.txt
  git -C "$repository" commit -q -m "OpsHaven fixture current"
  current="$(git -C "$repository" rev-parse HEAD)"
  git clone -q "$repository" "$releases/current-$current"
  ln -s "$releases/current-$current" "$base/current"
  printf '%s\n' "healthy $name" > "$repository/REVISION.txt"
  git -C "$repository" add REVISION.txt
  git -C "$repository" commit -q -m "OpsHaven fixture healthy"
  git -C "$repository" update-ref refs/remotes/origin/main HEAD
  node /opt/opshaven-fixtures/fixture-health.mjs "$port" "$name" >/tmp/"$name"-health.log 2>&1 &
}

provision_restricted_fixture_ownership() {
  attempts=0
  while ! id opshaven >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 1200 ]; then
      printf '%s\n' "restricted fixture account was not created" >&2
      return 1
    fi
    sleep 0.1
  done
  chown -R opshaven:opshaven /srv/opshaven-fixtures
  install -m 600 -o opshaven -g opshaven /dev/null /run/opshaven-fixtures-owned
}

install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /bootstrap/admin.pub /home/admin/.ssh/authorized_keys
git config --system --add safe.directory '*'
create_application_fixture sample-api 3000
create_application_fixture sample-worker 3001
provision_restricted_fixture_ownership &
exec /usr/sbin/sshd -D -e
