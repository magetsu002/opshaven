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

install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /bootstrap/admin.pub /home/admin/.ssh/authorized_keys
git config --system --add safe.directory '*'
create_application_fixture sample-api 3000
create_application_fixture sample-worker 3001
exec /usr/sbin/sshd -D -e
