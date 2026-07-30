#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ ! -f "$1" ]; then
  echo "Usage: scripts/install-dispatcher.sh /absolute/path/dispatcher.config.json logical-host-id" >&2
  exit 2
fi
case "$1" in
  /*) config_source="$1" ;;
  *) echo "Configuration path must be absolute" >&2; exit 2 ;;
esac
host_id="$2"
case "$host_id" in
  [a-z]*[!a-z0-9_-]*|[!a-z]*|*[!a-z0-9_-]*)
    echo "Host ID must be a configured logical ID" >&2
    exit 2
    ;;
  *) ;;
esac
[ "${#host_id}" -ge 2 ] && [ "${#host_id}" -le 64 ] || {
  echo "Host ID must be 2 to 64 characters" >&2
  exit 2
}

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
[ -d "$root/dist" ] || { echo "Run npm run build first" >&2; exit 1; }
node "$root/dist/cli.js" config validate --config "$config_source" >/dev/null
(cd "$root" && node --input-type=module - "$config_source" "$host_id") <<'NODE'
import { loadConfig } from "./dist/config/load.js";
const [, , configPath, hostId] = process.argv;
const config = await loadConfig(configPath);
if (!config.hosts.some((host) => host.id === hostId)) {
  process.stderr.write("Host ID is not present in the dispatcher configuration\n");
  process.exit(2);
}
NODE

install -d -o root -g root -m 0755 /opt/opshaven
rm -rf /opt/opshaven/dist.new
cp -R "$root/dist" /opt/opshaven/dist.new
chown -R root:root /opt/opshaven/dist.new
find /opt/opshaven/dist.new -type d -exec chmod 0755 {} \;
find /opt/opshaven/dist.new -type f -exec chmod 0644 {} \;
rm -rf /opt/opshaven/dist
mv /opt/opshaven/dist.new /opt/opshaven/dist

install -d -o root -g opshaven -m 0750 /etc/opshaven
install -o root -g opshaven -m 0640 "$config_source" /etc/opshaven/dispatcher.json
{
  printf '%s\n' '#!/bin/sh' 'set -eu'
  printf "export OPSHAVEN_HOST_ID='%s'\n" "$host_id"
  printf '%s\n' \
    'export OPSHAVEN_DISPATCH_CONFIG=/etc/opshaven/dispatcher.json' \
    'exec /usr/bin/env node /opt/opshaven/dist/dispatcher/cli.js'
} > /usr/local/bin/opshaven-dispatch
chmod 0755 /usr/local/bin/opshaven-dispatch
chown root:root /usr/local/bin/opshaven-dispatch

echo "Dispatcher installed for logical host ID: $host_id"
echo "Install and validate the forced-command SSH configuration before enabling access."
