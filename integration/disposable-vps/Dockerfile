FROM node:22-bookworm AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY types ./types
COPY src ./src
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build

FROM node:22-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssh-server git procps ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --shell /bin/bash opshaven \
  && install -d -m 700 -o opshaven -g opshaven /home/opshaven/.ssh \
  && install -d -m 755 /run/sshd /etc/opshaven /opt/opshaven/dist/src \
  && install -d -m 700 -o opshaven -g opshaven /var/lib/opshaven/remote-used
COPY --from=build /src/dist/src /opt/opshaven/dist/src
COPY integration/disposable-vps/remote.config.json /etc/opshaven/config.json
COPY integration/disposable-vps/entrypoint.sh /usr/local/bin/opshaven-entrypoint
RUN printf '%s\n' '#!/bin/sh' 'exec node /opt/opshaven/dist/src/remote/dispatcher.js "$@"' > /usr/local/bin/opshaven-dispatcher \
  && chmod 755 /usr/local/bin/opshaven-dispatcher /usr/local/bin/opshaven-entrypoint \
  && printf '%s\n' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'PermitRootLogin no' \
    'AllowUsers opshaven' \
    'X11Forwarding no' \
    'AllowTcpForwarding no' \
    'PermitTunnel no' \
    'GatewayPorts no' \
    'ClientAliveInterval 30' \
    'Match User opshaven' \
    '  ForceCommand /usr/local/bin/opshaven-dispatcher --config /etc/opshaven/config.json' \
    '  DisableForwarding yes' \
    '  PermitTTY no' \
    >> /etc/ssh/sshd_config
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/opshaven-entrypoint"]
