FROM node:22-bookworm-slim AS node

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=node /usr/local /usr/local
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-server openssl python3 sudo util-linux procps \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --shell /bin/bash admin \
  && passwd -d admin \
  && install -d -m 700 -o admin -g admin /home/admin/.ssh \
  && printf '%s\n' 'admin ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/opshaven-integration-admin \
  && chmod 440 /etc/sudoers.d/opshaven-integration-admin \
  && install -d -m 755 /run/sshd /bootstrap /opt/opshaven-fixtures \
  && ssh-keygen -A \
  && printf '%s\n' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'PermitRootLogin no' \
    'UsePAM no' \
    'AllowUsers admin opshaven' \
    'X11Forwarding no' \
    'GatewayPorts no' \
    'PermitTunnel no' \
    >> /etc/ssh/sshd_config
COPY integration/remote-setup-ubuntu/fixture-systemctl /usr/bin/systemctl
COPY integration/remote-setup-ubuntu/fixture-health.mjs /opt/opshaven-fixtures/fixture-health.mjs
COPY integration/remote-setup-ubuntu/entrypoint.sh /usr/local/bin/opshaven-ubuntu-entrypoint
RUN chmod 755 /usr/bin/systemctl /usr/local/bin/opshaven-ubuntu-entrypoint \
  && chmod 644 /opt/opshaven-fixtures/fixture-health.mjs
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/opshaven-ubuntu-entrypoint"]
