FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server git procps sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /opt/opshaven /etc/opshaven /var/lib/opshaven/.ssh \
    && useradd --system --home-dir /var/lib/opshaven --shell /bin/sh --gid nogroup opshaven \
    && chown -R opshaven:nogroup /var/lib/opshaven \
    && chmod 0700 /var/lib/opshaven/.ssh

COPY dist /opt/opshaven/dist
COPY integration/fixture/dispatcher.config.json /etc/opshaven/dispatcher.json
COPY integration/fixture/sshd_config /etc/ssh/sshd_config
COPY integration/fixture/opshaven-dispatch /usr/local/bin/opshaven-dispatch
COPY integration/fixture/entrypoint.sh /usr/local/bin/opshaven-fixture-entrypoint

RUN chmod 0755 /usr/local/bin/opshaven-dispatch /usr/local/bin/opshaven-fixture-entrypoint \
    && chown root:root /etc/opshaven/dispatcher.json /etc/ssh/sshd_config \
    && chmod 0644 /etc/opshaven/dispatcher.json /etc/ssh/sshd_config

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/opshaven-fixture-entrypoint"]
