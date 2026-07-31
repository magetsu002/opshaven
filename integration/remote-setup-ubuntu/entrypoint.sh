#!/bin/sh
set -eu
install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /bootstrap/admin.pub /home/admin/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
