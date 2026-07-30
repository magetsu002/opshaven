# Restricted dispatcher

The remote account is defense in depth, not a normal administration account.

* OpenSSH `ForceCommand` and the key option both pin `/usr/local/bin/opshaven-dispatch`.
* PTY, agent forwarding, TCP forwarding, tunnels, X11, user rc files, passwords, and keyboard-interactive auth are disabled.
* The dispatcher accepts no arguments and exactly one bounded JSON request on stdin.
* It independently parses the full configuration and request before selecting a fixed in-process handler.
* Handler subprocesses use fixed executables and argument arrays with `shell: false`.
* Sudoers entries name exact commands and exact units. Wildcards are prohibited.

The account uses `/bin/sh` only because OpenSSH launches forced commands through the account shell. A shell session remains unreachable because both `ForceCommand` and the authorized-key restriction are enforced.
