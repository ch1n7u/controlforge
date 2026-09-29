# CONTROLFORGE lab target: lab-ssh
# Deliberately weak SSH target: root login + password auth with the lab toy
# credential "toor" (PermitEmptyPasswords stays off).
#
# openssh is NOT present in alpine:3.20; it is installed at build time via
# apk, which is the one documented network dependency of this lab build.
FROM alpine:3.20

RUN apk add --no-cache openssh \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && echo 'root:toor' | chpasswd \
 && printf 'CONTROLFORGE lab-ssh: deliberately weak SSH target.\nThe root password is the lab toy credential "toor" - never reuse it.\n' > /etc/motd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

# Recreate /run/sshd (in case /run was cleared) and run sshd in the foreground.
CMD ["sh", "-c", "mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e"]
