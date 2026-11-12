FROM alpine:3.24
RUN apk add --no-cache openssh-server sqlite \
 && ssh-keygen -A \
 && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nStrictModes no\nAuthorizedKeysFile /etc/ssh/authorized_keys/%%u\n' | cat - /etc/ssh/sshd_config > /tmp/sshd_config \
 && mv /tmp/sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
