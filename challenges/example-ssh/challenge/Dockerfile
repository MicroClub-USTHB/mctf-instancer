FROM alpine:3.20

RUN apk add --no-cache openssh bash

# Create user
RUN adduser -D mctf && echo "mctf:mctf5" | chpasswd

# Setup SSH
RUN ssh-keygen -A

# allow password auth
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# add flag
RUN echo "MCTF{alpine_ssh_challenge}" > /flag.txt && \
    chmod 644 /flag.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
