FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Create challenge user
RUN useradd -m ctf

WORKDIR /home/ctf

# Copy challenge binary (placeholder)
COPY vuln.c /home/ctf/
COPY flag.txt /home/ctf/flag.txt

# Build the vulnerable binary
RUN apt-get update && apt-get install -y gcc && \
    gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie && \
    chmod +x vuln && \
    chmod 444 flag.txt && \
    apt-get remove -y gcc && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

USER ctf

EXPOSE 9999

CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:./vuln"]
