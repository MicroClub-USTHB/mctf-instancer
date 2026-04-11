#!/bin/sh

/usr/sbin/sshd

# keep container alive
tail -f /dev/null
