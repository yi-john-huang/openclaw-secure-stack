FROM coredns/coredns:1.11.1

COPY Corefile /etc/coredns/Corefile
COPY generate-zone.sh /usr/local/bin/generate-zone.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
