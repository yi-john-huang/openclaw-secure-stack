FROM coredns/coredns:1.11.1

COPY Corefile /etc/coredns/Corefile
COPY generate-zone.sh /usr/local/bin/generate-zone.sh

USER 65534

ENTRYPOINT ["/coredns", "-conf", "/etc/coredns/Corefile"]
