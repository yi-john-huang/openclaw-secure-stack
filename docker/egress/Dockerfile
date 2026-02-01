FROM coredns/coredns:1.11.1

COPY Corefile /etc/coredns/Corefile

ENTRYPOINT ["/coredns", "-conf", "/etc/coredns/Corefile"]
