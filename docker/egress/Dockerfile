# Pin by digest for reproducible builds. Update periodically.
FROM coredns/coredns:1.11.1@sha256:fdae4bea41058a21e1dcbebf29f5c1c25b0b5ed3a1f9b5c01e2b135f8a3e3bcf

COPY Corefile /etc/coredns/Corefile

ENTRYPOINT ["/coredns", "-conf", "/etc/coredns/Corefile"]
