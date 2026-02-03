# Pin by digest for reproducible builds. Update periodically.
# To find latest: podman pull coredns/coredns:1.11.1 && podman inspect --format='{{index .RepoDigests 0}}' coredns/coredns:1.11.1
FROM coredns/coredns:1.11.1@sha256:1eeb4c7316bacb1d4c8ead65571cd92dd21e27359f0d4917f1a5822a73b75db1

COPY Corefile /etc/coredns/Corefile

ENTRYPOINT ["/coredns", "-conf", "/etc/coredns/Corefile"]
