FROM scratch
ARG TARGETARCH
COPY package/linux-${TARGETARCH}/bin/kurd-node /usr/local/bin/kurd-node
COPY package/linux-${TARGETARCH}/bin/kurdctl /usr/local/bin/kurdctl
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kurd-node"]
CMD ["run", "--data-dir", "/var/lib/kurd-node", "--publication-file", "/var/lib/kurd-node/public/snapshot.kurd-publication"]
