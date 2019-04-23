FROM alpine:3.8
EXPOSE 2121-2122

COPY bin/ftp-ingest /bin/ftp-ingest
ENTRYPOINT [ "/bin/ftpserver"]
