FROM ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba-ad-dc samba-ad-provision samba-common-bin python3-samba python3-ldap \
    krb5-user ldap-utils bind9-dnsutils openssl ca-certificates \
    && dpkg-query -W > /usr/share/lab-package-versions.txt \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY bootstrap.py probe.py health.py /lab/
ENTRYPOINT ["/usr/bin/python3", "/lab/bootstrap.py"]
