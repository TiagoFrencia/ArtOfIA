FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      dnsutils \
      iproute2 \
      iputils-ping \
      jq \
      net-tools \
      nmap \
      procps \
      python3 \
      python3-pip \
      ripgrep \
      vim-tiny && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
