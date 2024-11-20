# FROM --platform=linux/arm/v7 arm32v7/ubuntu:20.04
# FROM --platform=linux/arm64/v8 arm64v8/ubuntu:24.04
# FROM --platform=linux/amd64 amd64/ubuntu:24.04
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Vienna
# RUN apt update && apt -y --no-install-recommends upgrade
RUN apt update && apt install --no-install-recommends -y \
    tzdata \
    python3-setuptools \
    python3-pip \
    python3 \
    python3-scapy \
    python3-prometheus-client

WORKDIR /usr/src/app
# install python modules
# COPY ./build/requirements.txt ./
# RUN pip3 install --disable-pip-version-check --no-cache-dir -r requirements.txt
RUN pip3 freeze
# this changes very often so put it at the end of the main section
COPY build/main.py /usr/src/app/main.py

# cleanup
# starting at 471MB
# with updates 473MB
# down to 227MB
RUN apt -y purge python3-pip python3-setuptools; \
    apt -y autoremove; \
    apt -y clean;

# add HEALTHCHECK command to check is container is running
# HEALTHCHECK --interval=5m --timeout=3s CMD curl -I http://localhost:9100/ || exit 1

# adding NON-ROOT user
# RUN groupadd --gid 1000 newuser && \
#     useradd \
#       --home-dir /usr/src/app \
#       --uid 1000 \
#       --gid 1000 \
#       --shell /bin/sh \
#       --no-create-home \
#       appuser
# RUN chown -R appuser /usr/src/app

# USER appuser
CMD ["python3", "-u", "/usr/src/app/main.py"]
