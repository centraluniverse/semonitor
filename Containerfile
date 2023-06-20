# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2023 Olliver Schinagl <oliver@schinagl.nl>

ARG PYTHON_VERSION="3-alpine"

FROM index.docker.io/library/python:${PYTHON_VERSION}


COPY requirements.txt /tmp/

RUN apk add --no-cache --virtual .build-deps \
	gcc \
	musl-dev \
	linux-headers \
    && \
    pip --no-cache-dir install --requirement '/tmp/requirements.txt' && \
    rm '/tmp/requirements.txt' && \
    apk del .build-deps && \
    addgroup -S 'semonitor' && \
    adduser -D -G 'semonitor' -h '/var/lib/semonitor' -s '/bin/nologin' -S 'semonitor' && \
    adduser 'semonitor' 'usb' && \
    install -d -m 775 -g 'semonitor' -o 'semonitor' '/var/lib/semonitor'

VOLUME /var/lib/semonitor

WORKDIR /usr/local/src/solaredge/

COPY conversion /usr/local/src/solaredge/conversion
COPY scripts/semonitor.sh /usr/local/bin/semonitor.sh
COPY se /usr/local/src/solaredge/se
COPY semonitor.py /usr/local/src/solaredge/semonitor.py
COPY services/container-entrypoint.sh /init
COPY utilities /usr/local/src/solaredge/utilities

ENTRYPOINT [ "/init" ]
