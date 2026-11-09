# Running semonitor in docker
SEMonitor can be run within a Docker container. This provides isolation from
other processes by running it in a containerized environment. As this is not
an in-depth tutorial on docker, those with Docker, containers or cgroups see
[docker.com][docker].

This guide is not a comprehensive guide, but just lists the most basic things!


## Building the container
Building the container is only needed if the official one is not sufficient,
or when developing on semonitor.

To build the image, the following can be used, where `ISSUE-123` is just used
as an example. It is important in that it will be re-used later.

```sh
docker image build \
    --file 'Containerfile' \
    --rm \
    --tag 'semonitor:ISSUE-123' \
    './'
```


## Running tests
The tests are not included in the container image, so we volume mount them to
make them available to the installed semonitor application.

```sh
docker container run \
    --interactive \
    --rm  \
    --tty \
    --volume "$(pwd)/test:/usr/local/src/semonitor/test" \
    'semonitor:ISSUE-123' \
    './test/test.sh'
```


## Running serial device
Running the semonitor on a serial device using the official latest image can
be done as follows.

```sh
docker container run \
    --device '/dev/solaredge0:/dev/ttyUSB0' \
    --interactive \
    --rm  \
    --tty \
    --volume "$(pwd)/semonitor_logs/:/semonitor/" \
    'ghcr.io/jbuehl/solaredge:latest' \
        -a \
        -b 115200 \
        -m \
        -o "/semonitor/json/__date__.json" \
        -r "/semonitor/rec/__date__.rec" \
        -s '1234567' \
        '/dev/ttyUSB0'
```

To ensure semonitor can accurately set the inverter's clock, the container
first waits for a valid system time. By default, anything older than the image
is invalid; override this with any `date -d` compatible `SE_START_EPOCH`, for
example:

```sh
--env 'SE_START_EPOCH=2024-01-01'
--env 'SE_START_EPOCH=2024-01-01 23:01:02'
--env 'SE_START_EPOCH=@1704067200'
```

## Using compose
It is also possible to run the container using `docker compose`. Here an
example. The device used is a udev symlinked serial to USB adapter, with
the appropriate permissions.

```yaml
networks:
  semonitor: {}

volumes:
  semonitor:

services:
  semonitor:
    image: ghcr.io/jbuehl/solaredge:master
    cap_drop:
      - all
    ulimits:
      nproc: 64
      nofile:
        soft: 4194304
        hard: 16777216
    devices:
      - /dev/solaredge:/dev/ttyUSB0
    env_file:
      - common.env
    volumes:
      - semonitor:/var/lib/semonitor:rw
    networks:
      - semonitor
    command: >-
      -a -b 115200
      -m
      -n
      -o /var/lib/semonitor/json/__date__.json
      -r /var/lib/semonitor/rec/__date__.rec
      -s 1234567
      /dev/ttyUSB0
    restart: unless-stopped
```
