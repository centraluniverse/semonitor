# Running semonitor in docker

semonitor can be run within a Docker container. This provides isolation from
other processes by running it in a containerized environment. This is not an
in-depth tutorial on Docker; for background on Docker or containers, see
[docker.com][docker].

This guide is not comprehensive; it only lists the most basic steps.


## Building the container

Building the container is only needed if the official one is not sufficient,
or when developing on semonitor.

To build the image, the following can be used, where `ISSUE-123` is just used
as an example. The same tag is reused later.

The version is taken from the git tags. As `.git` is not part of the build
context, it is passed in as a build argument; without it, the version is
`0+unknown`.

```sh
docker image build \
    --file 'Containerfile' \
    --build-arg "VERSION=$(pipx run setuptools-scm)" \
    --rm \
    --tag 'semonitor:ISSUE-123' \
    './'
```


## Running tests

The tests are not included in the container image, so we volume mount them to
make them available to the installed semonitor application. As there is no
source in the image, the tests run the semonitor that is installed in it.

```sh
docker container run \
    --interactive \
    --rm \
    --tty \
    --volume "$(pwd)/test:/usr/local/src/semonitor/test" \
    'semonitor:ISSUE-123' \
    './test/test.sh'
```

A second test checks that the image is complete: that every dependency,
including those of the extras, is installed and that every command loads. A
build succeeds without them, as the extras are only installed when asked for,
and `test.sh` only runs `semonitor`.

```sh
docker container run \
    --interactive \
    --rm \
    --tty \
    --volume "$(pwd)/test:/usr/local/src/semonitor/test" \
    'semonitor:ISSUE-123' \
    './test/test-install.sh'
```


## Running serial device

Running semonitor on a serial device using the official latest image can
be done as follows.

```sh
docker container run \
    --device '/dev/solaredge0:/dev/ttyUSB0' \
    --interactive \
    --rm \
    --tty \
    --volume "$(pwd)/semonitor_logs/:/semonitor/" \
    'ghcr.io/jbuehl/solaredge:latest' \
        -a \
        -b 115200 \
        -m \
        -o "/semonitor/json/__date__.json" \
        -r "/semonitor/rec/__date__.rec" \
        -s '1234567' \
        -t 4 \
        '/dev/ttyUSB0'
```

To ensure semonitor can accurately set the inverter's clock, it first waits
for a valid system time when it reads from a serial device. By default,
anything older than the image is invalid; override it by setting
`SE_START_EPOCH` to a UNIX epoch or an ISO 8601 date and time, for example:

```sh
--env 'SE_START_EPOCH=2024-01-01'
--env 'SE_START_EPOCH=2024-01-01T23:01:02'
--env 'SE_START_EPOCH=1704067200'
```

It gives up after `SE_START_TIMEOUT` seconds, 60 by default.


## Using compose

It is also possible to run the container using `docker compose`. Here is an
example. The device used is a udev-symlinked serial-to-USB adapter with
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
    expose:
      - "80/tcp"
      - "22221-22222/tcp"
    command: >-
      -a -b 115200
      -m
      -n
      -o /var/lib/semonitor/json/__date__.json
      -r /var/lib/semonitor/rec/__date__.rec
      -s 1234567
      -t 4 /dev/ttyUSB0
    restart: unless-stopped
```


## Running se2hass

`se2hass` pushes the output of semonitor to Home Assistant, and announces itself
with mDNS (`_semonitor._tcp`) so that Home Assistant can find and pair with it.
The image contains its dependencies. As it reads the output of `semonitor`, run
both in a pipeline. This is a separate service, as it has no `networks`:

```yaml
volumes:
  semonitor:

services:
  se2hass:
    image: ghcr.io/jbuehl/solaredge:master
    network_mode: host
    init: true
    cap_drop:
      - all
    devices:
      - /dev/solaredge:/dev/ttyUSB0
    env_file:
      - common.env
    volumes:
      - semonitor:/var/lib/semonitor:rw
    command:
      - sh
      - -c
      - semonitor -m -s 1234567 -t 4 /dev/ttyUSB0 | se2hass
    restart: unless-stopped
```

* **Host network:** mDNS uses multicast, which does not leave a bridge network,
  so without `network_mode: host` Home Assistant cannot find `se2hass`. The
  pairing API listens on port 22222/tcp of the host, or on the port given with
  `-p`. Open it in the firewall if there is one.
* **Init:** `init: true` runs `tini` as PID 1, which reaps the processes that
  are left over. It forwards SIGTERM only to the shell, not to the programs in
  the pipeline, and `exec` cannot be used for a pipeline. When the container
  stops they are killed, so `se2hass` does not get to send its mDNS goodbye,
  and Home Assistant keeps seeing the announcement until it expires.
* **Command:** the entrypoint runs a first argument that is an existing command
  as it is, which is why `sh` can be used here instead of `semonitor`.
* **State:** the pairing and the pairing code are kept in
  `/var/lib/semonitor/se2hass.json`, on the volume that `semonitor` uses, so
  they survive a restart of the container.
* **Interfaces:** with the host network, the addresses of `docker0` and of the
  `veth` interfaces can end up in the announcement. Use `-i` with the address
  of the host to announce that one only.

The pairing code is logged at every start. Find it with

```sh
docker compose logs se2hass
```

Without `--cert` and `--key` the API uses plain HTTP, and the code is sent in
the clear when Home Assistant pairs. To serve it over HTTPS, mount a
certificate and key into the container and pass them with `--cert` and `--key`.
The options are described in [se2hass](README.md#se2hass) in the README.

[docker]: https://www.docker.com/
