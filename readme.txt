
dependencies:
latest libbpf from source
apt: build-essential libelf-dev gcc-multilib pkg-config

steps:
make a folder /tmp/container1
start a container with `docker run -t -d -p 1234:80 -v "/tmp/container1":/shared --name nginx1 nginx:latest`
copy <guest filename> into /tmp/container1
start <host filename>
start <guest filename>
