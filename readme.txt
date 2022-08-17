
dependencies:
latest libbpf from github source
apt: build-essential libelf-dev gcc-multilib pkg-config

steps:
make a folder /tmp/container1
start a container with `docker run -t -d -p 1234:80 -v "/tmp/container1":/shared --name nginx1 nginx:latest`
run `./compile.sh`
start socket.o on the host
run `docker exec -it nginx1 /bin/bash`
start /shared/guest.o on the guest
load host xdp program with `ip link set dev <device name> xdp ./xdp_prog.o sec xdp`

use bpftool to add an element into the map dev_map (watch out for byte order),
ie to map all traffic from port 3000 to device 07 (the host side of the veth)
`bpftool map update name dev_map key hex B8 0B 00 00 value hex 07 00 00 00`
