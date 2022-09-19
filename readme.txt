
dependencies:
latest libbpf from github source
apt: build-essential libelf-dev gcc-multilib pkg-config docker.io

steps:
make a folder /tmp/container1
start a container with `docker run -t -d -p 1234:80 -v "/tmp/container1":/shared --name nginx1 nginx:latest`
run `./compile.sh`
run `sed -i 's/xdp_map1/xdp_mapX/g' guest_redirect.o`, where X is the container number, must be unique
run `./socket.o /sys/fs/bpf/xdp/globals/dev_map <port> xdp_mapX`, where port is the port you want redirected, and X matches above
in another window, run `docker exec -it nginx1 /shared/guest.o`
load host xdp program with `ip link set dev <device name> xdp obj ./xdp_prog.o sec xdp`

SHOULD BE UNNECESSARY NOW, maybe for debugging:
use bpftool to add an element into the map dev_map (watch out for byte order),
ie to map all traffic from port 3000 to device 07 (the host side of the veth)
`bpftool map update name dev_map key hex B8 0B 00 00 value hex 07 00 00 00`
