echo "Loading $2 onto $1, removing after 20s sleep"

ip link set dev $1 xdpgeneric obj $2 sec xdp

sleep 5

ip link set dev $1 xdpgeneric off

