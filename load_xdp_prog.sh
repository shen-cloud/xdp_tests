echo "Loading $2 onto $1, removing after 20s sleep"

ip link set dev $1 xdp obj $2 sec xdp

sleep 20 

ip link set dev $1 xdp off

