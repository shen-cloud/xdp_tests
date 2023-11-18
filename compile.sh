
#clang -lelf -lbpf make_map.c -o make_map.o -ggdb3 
clang -Wall socket.c -o socket.o  -ggdb3
#clang -Wall socket.c -o socket.o -fsanitize=address -ggdb3
clang -Wall guest.c -o guest.o -static -lpthread -flto -O3
clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect.c -o xdp_prog.o
clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect_map.c -o xdp_prog_map.o
clang -O2 -g -Wall -target bpf -c redirect_progs/host_redirect_lpm.c -o xdp_prog_lpm.o
clang -O2 -g -Wall -target bpf -c guest_redirect.c -o guest_prog.o

mkdir -p /tmp/container1/
mv ./guest.o /tmp/container1/guest.o
