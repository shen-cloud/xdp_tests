
clang -lelf -lbpf make_map.c -o make_map.o -ggdb3
clang -Wall socket.c -o socket.o
clang -Wall client.c -o client.o -static
clang -O2 -g -Wall -target bpf -c host_redirect.c -o xdp_prog.o

mv ./client.o /tmp/container1/client.o
