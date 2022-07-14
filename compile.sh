
clang -lelf -lbpf make_map.c -o make_map.o -ggdb3
clang -O2 -g -Wall -target bpf -c host_redirect.c -o xdp_prog.o
