#! /usr/bin/python

from pwn import *
import time


CONTAINERS = 1
BASE_PORT = 3000
DEV_MAP_PATH = '/sys/fs/bpf/xdp/globals/dev_map'
MAP_NAME = "xsk_map"
#args = [['echo', '1\n2\n3\n'], ['echo', '7\n8\n9\n']]
#arg = ['docker', 'exec', '-t', 'nginx1', '/shared/guest.o']
socket_arg = ['./socket.o', DEV_MAP_PATH]
#sed -i 's/xsk_map1/xsk_map2/g' ./guest_prog.o
#args = [arg, arg]
procs = []


def try_int(s):
    try:
        return int(s)
    except ValueError:
        return 0

def guest_args(container_number):
    return ['docker', 'exec', '-t', f'nginx{container_number}', '/shared/guest.o']
def socket_args(port, xsk_map_name):
    return ['./socket.o', DEV_MAP_PATH, port, xsk_map_name]
def sed_args(map_number):
    return ["sed", "-i", f"s/xsk_map[0123456789]\\+/xsk_map{map_number}/g", "./guest_prog.o"]

def main():
    for i in range(CONTAINERS):
        port = BASE_PORT + i
        sed_a = sed_args(i+1)
        print("sed args:", sed_a)
        subprocess.run(sed_a)
        sa = socket_args(str(port), 'xsk_map' + str(i+1))
        print("socket args: ", sa)
        subprocess.Popen(sa)
        time.sleep(1)
        arg = guest_args(i+1)
        print("guest args", arg)
        p = process(arg);
        time.sleep(1)
        procs.append(p)
    print(procs)


    try:
        j=0
        while(all([ p.can_recv() for p in procs]) or not any([p.poll() for p in procs])):
            try:
                total_pps = 0
                for i, p in enumerate(procs):
                    #print(f"waiting for line {j} of input from process {i}:")
                    raw_out = p.recvline()
                    raw_out2 = raw_out.replace(b'\r', b"")
                    raw_out3 = raw_out2.replace(b'\n', b"")
                    out = raw_out3.decode("utf-8")
                    pps_s = out.split(' ')[-1]
                    pps = try_int(pps_s)
                    total_pps += pps
                    #print(f'process {i}: {pps}')
                    print(f'process {i}: {out}')
                print(f"TOTAL: {total_pps}")
            except EOFError:
                print(f"EOF on process {i}")
            j+=1
    finally:
        print("killing children")
        for p in procs:
            p.kill()


if __name__ == '__main__':
    main()
