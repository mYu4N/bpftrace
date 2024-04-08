#!/usr/bin/python3
# author muyuan.y yufeng.s

import sys
import time
import math
import struct
import signal
import resource
import ctypes as ct
import multiprocessing

from bcc import BPF

bpf_text = '''
#include <linux/sched.h>
#include <linux/net.h>
#include <uapi/linux/un.h>
#include <net/af_unix.h>
#include <linux/version.h>
#include <uapi/linux/ptrace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>

#define SS_MAX_SEG_SIZE 51200
#define SS_MAX_SEGS_PER_MSG 10

#define SS_PACKET_F_ERR     1

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

struct packet {
    u32 pid;
    u32 ns_inum;
    u32 peer_pid;
    u32 len;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char path[UNIX_PATH_MAX];
    char data[SS_MAX_SEG_SIZE];
};

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);
BPF_PERF_OUTPUT(events);

int probe_unix_socket_sendmsg(struct pt_regs *ctx,
                              struct socket *sock,
                              struct msghdr *msg,
                              size_t len)
{
    struct packet *packet;
    struct unix_address *addr;
    char *buf, *sock_path;
    unsigned long path[__PATH_LEN_U64__] = {0};
    unsigned int n, match = 0, offset;
    struct iov_iter *iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    const struct iovec *iov;
#else
    const struct kvec *iov;
#endif
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct pid *peer_pid;

    addr = ((struct unix_sock *)sock->sk)->addr;
    if (addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        if (*sock_path == 0) {
            // abstract sockets start with \\0 and the name comes after
            // (they actually have no @ prefix but some tools use that)
            bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
        } else {
            bpf_probe_read(&path, __PATH_LEN__, sock_path);
        }
        __PATH_FILTER__
    }

    addr = ((struct unix_sock *)((struct unix_sock *)sock->sk)->peer)->addr;
    if (match == 0 && addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        if (*sock_path == 0) {
            // abstract sockets start with \\0 and the name comes after
            // (they actually have no @ prefix but some tools use that)
            bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
        } else {
            bpf_probe_read(&path, __PATH_LEN__, sock_path);
        }
        __PATH_FILTER__
    }

    if (match == 0)
        return 0;

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));
    bpf_probe_read(&packet->path, UNIX_PATH_MAX, sock_path);
    packet->peer_pid = sock->sk->sk_peer_pid->numbers->nr;
    task = (struct task_struct *)bpf_get_current_task();
    packet->ns_inum = task->nsproxy->pid_ns_for_children->ns.inum;
    __PID_FILTER__


    iter = &msg->msg_iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    if (iter->iter_type == ITER_UBUF) {
        packet->len = len;
        packet->flags = 0;
        buf = iter->ubuf;
        n = len;

        bpf_probe_read(
            &packet->data,
            // check size in args to make compiler/validator happy
            n > sizeof(packet->data) ? sizeof(packet->data) : n,
            buf);

        n += offsetof(struct packet, data);
        events.perf_submit(
            ctx,
            packet,
            // check size in args to make compiler/validator happy
            n > sizeof(*packet) ? sizeof(*packet) : n);

        return 0;
    }

    if (iter->iter_type != ITER_IOVEC || iter->iov_offset != 0) {
#else
    if (iter->iov_offset != 0) {
#endif
        packet->len = len;
        packet->flags = SS_PACKET_F_ERR;
        events.perf_submit(ctx, packet, offsetof(struct packet, data));
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    iov = iter->__iov;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    iov = iter->iov;
#else
    iov = iter->kvec;
#endif

    #pragma unroll
    for (int i = 0; i < SS_MAX_SEGS_PER_MSG; i++) {
        if (i >= iter->nr_segs)
            break;

        packet->len = iov->iov_len;
        packet->flags = 0;

        buf = iov->iov_base;
        n = iov->iov_len;
        bpf_probe_read(
            &packet->data,
            // check size in args to make compiler/validator happy
            n > sizeof(packet->data) ? sizeof(packet->data) : n,
            buf);

        n += offsetof(struct packet, data);
        events.perf_submit(
            ctx,
            packet,
            // check size in args to make compiler/validator happy
            n > sizeof(*packet) ? sizeof(*packet) : n);

        iov++;
    }

    return 0;
}
'''

TASK_COMM_LEN = 16
UNIX_PATH_MAX = 108


SS_MAX_SEGS_IN_BUFFER = 100

SS_PACKET_F_ERR = 1

outputs = {
    'string': None,
    'header': None,
}

import argparse

parser = argparse.ArgumentParser(
    description='Capture Unix domain socket data')
parser.add_argument(
    '--format', choices=outputs.keys(), default='header',
    help='output format,support string or header')
parser.add_argument(
    '--pid', default=None,
    help='Pid filter, default no filter')
parser.add_argument(
    '--cmd', default=None,
    help='Command filter, default no filter')
parser.add_argument(
    '--top', default=None, type=int,
    help='display topn unix socket data ,defautl top5')
parser.add_argument(
    'sock',
    help="\n".join([
        "unix socket path. Absolute path, regardless of where the socket runs \n",
        "# python udsdump.py --format string /tmp/php-cgi.sock. \n",
        " Start capture Unix socket data.... \n",
        "10:20:58.282 >>> Process: nginx Namespace: 4026532843 [214068 -> 214120] Path: /tmp/php-cgi.sock Len: 592(592). \n",
        "10:20:58.283 >>> Process: php-fpm Namespace: 4026532843 [214127 -> 214068] Path: /tmp/php-cgi.sock Len: 112(112). \n",
        "SX-Powered-By: PHP/7.4.33. \n",
        "Content-type: text/html; charset=UTF-8. \n",
        "3.1415926535898. \n",
    ]))

args = parser.parse_args()
cmd_filter = args.cmd
top_filter = args.top


def render_text(bpf_text, sock_path, pid=None, cmd=None, top=5):
    path_filter, path_len, path_len_u64 = build_filter(sock_path)
    replaces = {
        '__NUM_CPUS__': multiprocessing.cpu_count(),
        '__PATH_LEN__': path_len,
        '__PATH_LEN_U64__': max(path_len_u64, 1),
        '__PATH_FILTER__': path_filter,
    }

    if pid:
        replaces['__PID_FILTER__'] = 'if (packet->pid != %s && packet->peer_pid != %s) { return 0; }' % (pid, pid)
    else:
        replaces['__PID_FILTER__'] = ''

    for k, v in replaces.items():
        bpf_text = bpf_text.replace(k, str(v))
    return bpf_text


def build_filter(sock_path):
    sock_path_bytes = sock_path.encode()
    # if path ends with * - use prefix-based matching
    if sock_path[-1] == "*":
        sock_path_bytes = sock_path_bytes[:-1]
    elif sock_path[0] == "@":
        sock_path_bytes = sock_path_bytes[1:] + b'\0'
    else:
        sock_path_bytes += b'\0'

    path_len = len(sock_path_bytes)
    if path_len > UNIX_PATH_MAX:
        raise ValueError('invalid path')
    # match all paths
    if path_len == 0:
        return 'match = 1;', 0, 0

    path_len_u64 = (path_len + 7) // 8
    sock_path_bytes += b'\0' * (path_len_u64 * 8 - path_len)
    sock_path_u64s = [
        struct.unpack('Q', sock_path_bytes[i * 8:(i + 1) * 8])[0]
        for i in range(path_len_u64)
    ]

    filter = 'if ('
    filter += ' && '.join(
        'path[{}] == {}'.format(i, n)
        for (i, n) in enumerate(sock_path_u64s)
    )
    filter += ') match = 1;'

    return filter, path_len, path_len_u64


class Packet(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ('pid', ct.c_uint),
        ('ns_inum', ct.c_uint),
        ('peer_pid', ct.c_uint),
        ('len', ct.c_uint),
        ('flags', ct.c_uint),
        ('comm', ct.c_char * TASK_COMM_LEN),
        ('path', ct.c_char * UNIX_PATH_MAX),
        # variable length data
    ]


PCAP_LINK_TYPE = 147  # USER_0

PACKET_SIZE = ct.sizeof(Packet)

packet_count = 0


def parse_event(event, size):
    global packet_count

    packet_count += 1
    packet = ct.cast(event, ct.POINTER(Packet)).contents
    event += PACKET_SIZE

    size -= PACKET_SIZE
    data_len = packet.len
    if data_len > size:
        data_len = size

    data_type = ct.c_char * data_len
    data = ct.cast(event, ct.POINTER(data_type)).contents

    return packet, data


def print_header(packet, data):
    ts = time.time()
    ts = time.strftime('%H:%M:%S', time.localtime(ts)) + '.%03d' % (ts % 1 * 1000)

    print('\n %s >>> Process: %s Namespace: %d [%d -> %d] Path: %s Len: %d(%d)' % (
        ts, packet.comm.decode(), packet.ns_inum, packet.pid, packet.peer_pid,
        packet.path.decode(), len(data), packet.len))


def string_output(cpu, event, size, cmd_filter=cmd_filter, top_filter=top_filter):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    if cmd_filter is None or packet.comm.decode() == cmd_filter:
        raw = str(data.raw, encoding='ascii', errors='ignore')
        if top_filter:
            data_lines = raw.split('\n')
            top_lines = data_lines[:top_filter]
            raw = '\n'.join(top_lines)
        print(raw, end='', flush=True)


def header_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')


outputs['string'] = string_output
outputs['header'] = header_output


def ascii(c):
    if c < 32 or c > 126:
        return '.'
    return chr(c)


def sig_handler(signum, stack):
    print('\n%d packets captured' % packet_count, file=sys.stderr)
    sys.exit(signum)


def main(args):
    text = render_text(bpf_text, args.sock, args.pid, args.cmd, args.top)

    b = BPF(text=text)
    b.attach_kprobe(
        event='unix_stream_sendmsg', fn_name='probe_unix_socket_sendmsg')
    b.attach_kprobe(
        event='unix_dgram_sendmsg', fn_name='probe_unix_socket_sendmsg')

    npages = 51200 * 100 / resource.getpagesize()
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.format]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print('Start capture Unix socket data... ', file=sys.stderr)
    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    main(args)
