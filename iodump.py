#!/usr/bin/python3
import sys
import time
import math
import struct
import signal
import resource
import ctypes as ct
import multiprocessing

from bcc import BPF

# ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
# ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)

bpf_text = '''
#include <linux/sched.h>

#define IO_MAX_BUF_SIZE     __IO_MAX_BUF_SIZE__

#define IO_PACKET_F_WRITE   1

struct packet {
    u32 pid;
    u32 fd;
    s64 ret;
    u64 flags;
    char data[IO_MAX_BUF_SIZE];
};

struct rw_args {
    unsigned int fd;
    char *buf;
};

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);
BPF_HASH(rw_buf, u32, struct rw_args);
BPF_PERF_OUTPUT(events);

int kprobe_ksys_read_write(struct pt_regs *ctx,
                           unsigned int fd, char *buf, size_t count)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct rw_args args = { 0 };

    if (pid != __PID__)
        return 0;

    __FD_FILTER__

    args.fd = fd;
    args.buf = buf;

    rw_buf.update(&tid, &args);
    return 0;
}

static inline int kretprobe_ksys_read_write(struct pt_regs *ctx, u64 flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    int n;
    s64 ret;
    struct packet *packet;
    struct rw_args *args;

    args = rw_buf.lookup(&tid);
    if (args == NULL) {
        return 0;
    }
    rw_buf.delete(&tid);

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    ret = PT_REGS_RC(ctx);

    packet->pid = pid;
    packet->fd = args->fd;
    packet->ret = ret;
    packet->flags = flags;

    if (ret < 0) {
        events.perf_submit(ctx, packet, offsetof(struct packet, data));
        return 0;
    }

    n = ret;
    bpf_probe_read(
        &packet->data,
        // check size in args to make compiler/validator happy
        n > sizeof(packet->data) ? sizeof(packet->data) : n,
        args->buf
    );

    n += offsetof(struct packet, data);
    events.perf_submit(
        ctx,
        packet,
        // check size in args to make compiler/validator happy
        n > sizeof(*packet) ? sizeof(*packet) : n
    );

    return 0;
}

int kretprobe_ksys_read(struct pt_regs *ctx)
{
    return kretprobe_ksys_read_write(ctx, 0);
}

int kretprobe_ksys_write(struct pt_regs *ctx)
{
    return kretprobe_ksys_read_write(ctx, IO_PACKET_F_WRITE);
}
'''

TASK_COMM_LEN = 16
UNIX_PATH_MAX = 108

IO_MAX_BUF_SIZE = 1024 * 50
IO_MAX_QUEUE_LEN = 100

IO_PACKET_F_WRITE = 1

def build_fd_filter(fds):
    if len(fds) == 0:
        return ''

    filter = 'if ('
    filter += ' && '.join('fd != %d' % x for x in fds)
    filter += ') return 0;'

    return filter

def render_text(bpf_text, seg_size, pid, fd_filter):
    replaces = {
        '__IO_MAX_BUF_SIZE__': seg_size,
        '__NUM_CPUS__': multiprocessing.cpu_count(),
        '__PID__': pid,
        '__FD_FILTER__': fd_filter,
    }
    for k, v in replaces.items():
        bpf_text = bpf_text.replace(k, str(v))
    return bpf_text

class Packet(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ('pid', ct.c_uint),
        ('fd', ct.c_uint),
        ('ret', ct.c_long),
        ('flags', ct.c_ulong),
        # variable length data
    ]

PCAP_LINK_TYPE = 147    # USER_0

PACKET_SIZE = ct.sizeof(Packet)

packet_count = 0

def parse_event(event, size):
    global packet_count

    packet_count += 1

    packet = ct.cast(event, ct.POINTER(Packet)).contents
    if packet.ret < 0:
        return packet, b''

    event += PACKET_SIZE
    size -= PACKET_SIZE

    data_len = packet.ret
    if  data_len > size:
        data_len = size

    data_type = ct.c_char * data_len
    data = ct.cast(event, ct.POINTER(data_type)).contents.raw

    return packet, data

def print_header(packet, data):
    ts = time.time()
    ts = time.strftime('%H:%M:%S', time.localtime(ts)) + '.%03d' % (ts%1 * 1000)

    direction = 'WR >>>'
    if packet.flags & IO_PACKET_F_WRITE == 0:
        direction = 'RD <<<'
    line = '%s %s pid %d fd %d' % (ts, direction, packet.pid, packet.fd)
    if packet.ret < 0:
        line += ' err %d' % packet.ret
    else:
        line += ' len %d(%d)' % (packet.ret, len(data))

    print(line)

def string_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    print(str(data, encoding='ascii', errors='ignore'), end='', flush=True)

def ascii(c):
    if c < 32 or c > 126:
        return '.'
    return chr(c)

def hex_print(data):
    for i in range(0, len(data), 16):
        line = '{:04x}'.format(i)
        line += '  '
        line += '{:<23s}'.format(' '.join('%02x' % x for x in data[i:i+8]))
        line += '  '
        line += '{:<23s}'.format(' '.join('%02x' % x for x in data[i+8:i+16]))
        line += '  '
        line += ''.join(ascii(x) for x in data[i:i+16])
        print(line)

def hex_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    hex_print(data)

def pcap_write_header(snaplen, network):
    header = struct.pack('=IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, network)
    sys.stdout.write(header)

def pcap_write_record(ts_sec, ts_usec, orig_len, data):
    header = struct.pack('=IIII', ts_sec, ts_usec, len(data), orig_len)
    sys.stdout.write(header)
    sys.stdout.write(data)

def pcap_output(cpu, event, size):
    packet, data = parse_event(event, size)

    # FIXME: also dump error
    if packet.ret < 0:
        return

    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts % 1) * 10**6)

    if packet.flags & IO_PACKET_F_WRITE == 0:
        src = 0
        dst = packet.pid << 32 | packet.fd
    else:
        src = packet.pid << 32 | packet.fd
        dst = 0
    header = struct.pack('>QQ', dst, src)

    data = header + data
    size = len(header) + packet.ret
    pcap_write_record(ts_sec, ts_usec, size, data)

outputs = {
    'hex': hex_output,
    'string': string_output,
    'pcap': pcap_output,
}

def sig_handler(signum, stack):
    print('\n%d packets captured' % packet_count, file=sys.stderr)
    sys.exit(signum)

def main(args):
    fd_filter = build_fd_filter([int(x) for x in args.fd])
    text = render_text(bpf_text, args.max_buf_size, args.pid, fd_filter)
    if args.bpf:
        print(text)
        return 0

    b = BPF(text=text)
    b.attach_kprobe(
        event='ksys_read', fn_name='kprobe_ksys_read_write')
    b.attach_kretprobe(
        event='ksys_read', fn_name='kretprobe_ksys_read')
    b.attach_kprobe(
        event='ksys_write', fn_name='kprobe_ksys_read_write')
    b.attach_kretprobe(
        event='ksys_write', fn_name='kretprobe_ksys_write')

    npages = args.max_buf_size * args.max_queue_len / resource.getpagesize()
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.format]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    if args.format == 'pcap':
        sys.stdout = open(args.output, 'wb')
        pcap_write_header(args.max_buf_size, PCAP_LINK_TYPE)
    else:
        sys.stdout = open(args.output, 'w')

    print('waiting for data', file=sys.stderr)
    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Dump unix domain socket traffic')
    parser.add_argument(
        '--max-buf-size', type=int, default=IO_MAX_BUF_SIZE,
        help='max buffer size for read/write')
    parser.add_argument(
        '--max-queue-len', type=int, default=IO_MAX_QUEUE_LEN,
        help='max len of the dump queue')
    parser.add_argument(
        '--format', choices=outputs.keys(), default='hex',
        help='output format')
    parser.add_argument(
        '--output', default='/dev/stdout',
        help='output file')
    parser.add_argument(
        '--bpf', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument(
        '--fd', action='append', default=[],
        help='sniff this file descriptor')
    parser.add_argument(
        'pid', type=int,
        help='sniff this PID')
    args = parser.parse_args()
    sys.exit(main(args))
