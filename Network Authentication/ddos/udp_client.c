#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <math.h>

#define MAX_PACKET_SIZE 65536
#define PAYLOAD_PATTERN 'X'
#define DEFAULT_MTU 1500
#define BATCH_SIZE 64

volatile int running = 1;

/* Fast checksum calculation */
static inline uint16_t checksum(const void *data, int len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; i++) {
        sum += buf[i];
    }

    if (len & 1) {
        sum += ((uint8_t *)data)[len - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

/* Get MTU of network interface */
int get_mtu(const char *interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return DEFAULT_MTU;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        close(sock);
        return DEFAULT_MTU;
    }

    close(sock);
    return ifr.ifr_mtu;
}

/* Pin process to specific CPU core */
int pin_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
        printf("✓ Process pinned to CPU %d\n", cpu_id);
        return 0;
    } else {
        perror("sched_setaffinity");
        return -1;
    }
}

/* Set high priority */
int set_high_priority(void) {
    if (setpriority(PRIO_PROCESS, 0, -20) == 0) {
        printf("✓ High priority enabled (nice: -20)\n");
        return 0;
    } else {
        perror("setpriority");
        return -1;
    }
}

/* Lock memory to prevent swapping */
int lock_memory(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        printf("✓ Memory locked (no swapping)\n");
        return 0;
    } else {
        perror("mlockall");
        return -1;
    }
}

/* Create raw UDP packet with IP spoofing */
void create_udp_packet(uint8_t *packet, int packet_size,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint16_t pkt_id) {
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct iphdr));

    int payload_size = packet_size - sizeof(struct iphdr) - sizeof(struct udphdr);
    uint8_t *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    /* Fill payload */
    memset(payload, PAYLOAD_PATTERN, payload_size);

    /* IP header */
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(packet_size);
    ip_hdr->id = htons(pkt_id);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->check = 0;
    ip_hdr->saddr = src_ip;
    ip_hdr->daddr = dst_ip;
    ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

    /* UDP header */
    udp_hdr->source = htons(src_port);
    udp_hdr->dest = htons(dst_port);
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr->check = 0;
}

void signal_handler(int sig) {
    running = 0;
}

/* Send UDP packets using sendmmsg */
void send_packets(const char *src_ip_str, const char *dst_ip_str,
                  int packet_size, int duration, int mtu) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    /* Increase socket send buffer */
    int sndbuf = 32 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    int actual_sndbuf;
    socklen_t optlen = sizeof(actual_sndbuf);
    getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &actual_sndbuf, &optlen);
    printf("Send buffer size: requested %d, actual %d\n", sndbuf, actual_sndbuf);

    /* Determine effective packet size (must fit in MTU for sendmmsg) */
    int effective_packet_size = packet_size;
    if (packet_size > mtu) {
        effective_packet_size = mtu - 50;
        printf("Warning: Packet size %d > MTU %d, using %d bytes\n",
               packet_size, mtu, effective_packet_size);
    }

    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);

    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
        .sin_port = htons(5201)
    };

    /* Allocate batch of packets */
    struct mmsghdr *msgvec = calloc(BATCH_SIZE, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(BATCH_SIZE, sizeof(struct iovec));
    uint8_t **packets = calloc(BATCH_SIZE, sizeof(uint8_t *));

    if (!msgvec || !iovecs || !packets) {
        perror("malloc");
        close(sock);
        return;
    }

    /* Pre-allocate and prepare all packets */
    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = malloc(effective_packet_size);
        if (!packets[i]) {
            perror("malloc packet");
            for (int j = 0; j < i; j++) free(packets[j]);
            free(packets);
            free(iovecs);
            free(msgvec);
            close(sock);
            return;
        }

        create_udp_packet(packets[i], effective_packet_size, src_ip, dst_ip,
                         10000 + i, 5201, i);

        iovecs[i].iov_base = packets[i];
        iovecs[i].iov_len = effective_packet_size;

        msgvec[i].msg_hdr.msg_name = &dst_addr;
        msgvec[i].msg_hdr.msg_namelen = sizeof(dst_addr);
        msgvec[i].msg_hdr.msg_iov = &iovecs[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }

    printf("\nSending packets (duration: %d seconds)...\n", duration);

    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;

    uint16_t pkt_id = 0;
    uint16_t src_port = 10000;
    uint64_t packets_sent = 0;

    /* Pre-calculate header positions */
    struct iphdr **ip_hdrs = malloc(BATCH_SIZE * sizeof(struct iphdr *));
    struct udphdr **udp_hdrs = malloc(BATCH_SIZE * sizeof(struct udphdr *));
    for (int i = 0; i < BATCH_SIZE; i++) {
        ip_hdrs[i] = (struct iphdr *)packets[i];
        udp_hdrs[i] = (struct udphdr *)(packets[i] + sizeof(struct iphdr));
    }

    time_t last_report = start_time;
    uint64_t last_packets = 0;

    /* Main send loop */
    while (running) {
        /* Update variable fields for entire batch */
        for (int i = 0; i < BATCH_SIZE; i++) {
            ip_hdrs[i]->id = htons(pkt_id + i);
            udp_hdrs[i]->source = htons(src_port + i);

            ip_hdrs[i]->check = 0;
            ip_hdrs[i]->check = checksum(ip_hdrs[i], sizeof(struct iphdr));
        }

        /* Send entire batch */
        int sent = sendmmsg(sock, msgvec, BATCH_SIZE, 0);

        if (sent > 0) {
            packets_sent += sent;
            pkt_id += sent;
            src_port += sent;
            if (src_port > 65000) src_port = 10000;
        } else if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1);
                continue;
            } else if (errno != EINTR) {
                usleep(100);
            }
        }

        /* Per-second report */
        time_t now = time(NULL);
        if (now > last_report) {
            uint64_t packets_delta = packets_sent - last_packets;
            printf("  [%ld s] %lu packets/s\n", now - start_time, packets_delta);

            last_report = now;
            last_packets = packets_sent;

            if (now >= end_time) break;
        }
    }

    printf("\nDone. Total packets sent: %lu\n", packets_sent);

    free(ip_hdrs);
    free(udp_hdrs);
    for (int i = 0; i < BATCH_SIZE; i++) {
        free(packets[i]);
    }
    free(packets);
    free(iovecs);
    free(msgvec);
    close(sock);
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -s SRC_IP       Source IP (default: 127.0.0.1)\n");
    fprintf(stderr, "  -d DST_IP       Destination IP (required)\n");
    fprintf(stderr, "  -p PACKET_SIZE  Packet size in bytes (default: 8192)\n");
    fprintf(stderr, "  -t DURATION     Send duration in seconds (default: 10)\n");
    fprintf(stderr, "  -i INTERFACE    Network interface (default: eth0)\n");
    fprintf(stderr, "  -c CPU          Pin to CPU core\n");
    fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 8192 -c 2\n", prog);
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 1024 -t 30\n", prog);
}

int main(int argc, char *argv[]) {
    char src_ip[INET_ADDRSTRLEN] = "127.0.0.1";
    char dst_ip[INET_ADDRSTRLEN] = "";
    char interface[IFNAMSIZ] = "eth0";
    int packet_size = 8192;
    int duration = 10;
    int cpu_core = -1;

    int opt;
    while ((opt = getopt(argc, argv, "s:d:p:t:i:c:h")) != -1) {
        switch (opt) {
            case 's':
                strncpy(src_ip, optarg, INET_ADDRSTRLEN - 1);
                break;
            case 'd':
                strncpy(dst_ip, optarg, INET_ADDRSTRLEN - 1);
                break;
            case 'p':
                packet_size = atoi(optarg);
                break;
            case 't':
                duration = atoi(optarg);
                break;
            case 'i':
                strncpy(interface, optarg, IFNAMSIZ - 1);
                break;
            case 'c':
                cpu_core = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (strlen(dst_ip) == 0) {
        fprintf(stderr, "Error: Destination IP is required\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("=== UDP Client ===\n");
    printf("Configuration:\n");
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dst_ip);
    printf("  Packet size: %d bytes\n", packet_size);
    printf("  Duration: %d seconds\n", duration);
    printf("  Interface: %s\n", interface);

    int mtu = get_mtu(interface);
    printf("✓ Interface %s MTU: %d bytes\n", interface, mtu);

    printf("\nApplying optimizations:\n");
    set_high_priority();
    lock_memory();
    if (cpu_core >= 0) {
        pin_to_cpu(cpu_core);
    }

    signal(SIGINT, signal_handler);

    send_packets(src_ip, dst_ip, packet_size, duration, mtu);

    return 0;
}
