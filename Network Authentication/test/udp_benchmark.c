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
#define RTT_SAMPLES 100

volatile int running = 1;

struct benchmark_stats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    double bandwidth_mbps;
    double bandwidth_std;
    double duration;
};

struct rtt_stats {
    double avg_rtt;
    double std_rtt;
    double min_rtt;
    double max_rtt;
    int successful;
    int total;
};

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

/* Calculate standard deviation */
double calculate_std_dev(double *values, int count, double mean) {
    if (count <= 1) return 0.0;
    
    double sum_sq_diff = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    
    return sqrt(sum_sq_diff / (count - 1));
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

/* High-performance bandwidth test with sendmmsg - calculate std dev from per-second samples */
struct benchmark_stats bandwidth_test_sendmmsg(const char *src_ip_str, const char *dst_ip_str,
                                               int packet_size, int duration, int mtu) {
    struct benchmark_stats stats = {0};
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return stats;
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
        return stats;
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
            return stats;
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
    
    printf("\nStarting bandwidth test (duration: %d seconds)...\n", duration);
    
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;
    
    uint16_t pkt_id = 0;
    uint16_t src_port = 10000;
    
    /* Pre-calculate header positions */
    struct iphdr **ip_hdrs = malloc(BATCH_SIZE * sizeof(struct iphdr *));
    struct udphdr **udp_hdrs = malloc(BATCH_SIZE * sizeof(struct udphdr *));
    for (int i = 0; i < BATCH_SIZE; i++) {
        ip_hdrs[i] = (struct iphdr *)packets[i];
        udp_hdrs[i] = (struct udphdr *)(packets[i] + sizeof(struct iphdr));
    }
    
    /* Per-second tracking for standard deviation */
    double *per_second_bw = malloc(duration * sizeof(double));
    if (!per_second_bw) {
        perror("malloc per_second_bw");
        goto cleanup;
    }
    
    time_t last_report = start_time;
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    int second_count = 0;
    
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
            stats.packets_sent += sent;
            stats.bytes_sent += sent * effective_packet_size;
            
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
        
        /* Check time and record per-second bandwidth */
        time_t now = time(NULL);
        if (now > last_report) {
            uint64_t packets_delta = stats.packets_sent - last_packets;
            uint64_t bytes_delta = stats.bytes_sent - last_bytes;
            double interval_mbps = (bytes_delta * 8.0) / 1000000.0;
            
            if (second_count < duration) {
                per_second_bw[second_count] = interval_mbps;
                second_count++;
            }
            
            printf("  [%ld s] %lu packets/s, %.2f Mbps\n", 
                   now - start_time, packets_delta, interval_mbps);
            
            last_report = now;
            last_packets = stats.packets_sent;
            last_bytes = stats.bytes_sent;
            
            if (now >= end_time) break;
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    stats.duration = (end_ts.tv_sec - start_ts.tv_sec) + 
                     (end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
    
    /* Calculate overall bandwidth */
    if (stats.duration > 0) {
        stats.bandwidth_mbps = (stats.bytes_sent * 8.0) / (stats.duration * 1000000.0);
    }
    
    /* Calculate standard deviation from per-second samples */
    if (second_count > 1) {
        stats.bandwidth_std = calculate_std_dev(per_second_bw, second_count, stats.bandwidth_mbps);
    } else {
        stats.bandwidth_std = 0.0;
    }
    
    printf("\nTest completed:\n");
    printf("  Duration: %.3f seconds\n", stats.duration);
    printf("  Packets sent: %lu\n", stats.packets_sent);
    printf("  Bytes sent: %lu\n", stats.bytes_sent);
    printf("  Packets per second: %.0f\n", stats.packets_sent / stats.duration);
    printf("  Bandwidth: %.2f ± %.2f Mbps (%.2f ± %.2f Gbps)\n", 
           stats.bandwidth_mbps, stats.bandwidth_std,
           stats.bandwidth_mbps / 1000.0, stats.bandwidth_std / 1000.0);

cleanup:
    free(per_second_bw);
    free(ip_hdrs);
    free(udp_hdrs);
    for (int i = 0; i < BATCH_SIZE; i++) {
        free(packets[i]);
    }
    free(packets);
    free(iovecs);
    free(msgvec);
    close(sock);
    
    return stats;
}

/* RTT test with sendmmsg for sending, regular socket for receiving */
struct rtt_stats rtt_test_optimized(const char *src_ip_str, const char *dst_ip_str,
                                   int packet_size, int mtu) {
    struct rtt_stats stats = {0};
    stats.min_rtt = 999999.0;
    stats.max_rtt = 0.0;
    stats.total = RTT_SAMPLES;
    
    double *rtt_samples = malloc(RTT_SAMPLES * sizeof(double));
    if (!rtt_samples) {
        perror("malloc rtt_samples");
        return stats;
    }
    
    printf("\nRunning RTT test with %d samples...\n", RTT_SAMPLES);
    
    /* Create send socket (raw) */
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (send_sock < 0) {
        perror("socket send");
        free(rtt_samples);
        return stats;
    }
    
    int one = 1;
    setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    /* Create receive socket (dgram for echo responses) */
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        perror("socket recv");
        close(send_sock);
        free(rtt_samples);
        return stats;
    }
    
    /* Bind receive socket */
    struct sockaddr_in recv_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(src_ip_str),
        .sin_port = htons(5202)
    };
    
    /* Try to bind to spoofed IP, fallback to INADDR_ANY */
    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
            perror("bind");
            close(recv_sock);
            close(send_sock);
            free(rtt_samples);
            return stats;
        }
    }
    
    /* Set receive timeout */
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Increase receive buffer */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);
    
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
        .sin_port = htons(5201)
    };
    
    /* Determine effective packet size */
    int effective_packet_size = packet_size;
    if (packet_size > mtu) {
        effective_packet_size = mtu - 50;
        printf("  Using packet size: %d bytes (MTU limited)\n", effective_packet_size);
    }
    
    /* Allocate packet buffer */
    uint8_t *packet = malloc(effective_packet_size);
    uint8_t *recv_buf = malloc(65536);
    if (!packet || !recv_buf) {
        perror("malloc");
        free(packet);
        free(recv_buf);
        free(rtt_samples);
        close(recv_sock);
        close(send_sock);
        return stats;
    }
    
    /* Create packet template */
    create_udp_packet(packet, effective_packet_size, src_ip, dst_ip, 5202, 5201, 0);
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct iphdr));
    uint8_t *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    printf("  Sending RTT probes");
    fflush(stdout);
    
    /* Send RTT probes */
    for (int i = 0; i < RTT_SAMPLES; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        /* Embed sequence number in payload */
        uint32_t seq = htonl(i);
        memcpy(payload, &seq, sizeof(seq));
        
        /* Update packet ID */
        ip_hdr->id = htons(i);
        ip_hdr->check = 0;
        ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
        
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        /* Send packet */
        if (sendto(send_sock, packet, effective_packet_size, 0, 
                   (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
            if (errno != EINTR) {
                perror("sendto");
            }
            rtt_samples[i] = -1.0;  // Mark as failed
            continue;
        }
        
        /* Wait for echo response */
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t recv_len = recvfrom(recv_sock, recv_buf, 65536, 0,
                                    (struct sockaddr *)&from_addr, &from_len);
        
        if (recv_len > 0) {
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            double rtt_ms = ((end.tv_sec - start.tv_sec) * 1000.0) +
                           ((end.tv_nsec - start.tv_nsec) / 1000000.0);
            
            rtt_samples[i] = rtt_ms;
            stats.successful++;
            
            if (rtt_ms < stats.min_rtt) stats.min_rtt = rtt_ms;
            if (rtt_ms > stats.max_rtt) stats.max_rtt = rtt_ms;
        } else {
            rtt_samples[i] = -1.0;  // Mark as timeout
        }
        
        /* Small delay between probes */
        usleep(5000);  // 5ms
    }
    
    printf(" done\n");
    
    /* Calculate statistics */
    if (stats.successful > 0) {
        double sum = 0.0;
        for (int i = 0; i < RTT_SAMPLES; i++) {
            if (rtt_samples[i] > 0) {
                sum += rtt_samples[i];
            }
        }
        stats.avg_rtt = sum / stats.successful;
        stats.std_rtt = calculate_std_dev(rtt_samples, RTT_SAMPLES, stats.avg_rtt);
        
        /* Recalculate std dev using only successful samples */
        double sum_sq_diff = 0.0;
        for (int i = 0; i < RTT_SAMPLES; i++) {
            if (rtt_samples[i] > 0) {
                double diff = rtt_samples[i] - stats.avg_rtt;
                sum_sq_diff += diff * diff;
            }
        }
        if (stats.successful > 1) {
            stats.std_rtt = sqrt(sum_sq_diff / (stats.successful - 1));
        }
    }
    
    free(rtt_samples);
    free(packet);
    free(recv_buf);
    close(recv_sock);
    close(send_sock);
    
    return stats;
}

void signal_handler(int sig) {
    running = 0;
}

/* Get timestamp string */
const char* get_timestamp(void) {
    static char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    return timestamp;
}

/* Write results to JSON file with phase tagging */
void write_json_results(const char *filename, const char *src_ip, const char *dst_ip,
                        int packet_size, int duration, struct benchmark_stats bw_stats,
                        struct rtt_stats rtt_stats, const char *phase) {
    FILE *fp = fopen(filename, "r");
    int file_exists = (fp != NULL);
    if (fp) fclose(fp);
    
    if (!file_exists) {
        /* Create new JSON structure with three phase objects */
        fp = fopen(filename, "w");
        if (!fp) {
            fprintf(stderr, "Warning: Could not create %s\n", filename);
            return;
        }
        
        fprintf(fp, "{\n");
        fprintf(fp, "  \"metadata\": {\n");
        fprintf(fp, "    \"timestamp\": \"%s\",\n", get_timestamp());
        fprintf(fp, "    \"description\": \"UDP performance benchmark with sendmmsg and IP spoofing\",\n");
        fprintf(fp, "    \"source_ip\": \"%s\",\n", src_ip);
        fprintf(fp, "    \"dest_ip\": \"%s\",\n", dst_ip);
        fprintf(fp, "    \"duration\": %d\n", duration);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"results\": {\n");
        fprintf(fp, "    \"no_auth\": {\"bandwidth\": {}, \"bandwidth_std\": {}, \"rtt\": {}, \"rtt_std\": {}, \"rtt_min\": {}, \"rtt_max\": {}, \"packets_sent\": {}},\n");
        fprintf(fp, "    \"ebpf_auth\": {\"bandwidth\": {}, \"bandwidth_std\": {}, \"rtt\": {}, \"rtt_std\": {}, \"rtt_min\": {}, \"rtt_max\": {}, \"packets_sent\": {}},\n");
        fprintf(fp, "    \"kernel_auth\": {\"bandwidth\": {}, \"bandwidth_std\": {}, \"rtt\": {}, \"rtt_std\": {}, \"rtt_min\": {}, \"rtt_max\": {}, \"packets_sent\": {}}\n");
        fprintf(fp, "  }\n");
        fprintf(fp, "}\n");
        fclose(fp);
    }
    
    /* Use Python to properly update JSON */
    char python_cmd[4096];
    snprintf(python_cmd, sizeof(python_cmd),
        "python3 -c \"import json; "
        "data = json.load(open('%s')); "
        "data['results']['%s']['bandwidth']['%d'] = %.2f; "
        "data['results']['%s']['bandwidth_std']['%d'] = %.2f; "
        "data['results']['%s']['rtt']['%d'] = %.3f; "
        "data['results']['%s']['rtt_std']['%d'] = %.3f; "
        "data['results']['%s']['rtt_min']['%d'] = %.3f; "
        "data['results']['%s']['rtt_max']['%d'] = %.3f; "
        "data['results']['%s']['packets_sent']['%d'] = %lu; "
        "json.dump(data, open('%s', 'w'), indent=2)\"",
        filename,
        phase, packet_size, bw_stats.bandwidth_mbps,
        phase, packet_size, bw_stats.bandwidth_std,
        phase, packet_size, rtt_stats.avg_rtt,
        phase, packet_size, rtt_stats.std_rtt,
        phase, packet_size, rtt_stats.min_rtt,
        phase, packet_size, rtt_stats.max_rtt,
        phase, packet_size, bw_stats.packets_sent,
        filename);
    
    int ret = system(python_cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to update JSON results (is python3 installed?)\n");
    }
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -s SRC_IP       Source IP (default: 127.0.0.1)\n");
    fprintf(stderr, "  -d DST_IP       Destination IP (required)\n");
    fprintf(stderr, "  -p PACKET_SIZE  Packet size in bytes (default: 8192)\n");
    fprintf(stderr, "  -t DURATION     Bandwidth test duration in seconds (default: 10)\n");
    fprintf(stderr, "  -i INTERFACE    Network interface (default: eth0)\n");
    fprintf(stderr, "  -c CPU          Pin to CPU core\n");
    fprintf(stderr, "  -m MODE         Test mode: both, bandwidth, rtt (default: both)\n");
    fprintf(stderr, "  -r RUNS         Number of runs for std dev (default: 3)\n");
    fprintf(stderr, "  -o OUTPUT       Output JSON file (default: udp_benchmark_results.json)\n");
    fprintf(stderr, "  -a PHASE        Phase: no_auth, ebpf_auth, kernel_auth (default: no_auth)\n");
    fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 8192 -c 2 -a no_auth\n", prog);
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 1024 -m rtt -a ebpf_auth\n", prog);
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 8192 -r 5 -o results.json\n", prog);
}

int main(int argc, char *argv[]) {
    char src_ip[INET_ADDRSTRLEN] = "127.0.0.1";
    char dst_ip[INET_ADDRSTRLEN] = "";
    char interface[IFNAMSIZ] = "eth0";
    char mode[16] = "both";
    char output_file[256] = "udp_benchmark_results.json";
    char phase[32] = "no_auth";
    int packet_size = 8192;
    int duration = 10;
    int cpu_core = -1;
    int num_runs = 3;
    
    int opt;
    while ((opt = getopt(argc, argv, "s:d:p:t:i:c:m:r:o:a:h")) != -1) {
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
            case 'm':
                strncpy(mode, optarg, sizeof(mode) - 1);
                break;
            case 'r':
                num_runs = atoi(optarg);
                if (num_runs < 1) num_runs = 1;
                if (num_runs > 10) num_runs = 10;
                break;
            case 'o':
                strncpy(output_file, optarg, sizeof(output_file) - 1);
                break;
            case 'a':
                strncpy(phase, optarg, sizeof(phase) - 1);
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
    
    printf("=== Advanced UDP Benchmark Tool ===\n");
    printf("Configuration:\n");
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dst_ip);
    printf("  Packet size: %d bytes\n", packet_size);
    printf("  Duration: %d seconds (per run)\n", duration);
    printf("  Mode: %s\n", mode);
    printf("  Runs: %d\n", num_runs);
    printf("  Interface: %s\n", interface);
    printf("  Phase: %s\n", phase);
    printf("  Output file: %s\n", output_file);
    
    int mtu = get_mtu(interface);
    printf("✓ Interface %s MTU: %d bytes\n", interface, mtu);
    
    printf("\nApplying optimizations:\n");
    set_high_priority();
    lock_memory();
    if (cpu_core >= 0) {
        pin_to_cpu(cpu_core);
    }
    
    signal(SIGINT, signal_handler);
    
    printf("\n=== Starting Tests ===\n");
    
    struct benchmark_stats bw_stats = {0};
    struct rtt_stats rtt_stats = {0};
    
    if (strcmp(mode, "bandwidth") == 0 || strcmp(mode, "both") == 0) {
        printf("\n--- Bandwidth Test ---\n");
        bw_stats = bandwidth_test_sendmmsg(src_ip, dst_ip, packet_size, duration, mtu); // num_runs);
        
        printf("\nBandwidth Results:\n");
        printf("  Average: %.2f ± %.2f Mbps (%.2f ± %.2f Gbps)\n", 
               bw_stats.bandwidth_mbps, bw_stats.bandwidth_std,
               bw_stats.bandwidth_mbps / 1000.0, bw_stats.bandwidth_std / 1000.0);
        printf("  Total packets sent: %lu\n", bw_stats.packets_sent);
        printf("  Total bytes sent: %lu\n", bw_stats.bytes_sent);
        printf("  Total duration: %.2f seconds\n", bw_stats.duration);
    }
    
    if (strcmp(mode, "rtt") == 0 || strcmp(mode, "both") == 0) {
        if (strcmp(mode, "both") == 0) {
            printf("\n");
            sleep(2);  // Brief pause between tests
        }
        
        printf("--- RTT Test ---\n");
        rtt_stats = rtt_test_optimized(src_ip, dst_ip, packet_size, mtu);
        
        printf("\nRTT Results:\n");
        printf("  Average: %.3f ± %.3f ms\n", rtt_stats.avg_rtt, rtt_stats.std_rtt);
        printf("  Min: %.3f ms\n", rtt_stats.min_rtt);
        printf("  Max: %.3f ms\n", rtt_stats.max_rtt);
        printf("  Success rate: %d/%d (%.1f%%)\n", 
               rtt_stats.successful, rtt_stats.total,
               (rtt_stats.successful * 100.0) / rtt_stats.total);
    }
    
    printf("\n=== Test Complete ===\n");
    
    /* Save results to JSON */
    write_json_results(output_file, src_ip, dst_ip, packet_size, duration, 
                      bw_stats, rtt_stats, phase);
    printf("\n✓ Results saved to: %s\n", output_file);
    
    return 0;
}
