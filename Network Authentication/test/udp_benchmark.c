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

#define MAX_PACKET_SIZE 65536
#define PAYLOAD_PATTERN 'X'
#define BUFFER_SIZE 1024
#define DEFAULT_MTU 1500

volatile int running = 1;

struct benchmark_stats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    double bandwidth_mbps;
    double duration;
};

/* JSON results structure */
struct json_results {
    struct {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        int packet_size;
        int duration;
        char timestamp[32];
    } metadata;
    
    struct {
        //uint64_t packets_sent;
        double bandwidth_mbps;
        double avg_rtt;
    } results;
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

/* Get MTU of network interface */
int get_mtu(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return DEFAULT_MTU;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        close(sock);
        return DEFAULT_MTU;
    }
    
    close(sock);
    return ifr.ifr_mtu;
}

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
                        double avg_rtt, const char *phase) {
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
        fprintf(fp, "    \"description\": \"UDP performance benchmark with three authentication methods\",\n");
        fprintf(fp, "    \"source_ip\": \"%s\",\n", src_ip);
        fprintf(fp, "    \"dest_ip\": \"%s\",\n", dst_ip);
        fprintf(fp, "    \"duration\": %d\n", duration);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"results\": {\n");
        fprintf(fp, "    \"no_auth\": {\"bandwidth\": {}, \"rtt\": {}},\n"); //, \"packets_sent\": {}},\n");
        fprintf(fp, "    \"ebpf_auth\": {\"bandwidth\": {}, \"rtt\": {}},\n"); //, \"packets_sent\": {}},\n");
        fprintf(fp, "    \"kernel_auth\": {\"bandwidth\": {}, \"rtt\": {}},\n"); //, \"packets_sent\": {}}\n");
        fprintf(fp, "  }\n");
        fprintf(fp, "}\n");
        fclose(fp);
    }
    
    /* Use Python to properly update JSON */
    char python_cmd[2048];
    snprintf(python_cmd, sizeof(python_cmd),
        "python3 -c \"import json; "
        "data = json.load(open('%s')); "
        "data['results']['%s']['bandwidth']['%d'] = %.2f; "
        "data['results']['%s']['rtt']['%d'] = %.3f; "
        //"data['results']['%s']['packets_sent']['%d'] = %lu; "
        "json.dump(data, open('%s', 'w'), indent=2)\"",
        filename, 
        phase, packet_size, bw_stats.bandwidth_mbps,
        phase, packet_size, avg_rtt,
        //phase, packet_size, bw_stats.packets_sent,
        filename);
    
    int ret = system(python_cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to update JSON results\n");
    }
}

/* Create raw UDP packet with spoofed source IP */
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
    udp_hdr->check = 0;  /* Optional for IPv4 */
}

/* Bandwidth test - send as many packets as possible */
struct benchmark_stats bandwidth_test(const char *src_ip_str, const char *dst_ip_str,
                                      int packet_size, int duration) {
    struct benchmark_stats stats = {0};
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return stats;
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return stats;
    }
    
    /* Increase socket send buffer */
    int sndbuf = 4 * 1024 * 1024;  /* 4MB */
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    /* Get MTU for information */
    int mtu = get_mtu();
    
    if (packet_size > mtu) {
        printf("Warning: Packet size (%d) exceeds MTU (%d). Kernel will fragment.\n",
               packet_size, mtu);
        /* Disable MTU discovery to allow kernel fragmentation */
        int ip_pmtudisc = IP_PMTUDISC_DONT;
        setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &ip_pmtudisc, sizeof(ip_pmtudisc));
    }
    
    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);
    
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
        .sin_port = htons(5201)
    };
    
    /* Pre-allocate packet buffer */
    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        perror("malloc");
        close(sock);
        return stats;
    }
    
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;
    uint16_t pkt_id = 0;
    uint16_t src_port = 10000;
    
    /* Main send loop - optimized for speed */
    while (time(NULL) < end_time && running) {
        create_udp_packet(packet, packet_size, src_ip, dst_ip, src_port, 5201, pkt_id);
        
        int bytes_sent = sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dst_addr,
                               sizeof(dst_addr));
        
        if (bytes_sent < 0) {
            if (errno == EMSGSIZE) {
                fprintf(stderr, "sendto: Message too long (MTU=%d, packet_size=%d)\n", mtu, packet_size);
                break;
            } else if (errno != EINTR) {
                perror("sendto");
                break;
            }
        } else {
            stats.packets_sent++;
            stats.bytes_sent += bytes_sent;
        }
        
        pkt_id++;
        src_port++;
        if (src_port > 65000) {
            src_port = 10000;
        }
    }
    
    time_t actual_end = time(NULL);
    stats.duration = difftime(actual_end, start_time);
    
    if (stats.duration > 0) {
        stats.bandwidth_mbps = (stats.bytes_sent * 8.0) / (stats.duration * 1000000.0);
    }
    
    free(packet);
    close(sock);
    
    return stats;
}

/* RTT test - measure round-trip time with spoofed source IP */
double rtt_test(const char *src_ip_str, const char *dst_ip_str,
                int packet_size, int num_packets) {
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (send_sock < 0) {
        perror("socket");
        return 0.0;
    }
    
    int one = 1;
    setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    /* Create receive socket */
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        perror("socket");
        close(send_sock);
        return 0.0;
    }
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(src_ip_str),
        .sin_port = htons(5202)
    };
    
    /* Try to bind to spoofed IP, fallback to all interfaces */
    if (bind(recv_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(recv_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(recv_sock);
            close(send_sock);
            return 0.0;
        }
    }
    
    /* Set socket timeout to 2 seconds */
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);
    
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
        .sin_port = htons(5201)
    };
    
    uint8_t *packet = malloc(packet_size);
    uint8_t *recv_buf = malloc(packet_size + 100);
    if (!packet || !recv_buf) {
        perror("malloc");
        free(packet);
        free(recv_buf);
        close(recv_sock);
        close(send_sock);
        return 0.0;
    }
    
    int successful_responses = 0;
    double total_rtt = 0.0;
    
    for (int i = 0; i < num_packets; i++) {
        uint32_t seq = htonl(i);
        
        create_udp_packet(packet, packet_size, src_ip, dst_ip, 5202, 5201, i);
        /* Embed sequence in payload */
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), &seq, 4);
        
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        if (sendto(send_sock, packet, packet_size, 0, (struct sockaddr *)&dst_addr,
                   sizeof(dst_addr)) < 0) {
            perror("sendto");
            continue;
        }
        
        struct sockaddr_in src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        
        if (recvfrom(recv_sock, recv_buf, packet_size + 100, 0,
                    (struct sockaddr *)&src_addr, &src_addr_len) > 0) {
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            double rtt_ms = ((end.tv_sec - start.tv_sec) * 1000.0) +
                           ((end.tv_nsec - start.tv_nsec) / 1000000.0);
            total_rtt += rtt_ms;
            successful_responses++;
        }
        
        usleep(10000);  /* 10ms delay between packets */
    }
    
    free(packet);
    free(recv_buf);
    close(recv_sock);
    close(send_sock);
    
    if (successful_responses == 0) {
        return 0.0;
    }
    
    return total_rtt / successful_responses;
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-s SRC_IP] -d DST_IP [-p PACKET_SIZE] [-t DURATION] [-m MODE] [-o OUTPUT]\n", prog);
    fprintf(stderr, "  -s SRC_IP       Source IP (spoofed)\n");
    fprintf(stderr, "  -d DST_IP       Destination IP\n");
    fprintf(stderr, "  -p PACKET_SIZE  Packet size in bytes (default: 128)\n");
    fprintf(stderr, "  -t DURATION     Test duration in seconds (default: 10)\n");
    fprintf(stderr, "  -m MODE         Test mode: both, bandwidth, or rtt (default: both)\n");
    fprintf(stderr, "  -o OUTPUT       Output JSON file (default: udp_benchmark_results.json)\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  sudo %s -s 10.0.0.1 -d 192.168.1.100 -p 128 -t 10\n", prog);
    fprintf(stderr, "  sudo %s -s 10.0.0.1 -d 192.168.1.100 -p 128 -m rtt\n", prog);
}

void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    char src_ip[INET_ADDRSTRLEN] = "127.0.0.1";
    char dst_ip[INET_ADDRSTRLEN] = "";
    char output_file[256] = "udp_benchmark_results.json";
    char phase[32] = "no_auth";
    int packet_size = 128;
    int duration = 10;
    char mode[16] = "both";
    
    int opt;
    while ((opt = getopt(argc, argv, "s:d:p:t:m:o:a:h")) != -1) {
        switch (opt) {
            case 's':
                strncpy(src_ip, optarg, INET_ADDRSTRLEN - 1);
                break;
            case 'd':
                strncpy(dst_ip, optarg, INET_ADDRSTRLEN - 1);
                break;
            case 'p':
                packet_size = atoi(optarg);
                if (packet_size < 28 || packet_size > MAX_PACKET_SIZE) {
                    fprintf(stderr, "Packet size must be between 28 and %d\n", MAX_PACKET_SIZE);
                    return 1;
                }
                break;
            case 't':
                duration = atoi(optarg);
                break;
            case 'm':
                strncpy(mode, optarg, sizeof(mode) - 1);
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
    
    signal(SIGINT, signal_handler);
    
    struct benchmark_stats bw_stats = {0};
    double avg_rtt = 0.0;
    
    if (strcmp(mode, "bandwidth") == 0 || strcmp(mode, "both") == 0) {
        printf("Running bandwidth test...\n");
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Packet size: %d bytes\n", packet_size);
        printf("Duration: %d seconds\n", duration);
        printf("Phase: %s\n", phase);
        
        bw_stats = bandwidth_test(src_ip, dst_ip, packet_size, duration);
        
        printf("Results:\n");
        printf("  Packets sent: %lu\n", bw_stats.packets_sent);
        printf("  Bytes sent: %lu\n", bw_stats.bytes_sent);
        printf("  Bandwidth: %.2f Mbps\n", bw_stats.bandwidth_mbps);
        printf("  Duration: %.2f seconds\n\n", bw_stats.duration);
    }
    
    if (strcmp(mode, "rtt") == 0 || strcmp(mode, "both") == 0) {
        printf("Running RTT test...\n");
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Packet size: %d bytes\n", packet_size);
        
        avg_rtt = rtt_test(src_ip, dst_ip, packet_size, 100);
        printf("Average RTT: %.3f ms\n", avg_rtt);
    }
    
    /* Save results to JSON with phase tagging */
    if (strcmp(mode, "both") == 0 || strcmp(mode, "bandwidth") == 0) {
        write_json_results(output_file, src_ip, dst_ip, packet_size, duration, bw_stats, avg_rtt, phase);
        printf("Results saved to: %s\n", output_file);
    }
    
    if (strcmp(mode, "both") != 0 && strcmp(mode, "bandwidth") != 0 && strcmp(mode, "rtt") != 0) {
        fprintf(stderr, "Unknown mode: %s (use 'both', 'bandwidth', or 'rtt')\n", mode);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
