/*
 * High-Performance UDP Echo Server
 * 
 * Optimizations:
 * - CPU pinning
 * - High priority scheduling
 * - Large socket buffers
 * - Batch processing with recvmmsg/sendmmsg
 * - Memory locking
 * - Minimal processing overhead
 * 
 * Compile: gcc -o udp_echo_server_opt udp_echo_server.c -O3 -march=native
 * Run: sudo ./udp_echo_server_opt -p 5201 -c 3
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/mman.h>
#include <fcntl.h>

#define MAX_PACKET_SIZE 65536
#define DEFAULT_PORT 5201
#define BATCH_SIZE 64

volatile int running = 1;

void signal_handler(int sig) {
    printf("\nShutting down gracefully...\n");
    running = 0;
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

/* Set real-time priority (requires root) */
int set_realtime_priority(void) {
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    
    if (sched_setscheduler(0, SCHED_FIFO, &param) == 0) {
        printf("✓ Real-time scheduling enabled (SCHED_FIFO, priority: %d)\n", 
               param.sched_priority);
        return 0;
    } else {
        perror("sched_setscheduler");
        printf("  (Continuing without real-time priority)\n");
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

/* Standard echo server (baseline) */
void run_standard_echo_server(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    /* Socket options */
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    /* Increase socket buffers */
    int bufsize = 32 * 1024 * 1024;  /* 32MB */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    /* Bind */
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock);
        return;
    }
    
    printf("\n=== UDP Echo Server (Standard Mode) ===\n");
    printf("Listening on port %d\n", port);
    printf("Press Ctrl+C to stop\n\n");
    
    uint8_t *buffer = malloc(MAX_PACKET_SIZE);
    if (!buffer) {
        perror("malloc");
        close(sock);
        return;
    }
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    time_t last_stats = time(NULL);
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        /* Receive packet */
        ssize_t recv_len = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0,
                                    (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (recv_len < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        
        /* Echo back immediately */
        ssize_t sent_len = sendto(sock, buffer, recv_len, 0,
                                  (struct sockaddr *)&client_addr, client_addr_len);
        
        if (sent_len < 0) {
            if (errno != EINTR) {
                perror("sendto");
            }
            continue;
        }
        
        total_packets++;
        total_bytes += recv_len;
        
        /* Print stats every 5 seconds */
        time_t now = time(NULL);
        if (now - last_stats >= 5) {
            double elapsed = difftime(now, last_stats);
            double pps = total_packets / elapsed;
            double mbps = (total_bytes * 8.0) / (elapsed * 1000000.0);
            
            printf("[Stats] Packets: %lu (%.0f pps), Throughput: %.2f Mbps\n",
                   total_packets, pps, mbps);
            
            total_packets = 0;
            total_bytes = 0;
            last_stats = now;
        }
    }
    
    free(buffer);
    close(sock);
}

/* High-performance echo server with batch processing */
void run_batch_echo_server(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    /* Socket options */
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    /* Increase socket buffers */
    int bufsize = 64 * 1024 * 1024;  /* 64MB */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    /* Set socket to non-blocking for batch processing */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    /* Bind */
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock);
        return;
    }
    
    printf("\n=== UDP Echo Server (Batch Mode with recvmmsg/sendmmsg) ===\n");
    printf("Listening on port %d\n", port);
    printf("Batch size: %d packets\n", BATCH_SIZE);
    printf("Press Ctrl+C to stop\n\n");
    
    /* Allocate batch buffers */
    struct mmsghdr *recv_msgs = calloc(BATCH_SIZE, sizeof(struct mmsghdr));
    struct mmsghdr *send_msgs = calloc(BATCH_SIZE, sizeof(struct mmsghdr));
    struct iovec *recv_iovecs = calloc(BATCH_SIZE, sizeof(struct iovec));
    struct iovec *send_iovecs = calloc(BATCH_SIZE, sizeof(struct iovec));
    struct sockaddr_in *client_addrs = calloc(BATCH_SIZE, sizeof(struct sockaddr_in));
    uint8_t **buffers = calloc(BATCH_SIZE, sizeof(uint8_t *));
    
    if (!recv_msgs || !send_msgs || !recv_iovecs || !send_iovecs || !client_addrs || !buffers) {
        perror("malloc");
        goto cleanup;
    }
    
    /* Allocate packet buffers */
    for (int i = 0; i < BATCH_SIZE; i++) {
        buffers[i] = malloc(MAX_PACKET_SIZE);
        if (!buffers[i]) {
            perror("malloc buffer");
            goto cleanup;
        }
        
        /* Setup receive structures */
        recv_iovecs[i].iov_base = buffers[i];
        recv_iovecs[i].iov_len = MAX_PACKET_SIZE;
        
        recv_msgs[i].msg_hdr.msg_iov = &recv_iovecs[i];
        recv_msgs[i].msg_hdr.msg_iovlen = 1;
        recv_msgs[i].msg_hdr.msg_name = &client_addrs[i];
        recv_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        
        /* Setup send structures */
        send_iovecs[i].iov_base = buffers[i];
        send_iovecs[i].iov_len = MAX_PACKET_SIZE;
        
        send_msgs[i].msg_hdr.msg_iov = &send_iovecs[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
        send_msgs[i].msg_hdr.msg_name = &client_addrs[i];
        send_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    }
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    time_t last_stats = time(NULL);
    
    while (running) {
        /* Receive batch of packets */
        int num_received = recvmmsg(sock, recv_msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
        
        if (num_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No packets available, brief wait */
                usleep(1);
                continue;
            } else if (errno != EINTR) {
                perror("recvmmsg");
            }
            continue;
        }
        
        if (num_received == 0) continue;
        
        /* Update send message lengths based on received lengths */
        for (int i = 0; i < num_received; i++) {
            send_iovecs[i].iov_len = recv_msgs[i].msg_len;
            total_bytes += recv_msgs[i].msg_len;
        }
        
        /* Send batch of packets back */
        int num_sent = sendmmsg(sock, send_msgs, num_received, 0);
        
        if (num_sent < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                perror("sendmmsg");
            }
            continue;
        }
        
        total_packets += num_sent;
        
        /* Reset iovec lengths for next receive */
        for (int i = 0; i < num_received; i++) {
            recv_iovecs[i].iov_len = MAX_PACKET_SIZE;
        }
        
        /* Print stats every 5 seconds */
        time_t now = time(NULL);
        if (now - last_stats >= 5) {
            double elapsed = difftime(now, last_stats);
            double pps = total_packets / elapsed;
            double mbps = (total_bytes * 8.0) / (elapsed * 1000000.0);
            
            printf("[Stats] Packets: %lu (%.0f pps), Throughput: %.2f Mbps\n",
                   total_packets, pps, mbps);
            
            total_packets = 0;
            total_bytes = 0;
            last_stats = now;
        }
    }

cleanup:
    if (buffers) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            free(buffers[i]);
        }
        free(buffers);
    }
    free(client_addrs);
    free(send_iovecs);
    free(recv_iovecs);
    free(send_msgs);
    free(recv_msgs);
    close(sock);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    int cpu_core = -1;
    int use_batch = 1;  /* Default to batch mode */
    int use_realtime = 0;
    
    int opt;
    while ((opt = getopt(argc, argv, "p:c:srh")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'c':
                cpu_core = atoi(optarg);
                break;
            case 's':
                use_batch = 0;  /* Standard mode */
                break;
            case 'r':
                use_realtime = 1;  /* Real-time scheduling */
                break;
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                printf("  -p PORT    UDP port to listen on (default: %d)\n", DEFAULT_PORT);
                printf("  -c CPU     Pin to specific CPU core\n");
                printf("  -s         Use standard mode (default: batch mode)\n");
                printf("  -r         Enable real-time scheduling (requires root)\n");
                printf("\nExamples:\n");
                printf("  sudo %s -p 5201 -c 3 -r     # High-performance mode\n", argv[0]);
                printf("  sudo %s -p 5201 -s          # Standard mode\n", argv[0]);
                return 0;
            default:
                fprintf(stderr, "Use -h for help\n");
                return 1;
        }
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=== UDP Echo Server Optimizer ===\n");
    printf("Port: %d\n", port);
    printf("Mode: %s\n", use_batch ? "Batch (recvmmsg/sendmmsg)" : "Standard");
    printf("\nApplying optimizations:\n");
    
    set_high_priority();
    lock_memory();
    
    if (cpu_core >= 0) {
        pin_to_cpu(cpu_core);
    }
    
    if (use_realtime) {
        set_realtime_priority();
    }
    
    printf("\n💡 Performance Tips:\n");
    printf("   1. Increase system UDP buffer limits:\n");
    printf("      sudo sysctl -w net.core.rmem_max=134217728\n");
    printf("      sudo sysctl -w net.core.wmem_max=134217728\n");
    printf("   2. Set CPU governor to performance:\n");
    printf("      sudo cpupower frequency-set -g performance\n");
    printf("   3. Disable IRQ balance for network card\n");
    printf("   4. Increase NIC ring buffer:\n");
    printf("      sudo ethtool -G <interface> rx 4096 tx 4096\n");
    
    /* Run appropriate server mode */
    if (use_batch) {
        run_batch_echo_server(port);
    } else {
        run_standard_echo_server(port);
    }
    
    printf("\nServer stopped.\n");
    return 0;
}
