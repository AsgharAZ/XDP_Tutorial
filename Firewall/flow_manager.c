/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Flow key and state structures (must match kernel-side) */
struct flow_key_v4 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct flow_state {
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u8  tcp_state;
};

/* Flow timeout configuration (in milliseconds) */
#define TCP_TIMEOUT_MS    120000  /* 2 minutes for TCP */
#define UDP_TIMEOUT_MS    30000   /* 30 seconds for UDP */
#define ICMP_TIMEOUT_MS   10000   /* 10 seconds for ICMP */

/* Global variables */
static int map_fd = -1;
static FILE *log_file = NULL;
static volatile int running = 1;

/* Signal handler for graceful shutdown */
static void sig_handler(int sig)
{
    running = 0;
}

/* Convert IP address to string */
static void ip_to_string(__u32 ip, char *buf, size_t buf_size)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(buf, buf_size, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/* Convert protocol number to string */
static const char* proto_to_string(__u8 proto)
{
    switch(proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "UNKNOWN";
    }
}

/* Get timeout for protocol in nanoseconds */
static __u64 get_timeout_ns(__u8 proto)
{
    switch(proto) {
        case IPPROTO_TCP:  return (__u64)TCP_TIMEOUT_MS * 1000000ULL;
        case IPPROTO_UDP:  return (__u64)UDP_TIMEOUT_MS * 1000000ULL;
        case IPPROTO_ICMP: return (__u64)ICMP_TIMEOUT_MS * 1000000ULL;
        default: return (__u64)UDP_TIMEOUT_MS * 1000000ULL;
    }
}

/* Write flow to log file */
static void log_flow(const struct flow_key_v4 *key, const struct flow_state *state, const char *reason)
{
    char src_ip_str[16], dst_ip_str[16];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    ip_to_string(key->src_ip, src_ip_str, sizeof(src_ip_str));
    ip_to_string(key->dst_ip, dst_ip_str, sizeof(dst_ip_str));
    
    fprintf(log_file, "[%s] %s %s:%u -> %s:%u | Packets: %llu | Bytes: %llu | Reason: %s\n",
            time_str,
            proto_to_string(key->proto),
            src_ip_str, ntohs(key->src_port),
            dst_ip_str, ntohs(key->dst_port),
            state->packets, state->bytes, reason);
    fflush(log_file);
}

/* Check if flow should be expired */
static int should_expire_flow(const struct flow_state *state, __u8 proto)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    __u64 now_ns = (now.tv_sec * 1000000000ULL) + now.tv_nsec;
    __u64 timeout_ns = get_timeout_ns(proto);
    
    return (now_ns - state->last_seen_ns) > timeout_ns;
}

/* Process a single flow entry */
static int process_flow_entry(void *key, void *value, void *ctx)
{
    struct flow_key_v4 *flow_key = (struct flow_key_v4 *)key;
    struct flow_state *flow_state = (struct flow_state *)value;
    
    if (should_expire_flow(flow_state, flow_key->proto)) {
        log_flow(flow_key, flow_state, "TIMEOUT");
        
        /* Delete expired flow from map */
        if (bpf_map_delete_elem(map_fd, flow_key) < 0) {
            fprintf(stderr, "Failed to delete flow from map: %s\n", strerror(errno));
            return 1; /* Continue processing other flows */
        }
    }
    
    return 0; /* Continue processing */
}

/* Main flow management loop */
static void flow_manager_loop(void)
{
    printf("Starting flow manager...\n");
    printf("TCP timeout: %d seconds\n", TCP_TIMEOUT_MS / 1000);
    printf("UDP timeout: %d seconds\n", UDP_TIMEOUT_MS / 1000);
    printf("ICMP timeout: %d seconds\n", ICMP_TIMEOUT_MS / 1000);
    printf("Press Ctrl+C to stop\n\n");
    
    while (running) {
        /* Iterate through all flows in the map */
        struct flow_key_v4 key = {};
        struct flow_key_v4 next_key = {};
        
        /* Start iteration */
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            struct flow_state state = {};
            
            /* Get the flow state */
            if (bpf_map_lookup_elem(map_fd, &next_key, &state) == 0) {
                if (should_expire_flow(&state, next_key.proto)) {
                    log_flow(&next_key, &state, "TIMEOUT");
                    
                    /* Delete expired flow from map */
                    if (bpf_map_delete_elem(map_fd, &next_key) < 0) {
                        fprintf(stderr, "Failed to delete flow from map: %s\n", strerror(errno));
                    }
                }
            }
            
            /* Move to next key */
            key = next_key;
        }
        
        /* Sleep for 1 second before next check */
        sleep(1);
    }
}

/* Cleanup function */
static void cleanup(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    if (map_fd >= 0) {
        close(map_fd);
        map_fd = -1;
    }
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    int err;
    
    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Increase resource limits */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
        return 1;
    }
    
    /* Open log file */
    log_file = fopen("flow_log.txt", "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        return 1;
    }
    
    /* Load BPF object */
    obj = bpf_object__open_file("xdp_prog_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        cleanup();
        return 1;
    }
    
    /* Load BPF object */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        cleanup();
        return 1;
    }
    
    /* Find the flow map */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "flow_map");
    if (!map) {
        fprintf(stderr, "Failed to find flow_map in BPF object\n");
        cleanup();
        return 1;
    }
    
    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(-map_fd));
        cleanup();
        return 1;
    }
    
    printf("Successfully attached to flow_map\n");
    
    /* Start the flow manager loop */
    flow_manager_loop();
    
    printf("Flow manager stopped\n");
    cleanup();
    
    return 0;
}