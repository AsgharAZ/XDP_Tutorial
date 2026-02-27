// #include <stdio.h>
// #include <postgresql/libpq-fe.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
// #include <unistd.h>
// #include "../xdp-tutorial/lib/libbpf/src/bpf.h"
// #include "../xdp-tutorial/lib/libbpf/src/libbpf.h"

// int main()
// {
//     int map_fd = bpf_obj_get("/sys/fs/bpf/proto_map");
//     if (map_fd < 0) {
//         perror("bpf_obj_get");
//         return 1;
//     }

//     __u8 key, next_key;
//     __u64 value;

//     while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
//         key = next_key;
//         if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
//             printf("Protocol %u → %llu packets\n", key, value);
//         }
//     }

//     return 0;
// }

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>        // for sleep()
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <postgresql/libpq-fe.h>

int main()
{
    // Connect to PostgreSQL
    PGconn *conn = PQconnectdb(
        "host=localhost dbname=firewallxdp user=xdpuser password=xdp123"
    );

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Database connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    printf("Connected to database successfully.\n");

    // Get BPF map
    int map_fd = bpf_obj_get("/sys/fs/bpf/proto_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        PQfinish(conn);
        return 1;
    }

    while (1) {  // infinite loop
        printf("---- Packet counts ----\n");

        __u8 key, next_key;
        __u64 value;

        int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
        while (err == 0) {
            key = next_key;

            if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
                // Print clean output
                printf("Protocol %u → %llu packets\n", key, value);

                // Insert/Update DB (one row per protocol)
                char query[512];
                snprintf(query, sizeof(query),
                         "INSERT INTO protocol_stats (protocol, packet_count, last_updated) "
                         "VALUES (%u, %llu, NOW()) "
                         "ON CONFLICT (protocol) "
                         "DO UPDATE SET packet_count = EXCLUDED.packet_count, last_updated = NOW();",
                         key, value);

                PGresult *res = PQexec(conn, query);
                if (PQresultStatus(res) != PGRES_COMMAND_OK)
                    fprintf(stderr, "Insert/Update failed: %s\n", PQerrorMessage(conn));
                PQclear(res);
            }

            err = bpf_map_get_next_key(map_fd, &key, &next_key);
        }

        printf("----------------------\n");
        sleep(5); // wait 5 seconds before next poll
    }

    // Close DB connection (never reached unless loop is broken)
    PQfinish(conn);

    return 0;
}