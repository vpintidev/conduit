// conduit_ping.c — Send and receive a real Conduit packet over UDP.
//
// This bridges two things we built separately: the Conduit header (encode/decode)
// and raw UDP I/O. It builds a HEARTBEAT header, puts it in a datagram, and sends
// it; the receiver parses the header back out and prints it. Unlike the unit test,
// the bytes here actually cross the network stack, so you can watch them with an
// external tool such as tcpdump (see the README / chat for how).
//
// Build (from the repo root):
//   make ping
// or, by hand:
//   cc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Isrc examples/conduit_ping.c src/conduit.c -o build/conduit_ping
//
// Usage:
//   ./build/conduit_ping recv 9000
//   ./build/conduit_ping send 127.0.0.1 9000

#include "conduit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
}

static int run_receiver(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return 1;
    }
    printf("waiting for a Conduit packet on UDP port %d ...\n", port);

    uint8_t buf[1500];
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (n < 0) { perror("recvfrom"); close(fd); return 1; }

    printf("received %zd raw bytes: ", n);
    hexdump(buf, (size_t)n);

    /* Hand the raw bytes to the Conduit parser. */
    conduit_header h;
    conduit_result r = conduit_header_decode(buf, (size_t)n, &h);
    if (r != CONDUIT_OK) {
        printf("not a valid Conduit header (decode code %d)\n", (int)r);
        close(fd); return 1;
    }
    printf("parsed Conduit header: connection_id=0x%08X  type=%s(0x%02X)  flags=0x%04X\n",
           (unsigned)h.connection_id,
           conduit_packet_type_name(h.type), (unsigned)h.type,
           (unsigned)h.flags);

    close(fd);
    return 0;
}

static int run_sender(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", ip); close(fd); return 1;
    }

    /* Build a real Conduit header and serialize it to wire format. */
    conduit_header h = {
        .connection_id = 0xABCD1234u,
        .type          = CONDUIT_PKT_HEARTBEAT,
        .flags         = 0
    };
    uint8_t buf[CONDUIT_HEADER_SIZE];
    size_t len = conduit_header_encode(&h, buf);

    printf("sending %zu bytes: ", len);
    hexdump(buf, len);

    /* Put the header bytes in a UDP datagram and send it. */
    ssize_t n = sendto(fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (n < 0) { perror("sendto"); close(fd); return 1; }

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "recv") == 0) {
        return run_receiver(atoi(argv[2]));
    }
    if (argc >= 4 && strcmp(argv[1], "send") == 0) {
        return run_sender(argv[2], atoi(argv[3]));
    }
    fprintf(stderr,
        "usage:\n"
        "  %s recv <port>\n"
        "  %s send <ip> <port>\n",
        argv[0], argv[0]);
    return 2;
}