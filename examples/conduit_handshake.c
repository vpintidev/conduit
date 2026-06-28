// conduit_handshake.c — Demonstrate Conduit's three-message handshake over UDP.
//
// Run the responder in one terminal and the initiator in another, and watch the
// three-way exchange (INIT -> RESP -> CONFIRM) and the state transitions on both
// sides as a logical connection is established over connectionless UDP.
//
// Build:  make handshake
// Usage:  ./build/conduit_handshake responder 9000
//         ./build/conduit_handshake initiator 127.0.0.1 9000
//
// SCOPE: this demo assumes no packet loss (it runs over loopback) and handles a
// single connection. Handshake retransmission on loss, connection timeouts, and
// a table of many connections are deferred to later steps. The circle-1 token is
// a plain random value proving round-trip only, not a cryptographic token.

#include "conduit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int make_udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) perror("socket");
    return fd;
}

static int run_responder(int port) {
    int fd = make_udp_socket();
    if (fd < 0) return 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return 1;
    }

    /* Real code would generate a unique ID; we hardcode a recognizable one. */
    const uint32_t my_cid = 0x0000BBBBu;
    printf("[responder] state=LISTEN  my connection ID=0x%08X\n", (unsigned)my_cid);

    uint8_t buf[64], out[64];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);

    /* --- wait for INIT --- */
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
    if (n < 0) { perror("recvfrom"); close(fd); return 1; }

    conduit_header h;
    if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK ||
        h.type != CONDUIT_PKT_HANDSHAKE_INIT) {
        printf("[responder] ignoring unexpected packet\n"); close(fd); return 1;
    }
    conduit_handshake_init hi;
    if (conduit_parse_init(buf, (size_t)n, &hi) != CONDUIT_OK) {
        printf("[responder] malformed INIT\n"); close(fd); return 1;
    }
    if (hi.version != CONDUIT_PROTOCOL_VERSION) {
        printf("[responder] version mismatch (got %u, want %u) -> rejecting\n",
               (unsigned)hi.version, CONDUIT_PROTOCOL_VERSION);
        close(fd); return 1;
    }
    uint32_t peer_cid = hi.initiator_cid;
    printf("[responder] <- INIT from peer cid=0x%08X (version %u)\n",
           (unsigned)peer_cid, (unsigned)hi.version);

    /* --- send RESP with a freshly generated token --- */
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    uint32_t token = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    size_t len = conduit_build_resp(peer_cid, my_cid, token, out, sizeof(out));
    sendto(fd, out, len, 0, (struct sockaddr *)&peer, peer_len);
    printf("[responder] -> RESP my cid=0x%08X token=0x%08X  state=RESP_SENT\n",
           (unsigned)my_cid, (unsigned)token);

    /* --- wait for CONFIRM and validate the echoed token --- */
    n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
    if (n < 0) { perror("recvfrom"); close(fd); return 1; }
    if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK ||
        h.type != CONDUIT_PKT_HANDSHAKE_CONFIRM) {
        printf("[responder] ignoring unexpected packet\n"); close(fd); return 1;
    }
    if (h.connection_id != my_cid) {
        printf("[responder] CONFIRM addressed to 0x%08X, not me -> dropping\n",
               (unsigned)h.connection_id);
        close(fd); return 1;
    }
    conduit_handshake_confirm hc;
    if (conduit_parse_confirm(buf, (size_t)n, &hc) != CONDUIT_OK) {
        printf("[responder] malformed CONFIRM\n"); close(fd); return 1;
    }
    if (hc.token != token) {
        printf("[responder] token mismatch -> rejecting (got 0x%08X)\n",
               (unsigned)hc.token);
        close(fd); return 1;
    }
    printf("[responder] <- CONFIRM token ok\n");
    printf("[responder] state=ESTABLISHED  connection with peer cid=0x%08X\n",
           (unsigned)peer_cid);

    close(fd);
    return 0;
}

static int run_initiator(const char *ip, int port) {
    int fd = make_udp_socket();
    if (fd < 0) return 1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", ip); close(fd); return 1;
    }

    const uint32_t my_cid = 0x0000AAAAu;
    printf("[initiator] my connection ID=0x%08X\n", (unsigned)my_cid);

    /* --- send INIT --- */
    uint8_t buf[64], out[64];
    size_t len = conduit_build_init(my_cid, out, sizeof(out));
    sendto(fd, out, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    printf("[initiator] -> INIT my cid=0x%08X  state=INIT_SENT\n", (unsigned)my_cid);

    /* --- wait for RESP --- */
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (n < 0) { perror("recvfrom"); close(fd); return 1; }

    conduit_header h;
    if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK ||
        h.type != CONDUIT_PKT_HANDSHAKE_RESP) {
        printf("[initiator] ignoring unexpected packet\n"); close(fd); return 1;
    }
    if (h.connection_id != my_cid) {
        printf("[initiator] RESP addressed to 0x%08X, not me -> dropping\n",
               (unsigned)h.connection_id);
        close(fd); return 1;
    }
    conduit_handshake_resp hr;
    if (conduit_parse_resp(buf, (size_t)n, &hr) != CONDUIT_OK) {
        printf("[initiator] malformed RESP\n"); close(fd); return 1;
    }
    if (hr.version != CONDUIT_PROTOCOL_VERSION) {
        printf("[initiator] version mismatch (got %u) -> rejecting\n",
               (unsigned)hr.version);
        close(fd); return 1;
    }
    uint32_t peer_cid = hr.responder_cid;
    printf("[initiator] <- RESP peer cid=0x%08X token=0x%08X\n",
           (unsigned)peer_cid, (unsigned)hr.token);

    /* --- send CONFIRM, echoing the token --- */
    len = conduit_build_confirm(peer_cid, hr.token, out, sizeof(out));
    sendto(fd, out, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    printf("[initiator] -> CONFIRM token=0x%08X\n", (unsigned)hr.token);
    printf("[initiator] state=ESTABLISHED  connection with peer cid=0x%08X\n",
           (unsigned)peer_cid);

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "responder") == 0) {
        return run_responder(atoi(argv[2]));
    }
    if (argc >= 4 && strcmp(argv[1], "initiator") == 0) {
        return run_initiator(argv[2], atoi(argv[3]));
    }
    fprintf(stderr,
        "usage:\n"
        "  %s responder <port>\n"
        "  %s initiator <ip> <port>\n",
        argv[0], argv[0]);
    return 2;
}