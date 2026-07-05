// conduit_handshake.c — Demonstrate Conduit's three-message handshake over UDP,
// now driven by the library's retransmitting handshake state machine.
//
// Run the responder in one terminal and the initiator in another, and watch the
// three-way exchange (INIT -> RESP -> CONFIRM) and the state transitions on both
// sides as a logical connection is established over connectionless UDP.
//
// Unlike the earlier version, the handshake is driven by conduit_handshake_state
// (the library's INIT-retransmission state machine): the initiator re-sends INIT
// on an exponential backoff until RESP arrives or it gives up. To *see* that
// happen on lossless loopback, either side can be told to drop the first few
// handshake packets it receives with --drop N.
//
// Build:  make handshake
// Usage:  ./build/conduit_handshake responder 9000 [--drop N]
//         ./build/conduit_handshake initiator 127.0.0.1 9000 [--drop N]
//
// Try:
//   # terminal 1: make the responder ignore the first INIT it hears
//   ./build/conduit_handshake responder 9000 --drop 1
//   # terminal 2: watch the initiator re-send INIT after the backoff
//   ./build/conduit_handshake initiator 127.0.0.1 9000
//
// SCOPE: single connection, no CID table. The circle-1 token is a plain random
// value proving round-trip only, not a cryptographic token. A lost CONFIRM is
// intentionally NOT retransmitted here: the responder stays half-open and, in a
// full app, the keep-alive timeout (see conduit_rtt) would tear it down. This
// demo therefore reports a dropped CONFIRM rather than recovering from it.

#include "conduit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Handshake retransmission policy for this demo (injected into the driver).
 * Short backoff so a re-send is quick to watch; small cap and attempt count so
 * a truly dead peer fails fast. */
#define DEMO_BACKOFF_MS 500u
#define DEMO_BACKOFF_CAP_MS 4000u
#define DEMO_MAX_ATTEMPTS 6u

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int make_udp_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        perror("socket");
    return fd;
}

/* Parse an optional "--drop N" out of argv, returning N (0 if absent). */
static int parse_drop(int argc, char **argv, int from)
{
    for (int i = from; i + 1 < argc; i++)
    {
        if (strcmp(argv[i], "--drop") == 0)
            return atoi(argv[i + 1]);
    }
    return 0;
}

static int run_responder(int port, int drop)
{
    int fd = make_udp_socket();
    if (fd < 0)
        return 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(fd);
        return 1;
    }

    /* Real code would generate a unique ID; we hardcode a recognizable one. */
    const uint32_t my_cid = 0x0000BBBBu;
    conduit_handshake_state hs;
    conduit_handshake_init_responder(&hs, my_cid);
    printf("[responder] state=LISTEN  my connection ID=0x%08X\n", (unsigned)my_cid);
    if (drop > 0)
        printf("[responder] (will drop the first %d handshake packet(s) received)\n", drop);

    /* Token generator (caller-supplied; the library depends on no RNG). */
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    uint8_t buf[64], out[64];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);

    /* Loop until ESTABLISHED. The loop (rather than a straight-line sequence)
     * lets the responder answer a repeat INIT by re-issuing RESP — which is how
     * a lost RESP is recovered once the initiator re-sends INIT. */
    while (conduit_handshake_status(&hs) != CONDUIT_HS_ESTABLISHED)
    {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0)
        {
            perror("recvfrom");
            close(fd);
            return 1;
        }

        conduit_header h;
        if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK)
        {
            printf("[responder] undecodable packet -> dropping\n");
            continue;
        }

        if (drop > 0)
        {
            drop--;
            printf("[responder] (simulated loss) dropped %s\n",
                   conduit_packet_type_name(h.type));
            continue;
        }

        if (h.type == CONDUIT_PKT_HANDSHAKE_INIT)
        {
            /* Peek the version for a friendly message / rejection. */
            conduit_handshake_init hi;
            if (conduit_parse_init(buf, (size_t)n, &hi) != CONDUIT_OK)
            {
                printf("[responder] malformed INIT -> dropping\n");
                continue;
            }
            if (hi.version != CONDUIT_PROTOCOL_VERSION)
            {
                printf("[responder] version mismatch (got %u, want %u) -> rejecting\n",
                       (unsigned)hi.version, CONDUIT_PROTOCOL_VERSION);
                close(fd);
                return 1;
            }
            printf("[responder] <- INIT from peer cid=0x%08X (version %u)\n",
                   (unsigned)hi.initiator_cid, (unsigned)hi.version);

            uint32_t token = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
            size_t len = conduit_handshake_on_init(&hs, buf, (size_t)n, token,
                                                   out, sizeof(out));
            if (len == 0)
            {
                printf("[responder] could not build RESP -> dropping\n");
                continue;
            }
            sendto(fd, out, len, 0, (struct sockaddr *)&peer, peer_len);
            printf("[responder] -> RESP my cid=0x%08X token=0x%08X  state=RESP_SENT\n",
                   (unsigned)my_cid, (unsigned)token);
        }
        else if (h.type == CONDUIT_PKT_HANDSHAKE_CONFIRM)
        {
            if (h.connection_id != my_cid)
            {
                printf("[responder] CONFIRM addressed to 0x%08X, not me -> dropping\n",
                       (unsigned)h.connection_id);
                continue;
            }
            if (conduit_handshake_on_confirm(&hs, buf, (size_t)n) == 1)
            {
                printf("[responder] <- CONFIRM token ok\n");
                printf("[responder] state=ESTABLISHED  connection with peer cid=0x%08X\n",
                       (unsigned)conduit_handshake_peer_cid(&hs));
            }
            else
            {
                printf("[responder] CONFIRM token mismatch -> rejecting\n");
                /* stay in RESP_SENT; a correct CONFIRM may still arrive */
            }
        }
        else
        {
            printf("[responder] ignoring unexpected %s packet\n",
                   conduit_packet_type_name(h.type));
        }
    }

    close(fd);
    return 0;
}

static int run_initiator(const char *ip, int port, int drop)
{
    int fd = make_udp_socket();
    if (fd < 0)
        return 1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1)
    {
        fprintf(stderr, "invalid address: %s\n", ip);
        close(fd);
        return 1;
    }

    /* Wake up ~5x/second so the retransmission timer can advance while we wait
     * for RESP. Without a receive timeout, a lost RESP would block us forever. */
    struct timeval tv = {0, 200000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const uint32_t my_cid = 0x0000AAAAu;
    conduit_handshake_state hs;
    conduit_handshake_init_initiator(&hs, my_cid,
                                     DEMO_BACKOFF_MS, DEMO_BACKOFF_CAP_MS,
                                     DEMO_MAX_ATTEMPTS);
    printf("[initiator] my connection ID=0x%08X  state=INIT_SENT\n", (unsigned)my_cid);
    if (drop > 0)
        printf("[initiator] (will drop the first %d handshake packet(s) received)\n", drop);

    uint8_t buf[64], out[64];

    for (;;)
    {
        uint64_t t = now_ms();

        /* Send an INIT if one is due (immediately at first, then on backoff). */
        size_t sn = conduit_handshake_tick(&hs, t, out, sizeof(out));
        if (sn > 0)
        {
            sendto(fd, out, sn, 0, (struct sockaddr *)&dst, sizeof(dst));
            printf("[initiator] -> INIT my cid=0x%08X  (attempt via backoff)\n",
                   (unsigned)my_cid);
        }

        if (conduit_handshake_status(&hs) == CONDUIT_HS_FAILED)
        {
            printf("[initiator] no RESP after %u attempts -> handshake FAILED\n",
                   DEMO_MAX_ATTEMPTS);
            close(fd);
            return 1;
        }
        if (conduit_handshake_status(&hs) == CONDUIT_HS_ESTABLISHED)
            break;

        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue; /* timeout: loop back so tick() can retransmit */
            perror("recvfrom");
            close(fd);
            return 1;
        }

        conduit_header h;
        if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK)
        {
            printf("[initiator] undecodable packet -> dropping\n");
            continue;
        }

        if (drop > 0)
        {
            drop--;
            printf("[initiator] (simulated loss) dropped %s\n",
                   conduit_packet_type_name(h.type));
            continue;
        }

        if (h.type != CONDUIT_PKT_HANDSHAKE_RESP)
        {
            printf("[initiator] ignoring unexpected %s packet\n",
                   conduit_packet_type_name(h.type));
            continue;
        }
        if (h.connection_id != my_cid)
        {
            printf("[initiator] RESP addressed to 0x%08X, not me -> dropping\n",
                   (unsigned)h.connection_id);
            continue;
        }
        /* Peek the version for a friendly message / rejection. */
        conduit_handshake_resp hr;
        if (conduit_parse_resp(buf, (size_t)n, &hr) != CONDUIT_OK)
        {
            printf("[initiator] malformed RESP -> dropping\n");
            continue;
        }
        if (hr.version != CONDUIT_PROTOCOL_VERSION)
        {
            printf("[initiator] version mismatch (got %u) -> rejecting\n",
                   (unsigned)hr.version);
            close(fd);
            return 1;
        }
        printf("[initiator] <- RESP peer cid=0x%08X token=0x%08X\n",
               (unsigned)hr.responder_cid, (unsigned)hr.token);

        /* RESP accepted: the driver emits CONFIRM and moves to ESTABLISHED. */
        size_t cn = conduit_handshake_on_resp(&hs, buf, (size_t)n, out, sizeof(out));
        if (cn == 0)
        {
            printf("[initiator] could not build CONFIRM -> dropping\n");
            continue;
        }
        sendto(fd, out, cn, 0, (struct sockaddr *)&dst, sizeof(dst));
        printf("[initiator] -> CONFIRM token=0x%08X\n", (unsigned)hr.token);
        printf("[initiator] state=ESTABLISHED  connection with peer cid=0x%08X\n",
               (unsigned)conduit_handshake_peer_cid(&hs));
        break;
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush each line, even when piped */
    if (argc >= 3 && strcmp(argv[1], "responder") == 0)
    {
        return run_responder(atoi(argv[2]), parse_drop(argc, argv, 3));
    }
    if (argc >= 4 && strcmp(argv[1], "initiator") == 0)
    {
        return run_initiator(argv[2], atoi(argv[3]), parse_drop(argc, argv, 4));
    }
    fprintf(stderr,
            "usage:\n"
            "  %s responder <port> [--drop N]\n"
            "  %s initiator <ip> <port> [--drop N]\n",
            argv[0], argv[0]);
    return 2;
}