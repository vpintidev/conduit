// conduit_reliable.c — Reliable DATA over UDP: sequence numbers, cumulative
// acknowledgement, and retransmission (spec Section 4), driven by the library's
// conduit_tx (sender) and conduit_rx (receiver).
//
// A sender pushes N numbered DATA packets to a receiver and stops once every one
// has been acknowledged. The receiver delivers each new payload once, discards
// duplicates, and replies with a cumulative DATA_ACK. Tell the receiver to drop
// the first few DATA packets it hears (--drop N) to watch the sender retransmit
// on its RTO and the transfer still complete.
//
// Build:  make reliable
// Usage:  ./build/conduit_reliable recv 9000 [--drop N]
//         ./build/conduit_reliable send 127.0.0.1 9000 [--count N]
//
// Try:
//   # terminal 1: receiver drops the first 2 DATA packets it receives
//   ./build/conduit_reliable recv 9000 --drop 2
//   # terminal 2: send 5 packets and watch #1 and #2 get retransmitted
//   ./build/conduit_reliable send 127.0.0.1 9000 --count 5
//   # terminal 3 (optional): watch the wire
//   sudo tcpdump -i lo -X udp port 9000
//
// SCOPE: the connection is assumed already established (CIDs hardcoded); in a
// real app they come from the handshake. This demo isolates reliability. It is
// one-directional (data flows send -> recv, acks flow back) and unordered: the
// receiver delivers payloads as they arrive. Ordering, channels, and
// fragmentation are later work (spec Section 5).

#include "conduit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Established-connection CIDs, hardcoded for this demo (see SCOPE). */
#define SENDER_CID 0x0000AAAAu
#define RECVER_CID 0x0000BBBBu

/* Sender RTO policy (injected into conduit_tx). Short so retransmits are quick
 * to watch on loopback, where the real RTT is microseconds. */
#define RTO_INITIAL_MS 500u
#define RTO_MIN_MS     200u
#define RTO_MAX_MS     4000u

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Parse an optional "--flag N" out of argv, returning N (or `dflt` if absent). */
static int parse_int_flag(int argc, char **argv, int from,
                          const char *flag, int dflt)
{
    for (int i = from; i + 1 < argc; i++)
        if (strcmp(argv[i], flag) == 0)
            return atoi(argv[i + 1]);
    return dflt;
}

static int run_receiver(int port, int drop)
{
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

    conduit_rx rx;
    conduit_rx_init(&rx);
    printf("[recv] up on port %d  my cid=0x%08X\n", port, (unsigned)RECVER_CID);
    if (drop > 0)
        printf("[recv] (will drop the first %d DATA packet(s) received)\n", drop);

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    uint8_t buf[1500], out[64];

    for (;;) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) { perror("recvfrom"); close(fd); return 1; }

        conduit_header h;
        if (conduit_header_decode(buf, (size_t)n, &h) != CONDUIT_OK)
            continue;
        if (h.type != CONDUIT_PKT_DATA)
            continue;

        conduit_data d;
        if (conduit_parse_data(buf, (size_t)n, &d) != CONDUIT_OK)
            continue;

        if (drop > 0) {
            drop--;
            printf("[recv] (simulated loss) dropped DATA seq=%u\n",
                   (unsigned)d.sequence);
            continue; /* no ack: to the sender it looks lost */
        }

        conduit_recv_result r = conduit_rx_on_data(&rx, d.sequence);
        if (r == CONDUIT_RECV_NEW) {
            /* Deliver to the "application": here, just print the payload. */
            printf("[recv] <- DATA seq=%u  \"%.*s\"  (deliver)  cum-ack=%u\n",
                   (unsigned)d.sequence, (int)d.payload_len, d.payload,
                   (unsigned)conduit_rx_ack(&rx));
        } else if (r == CONDUIT_RECV_DUPLICATE) {
            printf("[recv] <- DATA seq=%u  (duplicate, drop)  cum-ack=%u\n",
                   (unsigned)d.sequence, (unsigned)conduit_rx_ack(&rx));
        } else {
            printf("[recv] <- DATA seq=%u  (invalid, drop)\n", (unsigned)d.sequence);
            continue;
        }

        /* Acknowledge — cumulatively — even for a duplicate: our previous ack
         * may have been the thing that was lost. */
        size_t an = conduit_build_data_ack(SENDER_CID, conduit_rx_ack(&rx),
                                           out, sizeof(out));
        sendto(fd, out, an, 0, (struct sockaddr *)&peer, peer_len);
        printf("[recv] -> ACK cum=%u\n", (unsigned)conduit_rx_ack(&rx));
    }

    close(fd);
    return 0;
}

static int run_sender(const char *ip, int port, int count)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", ip); close(fd); return 1;
    }

    /* Wake up ~10x/second so the RTO can fire while we wait for acks. */
    struct timeval tv = {0, 100000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    conduit_tx tx;
    conduit_tx_init(&tx, RECVER_CID, RTO_INITIAL_MS, RTO_MIN_MS, RTO_MAX_MS);
    printf("[send] to %s:%d  my cid=0x%08X  sending %d packet(s)\n",
           ip, port, (unsigned)SENDER_CID, count);

    int queued = 0; /* how many new DATA we have injected so far */
    uint8_t out[1500], buf[1500];

    /* Done when every packet has been queued AND acknowledged. */
    while (!(queued >= count && conduit_tx_outstanding(&tx) == 0)) {
        uint64_t t = now_ms();

        /* 1. Fill the send window with new packets while we have some left. */
        while (queued < count && conduit_tx_can_send(&tx)) {
            char msg[64];
            int mlen = snprintf(msg, sizeof(msg), "packet #%d", queued + 1);
            size_t sn = conduit_tx_send(&tx, (const uint8_t *)msg, (size_t)mlen,
                                        t, out, sizeof(out));
            if (sn == 0) break; /* window full or buffer issue */
            queued++;
            /* Read the sequence back out for a friendly log line. */
            conduit_data d;
            conduit_parse_data(out, sn, &d);
            sendto(fd, out, sn, 0, (struct sockaddr *)&dst, sizeof(dst));
            printf("[send] -> DATA seq=%u  \"%s\"\n", (unsigned)d.sequence, msg);
        }

        /* 2. Drain any acks that have arrived. */
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* timeout: fall through to retransmission check */
            } else {
                perror("recvfrom"); close(fd); return 1;
            }
        } else {
            conduit_header h;
            if (conduit_header_decode(buf, (size_t)n, &h) == CONDUIT_OK &&
                h.type == CONDUIT_PKT_DATA_ACK) {
                conduit_data_ack a;
                if (conduit_parse_data_ack(buf, (size_t)n, &a) == CONDUIT_OK) {
                    conduit_tx_on_ack(&tx, a.ack, now_ms());
                    uint32_t rto = conduit_tx_rto_ms(&tx);
                    printf("[send] <- ACK cum=%u  (outstanding=%u, rto=%u ms)\n",
                           (unsigned)a.ack, (unsigned)conduit_tx_outstanding(&tx),
                           (unsigned)rto);
                }
            }
        }

        /* 3. Retransmit anything whose RTO has elapsed (flush all that are due). */
        uint64_t t2 = now_ms();
        for (;;) {
            size_t rn = conduit_tx_tick(&tx, t2, out, sizeof(out));
            if (rn == 0) break;
            conduit_data d;
            conduit_parse_data(out, rn, &d);
            sendto(fd, out, rn, 0, (struct sockaddr *)&dst, sizeof(dst));
            printf("[send] -> DATA seq=%u  (retransmit)\n", (unsigned)d.sequence);
        }
    }

    printf("[send] all %d packet(s) acknowledged -> done\n", count);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush each line, even when piped */
    if (argc >= 3 && strcmp(argv[1], "recv") == 0) {
        return run_receiver(atoi(argv[2]), parse_int_flag(argc, argv, 3, "--drop", 0));
    }
    if (argc >= 4 && strcmp(argv[1], "send") == 0) {
        return run_sender(argv[2], atoi(argv[3]),
                          parse_int_flag(argc, argv, 4, "--count", 5));
    }
    fprintf(stderr,
        "usage:\n"
        "  %s recv <port> [--drop N]\n"
        "  %s send <ip> <port> [--count N]\n",
        argv[0], argv[0]);
    return 2;
}
