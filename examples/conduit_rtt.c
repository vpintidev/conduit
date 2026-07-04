// conduit_rtt.c — Keep an (assumed-established) connection alive over UDP:
// heartbeats, RTT measurement, and timeout-based death detection.
//
// Two symmetric peers on fixed loopback ports. Run both, watch RTT; kill one
// (Ctrl-C) and the other declares the connection LOST after a few unanswered
// probes. Observe on the wire with:
//   sudo tcpdump -i lo -X udp port 9000 or udp port 9001
//
// Build:  make rtt
// Usage:  ./build/conduit_rtt a      (binds 9000, talks to 9001)
//         ./build/conduit_rtt b      (binds 9001, talks to 9000)
//
// SCOPE: the connection is assumed already established (CIDs hardcoded); in a
// real app they come from the handshake. This demo isolates liveness. It also
// counts only heartbeat sends as "activity" for the idle timer; a fuller
// implementation resets the timer on any packet sent and skips heartbeats while
// application data flows (see spec section 3.2).

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

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int run_peer(const char *name, int my_port, int peer_port,
                    uint32_t my_cid, uint32_t peer_cid)
{
    (void)my_cid; /* not needed to send; kept for clarity/symmetry */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return 1;
    }

    struct sockaddr_in me;
    memset(&me, 0, sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    me.sin_port = htons((uint16_t)my_port);
    if (bind(fd, (struct sockaddr *)&me, sizeof(me)) < 0)
    {
        perror("bind");
        close(fd);
        return 1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)peer_port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    /* Wake up ~10x/second so heartbeats and timeouts advance even when idle. */
    struct timeval tv = {0, 100000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    conduit_conn c;
    conduit_conn_init(&c, peer_cid, 1000u /*heartbeat ~1s*/, 3u /*lost after 3 unacked*/);
    printf("[%s] up on port %d, talking to %d\n", name, my_port, peer_port);

    for (;;)
    {
        uint8_t buf[64];
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        uint64_t t = now_ms();

        if (n < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                perror("recvfrom");
                break;
            }
            /* else: idle timeout, no packet this cycle */
        }
        else
        {
            conduit_header h;
            if (conduit_header_decode(buf, (size_t)n, &h) == CONDUIT_OK)
            {
                if (h.type == CONDUIT_PKT_HEARTBEAT)
                {
                    conduit_heartbeat probe;
                    if (conduit_parse_heartbeat(buf, (size_t)n, &probe) == CONDUIT_OK)
                    {
                        conduit_conn_note_recv(&c);
                        uint8_t ack[64];
                        size_t an = conduit_build_heartbeat_ack(peer_cid, probe.sequence,
                                                                ack, sizeof(ack));
                        sendto(fd, ack, an, 0, (struct sockaddr *)&dst, sizeof(dst));
                    }
                }
                else if (h.type == CONDUIT_PKT_HEARTBEAT_ACK)
                {
                    conduit_heartbeat echoed;
                    if (conduit_parse_heartbeat(buf, (size_t)n, &echoed) == CONDUIT_OK)
                    {
                        conduit_conn_on_ack(&c, echoed.sequence, t);
                        uint32_t rtt;
                        if (conduit_conn_rtt_ms(&c, &rtt))
                            printf("[%s] ack seq=%u  RTT=%u ms\n",
                                   name, (unsigned)echoed.sequence, (unsigned)rtt);
                    }
                }
            }
        }

        uint8_t out[64];
        size_t sn = conduit_conn_tick(&c, t, out, sizeof(out));
        if (sn > 0)
        {
            sendto(fd, out, sn, 0, (struct sockaddr *)&dst, sizeof(dst));
        }

        if (conduit_conn_status(&c) == CONDUIT_CONN_LOST)
        {
            printf("[%s] peer unresponsive -> connection LOST\n", name);
            break;
        }
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush each line, even when piped */
    if (argc >= 2 && strcmp(argv[1], "a") == 0)
        return run_peer("a", 9000, 9001, 0x0000AAAAu, 0x0000BBBBu);
    if (argc >= 2 && strcmp(argv[1], "b") == 0)
        return run_peer("b", 9001, 9000, 0x0000BBBBu, 0x0000AAAAu);
    fprintf(stderr, "usage: %s a|b\n", argv[0]);
    return 2;
}