// conduit_rtt.c — Keep an (assumed-established) connection alive over UDP:
// heartbeats, RTT measurement, and timeout-based death detection.
//
// Two symmetric peers on fixed loopback ports. Run both, watch RTT. Then:
//   - Ctrl-C one peer: it sends a best-effort CLOSE, and the other prints
//     "<- CLOSE ... connection CLOSED" at once (no waiting for a timeout).
//   - Or kill -9 one peer (no CLOSE sent): the other falls back to declaring
//     the connection LOST after a few unanswered probes.
// Observe on the wire with:
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
// application data flows (see spec section 3.2). The CLOSE is best-effort: it is
// not acked or retransmitted (spec section 3.3).

#include "conduit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Set from the SIGINT handler so the main loop can exit cleanly and send a
 * CLOSE on the way out. volatile sig_atomic_t is the only thing it is safe to
 * touch from a signal handler. */
static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;
}

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

    /* Catch Ctrl-C so we can send a CLOSE before exiting instead of vanishing. */
    signal(SIGINT, on_sigint);

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
            if (errno == EINTR)
            {
                /* Interrupted by SIGINT: fall through so the g_stop check below
                 * can exit the loop cleanly. Not an error. */
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK)
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
                else if (h.type == CONDUIT_PKT_CLOSE)
                {
                    conduit_close cl;
                    if (conduit_parse_close(buf, (size_t)n, &cl) == CONDUIT_OK)
                    {
                        conduit_conn_close(&c);
                        printf("[%s] <- CLOSE (reason=%s) -> connection CLOSED\n",
                               name, conduit_close_reason_name(cl.reason));
                        break; /* peer is gone by its own choice; stop */
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

        /* Ctrl-C: leave the loop so we can close the connection gracefully. */
        if (g_stop)
        {
            printf("\n[%s] interrupted -> closing connection\n", name);
            break;
        }
    }

    /* If we are still ALIVE on the way out (i.e. the user interrupted us rather
     * than the peer vanishing or closing first), tell the peer with a best-effort
     * CLOSE. It is not acked or retransmitted: if it is lost, the peer falls back
     * to its keep-alive timeout. */
    if (conduit_conn_status(&c) == CONDUIT_CONN_ALIVE)
    {
        uint8_t out[64];
        size_t cn = conduit_build_close(peer_cid, CONDUIT_CLOSE_SHUTDOWN,
                                        out, sizeof(out));
        if (cn > 0)
        {
            sendto(fd, out, cn, 0, (struct sockaddr *)&dst, sizeof(dst));
            printf("[%s] -> CLOSE (reason=SHUTDOWN)\n", name);
        }
        conduit_conn_close(&c);
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