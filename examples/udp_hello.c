// udp_hello.c — A minimal "hello over the network" spike for the Conduit project.
//
// This is NOT part of the framework. It exists only to get comfortable with the
// POSIX UDP socket API before we build anything real. Run one copy as the
// receiver and another as the sender, and watch a message cross the network stack.
//
// Build:  gcc -Wall -Wextra -o udp_hello udp_hello.c
// Usage:  ./udp_hello recv 9000
//         ./udp_hello send 127.0.0.1 9000 "hello"

#include <stdio.h>      // printf, perror, fprintf
#include <stdlib.h>     // exit, atoi
#include <string.h>     // memset, strlen
#include <stdint.h>     // uint16_t
#include <unistd.h>     // close
#include <sys/socket.h> // socket, bind, sendto, recvfrom
#include <netinet/in.h> // struct sockaddr_in
#include <arpa/inet.h>  // htons, htonl, ntohs, inet_pton, inet_ntop

static int run_receiver(int port) {
    // 1. Create a UDP socket. AF_INET = IPv4, SOCK_DGRAM = datagrams (UDP).
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // 2. Describe the local address to listen on: any interface, the given port.
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // accept on all local interfaces
    addr.sin_port = htons((uint16_t)port);    // port must be in network byte order

    // 3. Bind the socket to that address, so datagrams sent there reach us.
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return 1;
    }

    printf("listening for UDP on port %d ...\n", port);

    // 4. Block until a datagram arrives, then print it. recvfrom also tells us
    //    who sent it (the source address) — we will need that later, when the
    //    transport layer must decide which connection a packet belongs to.
    char buf[1500];                 // 1500 ~ a typical Ethernet MTU; plenty for "hello"
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&from, &from_len);
    if (n < 0) { perror("recvfrom"); close(fd); return 1; }

    buf[n] = '\0'; // turn the received bytes into a printable C string

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
    printf("received %zd bytes from %s:%d -> \"%s\"\n",
           n, ip, ntohs(from.sin_port), buf);

    close(fd);
    return 0;
}

static int run_sender(const char *ip, int port, const char *msg) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // Describe the destination address.
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", ip);
        close(fd); return 1;
    }

    // Send the bytes. No connection, no handshake — this is what raw UDP gives us.
    ssize_t n = sendto(fd, msg, strlen(msg), 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (n < 0) { perror("sendto"); close(fd); return 1; }

    printf("sent %zd bytes to %s:%d -> \"%s\"\n", n, ip, port, msg);

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "recv") == 0) {
        return run_receiver(atoi(argv[2]));
    }
    if (argc >= 5 && strcmp(argv[1], "send") == 0) {
        return run_sender(argv[2], atoi(argv[3]), argv[4]);
    }
    fprintf(stderr,
        "usage:\n"
        "  %s recv <port>\n"
        "  %s send <ip> <port> <message>\n",
        argv[0], argv[0]);
    return 2;
}
