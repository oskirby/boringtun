#include "wg_bench_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __linux
#include <sys/epoll.h>
#include <sys/timerfd.h>
#else
#include <sys/event.h>
#endif

#define WG_BENCH_MTU 2048

static void wg_worker_sigmask() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
}

struct wg_bench_iphdr {
    uint8_t vlen;
    uint8_t qos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t cksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct wg_bench_udphdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t cksum;
    uint8_t  dgram[];
};

static void* wg_bench_send_worker(void *arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;
    struct wireguard_result result;
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    uint8_t plaintext[WG_BENCH_MTU];

    struct wg_bench_iphdr *ip = (struct wg_bench_iphdr*)plaintext;
    struct wg_bench_udphdr *udp = (struct wg_bench_udphdr*)(ip+1);
    const in_addr_t src = inet_addr("172.16.0.123");
    const in_addr_t dst = inet_addr("172.16.0.1");

    // Generate a sample IPv4 packet header.
    memset(ip, 0, sizeof(struct wg_bench_iphdr));
    ip->vlen = 0x40 + (sizeof(struct wg_bench_iphdr) / 4);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = htonl(src);
    ip->daddr = htonl(dst);
    udp->sport = 0x1234;
    udp->dport = 0x5678;
    udp->cksum = 0;

    // Create a separate socket for the send workflows.
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "worker socket error: %s\n", strerror(errno));
        return NULL;
    }
    if (connect(fd, (const struct sockaddr*)&client->peer, sizeof(client->peer)) < 0) {
        fprintf(stderr, "worker connect error: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    while (!client->worker_shutdown) {
        // Pick a random datagram size between 512-1024 and fill with a random byte.
        int dsize = 512 + (rand() % 512);
        int pktlen = sizeof(struct wg_bench_iphdr) + sizeof(struct wg_bench_udphdr) + dsize;
        memset(udp->dgram, rand() & 0xff, dsize);
        udp->length = htons(sizeof(struct wg_bench_udphdr) + dsize);
        udp->cksum = 0;
        ip->tot_len = htons(pktlen);
        ip->cksum = 0;

        // Encrypt the packet.
        result = wireguard_try_write(client->tunnel, plaintext, pktlen,
                                     ciphertext, sizeof(ciphertext));
        switch (result.op) {
            case WIREGUARD_DONE:
                break;

            case WIREGUARD_ERROR:
                if (result.size < WG_BENCH_MAX_ERRORS) {
                    atomic_fetch_add(&client->stats.errors[result.size], 1);
                }
                fprintf(stderr, "worker encrypt error: %zu\n", result.size);
                break;

            case WRITE_TO_NETWORK:
                atomic_fetch_add(&client->stats.tx_packets, 1);
                atomic_fetch_add(&client->stats.tx_bytes, pktlen);
                if (send(fd, ciphertext, result.size, 0) < 0) {
                    atomic_fetch_add(&client->stats.tx_drops, 1);
                    if (errno == EAGAIN) continue;
                    if (errno == ENOBUFS) continue;
                    if (!client->worker_shutdown) {
                        fprintf(stderr, "worker tx error: %s\n", strerror(errno));
                    }
                    close(fd);
                    return NULL;
                }
                break;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                // Not expected in this case.
                fprintf(stderr, "worker encrypt tunnel\n");
                break;

            default:
                fprintf(stderr, "worker encrypt unknown: %d\n", result.op);
                break;
        }
    }

    return NULL;
}

static void wg_bench_tick(struct wg_bench_client *client) {
    const struct sockaddr* peer = (const struct sockaddr*)&client->peer;
    socklen_t peerlen = sizeof(client->peer);

    while (true) {
        uint8_t ciphertext[WG_BENCH_MTU + 32];
        struct wireguard_result result;
        result = wireguard_tick(client->tunnel, ciphertext, sizeof(ciphertext));

        // Process timeouts and state updates.
        switch (result.op) {
            case WIREGUARD_DONE:
                return;

            case WIREGUARD_ERROR:
                fprintf(stderr, "worker tick error: %zu\n", result.size);
                return;

            case WRITE_TO_NETWORK:
                if (sendto(client->fd, ciphertext, result.size, MSG_DONTWAIT, peer, sizeof(client->peer)) < 0) {
                    atomic_fetch_add(&client->stats.tx_drops, 1);
                }
                continue;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                // not expected
                fprintf(stderr, "worker tick tunnel");
                break;
            
            default:
                fprintf(stderr, "worker tick unknown: %d\n", result.op);
                return;
        }
    }
}

static void wg_bench_recv(struct wg_bench_client *client) {
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    uint8_t plaintext[WG_BENCH_MTU];
    struct wireguard_result result;

    const struct sockaddr* peer = (const struct sockaddr*)&client->peer;
    socklen_t peerlen = sizeof(client->peer);

    // Read a packet.
    ssize_t rx = recv(client->fd, ciphertext, sizeof(ciphertext), 0);
    if (rx == 0) {
        fprintf(stderr, "worker shutdown\n");
        return;
    }
    if (rx < 0) {
        if (!client->worker_shutdown) {
            //fprintf(stderr, "worker rx error: %s\n", strerror(errno));
        }
        return;
    }

    result = wireguard_read(client->tunnel, ciphertext, rx, plaintext, sizeof(plaintext));
    switch (result.op) {
        case WIREGUARD_DONE:
            break;
        
        case WIREGUARD_ERROR:
            if (result.size < WG_BENCH_MAX_ERRORS) {
                atomic_fetch_add(&client->stats.errors[result.size], 1);
            }
            break;

        case WRITE_TO_NETWORK:
            // This is not expected, but I guess it's possible
            if (sendto(client->fd, plaintext, result.size, MSG_DONTWAIT, peer, peerlen) < 0) {
                atomic_fetch_add(&client->stats.tx_drops, 1);
            }
            break;

        case WRITE_TO_TUNNEL_IPV4:
        case WRITE_TO_TUNNEL_IPV6:
            atomic_fetch_add(&client->stats.rx_packets, 1);
            atomic_fetch_add(&client->stats.rx_bytes, result.size);
            break;

        default:
            break;
    }
}

static void* wg_bench_worker(void *arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;

    wg_worker_sigmask();
    while (!client->worker_shutdown) {
#ifdef __linux
        // Wait for an event to handle.
        struct epoll_event ev[16];
        int maxev = sizeof(ev)/sizeof(struct epoll_event);
        int nev = epoll_wait(client->queue, ev, maxev, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            fprintf(stderr, "worker epoll error: %s\n", strerror(errno));
            continue;
        }
    
        // Handle events.
        for (int i = 0; i < nev; i++) {
            if (ev[i].data.fd < 0) {
                wg_bench_tick(client);
            } else if (ev[i].data.fd == client->fd) {
                wg_bench_recv(client);
            }
        }
#else
        // Wait for an event to handle.
        struct kevent kev[16];
        int maxev = sizeof(kev)/sizeof(struct kevent);
        int nev = kevent(client->queue, NULL, 0, kev, maxev, NULL);
        if (nev < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "worker kevent error: %s\n", strerror(errno));
            continue;
        }

        // Handle events.
        for (int i = 0; i < nev; i++) {
            if (kev[i].filter == EVFILT_TIMER) {
                wg_bench_tick(client);
            } else if (kev[i].filter == EVFILT_READ) {
                wg_bench_recv(client);
            }
        }
#endif
    }

    return NULL;
}

// Fill a sockaddr_un with the named pipe for a given public key.
static struct sockaddr* wg_bench_sockaddr(const char* pubkey, struct sockaddr_un *addr) {
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
#ifdef SUN_LEN
    addr->sun_len = sizeof(struct sockaddr_un);
#endif

    // Set the name to /tmp/ffi-bench-<base64key>.sock, using URL-safe encoding.
    strcpy(addr->sun_path, "/tmp/ffi-bench-");
    char *urlsafe = strchr(addr->sun_path, '\0');
    while (*pubkey != '\0') {
        char c = *pubkey++;
        if (c == '+') *urlsafe++ = '-';
        else if (c == '/') *urlsafe++ = '_';
        else if (c != '=') *urlsafe++ = c;
    }
    strcat(urlsafe, ".sock");

    return (struct sockaddr*)addr;
}

struct wg_bench_client* wg_bench_create() {
    struct wg_bench_client* client = calloc(sizeof(struct wg_bench_client), 1);
    if (!client) {
        return NULL;
    }
    client->secret = x25519_secret_key();
    client->pubkey = x25519_key_to_base64(x25519_public_key(client->secret));

    // Create a named datagram pipe for handling packets.
    client->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (client->fd < 0) {
        x25519_key_to_str_free(client->pubkey);
        free(client);
        return NULL;
    }

    struct sockaddr* sa = wg_bench_sockaddr(client->pubkey, &client->addr);
    if (bind(client->fd, sa, sizeof(client->addr)) < 0) {
        x25519_key_to_str_free(client->pubkey);
        close(client->fd);
        free(client);
        return NULL;
    }

    fcntl(client->fd, F_SETFL, fcntl(client->fd, F_GETFL) | O_NONBLOCK);
#ifdef __linux
    client->queue = epoll_create1(0);
#else
    client->queue = kqueue();
#endif
    return client;
}

void wg_bench_connect(struct wg_bench_client* client, const char* pubkey) {
    const char* statickey = x25519_key_to_base64(client->secret);
    client->tunnel = new_tunnel(statickey, pubkey, NULL, 5, rand() & 0xffffff);
    x25519_key_to_str_free(statickey);

    wg_bench_sockaddr(pubkey, &client->peer);

    // Begin packet processing.
#ifdef __linux
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client->fd;
    epoll_ctl(client->queue, EPOLL_CTL_ADD, client->fd, &ev);

    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    ev.events = EPOLLIN;
    ev.data.fd = -1;
    epoll_ctl(client->queue, EPOLL_CTL_ADD, timer, &ev);

    struct itimerspec itspec;
    itspec.it_value.tv_sec = 0;
    itspec.it_value.tv_nsec = 100000000;
    itspec.it_interval.tv_sec = 0;
    itspec.it_interval.tv_nsec = 100000000;
    timerfd_settime(timer, 0, &itspec, NULL);
#else
    struct kevent kev[2];
    EV_SET(&kev[0], client->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&kev[1], 1, EVFILT_TIMER, EV_ADD, 0, 100, NULL);
    kevent(client->queue, kev, 2, NULL, 0, NULL);
#endif
}

void wg_bench_start_handshake(struct wg_bench_client* client) {
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    struct wireguard_result result;
    result = wireguard_force_handshake(client->tunnel, ciphertext, sizeof(ciphertext));

    const struct sockaddr* peer = (const struct sockaddr*)&client->peer;
    socklen_t peerlen = sizeof(client->peer);

    // Process timeouts and state updates.
    switch (result.op) {
        case WIREGUARD_DONE:
            break;

        case WIREGUARD_ERROR:
            fprintf(stderr, "worker handshake error: %zu\n", result.size);
            break;

        case WRITE_TO_NETWORK:
            if (sendto(client->fd, ciphertext, result.size, MSG_DONTWAIT, peer, sizeof(client->peer)) < 0) {
                atomic_fetch_add(&client->stats.tx_drops, 1);
            }
            break;

        case WRITE_TO_TUNNEL_IPV4:
        case WRITE_TO_TUNNEL_IPV6:
            // not expected
            fprintf(stderr, "worker handshake tunnel");
            break;
        
        default:
            fprintf(stderr, "worker handshake unknown: %d\n", result.op);
            return;
    }
}

void wg_bench_start_worker(struct wg_bench_client* client) {
    if (client->worker_count >= WG_BENCH_MAX_THREADS) {
        return;
    }
    if (pthread_create(&client->workers[client->worker_count], NULL, wg_bench_worker, client) != 0) {
        return;
    }
    client->worker_count++;
}

void wg_bench_start_send(struct wg_bench_client* client) {
    if (client->worker_count >= WG_BENCH_MAX_THREADS) {
        return;
    }
    if (pthread_create(&client->workers[client->worker_count], NULL, wg_bench_send_worker, client) != 0) {
        return;
    }
    client->worker_count++;
}

void wg_bench_fetch_stats(const struct wg_bench_client* client, struct wg_bench_statistics* st) {
    atomic_fetch_add(&st->tx_packets, atomic_load(&client->stats.tx_packets));
    atomic_fetch_add(&st->tx_drops, atomic_load(&client->stats.tx_drops));
    atomic_fetch_add(&st->tx_bytes, atomic_load(&client->stats.tx_bytes));
    atomic_fetch_add(&st->rx_packets, atomic_load(&client->stats.rx_packets));
    atomic_fetch_add(&st->rx_bytes, atomic_load(&client->stats.rx_bytes));
    for (int i = 0; i < WG_BENCH_MAX_ERRORS; i++) {
        atomic_fetch_add(&st->errors[i], atomic_load(&client->stats.errors[i]));
    }
}

void wg_bench_close(struct wg_bench_client* client) {
    // Signal that we are shutting down and terminate workers.
    client->worker_shutdown = 1;
    for (int i = 0; i < client->worker_count; i++) {
        pthread_cancel(client->workers[i]);
        pthread_kill(client->workers[i], SIGHUP);
        pthread_join(client->workers[i], NULL);
    }
    close(client->queue);

    shutdown(client->fd, SHUT_RDWR);
    unlink(client->addr.sun_path);
    close(client->fd);

    x25519_key_to_str_free(client->pubkey);
    tunnel_free(client->tunnel);
}
