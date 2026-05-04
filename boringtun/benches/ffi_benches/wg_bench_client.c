#include "wg_bench_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

static void* wg_bench_background(void *arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;
    struct wireguard_result result;
    uint8_t ciphertext[WG_BENCH_MTU + 32];

    // Create a separate socket for this thread.
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "background socket error: %s\n", strerror(errno));
        return NULL;
    }
    if (connect(fd, (const struct sockaddr*)&client->peer, sizeof(client->peer)) < 0) {
        fprintf(stderr, "background connect error: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    wg_worker_sigmask();
    while (true) {
        if (client->worker_handshake) {
            client->worker_handshake = false;
            result = wireguard_force_handshake(client->tunnel, ciphertext, sizeof(ciphertext));
        } else {
            result = wireguard_tick(client->tunnel, ciphertext, sizeof(ciphertext));
        }

        // Process timeouts and state updates.
        switch (result.op) {
            case WIREGUARD_DONE:
                // Sleep for 100ms before trying again.
                usleep(100000);
                break;

            case WIREGUARD_ERROR:
                fprintf(stderr, "worker tick error: %zu\n", result.size);
                break;

            case WRITE_TO_NETWORK:
                if (send(fd, ciphertext, result.size, MSG_DONTWAIT) < 0) {
                    atomic_fetch_add(&client->stats.tx_drops, 1);
                    if (errno == EAGAIN) break;
                    fprintf(stderr, "worker tick send: %s\n", strerror(errno));
                }
                break;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                // not expected
                fprintf(stderr, "worker tick tunnel");
                break;
            
            default:
                fprintf(stderr, "worker tick unknown: %d\n", result.op);
                break;
        }
    }
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

static void* wg_bench_recv_worker(void *arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;
    const struct sockaddr* peer = (const struct sockaddr*)&client->peer;
    socklen_t peerlen = sizeof(client->peer);
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    uint8_t plaintext[WG_BENCH_MTU];

    wg_worker_sigmask();
    while (!client->worker_shutdown) {
        // Read a packet.
        ssize_t rx = recv(client->fd, ciphertext, sizeof(ciphertext), MSG_DONTWAIT);
        if (rx == 0) {
            fprintf(stderr, "worker shutdown\n");
            return NULL;
        }
        if (rx < 0) {
            if (errno == EAGAIN) continue;
            if (!client->worker_shutdown) {
                fprintf(stderr, "worker rx error: %s\n", strerror(errno));
            }
            return NULL;
        }

        struct wireguard_result result;
        if (ciphertext[0] == 0x04) {
            // Fast path - decrypt data packets without locking.
            result = wireguard_try_read(client->tunnel, ciphertext, rx, plaintext, sizeof(plaintext));
        } else {
            // Slow path - handle handshake and state changes while locking.
            result = wireguard_read(client->tunnel, ciphertext, rx, plaintext, sizeof(plaintext));
        }
        switch (result.op) {
            case WIREGUARD_DONE:
                continue;
            
            case WIREGUARD_ERROR:
                if (result.size < WG_BENCH_MAX_ERRORS) {
                    atomic_fetch_add(&client->stats.errors[result.size], 1);
                }
                continue;

            case WRITE_TO_NETWORK:
                if (sendto(client->fd, plaintext, result.size, MSG_DONTWAIT, peer, peerlen) < 0) {
                    atomic_fetch_add(&client->stats.tx_drops, 1);
                }
                continue;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                atomic_fetch_add(&client->stats.rx_packets, 1);
                atomic_fetch_add(&client->stats.rx_bytes, result.size);
                break;

            default:
                continue;
        }
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

    return client;
}

void wg_bench_connect(struct wg_bench_client* client, const char* pubkey) {
    const char* statickey = x25519_key_to_base64(client->secret);
    client->tunnel = new_tunnel(statickey, pubkey, NULL, 5, rand() & 0xffffff);
    x25519_key_to_str_free(statickey);

    wg_bench_sockaddr(pubkey, &client->peer);

    // Start the background worker to drive wireguard_tick();
    pthread_create(&client->background, NULL, wg_bench_background, client);
}

void wg_bench_start_handshake(struct wg_bench_client* client) {
    client->worker_handshake = true;
    pthread_kill(client->background, SIGHUP);
}

void wg_bench_start_recv(struct wg_bench_client* client) {
    if (client->worker_count >= WG_BENCH_MAX_THREADS) {
        return;
    }
    if (pthread_create(&client->workers[client->worker_count], NULL, wg_bench_recv_worker, client) != 0) {
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
    pthread_cancel(client->background);
    pthread_kill(client->background, SIGHUP);
    pthread_join(client->background, NULL);
    for (int i = 0; i < client->worker_count; i++) {
        pthread_cancel(client->workers[i]);
        pthread_kill(client->workers[i], SIGHUP);
        pthread_join(client->workers[i], NULL);
    }

    shutdown(client->fd, SHUT_RDWR);
    close(client->fd);

    x25519_key_to_str_free(client->pubkey);
    tunnel_free(client->tunnel);
}
