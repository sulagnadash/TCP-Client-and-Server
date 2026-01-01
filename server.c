#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <argp.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "hash.h"

#define BACKLOG 5

struct server_arguments
{
    int port;
    char *salt;
    size_t salt_len;
};

error_t server_parser(int key, char *arg, struct argp_state *state)
{
    struct server_arguments *args = state->input;
    error_t ret = 0;

    switch (key)
    {
    case 'p':
        /* Validate that port is correct and a number, etc!! */
        args->port = atoi(arg);
        if (args->port <= 1024)
        {
            argp_error(state, "Invalid option for port, must be a number greater than 1024");
        }
        break;
    case 's':
        args->salt_len = strlen(arg);
        args->salt = malloc(args->salt_len + 1);
        if (!args->salt)
        {
            argp_error(state, "Failed to allocate memory for salt");
        }
        strcpy(args->salt, arg);
        break;
    default:
        ret = ARGP_ERR_UNKNOWN;
        break;
    }
    return ret;
}

void server_parseopt(struct server_arguments *out, int argc, char *argv[])
{
    /* bzero ensures that "default" parameters are all zeroed out */
    bzero(out, sizeof(*out));

    struct argp_option options[] = {
        {"port", 'p', "port", 0, "The port to be used for the server", 0},
        {"salt", 's', "salt", 0, "The salt to be used for the server. Zero by default", 0},
        {0}};

    struct argp argp_settings = {options, server_parser, 0, 0, 0, 0, 0};
    if (argp_parse(&argp_settings, argc, argv, 0, NULL, out) != 0)
    {
        printf("Got an error condition when parsing\n");
    }

    /* Check args values for sanity and required parameters being filled in */
    if (out->port == 0)
    {
        fprintf(stderr, "Server: must specify port with -p (value > 1024)\n");
        exit(EXIT_FAILURE);
    }

    printf("Got port %d and salt %s with length %zu\n",
           out->port, out->salt ? out->salt : "(none)", out->salt_len);
}

static int send_all(int sockfd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t r = send(sockfd, p + sent, len - sent, 0);
        if (r <= 0)
            return -1;
        sent += (size_t)r;
    }
    return 0;
}

static int recv_all(int sockfd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len)
    {
        ssize_t r = recv(sockfd, p + got, len - got, 0);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Initialization message, acknowledgement, hash request, hash response */
enum
{
    MSG_INIT = 1,
    MSG_ACK = 2,
    MSG_HASHREQ = 3,
    MSG_HASHRESP = 4
};

int main(int argc, char *argv[])
{
    struct server_arguments args;
    server_parseopt(&args, argc, argv);

    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in local;
    bzero(&local, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons((uint16_t)args.port);

    if (bind(listen_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        perror("bind");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, BACKLOG) < 0)
    {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    for (;;)
    {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (client_fd < 0)
            continue;

        uint32_t type_net, n_net;
        if (recv_all(client_fd, &type_net, 4) < 0 ||
            recv_all(client_fd, &n_net, 4) < 0)
        {
            close(client_fd);
            continue;
        }

        uint32_t type = ntohl(type_net);
        uint32_t N = ntohl(n_net);
        if (type != MSG_INIT)
        {
            close(client_fd);
            continue;
        }

        uint32_t ack_type_net = htonl(MSG_ACK);
        uint32_t ack_len_net = htonl(40u * N);
        if (send_all(client_fd, &ack_type_net, 4) < 0 ||
            send_all(client_fd, &ack_len_net, 4) < 0)
        {
            close(client_fd);
            continue;
        }

        struct checksum_ctx *ctx = checksum_create(
            args.salt_len ? (const uint8_t *)args.salt : NULL,
            args.salt_len);

        for (uint32_t idx = 0; idx < N; ++idx)
        {
            uint32_t req_type_net, len_net;
            if (recv_all(client_fd, &req_type_net, 4) < 0 ||
                recv_all(client_fd, &len_net, 4) < 0)
                break;

            if (ntohl(req_type_net) != MSG_HASHREQ)
                break;
            uint32_t payload_len = ntohl(len_net);

            checksum_reset(ctx);

            uint8_t buffer[UPDATE_PAYLOAD_SIZE];
            uint32_t remaining = payload_len;

            while (remaining >= UPDATE_PAYLOAD_SIZE)
            {
                recv_all(client_fd, buffer, UPDATE_PAYLOAD_SIZE);
                checksum_update(ctx, buffer);
                remaining -= UPDATE_PAYLOAD_SIZE;
            }

            uint8_t remainder[UPDATE_PAYLOAD_SIZE];
            if (remaining > 0)
                recv_all(client_fd, remainder, remaining);

            uint8_t digest[32];
            checksum_finish(ctx, remaining ? remainder : NULL, remaining, digest);

            uint32_t resp_type_net = htonl(MSG_HASHRESP);
            uint32_t resp_idx_net = htonl(idx);
            send_all(client_fd, &resp_type_net, 4);
            send_all(client_fd, &resp_idx_net, 4);
            send_all(client_fd, digest, sizeof(digest));
        }

        checksum_destroy(ctx);
        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
