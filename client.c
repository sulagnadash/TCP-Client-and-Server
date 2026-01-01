#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <argp.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "hash.h"

struct client_arguments
{
    char ip_address[16]; /* You can store this as a string, but I probably wouldn't */
    int port;            /* is there already a structure you can store the address
                          * and port in instead of like this? */
    int hashnum;
    int smin;
    int smax;
    char *filename; /* you can store this as a string, but I probably wouldn't */
};

error_t client_parser(int key, char *arg, struct argp_state *state)
{
    struct client_arguments *args = state->input;
    error_t ret = 0;
    int len;

    switch (key)
    {
    case 'a':
        /* validate that address parameter makes sense */
        strncpy(args->ip_address, arg, sizeof(args->ip_address) - 1);
        if (strlen(arg) >= sizeof(args->ip_address))
        {
            argp_error(state, "Invalid address: too long");
        }
        break;
    case 'p':
        /* Validate that port is correct and a number, etc!! */
        args->port = atoi(arg);
        if (args->port <= 1024)
        {
            argp_error(state, "Invalid option for port, must be greater than 1024");
        }
        break;
    case 'n':
        /* validate argument makes sense */
        args->hashnum = atoi(arg);
        if (args->hashnum <= 0)
        {
            argp_error(state, "Number of hash requests (-n) must be positive");
        }
        break;
    case 300:
        args->smin = atoi(arg);
        break;
    case 301:
        args->smax = atoi(arg);
        break;
    case 'f':
        len = strlen(arg);
        args->filename = malloc(len + 1);
        strcpy(args->filename, arg);
        break;
    default:
        ret = ARGP_ERR_UNKNOWN;
        break;
    }
    return ret;
}

void client_parseopt(struct client_arguments *out, int argc, char *argv[])
{
    struct argp_option options[] = {
        {"addr", 'a', "addr", 0, "The IP address the server is listening at", 0},
        {"port", 'p', "port", 0, "The port that is being used at the server", 0},
        {"hashreq", 'n', "hashreq", 0, "The number of hash requests to send to the server", 0},
        {"smin", 300, "minsize", 0, "The minimum size for the data payload in each hash request", 0},
        {"smax", 301, "maxsize", 0, "The maximum size for the data payload in each hash request", 0},
        {"file", 'f', "file", 0, "The file that the client reads data from for all hash requests", 0},
        {0}};

    struct argp argp_settings = {options, client_parser, 0, 0, 0, 0, 0};

    /* bzero ensures that "default" parameters are all zeroed out */
    bzero(out, sizeof(*out));

    if (argp_parse(&argp_settings, argc, argv, 0, NULL, out) != 0)
    {
        printf("Got error in parse\n");
    }

    /* If they don't pass in all required settings, you should detect
     * this and return a non-zero value from main */
    if (out->ip_address[0] == '\0' || out->port == 0 || out->hashnum <= 0 ||
        out->smin <= 0 || out->smax <= 0 || out->smin > out->smax || !out->filename)
    {
        fprintf(stderr, "Client: Missing or invalid arguments\n");
        exit(EXIT_FAILURE);
    }

    printf("Got %s on port %d with n=%d smin=%d smax=%d filename=%s\n",
           out->ip_address, out->port, out->hashnum,
           out->smin, out->smax, out->filename);
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

/* Initialization message, acknowledgement, hash request, hash response*/
enum
{
    MSG_INIT = 1,
    MSG_ACK = 2,
    MSG_HASHREQ = 3,
    MSG_HASHRESP = 4
};

int main(int argc, char *argv[])
{
    struct client_arguments args;
    client_parseopt(&args, argc, argv);

    FILE *fp = fopen(args.filename, "rb");
    if (!fp)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        perror("socket");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(args.port);
    inet_pton(AF_INET, args.ip_address, &servaddr.sin_addr.s_addr);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        fclose(fp);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    srand((unsigned)time(NULL));

    uint32_t init_type = htonl(MSG_INIT);
    uint32_t n_val = htonl(args.hashnum);
    send_all(sockfd, &init_type, 4);
    send_all(sockfd, &n_val, 4);

    uint32_t ack_type_net, ack_len_net;
    recv_all(sockfd, &ack_type_net, 4);
    recv_all(sockfd, &ack_len_net, 4);

    for (int i = 0; i < args.hashnum; i++)
    {
        int len = (rand() % (args.smax - args.smin + 1)) + args.smin;
        uint8_t *buffer = malloc(len);

        size_t bytes_read = fread(buffer, 1, len, fp);
        if (bytes_read < (size_t)len)
        {
            rewind(fp);
            fread(buffer + bytes_read, 1, len - bytes_read, fp);
        }

        uint32_t req_type_net = htonl(MSG_HASHREQ);
        uint32_t len_net = htonl(len);
        send_all(sockfd, &req_type_net, 4);
        send_all(sockfd, &len_net, 4);
        send_all(sockfd, buffer, len);

        uint32_t resp_type_net, resp_idx_net;
        uint8_t digest[32];
        recv_all(sockfd, &resp_type_net, 4);
        recv_all(sockfd, &resp_idx_net, 4);
        recv_all(sockfd, digest, sizeof(digest));

        printf("%d: 0x", i + 1);
        for (size_t j = 0; j < 32; j++)
            printf("%02x", digest[j]);
        putchar('\n');

        free(buffer);
    }

    fclose(fp);
    close(sockfd);
    return 0;
}
