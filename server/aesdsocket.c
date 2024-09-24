#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>

#define PORT "9000" // the port users will be connecting to
#define BACKLOG 10  // how many pending connections queue will hold
#define pkt_log_file "/var/tmp/aesdsocketdata"
#define BUF_SZ 512
#define MAX_BUF_SZ 1024
int sockfd = 0;
int new_fd = 0; // listen on sock_fd, new connection on new_fd
int file_fd = 0;
int zombie = 0;

typedef struct tx_t
{
    size_t sz;
    size_t last;
    char *txt;
    int done;
} tx_t;

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while ((s < 0 || s >= 0) && waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
    if (!zombie)
        remove(pkt_log_file);
}

void sig_handler(int s)
{
    if (s == SIGINT || s == SIGTERM)
    {
        syslog(LOG_DEBUG, "Caught signal, exiting");
        if (file_fd > 0)
            close(file_fd);
        if (new_fd > 0)
            close(new_fd);
        if (sockfd > 0)
            close(sockfd);
        remove(pkt_log_file);
    }
}
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int sendall(int s, char *buf, int *len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;

    while (total < *len)
    {
        n = send(s, buf + total, bytesleft, 0);
        syslog(LOG_DEBUG, "Have sent %d to %d", n, s);
        if (n == -1)
        {
            break;
        }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n == -1 ? -1 : 0; // return -1 on failure, 0 on success
}

char *expand_buffer(size_t src_sz,  /* Size of src[] */
                    char *src,      /* src[] */
                    size_t *new_sz) /* The size of the new buffer to update by this function*/
{
    /* Creates a bigger buffer and copies content of src to it*/
    size_t additional = 2 * src_sz;
    char *res = NULL;
    while (!res && additional > 4)
    {
        additional = additional / 2;
        *new_sz = src_sz + additional;
        res = (char *)malloc(*new_sz);
    }
    if (res)
    {
        memcpy(res, src, src_sz);
        free(src);
    }
    else
    { /* Could not expand the buffer */
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return res;
}
void write_tx_t_to_file(struct tx_t *st, int file_fd)
{
    if (!st || !st->last)
        return;
    write(file_fd, st->txt, st->last);
}

void write_char_to_tx_t(tx_t *dest, char c, int file_fd)
{
    if (!dest)
    {
        perror("Writing to null ptr");
        exit(EXIT_FAILURE);
    }
    if (dest->last > dest->sz - 2)
    {
        dest->txt = expand_buffer(dest->sz, dest->txt, &dest->sz);
    }
    dest->txt[dest->last++] = c;
    if (c == '\n')
    {
        write_tx_t_to_file(dest, file_fd);
        dest->txt[dest->last] = '\0';
        printf("Writing %ld characters %s", dest->last, dest->txt);
        dest->last = 0; /*resets the string to empty*/
    }
}

/*
 * Write cnt characters to st_t
 * When writing a '\n' write the content of st_t to file and reset the st_t
 * continue writing the rest of cnt characters to the reset st_t
 */
size_t read_to_str(size_t src_sz, /* Size of src[] */
                   char *src,     /* src[] */
                   size_t cnt,    /* number of characters to copy */
                   tx_t *dest,    /* info in dest , including the last written index */
                   int file_fd)
{
    if (!src || !dest || !dest->txt)
        return 0;
    if (cnt > src_sz)
        cnt = src_sz; /*Write only the content of src*/
    size_t i = 0;
    while (i < cnt)
    {
        write_char_to_tx_t(dest, src[i++], file_fd);
    }
    return i;
}
int main(int argc, char **argv)
{

    if (argc >= 3)
    {
        syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
        return 1;
    }

    if (argc == 2 && !strcmp(argv[1], "-d"))
    {
        zombie = 1;
    }
    if (zombie)
        printf("I am a zombie\n"); /*Remove Remove*/
    openlog(NULL, 0, LOG_USER);

    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            sockfd = 0;
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (!zombie && sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while (1)
    { // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);
        syslog(LOG_DEBUG, "Accepted connection from %s", s);
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
        if (!fork())
        { // this is the child process
            signal(SIGINT, sig_handler);
            signal(SIGTERM, sig_handler);
            close(sockfd); // child doesn't need the listener
            /* Open the file for writing (create if it doesn't exist, truncate if it does) */
            file_fd = open(pkt_log_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (file_fd < 0)
            {
                perror("open");
                exit(EXIT_FAILURE);
            }
            syslog(LOG_DEBUG, "Opened file %s for writing", pkt_log_file);
            char re_msg[MAX_BUF_SZ];
            tx_t str;
            memset(&str, 0, sizeof(str));
            str.sz = BUF_SZ;
            str.txt = (char *)malloc(BUF_SZ);
            int bytes = recv(new_fd, re_msg, MAX_BUF_SZ - 1, 0);
            syslog(LOG_DEBUG, "Received %d bites from %d", bytes, new_fd);
            while (bytes > 0)
            {
                re_msg[MAX_BUF_SZ - 1] = '\0';
                read_to_str(MAX_BUF_SZ - 1, re_msg, bytes, &str, file_fd);
                bytes = recv(new_fd, re_msg, MAX_BUF_SZ - 1, 0);
                syslog(LOG_DEBUG, "Received (inner) %d bites from %d", bytes, new_fd);
            }
            if (bytes == -1)
            {
                perror("recv");
                exit(1);
            }
            if (str.last)
            {
                write_char_to_tx_t(&str, '\n', file_fd);
            }

            close(file_fd);
            syslog(LOG_DEBUG, "Closed file %s for writing", pkt_log_file);
            file_fd = open(pkt_log_file, O_RDONLY, 0644);
            if (file_fd < 0)
            {
                perror("open for read");
                exit(EXIT_FAILURE);
            }
            syslog(LOG_DEBUG, "Opend file %s for reading", pkt_log_file);
            ssize_t rd;
            while ((rd = read(file_fd, re_msg, MAX_BUF_SZ - 1)))
            {
                re_msg[rd] = '\0';
                int read = rd;
                syslog(LOG_DEBUG, "Have read %s %ld from file", re_msg, rd);
                int err = sendall(new_fd, re_msg, &read);
                if (err == -1)
                {
                    perror("send");
                    break;
                }
            }
            close(file_fd);
            file_fd = 0;
            close(new_fd);
            new_fd = 0;
            syslog(LOG_DEBUG, "Closed connection from %s", s);
            exit(0);
        }
        close(new_fd); // parent doesn't need this
        new_fd = 0;
    }

    closelog();
    return 0;
}
