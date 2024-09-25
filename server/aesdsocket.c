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
#include <sys/stat.h>
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
FILE *log_file;

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
        if (log_file)
            fclose(log_file);
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
/*
 * Opens a file filename sends its content to sock then closes it.
 * Not much checks on sending less than asked
 */
int send_file_content(int sock, const char *fname)
{
    struct stat finfo;
    if (stat(fname, &finfo))
    {
        syslog(LOG_ERR, "Could not stat file %s for read", fname);
        exit(EXIT_FAILURE);
    }
    FILE *f_desc = fopen(fname, "r");
    if (!f_desc)
    {
        syslog(LOG_ERR, "Could not open file %s for read", fname);
        exit(EXIT_FAILURE);
    }
    char *buf = (char *)malloc(finfo.st_size + 1);
    if (!buf)
    {
        syslog(LOG_ERR, "Could not allocate memory sized at %ld", finfo.st_size);
        exit(EXIT_FAILURE);
    }
    char *ret = fgets(buf, (int)finfo.st_size, f_desc);
    size_t read_chars_count;
    while (ret)
    {
        read_chars_count = strlen(ret);
        int sent = send(sock, buf, read_chars_count, 0);
        if (sent == -1)
        {
            syslog(LOG_ERR, "Could not send data");
            free(buf);
            exit(EXIT_FAILURE);
        }
        ret = fgets(buf, (int)finfo.st_size, f_desc);
    }
    free(buf);
    fclose(f_desc);
    // remove(fname);
    return 0;
}
int find_char(char *buf, size_t ln, char c)
{
    size_t res = 0;
    while (res < ln && buf[res] != c)
        ++res;
    if (res + 1 > ln)
        return -1;
    return res;
}

/*
 * Opens a file filename sends packets content to it then closes it.
 * Not much checks on sending less than asked
 */
int read_content_to_file(int sock, FILE *f_desc)
{
    int same_line = 1;
    char *buf = (char *)malloc(MAX_BUF_SZ);
    int rd = 1;
    while (same_line)
    {
        rd = read(sock, buf, MAX_BUF_SZ);
        if (rd == -1)
        {
            syslog(LOG_ERR, "Could not read data from Socket");
            free(buf);
            exit(EXIT_FAILURE);
        }

        if (fwrite(buf, sizeof(char), rd, f_desc) < (size_t)rd)
        {
            syslog(LOG_ERR, "Could not write data to file ");
            free(buf);
            exit(EXIT_FAILURE);
        }
        syslog(LOG_DEBUG, "Writing to file ");
        int pos = find_char(buf, rd, '\n');
        if (pos == rd - 1)
        {
            same_line = 0;
        }
    }
    free(buf);

    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    FILE *f_desc = fopen(pkt_log_file, "w");
    if (!f_desc)
    {
        syslog(LOG_ERR, "Could not open file %s for read", pkt_log_file);
        exit(EXIT_FAILURE);
    }
    if (argc >= 3)
    {
        syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
        return 1;
    }

    if (argc == 2 && !strcmp(argv[1], "-d"))
    {
        daemon(0, 0);
    }

    openlog(NULL, 0, LOG_USER);
    /*system("sudo apt -y install netcat");*/
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
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
    /*struct sigaction sa;
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP;
    if (0 && sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    } */

    while (1)
    {
        // main accept() loop

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

        if (!fork())
        { // this is the child process
            /*signal(SIGINT, sig_handler);
            signal(SIGTERM, sig_handler);*/
            // close(sockfd);

            read_content_to_file(new_fd, f_desc);
            fclose(f_desc);

            send_file_content(new_fd, pkt_log_file);

            close(file_fd);
            file_fd = 0;
            close(new_fd);
            new_fd = 0;
            syslog(LOG_DEBUG, "Closed connection from %s", s);
            exit(0);
        }
    }

    return 0;
}
