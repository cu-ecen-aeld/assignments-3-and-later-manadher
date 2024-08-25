#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    openlog(NULL, 0, LOG_USER);
    if (argc != 3)
    {
        syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
        return 1;
    }
    FILE *f;
    f = fopen(argv[1], "w");
    if (NULL == f)
    {
        syslog(LOG_ERR, "Could not write: %s", argv[2]);
        closelog();
        return 1;
    }
    int n_char = 0;
    n_char = fprintf(f, "%s", argv[2]);
    if (n_char < 0)
    {
        syslog(LOG_ERR, "Could not write: %s", argv[2]);
         fclose(f);
         closelog();
        return 1;
    }
    else
    {
        syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
    }
    fclose(f);
    closelog();
    return 0;
}