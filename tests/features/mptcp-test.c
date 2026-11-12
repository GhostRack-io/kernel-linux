/* Opens socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) and checks it fails with
 * EPROTONOSUPPORT, the error Go's listeners fall back to plain TCP on. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (fd >= 0) {
        close(fd);
        puts("an MPTCP socket was made");
        return 1;
    }
    printf("socket: %s\n", strerror(errno));
    return errno == EPROTONOSUPPORT ? 0 : 1;
}
