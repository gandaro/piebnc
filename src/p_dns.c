#define P_DNS

#include <p_global.h>
#include <ares.h>

static ares_channel resolver;

/**
 * Initialize the DNS resolver for use. If this function fails the BNC will not be able to function
 * properly.
 */
int p_dns_init()
{
    int ret;

    if ((ret = ares_init(&resolver)) != ARES_SUCCESS)
    {
        p_log(LOG_ERROR, -1, "Failed to initialize ares resolver: %s", ares_strerror(ret));
        return 0;
    }

    p_log(LOG_INFO, -1, "Asynchronous resolver initialized: c-ares %s", ares_version(NULL));
    return 1;
}

/**
 * Fill the 'readers' and 'writers' file-descriptor sets with the DNS resolver's reader and writer sockets. 
 * These will be the sockets that are either sending a query, or are receiving a response. Returns a value
 * representing the number of active file descriptors or 0 if the DNS resolver is not executing a query.
 *
 * This function should be called before calling and assumes that the fdsets have been properly initialized
 * with something like FD_ZERO()
 */
int p_dns_fds(fd_set *read_fds, fd_set *write_fds)
{
    pcontext;
    return ares_fds(resolver, read_fds, write_fds);
}

/**
 * Tell the DNS resolver that the select() has finished and it can check if any of its sockets had any data
 * on it.
 *
 * This function should be called after calling p_dns_fds() and select(). It ignores any file descriptors that
 * do not belong to it (e.g. IRC connections).
 */
void p_dns_process(fd_set *read_fds, fd_set *write_fds)
{
    pcontext;
    ares_process(resolver, read_fds, write_fds);
}

void p_dns_gethostbyname(char *hostname, int af, dns_host_callback callback, void *arg)
{
    pcontext;
    ares_gethostbyname(resolver, hostname, af, (ares_host_callback)callback, arg);
}

void p_dns_gethostbyaddr(const void *address, int addrlen, int family, dns_host_callback callback, void *arg)
{
    pcontext;
    ares_gethostbyaddr(resolver, address, addrlen, family, (ares_host_callback)callback, arg);
}

int p_dns_success(int status)
{
    return (status == ARES_SUCCESS);
}

const char *p_dns_strerror(int status)
{
    pcontext;
    return ares_strerror(status);
}
