/************************************************************************
 *   psybnc, src/p_socket.c
 *   Copyright (C) 2003 the most psychoid  and
 *                      the cool lam3rz IRC Group, IRCnet
 *          http://www.psychoid.lam3rz.de
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define P_SOCKET

#include <p_global.h>

#define MAX_SENDQ 1000

sigjmp_buf  alarmret;

/* callbacks and connection functions */

static void acceptcb(void *arg, int status, int timeouts, struct hostent *hostent);
static void connectcb(void *arg, int status, int timeouts, struct hostent *hostent);
static void doconnect(struct conndata *conn);

/* clean up functions */

static void freeconndata(struct conndata *conn);
static void freeacceptdata(struct acceptdata *adata);

/* utility functions */

static int convert_v6(struct socketnodes *snode);
int getprotocol(char *ip);


int flushsendq(int socket, int forced);
int writesock_STREAM(int socket, char *data, unsigned int size);
int writesock (int socket, char *data);

int nolog = 0;

/* gets a socketnode from the corresponding system socket number */

struct socketnodes *previous;

struct socketnodes *getpsocketbysock(int syssock)
{
    struct socketnodes *th;
    th=socketnode;
    previous=socketnode;
    while(th!=NULL)
    {
    if (th->sock!=NULL)
    {
        if (th->sock->syssock==syssock) return th;
    }
    previous=th;
    th=th->next;
    }
    return NULL;
}

struct socketnodes *getpsocketbygroup(struct socketnodes *first, unsigned long group, int notsock)
{
    struct socketnodes *lkm;
    lkm=first;
    while(lkm)
    {
    if(lkm->sock)
        if(lkm->sock->sockgroup==group && lkm->sock->syssock!=notsock && lkm->sock->syssock!=notsocket)
        return lkm;
    lkm=lkm->next;
    }
    return NULL;
}

/* creates a socket */

int createsocket(int syssock,int type,int index,unsigned long group,int(*constructor)(int),int(*constructed)(int),int(*errorhandler)(int,int),int(*handler)(int),int(*destructor)(int),int(*remapper)(int,int),int proto,int ssl)
{
    struct psockett *th;
    struct socketnodes *lkm;
    int flags,ret;
    int lsock;
    time_t tm;
    time(&tm);
    lsock=syssock;
    if(syssock!=0)
    {
    lkm=getpsocketbysock(lsock);
    if (lkm!=NULL) return lsock; /* already existent.. so why the hell... */
    } else 
        lsock = socket (proto, SOCK_STREAM, IPPROTO_TCP);
    if(lsock<=0)
    {
    p_log(LOG_ERROR,-1,lngtxt(790));
    return 0x0;
    }
    flags = fcntl(lsock,F_GETFL,0);
    ret = fcntl(lsock,F_SETFL,flags | O_NONBLOCK);
    lkm=socketnode;
    while (lkm!=NULL)
    {
    if (lkm->next==NULL || lkm->sock==NULL)
    {
        if(lkm->sock!=NULL)
        {
        lkm->next=(struct socketnodes *) pmalloc(sizeof(struct socketnodes));
        lkm=lkm->next;
        }
        lkm->sock=(struct psockett *) pmalloc(sizeof(struct psockett));
        lkm->next=NULL;
        th=lkm->sock;
        th->type=type;
        th->protocol=proto;
        th->flag=SOC_NOUSE;
        th->syssock=lsock;
#ifdef HAVE_SSL
        th->ssl=ssl;
        th->sslfd=NULL;
#endif
        th->constructor=constructor;
        th->constructed=constructed;
        th->errorhandler=errorhandler;
        th->handler=handler;
        th->destructor=destructor;
        th->remapper=remapper;
        pcontext;
        th->commbuf=(char *)pmalloc(8192);
        th->bytesin=0;
        th->bytesout=0;
        th->param=index;
        th->sockgroup=group;
        pcontext;
        strmncpy(th->since,ctime(&tm),sizeof(th->since));
        break;
    }
    lkm=lkm->next;
    }
    if(lkm==NULL)
    {
    p_log(LOG_ERROR,-1,lngtxt(791));
    exit(0x0);
    }
    return lsock;
}

/* kill a socket. used instead of close. possibly called iterative */

int reallykillsocket(int syssock) 
{
    struct socketnodes *lkm,*ekm;
    struct socketnodes *siccur=currentsocket;
    int first=0;
    int(*caller)(int);
    int rc,i,t;
    lkm=getpsocketbysock(syssock);    
    p_log(LOG_INFO, -1, "Reallykillsocket!");
    if(lkm==NULL) return 0x0;
    if(lkm==socketnode) first=1;
    if(lkm->sock!=NULL)
    {
        p_log(LOG_INFO, -1, "sock != NULL");

    /* dont care about a static listener */
    //if(lkm->sock->type==ST_LISTEN && lkm->sock->constructed==checknewlistener)
    //    return 0x0;
    /* if its a socketgroup, switch to another socket */
    if(lkm->sock->sockgroup >0 && (ekm=getpsocketbygroup(socketnode,lkm->sock->sockgroup,lkm->sock->syssock)))
    {
        p_log(LOG_INFO, -1, "ingroup");
        if(lkm->sock->remapper!=NULL && ekm->sock!=NULL)
        {
        rc=(*lkm->sock->remapper)(lkm->sock->param,ekm->sock->syssock);
        }
    } else
        p_log(LOG_INFO, -1, "notingroup");

    /* call a destructor, if available */
    if(lkm->sock->destructor!=NULL)
    {
        p_log(LOG_INFO, -1, "destruct");
        caller=lkm->sock->destructor;
        lkm->sock->destructor=NULL;
        lkm->sock->errorhandler=NULL;
        currentsocket=lkm;
        rc=(*caller)(lkm->sock->param);
        currentsocket=siccur;
        lkm=getpsocketbysock(syssock); /* if we are destroyed.. */
        if(lkm==NULL) return 0x0;
    }
    p_log(LOG_INFO, -1, "stoned");

    lkm->sock->serverstoned=0; /* would loop infinitely if */
    lkm->sock->serversocket=0;

    p_log(LOG_INFO, -1, "sendq..");

    t=lkm->sock->entrys;
        for(i=0;i<=t;i++)
        flushsendq(lkm->sock->syssock,Q_FORCED);
    p_log(LOG_INFO, -1, "ssl");

#ifdef HAVE_SSL
    if(lkm->sock->ssl==SSL_ON)
    {
        if(lkm->sock->sslfd!=NULL)
        {
        SSL_shutdown(lkm->sock->sslfd);
        SSL_free(lkm->sock->sslfd);
        lkm->sock->sslfd=NULL;
        }
    }
#endif

    p_log(LOG_INFO, -1, "free sock->combuff");

    free(lkm->sock->commbuf);
    p_log(LOG_INFO, -1, "free sock->");
    free(lkm->sock);
    p_log(LOG_INFO, -1, "free checkfirst");

    if(first) {
        p_log(LOG_INFO, -1, "free FIRST");
        if (lkm->next == NULL) {
            p_log(LOG_INFO, -1, "->next is null, bb?");
        }
        socketnode=lkm->next;
        p_log(LOG_INFO, -1, "still there!");
    } else {
        p_log(LOG_INFO, -1, "free notfirst");
        previous->next=lkm->next;
    }
    
    p_log(LOG_INFO, -1, "free bb!");
    free(lkm);
    }

    p_log(LOG_INFO, -1, "shutdown");
    shutdown(syssock,2);
    p_log(LOG_INFO, -1, "close");
    close(syssock);
    p_log(LOG_INFO, -1, "return");
    return 0x0;

}

int killsocket(int syssock)
{
    struct socketnodes *lkm,*ekm;
    struct socketnodes *siccur=currentsocket;
    int first=0;
    int(*caller)(int);
    int rc,i,t;
    lkm=getpsocketbysock(syssock);    
    if(lkm==NULL) return 0x0;
    if(lkm==socketnode) first=1;
    if(lkm->sock!=NULL)
    {
    /* dont kill a static listener */
    if(lkm->sock->type==ST_LISTEN && lkm->sock->constructed==checknewlistener)
        return 0x0;
    /* if its a socketgroup, switch to another socket */
    if(lkm->sock->sockgroup >0 && (ekm=getpsocketbygroup(socketnode,lkm->sock->sockgroup,lkm->sock->syssock)))
    {
        if(lkm->sock->remapper!=NULL && ekm->sock!=NULL)
        {
        rc=(*lkm->sock->remapper)(lkm->sock->param,ekm->sock->syssock);
        }
    } else
    /* call a destructor, if available */
    if(lkm->sock->destructor!=NULL)
    {
        caller=lkm->sock->destructor;
        lkm->sock->destructor=NULL;
        lkm->sock->errorhandler=NULL;
        currentsocket=lkm;
        rc=(*caller)(lkm->sock->param);
        currentsocket=siccur;
        lkm=getpsocketbysock(syssock); /* if we are destroyed.. */
        if(lkm==NULL) return 0x0;
    }
    lkm->sock->serverstoned=0; /* would loop infinitely if */
    lkm->sock->serversocket=0;
    t=lkm->sock->entrys;
        for(i=0;i<=t;i++)
        flushsendq(lkm->sock->syssock,Q_FORCED);
#ifdef HAVE_SSL
    if(lkm->sock->ssl==SSL_ON)
    {
        if(lkm->sock->sslfd!=NULL)
        {
        SSL_shutdown(lkm->sock->sslfd);
        SSL_free(lkm->sock->sslfd);
        lkm->sock->sslfd=NULL;
        }
    }
#endif
    free(lkm->sock->commbuf);
    free(lkm->sock);
    if(first)
        socketnode=lkm->next;
    else
        previous->next=lkm->next;
    free(lkm);
    }
    shutdown(syssock,2);
    close(syssock);
    return 0x0;
}

/* create a single listener
   changed for 2.3.1 - only ips in host argument */

int createlistener(char *host,int listenport,int proto,int pending, int(*listenhandler)(int), int(*errorhandler)(int,int), int(*datahandler)(int), int(*closehandler)(int))
{
#ifdef IPV6
  struct sockaddr_in6 listen_sa6;
#endif
  struct sockaddr_in listen_sa;
  struct socketnodes *lkm;
  int sopts = 1;
  int issl=SSL_OFF;
  char vsl[10];
  int opt;
  char *ho;
  int listensocket;
  int rc;
  const char *pt;
  vsl[0]=0;
  if(host==NULL) return 0;
#ifdef HAVE_SSL
  if(strstr(host,"S=")==host)
  {
    ho=host+2;
    issl=SSL_ON;
    strmncpy(vsl,lngtxt(792),sizeof(vsl));
  } else
#endif
    ho=host;
  listensocket = socket (proto, SOCK_STREAM, IPPROTO_TCP);
  if(listensocket<=0) return 0;
  listensocket = createsocket(listensocket,ST_LISTEN,0,SGR_NONE,NULL,listenhandler,errorhandler,datahandler,closehandler,NULL,proto,issl);
  lkm=getpsocketbysock(listensocket);
  if(lkm==NULL || listensocket==0)
  {
      if(pending==0)
          p_log(LOG_ERROR,-1,lngtxt(793),ho,listenport,vsl);
      return 0;
  }
  strmncpy(lkm->sock->source,host,sizeof(lkm->sock->source));
  strcpy(lkm->sock->dest,"*");    
  lkm->sock->sport=listenport;
  lkm->sock->dport=0;
  lkm->sock->flag=SOC_SYN; /* we are open */
  highestsocket = listensocket;

  opt=sizeof(int);
  setsockopt (listensocket, SOL_SOCKET, SO_REUSEADDR, &sopts, opt);
#ifdef IPV6
  if(proto==AF_INET6)
     memset (&listen_sa6, 0, sizeof (struct sockaddr_in6));
  else
#endif
     memset (&listen_sa, 0, sizeof (struct sockaddr_in));

#ifdef IPV6
  if(proto==AF_INET6)
  {
      listen_sa6.sin6_port = htons (listenport);
      if(*ho=='*')
      {
          memcpy(&listen_sa6.sin6_addr,&in6addr_any,16);
      listen_sa6.sin6_family=AF_INET6;
      } else {
          if(inet_pton(AF_INET6,ho,&listen_sa6.sin6_addr)<=0)
          {
              killsocket(listensocket);
              if(pending==0)
                  p_log(LOG_ERROR,-1,lngtxt(794),ho,listenport,vsl);
          return 0x0;
          }                   
          listen_sa6.sin6_family=AF_INET6;
      }
      pt=ho;
/* ipv6 dcc not yet specified
      if(dcc6host[0]==0) strmncpy(dcc6host,lkm->sock->source,sizeof(dcc6host)); */
  } else {
#endif
      listen_sa.sin_port = htons (listenport);
      if(*ho=='*')
      {
          listen_sa.sin_addr.s_addr=htonl(INADDR_ANY);
      listen_sa.sin_family=AF_INET;
      } else {
          if(inet_aton(ho,&listen_sa.sin_addr)<=0)
          {
              killsocket(listensocket);
              if(pending==0)
                  p_log(LOG_ERROR,-1,lngtxt(795),host,listenport,vsl);
          return 0x0;
          }
          listen_sa.sin_family=AF_INET;
      }
      strmncpy(lkm->sock->source,inet_ntoa(listen_sa.sin_addr),sizeof(lkm->sock->source));
      if(dcchost[0]==0)
      strmncpy(dcchost,lkm->sock->source,sizeof(dcchost));
#ifdef IPV6
  }
  if(proto==AF_INET6)
    rc=bind(listensocket, (struct sockaddr *) &listen_sa6, sizeof(listen_sa6));
  else  
#endif
    rc=bind(listensocket, (struct sockaddr *) &listen_sa, sizeof (struct sockaddr_in));

  if (rc < 0)
  { 
      killsocket(listensocket);
      if(pending==0)
          p_log(LOG_ERROR,-1,lngtxt(796),ho,listenport,vsl);
      return 0; /* cannot create socket */
  } 
  if ((listen (listensocket, 1)) == -1)
  { 
      killsocket(listensocket);
      if(pending==0)
          p_log(LOG_ERROR,-1,lngtxt(797),ho,listenport,vsl);
      return 0; /* cannot create socket */
  }
  if(pending==0)
  {
      if (nolog != 666) {
          printf(lngtxt(798),lkm->sock->source,listenport,vsl);
      }
      p_log(LOG_INFO,-1,lngtxt(799),lkm->sock->source,listenport,vsl);
  }
  return listensocket;
}


/* conntectto - builds a connection to a host and port using a given vhost */

int rsock;

/* freeconndata - free up a conndata structure */

static void freeconndata(struct conndata *conn)
{
    if (conn != NULL)
    {
        if (conn->host != NULL) free(conn->host);
        if (conn->vhost != NULL) free(conn->vhost);

        if (conn->host_addr != NULL) free(conn->host_addr);
        if (conn->vhost_addr != NULL) free(conn->vhost_addr);
    
        free(conn);
    }
}

/* freeacceptdata - free up an acceptdata structure */

static void freeacceptdata(struct acceptdata *adata)
{
    if (adata != NULL)
    {
        if (adata->ip_addr != NULL) free(adata->ip_addr);
        free(adata);
    }
}

int connectto(int sockt, char *host, int port, char *vhost)
{
    struct socketnodes *snode = getpsocketbysock(sockt);
    struct conndata *conn;
    int family = AF_INET;

    // Store some information about the connection attempt so that we can finish connecting if
    // the hostname has been resolved, or inform the user that we failed to resolve the host.

    conn = calloc(1, sizeof(*conn));
    conn->sock  = sockt;
    conn->host  = strdup(host);
    conn->port  = port;
    conn->vhost = (vhost == NULL || strlen(vhost) == 0 ? NULL : strdup(vhost));

    #ifdef IPV6   
    if (snode && snode->sock && user(snode->sock->param)->preferipv6 == 1)
    {
        p_log(LOG_INFO, -1, "Debug: This user prefers IPv6, IPv6 is used.");

        // The user prefers ipv6, use IPv6.
        family = AF_INET6;
    }
    else if (conn->vhost != NULL && getprotocol(conn->vhost) == AF_INET6)
    {
        p_log(LOG_INFO, -1, "Debug: An IPv6 vhost (%s) was specified, IPv6 is used.", conn->vhost);

        // A vhost has been provided and it is an IPv6 address, use IPv6.
        family = AF_INET6;
    }
    else if (conn->vhost == NULL && getprotocol(conn->host) == AF_INET6)
    {
        p_log(LOG_INFO, -1, "Debug: An IPv6 host (%s) was specified, IPv6 is used.", conn->host);

        // No vhost has been provided, but the server address/hostname is an IPv6 address, use IPv6.
        family = AF_INET6;
    }
    else if (defaultipv6 == 1 && user(snode->sock->param)->preferipv6 == -1)
    {
        p_log(LOG_INFO, -1, "Debug: Default IPv6 is set to %d, IPv6 is used.", defaultipv6);

        // The vhost/host is not an IPv6 address, no preference has been set, but the default is to
        // use IPv6, so use IPv6.
        family = AF_INET6;
    } 
    else
    {
        p_log(LOG_INFO, -1, "Debug: IPv4 is used.");
    }
    #endif

    // Update the socket status to 'Resolving', if possible.

    if (snode && snode->sock)
    {
        snode->sock->flag = SOC_RESOLVE;
    }

    // Tell the DNS resolver (c-ares) to resolve the vhost (or host of the server if no vhost
    // is set) and to call our callback function when done resolving (successful or not).
    
    if (conn->vhost != NULL)
    {
        conn->state = CONN_RESOLVE_VHOST;
        p_dns_gethostbyname(conn->vhost, family, connectcb, conn);
    }
    else
    {
        conn->state = CONN_RESOLVE_HOST;
        p_dns_gethostbyname(conn->host, family, connectcb, conn);
    }
    
    // Inform the bouncer that we are working on it (a return value of zero would mean that
    // something failed).

    return sockt;
}

/* duplicate_in_addr - Reserves memory for, and copies, an in_addr (IP address structure) for use by other functions */

struct in_addr *duplicate_in_addr(int family, struct in_addr *address, int *address_length)
{
    struct in_addr *newaddr;
    int length = 0;

    if (family != AF_INET && family != AF_INET6)
    {
        p_log(LOG_ERROR, -1, "duplicate_in_addr: Unsupported address type: %d", family);
        return NULL;
    }

    #ifdef IPV6
    if (family == AF_INET6)
    {
        length = sizeof(struct in6_addr);
        newaddr = (struct in_addr *)calloc(1, sizeof(struct in6_addr));
        memcpy(newaddr, address, sizeof(struct in6_addr));
    }
    else
    #endif
    {
        length = sizeof(struct in_addr);
        newaddr = (struct in_addr *)calloc(1, sizeof(struct in_addr));
        memcpy(newaddr, address, sizeof(struct in_addr));
    }

    if (address_length)
        *address_length = length;

    return newaddr;
}

/* connectcb - Callback for the DNS resolver, gets called when the host or vhost has been resolved for an outgoing connection */

static void connectcb(void *arg, int status, int timeouts, struct hostent *hostent)
{
    struct conndata *conn = (struct conndata *)arg;
    struct socketnodes *snode = getpsocketbysock(conn->sock);
    char address[512] = "";   

    if (snode == NULL || snode->sock == NULL)
    {
        // The BNC does not know about this socket. This *should* never happen, but if
        // it does we don't want the socket lingering/leak memory, so we kill the socket
        // and free the connection data.
        
        killsocket(conn->sock);
        freeconndata(conn);
        return;
    }

    if (!p_dns_success(status))
    {
        // The host or vhost could not be resolved. We can't continue connecting so a message is
        // displayed and the connection is closed.

        if (conn->state == CONN_RESOLVE_HOST)
        {
            p_log(LOG_ERROR, -1, "Cannot resolve host '%s': %s. Connection to %s:%d cancelled", conn->host, p_dns_strerror(status), conn->host, conn->port);
        }
        else
        {
            p_log(LOG_ERROR, -1, "Cannot resolve virtual host '%s': %s. Connection to %s:%d cancelled", conn->vhost, p_dns_strerror(status), conn->host, conn->port);
        }

        killsocket(conn->sock);
        freeconndata(conn);
        return;
    }

    // The host or vhost was resolved, now we have to store the IP address in the conndata structure
    // so that 'doconnect' can connect to it/bind to it.

    if (conn->state == CONN_RESOLVE_HOST)
    {            
        conn->host_addr = duplicate_in_addr(hostent->h_addrtype, (struct in_addr *)hostent->h_addr_list[0], NULL);
        conn->host_family = hostent->h_addrtype;
    }
    else
    {
        conn->vhost_addr = duplicate_in_addr(hostent->h_addrtype, (struct in_addr *)hostent->h_addr_list[0], NULL);
        conn->vhost_family = hostent->h_addrtype;
    }

    if (conn->state == CONN_RESOLVE_VHOST)
    {
        // A vhost has been provided and we have resolved it. Now that we know the type of 
        // address (IPv4 or IPv6) we can start looking for the server.

        conn->state = CONN_RESOLVE_HOST;
        p_dns_gethostbyname(conn->host, conn->vhost_family, connectcb, conn);
    }
    else
    {
        p_log(LOG_INFO, -1, "DNS: All hosts resolved for socket %d, should be able to connect..", conn->sock);
        
        inet_ntop(conn->host_family, conn->host_addr, address, sizeof(address));
        p_log(LOG_INFO, -1, "DNS: `- Server '%s' = '%s' (socket: %d, vhost: %s)", conn->host, address, conn->sock, (conn->vhost ? conn->vhost : "none.."));
        
        if (conn->vhost)
        {
            inet_ntop(conn->vhost_family, conn->vhost_addr, address, sizeof(address));
            p_log(LOG_INFO, -1, "DNS: `- Vhost '%s' = '%s' (socket: %d)", conn->vhost, address, conn->sock);
        }

        // Make the actual connection and clean up the connection data.

        doconnect(conn);
        freeconndata(conn);
    }
}

/* doconnect - Make the actual connection after the hostname and vhost (if any) have been resolved */

static void doconnect(struct conndata *conn)
{
    struct socketnodes *snode = getpsocketbysock(conn->sock);
    char myhost[60] = "";
    char hishost[60] = "";
    int ret = 0;

    if (snode == NULL || snode->sock == NULL)
    {
        return;
    }

    // Convert the addresses into printable formats.

    inet_ntop(conn->host_family, (struct in_addr *)conn->host_addr, hishost, sizeof(hishost));
    if (conn->vhost)
    {
        inet_ntop(conn->vhost_family, (struct in_addr *)conn->vhost_addr, myhost, sizeof(myhost));
    }

    #ifdef IPV6

    // Make sure there is not an address mismatch (e.g. IPv4 server with IPv6 vhost, or IPv6 server
    // with IPv4 vhost).

    if (conn->vhost != NULL && conn->host_family != conn->vhost_family)
    {
        if (conn->host_family == AF_INET6)
        {
            p_log(LOG_ERROR, -1, "Unable to connect: Address type mismatch. Virtual host '%s' is IPv4, but server '%s' is IPv6.", myhost, hishost);
        }
        else
        {
            p_log(LOG_ERROR, -1, "Unable to connect: Address type mismatch. Virtual host '%s' is IPv6, but server '%s' is IPv4.", myhost, hishost);
        }

        killsocket(conn->sock);
        return;
    }

    if (conn->host_family == AF_INET6)
    {
        // Convert the socket into an IPv6 socket. This has to be done because psyBNC assumes that 
        // a socket is IPv4 by default.

        conn->sock = convert_v6(snode);
    }

    #endif

    // Attempt to bind to the vhost if one is set.

    if (conn->vhost != NULL)
    {
        // Bind to an IPv6 vhost.

        #ifdef IPV6
        if (conn->vhost_family == AF_INET6)
        {               
            struct sockaddr_in6 sin6;
            memset(&sin6, 0, sizeof(struct sockaddr_in6));
            sin6.sin6_family = AF_INET6;

            memcpy(&sin6.sin6_addr, conn->vhost_addr, sizeof(struct in6_addr));
            ret = bind(conn->sock, (struct sockaddr *)&sin6, sizeof(sin6));
        }
        else
        #endif
        {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(struct sockaddr_in));
            sin.sin_family = AF_INET;

            memcpy(&sin.sin_addr, conn->vhost_addr, sizeof(struct in_addr));
            ret = bind(conn->sock, (struct sockaddr *)&sin, sizeof(sin));
        }

        // Abort if the vhost could not be bound.

        if (ret < 0)
        {
            p_log(LOG_ERROR, -1, "Failed to bind vhost '%s': %s", myhost, strerror(errno));
            killsocket(conn->sock);
            return;
        }
    }

    // Connect to an IPv6 server.

    #ifdef IPV6
    if (conn->host_family == AF_INET6)
    {      
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(struct sockaddr_in6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(conn->port);

        memcpy(&sin6.sin6_addr, conn->host_addr, sizeof(struct in6_addr));
        ret = connect(conn->sock, (struct sockaddr *)&sin6, sizeof(sin6));
    }
    else
    #endif
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(conn->port);

        memcpy(&sin.sin_addr, conn->host_addr, sizeof(struct in_addr));
        ret = connect(conn->sock, (struct sockaddr *)&sin, sizeof(sin));
    }

    // Abort if the connection could not be made.

    if (ret < 0 && errno != EINPROGRESS && ret != -EINPROGRESS)
    {
        p_log(LOG_ERROR, -1, "Failed to connect to '%s': %s", hishost, strerror(errno));
        killsocket(conn->sock);
        return;
    }

    // Update the socket's flags, set the ip addresses, etc.
    
    snode->sock->flag = SOC_SYN;
    snode->sock->delay = 0;
    
    if (socketnode->sock != NULL)
    {
        snode->sock->sport = socketnode->sock->sport;
    }

    snode->sock->dport = conn->port;

    // This is probably some hack to prevent the '%' from showing up
    // in snprintf and friends..

    replace(myhost, '%', 127);
    replace(hishost, '%', 127);

    strmncpy(snode->sock->source, myhost, sizeof(snode->sock->source));
    strmncpy(snode->sock->dest, hishost, sizeof(snode->sock->dest));
    
    #ifdef OIDENTD
    create_oidentd_conf();
    #endif
}

/* convert_v6 - Convert an IPv4 socket to an IPv6 socket */

static int convert_v6(struct socketnodes *snode)
{
    int newsock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    int flags, ret;

    if (newsock > 0)
    {
        flags = fcntl(newsock, F_GETFL, 0);
        fcntl(newsock, F_SETFL, flags | O_NONBLOCK);

        if (snode->sock->remapper != NULL)
        {
            ret = (*snode->sock->remapper)(snode->sock->param, newsock);
        }
        
        close(snode->sock->syssock);
        snode->sock->syssock = newsock;
    }

    return newsock;
}

int urgent=0;

/* flush the queue */

int flushsendq(int socket, int forced)
{
    struct socketnodes *lkm;
    struct sendqt *msq,*emsq;
    char *msqd;
    int dummy;
    size_t msglen;
    lkm=getpsocketbysock(socket);
    if(lkm==NULL) return 0x0; /* no socket, no queue */
    msq=lkm->sock->sendq;
    if(msq==NULL) return 0x0; /* nothing to flush */
    if(lkm->sock->flag<SOC_CONN) return 0x0; /* not yet connected.. no flush */
    if(forced!=Q_FORCED)
    {
    if(msq->delay>0)
    {
        msq->delay-=delayinc;
        return 0x0;
    }
    }
    if(lkm->sock->serversocket==1 && lkm->sock->flag==SOC_CONN)
    {
    if(lkm->sock->serverstoned>0) return 0x0;
    if(lkm->sock->serverbytes+strlen(msq->data)>700)
    {
        if(strlen(msq->data)<700)
        {
        lkm->sock->serverstoned=20;
        if(lkm->sock->flag==SOC_CONN)
        {
#ifdef HAVE_SSL
            if(lkm->sock->ssl==SSL_ON && lkm->sock->sslfd!=NULL)
            SSL_write(lkm->sock->sslfd,lngtxt(800),9);
            else
#endif
            dummy = write(socket,lngtxt(801),9);
        }
        return 0x0;     
        }
    }
    lkm->sock->serverbytes+=strlen(msq->data);
    }
    urgent=1;
    msglen=msq->len;
    msqd=msq->data;
    emsq=msq;
    msq=msq->next;
    free(emsq);
    lkm->sock->sendq=msq;
    lkm->sock->entrys--;
    if(lkm->sock->dataflow==SD_STREAM)
        writesock_STREAM(socket,msqd,msglen);
    else
        writesock(socket,msqd);
    free(msqd);
    return 0x0;
}

/* add data to a queue */

int readd=0;

int addq(int socket, char *data, size_t len, int sqdelay)
{
    struct socketnodes *lkm=socketnode;
    struct socketnodes *akm;
    struct sendqt *msq;
    unsigned long group=0;
    int lp=1;
    akm=getpsocketbysock(socket);
    if(akm)
    {
    if(akm->sock)
        group=akm->sock->sockgroup;
    }
    while(lp)
    {
    if(group)
        lkm=getpsocketbygroup(lkm->next,group,-1);
    else
        lkm=akm;
    if(lkm==NULL) /* no socket descriptor, URGENT sent */
    {
        if(group==0)
        {
        urgent=1;
        writesock(socket,data);
        }
    } else {
        lkm->sock->entrys++;
        /* changed for 2.3.1 - if this is an ssl socket, this would lead to a loop
               if x509-lookup still would run  */
#ifndef HAVE_SSL
            if(lkm->sock->entrys>MAX_SENDQ && lkm->sock->serverstoned==0)
#else
            if(lkm->sock->entrys>MAX_SENDQ && lkm->sock->serverstoned==0 && lkm->sock->ssl!=SSL_ON)
#endif
            flushsendq(socket,Q_FORCED); /* too many entries -> flushing */
        if (lkm->sock->sendq==NULL)
        {
        lkm->sock->sendq=(struct sendqt *)pmalloc(sizeof(struct sendqt));
                msq=lkm->sock->sendq;
        } else {
        /* changed in 2.3.1 - readd an entry at the start of the queue */
        if(readd)
        {
            sqdelay=5;
                msq=(struct sendqt *)pmalloc(sizeof(struct sendqt));
                msq->next=lkm->sock->sendq;
                lkm->sock->sendq=msq;
        } else {
                msq=lkm->sock->sendq;
                while(msq->next!=NULL) msq=msq->next;
                msq->next=(struct sendqt *)pmalloc(sizeof(struct sendqt));
            msq=msq->next;
        }
        }
        msq->data=(char *)pmalloc(len+2);
        msq->len=len;
        msq->delay=sqdelay;
        memcpy(msq->data,data,len);
    }
    if(group)
    {
        if(!lkm) lp=0;
    }
    else
        lp=0;
    }
    return 0x0;
}

/* write data to a binary socket */

int writesock_STREAM(int socket, char *data, unsigned int size)
{
    int rc;
    int dummy;
    struct socketnodes *lkm;
    lkm=getpsocketbysock(socket);
    if(lkm==NULL) return 0x0;
    if(urgent==0)
    {
    addq(socket, data,size,0);
    return 0x0;
    } else
    if(lkm->sock->flag==SOC_CONN)
    {
#ifdef HAVE_SSL
    if(lkm->sock->ssl==SSL_ON && lkm->sock->sslfd!=NULL)
    {
        rc=SSL_write(lkm->sock->sslfd,data,size);
        switch(SSL_get_error(lkm->sock->sslfd,rc))
        {
            case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            /* back onto the queue */
            readd=1;
            addq(lkm->sock->syssock, data,size,0);
            readd=0;
            return 0x0;
        default:
            return -1;
        }
    } else
#endif
        dummy = write(socket,data,size);
    }
    lkm->sock->bytesout+=size;
    urgent=0;
    return 0x0;
}

/* write data to a socket */

int writesock (int socket, char *data)
{
    static char buf[8200];
    char sbuf[8200];
    char *po;
    int rc;
    int dummy;

    struct socketnodes *lkm;
    lkm=getpsocketbysock(socket);
    if(lkm==NULL) return 0x0;
    if(lkm->sock==NULL) return 0x0;
    if(lkm->sock->flag<SOC_CONN) urgent=0;
    if(urgent==0 && lkm->sock->nowfds !=1)
    {
    addq(socket,data,strlen(data)+1,0);
    return 0x0;
    }
    if (socket == 0) return -1;
    if(*data==0) return 0x0;
    strmncpy(buf,data,sizeof(buf));
    po=strchr(buf,'\n');
    if (po == NULL) strcat(buf,"\r\n");
    if(po!=NULL)
    {
        po--;
        if (*po!='\r')
        {
            po++;
        *po='\r';
        po++;
        *po='\n';
        po++;
        *po=0;
    }
    }
    errn=0;
    if(lkm!=NULL)
    {
    if(lkm->sock!=NULL)
    {
        lkm->sock->bytesout+=strlen(buf);
    }
    }
    if(urgent==1 || lkm->sock->nowfds == 1)
    {
    replace(buf,127,'%');
    if(lkm->sock->flag==SOC_CONN)
    {
#ifdef HAVE_SSL
        if(lkm->sock->ssl==SSL_ON && lkm->sock->sslfd!=NULL)
        {
        strcpy(sbuf,buf);
        rc=SSL_write(lkm->sock->sslfd,sbuf,strlen(sbuf));
        switch(SSL_get_error(lkm->sock->sslfd,rc))
        {
            case SSL_ERROR_NONE:
            break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
            /* put it back on the queue, dont block here */
            readd=1;
            addq(lkm->sock->syssock,sbuf,strlen(sbuf)+1,0);
            readd=0;
            break;
            default:
            break;
        }
        } else
#endif
        dummy = write(socket,buf,strlen(buf));
    }
    lkm->sock->delay=300;
    urgent=0;   
    }
    if (errn == 1) {
       /* heavy error on writing */
       return -1;
    }
    return 0x0;
}

/* urgent writes */

int writesock_URGENT (int socket, char *data)
{
    urgent=1;
    return writesock(socket,data);
}

/* write in a delay */

int writesock_DELAY (int socket, char *data, int delay)
{
    return addq(socket,data,strlen(data)+1,delay);
}

/* write with format */

int 
ssnprintf(int sock, char *format,...)
{
    va_list va;
    static char buf[8192];
    va_start(va,format);
    ap_vsnprintf(buf,sizeof(buf),format,va);
    writesock(sock,buf);
    va_end(va);
    return strlen(buf);
}

/* determine the protocol based on a given ip */

int getprotocol(char *ip)
{
    #ifdef IPV6
    unsigned char inaddr6[16];
    if(inet_pton(AF_INET6, ip, &inaddr6[0]) > 0)
    { 
        return AF_INET6;
    }
    #endif

    return AF_INET;
}

/* recv from a socket */

int receivesock(struct psockett *sock)
{
    int ret = 1;
    int sz = 8191;
    int rc;
    char *br,*ebr;
    int esck;
    char *pt;
    static char buf[8192];

    sz-=sock->bytesread;
    ircbuf[0]=0;
    if(sz>0)
    {
    errno=0;
#ifdef HAVE_SSL
    if(sock->ssl==SSL_ON)
    {
        if(sock->sslfd==NULL)
        ret=0;
        else
        ret=SSL_read((SSL *)sock->sslfd,sock->commbuf+sock->bytesread,sz);
        if(ret==-1 && (rc = SSL_get_error((SSL *)sock->sslfd,ret)) == SSL_ERROR_WANT_READ)
        {
        *ircbuf=0;
        return 1;
        }
        if(ret<=0) return ret;
        sock->bytesread+=ret;
    } else {
#endif
        ret=recv(sock->syssock,sock->commbuf+sock->bytesread,sz,0);
        if (ret>0) sock->bytesread+=ret;
        if (ret==-1 && ((errno == EWOULDBLOCK) || (errno == EAGAIN))) { *ircbuf=0; return 1; }
        if (ret<=0) return ret;
#ifdef HAVE_SSL
    }
#endif
    } else {
    /* a bug found by Tom R. Flo */
    killsocket(sock->syssock);
    *ircbuf=0;
    return 0x1;
    }
    if (ret>0) sock->bytesin+=ret;
    if(sock->dataflow==SD_STREAM)
    {
    if(ret<=0 || ret>sizeof(ircbuf)) return 1;
    memcpy(&ircbuf,sock->commbuf,ret);
    sock->datalen=ret;
    sock->bytesread=0;
    if (sock->handler!=NULL)
    {
        rc=(*sock->handler)(sock->param);
    }
    return ret;
    }
    esck=sock->syssock;
    br=strchr(sock->commbuf,'\n');
    if(br==NULL) br=strchr(sock->commbuf,10); /* nulline, ignore */
    while(br!=NULL && getpsocketbysock(esck)!=NULL && ret>0)
    {
        br++; /* :) */
    memset(ircbuf,0x0,sizeof(ircbuf));
    memcpy((void *)ircbuf,(void *)sock->commbuf,(br-sock->commbuf));
    memcpy((void *)buf,(void *)br,8192-((br-sock->commbuf)));
    memcpy((void *)sock->commbuf,(void *)buf,8192-((br-sock->commbuf)));
    sock->bytesread-=((br-sock->commbuf));
    memset((void *)sock->commbuf+sock->bytesread,0x0,(8191-sock->bytesread));
    replace(ircbuf,'%',127);
    ebr=strchr(ircbuf,'\r');
    if(ebr==NULL) ebr=strchr(ircbuf,'\n');
    esck=sock->syssock;
    if (sock->serversocket==1)
    {
        pt=strchr(ircbuf,' ');
        if(pt!=NULL)
        {
        pt++;
        if(strstr(pt,lngtxt(802))==pt) /* received PONG, resetting stone */
        {
            if(sock->serverstoned!=0)
            {
            sock->serverstoned=0;
            sock->serverbytes=0;
            } else {
            user(sock->param)->pinged=0;
            user(sock->param)->pingtime=time(NULL);
            }
            ircbuf[0]=0;
        }
        }
    }
    if (sock->handler!=NULL && strlen(ircbuf)>1)
    {
        rc=(*sock->handler)(sock->param);
    }
        if (getpsocketbysock(esck)==NULL) { ret=-1;break; }
    br=strchr(sock->commbuf,'\n');
    if(br==NULL) br=strchr(sock->commbuf,10);
    }
    return ret;
}

unsigned long oldsec=0;

int socket_connect()
{
    int ern,rc;
    ern=0;
#ifdef HAVE_SSL
    if(currentsocket->sock->ssl==SSL_ON && currentsocket->sock->sslfd!=NULL)
    {
    rc=SSL_set_fd(currentsocket->sock->sslfd,currentsocket->sock->syssock);
    if(rc==-1)
    {
        ern=SSL_get_error((SSL *)currentsocket->sock->sslfd,rc);
        if(ern!=SSL_ERROR_WANT_READ && ern!=SSL_ERROR_WANT_WRITE && ern!=SSL_ERROR_NONE)
        {
            p_log(LOG_ERROR,-1,lngtxt(803),currentsocket->sock->syssock,currentsocket->sock->param);
            ern=-1;
        }
        else
            ern=0;
    }
    if(ern==0)
    {                   
        /* blocking ? i hope not */
        SSL_set_connect_state(currentsocket->sock->sslfd);
        rc=SSL_connect(currentsocket->sock->sslfd);
        if(rc==-1)
        {
            ern=SSL_get_error((SSL *)currentsocket->sock->sslfd,rc);
            if(ern!=SSL_ERROR_WANT_READ && ern!=SSL_ERROR_WANT_WRITE && ern!=SSL_ERROR_NONE)
            {
                p_log(LOG_ERROR,-1,lngtxt(804),currentsocket->sock->syssock,currentsocket->sock->param);
            ern=-1;
            }
        else
            ern=0;
        }                                                                   
    }
    }
#endif
    return ern;
}

#ifdef HAVE_SSL

char sgcert[1024];

char *sslgetcert(SSL *ssls)
{
    struct X509 *x5r;
    char *str;
    x5r=(struct X509 *)SSL_get_peer_certificate((SSL *)ssls);
    if(x5r!=NULL)
    {
    str=X509_NAME_oneline(X509_get_subject_name((X509 *)x5r),0,0);
    if(str!=NULL)
    {
        strmncpy(sgcert,str,sizeof(sgcert));
        free(str);
        str=X509_NAME_oneline(X509_get_issuer_name((X509 *)x5r),0,0);
        if(str!=NULL)
        {
        strncat(sgcert," ",sizeof(sgcert));
        sgcert[sizeof(sgcert)-1]=0;
        strncat(sgcert,str,(sizeof(sgcert) - 1));
        sgcert[sizeof(sgcert)-1]=0;
        free(str);
        str=sgcert;
        } else
        str=NULL; /* no issuer */
    } else
        str=NULL; /* no subject */
    X509_free((X509 *)x5r);        
    } else
    str=NULL; /* no cert. */
    
    return str;
}

/* check the cert
 * logitem should be "Link #n" or "User FooBar"
 */

int sslcheckcert(int socket, char *cert, char *logitem)
{
    struct socketnodes *ps;
    char *ccert;
    int rc;
    ps=getpsocketbysock(socket);
    if(ps!=NULL) 
    {
    if(ps->sock->sslfd!=NULL) 
    {
        ccert=sslgetcert(ps->sock->sslfd);
        if(ccert==NULL)
        {
        if(SSLSEC==0)
        {
            p_log(LOG_INFO,-1,lngtxt(805),logitem);
            rc=1;
        } else {
            p_log(LOG_ERROR,-1,lngtxt(806),logitem);
            rc=0;
        }
        } else {
        if(strmcmp(ccert,cert))     
        {
            p_log(LOG_INFO,-1,lngtxt(807),logitem);
            rc=1;
        } else {
            if(SSLSEC==0)
            {
            p_log(LOG_INFO,-1,lngtxt(810),logitem,ccert);
            rc=1;
            }
            else
            {
            p_log(LOG_INFO,-1,lngtxt(811),logitem,ccert);
            rc=0;
            }
        }
        }
    } else
        rc=-1;
    } else
    rc=-1;
    return rc;
}



#endif

#ifdef IPV6
char acip6[16];
#endif
unsigned long acip;

/* accept incoming call on listener */

int p_accept(int lsock)
{
    struct socketnodes *lkm = getpsocketbysock(lsock);
    socklen_t length = 0;
    int ret = 0;

    if(lkm == NULL)
    {
        return -1;
    }

    #ifdef IPV6
    if(lkm->sock->protocol == AF_INET6)
    {
        struct sockaddr_in6 addr6;
        length = sizeof(addr6);
        ret = accept(lsock, (struct sockaddr *)&addr6, &length);
        if(ret == -1) 
        {
            lkm->sock->constructed = NULL;
            killsocket(lsock);
            return -1;      
        }

        memcpy(&acip6[0], addr6.sin6_addr.s6_addr, 16);
        acceptport = ntohs(addr6.sin6_port);
    }
    else
    #endif
    {
        struct sockaddr_in addr;
        length = sizeof(addr);
        ret = accept(lsock, (struct sockaddr * )&addr, &length);
        if (ret == -1) 
        {
            lkm->sock->constructed = NULL;
            killsocket(lsock);
            return -1;      
        }

        acip = addr.sin_addr.s_addr;
        acceptport = ntohs(addr.sin_port);
    }

    return ret;
}

int socket_accept()
{
    struct acceptdata *adata;
    int asocket;
    int listensocket;
    int length = 0;

    listensocket = currentsocket->sock->syssock;
    asocket = p_accept(listensocket);
    if(asocket <= 0) 
    {
        return -1;
    }

    mastersocket = currentsocket;
    if(mastersocket == NULL)
    {
        p_log(LOG_ERROR, -1, lngtxt(812)); // msg 812: "Could not find the listening socket."
        shutdown(asocket, 2);
        close(asocket);
        return -1;
    }

    // Restore the mastersocket's flags.

    mastersocket->sock->flag = SOC_SYN;

    // Start resolving the IP adress to an hostname. As this happens asynchronously we set up the 'acceptdata' 
    // structure so that the callback function knows what it is getting an answer for.

    adata = (struct acceptdata *)calloc(1, sizeof(*adata));
    adata->sock = asocket;
    adata->syssock = mastersocket->sock->syssock;
    adata->ip_family = mastersocket->sock->protocol;
    
    #ifdef IPV6
    if (adata->ip_family == AF_INET6)
    {
        adata->ip_addr = duplicate_in_addr(AF_INET6, (struct in_addr *)&acip6, &length);
    }
    else
    #endif    
    {
        adata->ip_addr = duplicate_in_addr(AF_INET, (struct in_addr *)&acip, &length);
    }

    // Execute the reverse dns (ip -> name) lookup, will call 'acceptcb' when done.

    p_dns_gethostbyaddr(adata->ip_addr, length, adata->ip_family, acceptcb, adata);
    return -1;
}

static void acceptcb(void *arg, int status, int timeouts, struct hostent *hostent)
{
    struct acceptdata *adata = (struct acceptdata *)arg;
    char sebuf[1000] = "";
    int rc;

    inet_ntop(adata->ip_family, adata->ip_addr, acceptip, sizeof(acceptip));   

    if (p_dns_success(status))
    {
        strmncpy(accepthost, hostent->h_name, sizeof(accepthost));
    }
    else
    {
        strmncpy(accepthost, acceptip, sizeof(accepthost));
    }

    // Store the IP address (might just do this earlier in the process? :p)

    mastersocket = getpsocketbysock(adata->syssock);
    if (mastersocket == NULL)
    {
        p_log(LOG_ERROR, -1, "Master socket for %d is NULL.", adata->syssock);

        shutdown(adata->sock, 2);
        close(adata->sock);
        freeacceptdata(adata);
        return;
    }

    // Check if the IP address or hostname is allowed to connect, kill the connection
    // if not.

    if (checkhostallows(acceptip) == -1 && checkhostallows(accepthost) == -1)
    {
        p_log(LOG_ERROR, -1, lngtxt(813), accepthost);

        #ifdef HAVE_SSL 
        if(mastersocket->sock->sslfd != NULL && mastersocket->sock->ssl == SSL_ON) 
        { 
            SSL_shutdown(mastersocket->sock->sslfd);
            SSL_free(mastersocket->sock->sslfd);
            mastersocket->sock->sslfd = NULL; 
        }
        #endif

        shutdown(adata->sock, 2);
        close(adata->sock);
        freeacceptdata(adata);
        return;
    }

    p_log(LOG_WARNING, -1, lngtxt(814), accepthost); // msg 814: "connect from %s"

    // Create a new socket to accept the connection and abort if this fails for
    // some reason.

    #ifdef HAVE_SSL
    adata->sock = createsocket(adata->sock, ST_LISTEN, 0, SGR_NONE, NULL, NULL, mastersocket->sock->errorhandler, mastersocket->sock->handler, mastersocket->sock->destructor, mastersocket->sock->remapper, adata->ip_family, mastersocket->sock->ssl);
    #else
    adata->sock = createsocket(adata->sock, ST_LISTEN, 0, SGR_NONE, NULL, NULL, mastersocket->sock->errorhandler, mastersocket->sock->handler, mastersocket->sock->destructor, mastersocket->sock->remapper, adata->ip_family, 0);
    #endif
    if (adata->sock == -1)
    {
        freeacceptdata(adata);
        return;
    }

    currentsocket = getpsocketbysock(adata->sock);

    // Set up SSL if required.

    #ifdef HAVE_SSL
    if(currentsocket != NULL)
    {
        currentsocket->sock->ssl = mastersocket->sock->ssl;
        currentsocket->sock->sslfd = mastersocket->sock->sslfd;

        mastersocket->sock->sslfd = NULL;
        if (currentsocket->sock->ssl == SSL_ON && currentsocket->sock->sslfd != NULL)          
        {
            SSL_set_fd(currentsocket->sock->sslfd, adata->sock);
            SSL_set_accept_state(currentsocket->sock->sslfd);

            rc = SSL_accept(currentsocket->sock->sslfd);
            if(rc == -1)
            {
                rc = SSL_get_error(currentsocket->sock->sslfd,rc);
                switch(rc)
                {
                    case SSL_ERROR_NONE:
                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_X509_LOOKUP:
                        break;
                    default:
                        ERR_error_string(rc, sebuf);
                        p_log(LOG_ERROR, -1, lngtxt(815), accepthost, sebuf); // msg 815: "Cannot initialize ssl-Connection from %s: %s. Closing Connection."
                        killsocket(adata->sock);
                        freeacceptdata(adata);
                        return;
                }
            }
            
            p_log(LOG_INFO, -1, lngtxt(816), accepthost); // msg 816: "Accepted SSL-Connection from %s"
        }
    }
    #endif

    // Copy the IP addresses and set up the socket for display and debugging purposes.

    strmncpy(currentsocket->sock->source, acceptip, sizeof(currentsocket->sock->source));
    strmncpy(currentsocket->sock->dest, mastersocket->sock->source, sizeof(currentsocket->sock->dest));

    currentsocket->sock->flag  = SOC_CONN;
    currentsocket->sock->param = mastersocket->sock->param;
    currentsocket->sock->sport = acceptport;
    currentsocket->sock->dport = mastersocket->sock->sport;

    // Call the 'socket constructed' handler if one is set

    if(mastersocket->sock->constructed != NULL)
    {
        rc = (*mastersocket->sock->constructed)(mastersocket->sock->param);
    }

    freeacceptdata(adata);
    return;    
}

/* helper routine for checking sockets state without delay. needed for garbage collection.
   Input:  System socket #
   Output: 1 = data waiting
       0 = no data waiting
      <0 = socket error
   */

int socketdatawaiting(int syssock)
{
    fd_set rfds;
    static struct timeval tv;
    if(getpsocketbysock(syssock)==NULL) return 0x0; /* socket not existant, dont raise an error */
    tv.tv_usec = 0;
    tv.tv_sec = 0; /* return without any delay, dont _wait_ for data */
    FD_ZERO(&rfds);
    FD_SET(syssock,&rfds);
    return select(syssock+1,&rfds,NULL,NULL,&tv);
}

/* central socketdriver event routine */

unsigned long socketdriver()
{
    fd_set rfds;
    fd_set wfds;
    struct socketnodes *th,*par;
    int rc,altsock;
    int goterr=0;
    int fdscnt=0,wfdscnt=0;
    int sockit=0,sockat=9999, noadv,ln;
    
    socklen_t opt;
    int optbuf;
    int sck,ssck;
#ifdef HAVE_SSL
    SSL_CIPHER *c;
/*    int bits=0; Should be defined - but which int?*/
    int bits;
#endif
    int ssl_fd;
    static struct timeval tv;
    static int nodelays=0;
    struct sendqt *msq;
    int toutw;
    int nowf=0;
    time_t tm,em;
    /* checking the advancing timer */
    delayinc=0;
    time(&tm);
    if (tm!=oldsec)
    {
    delayinc=1;
    nodelays=0;
    }
    else
    nodelays++; /* disallow process to blast up */
    oldsec=tm;
    th=socketnode;
    par=th;
    /* constructors / socket set / selects */
    FD_ZERO( &rfds);
    FD_ZERO( &wfds);

    while(th!=NULL)
    {
        rc=0;noadv=0;
        if(th->sock!=NULL)
        {
            if(th->sock->serversocket)
            {
                if(th->sock->serverstoned>0)
                {
                    th->sock->serverstoned-=delayinc;
                    /* if the socket was stoned, we just go on sending */
                    if(th->sock->serverstoned==0) th->sock->serverbytes=0;
                }
            }
            if (th->sock->syssock>sockit) sockit=th->sock->syssock;
            if (th->sock->syssock<sockat) sockat=th->sock->syssock;
            if (th->sock->flag==SOC_NOUSE)
            {
            currentsocket=th;
            altsock=th->sock->syssock;
            if(th->sock->constructor!=NULL)
                rc=(*th->sock->constructor)(th->sock->param);
            th=par->next;
            if(th!=NULL)
            {
                if(altsock==th->sock->syssock)
                th->sock->flag=SOC_SYN;    
                else
                noadv=1;
            } else
                noadv=1;
            } else {
            if (th->sock->flag==SOC_SYN || (th->sock->flag==SOC_CONN && th->sock->syssock > 0))
            {
    #ifdef HAVE_SSL
                if(th->sock->ssl==SSL_ON && th->sock->sslfd!=NULL)
                {
                ssl_fd=SSL_get_fd(th->sock->sslfd);
                if(ssl_fd>0)
                {
                    if(ssl_fd<sockat) sockat=ssl_fd;
                    if(ssl_fd>sockit) sockit=ssl_fd;
                    FD_SET(ssl_fd,&rfds);
                }
                } else
    #endif
                if(th->sock->syssock>0)
                    FD_SET(th->sock->syssock, &rfds);
                fdscnt++;
                toutw=0;
                msq=th->sock->sendq;
                if(msq)
                {
                if(msq->delay>0)
                {
                    toutw=-1;
                    msq->delay-=delayinc;
                }
                }
                if(toutw==0 && (th->sock->flag==SOC_SYN || (th->sock->sendq!=NULL && th->sock->serverstoned==0)))
                {
                    
    #ifdef HAVE_SSL
                if(th->sock->ssl==SSL_ON && th->sock->sslfd!=NULL)
                {
                    ssl_fd=SSL_get_fd(th->sock->sslfd);
                    if(ssl_fd>0)
                    {
                    if(ssl_fd<sockat) sockat=ssl_fd;
                    if(ssl_fd>sockit) sockit=ssl_fd;
                    FD_SET(ssl_fd,&wfds);
                    }
                } else
    #endif
                    if(th->sock->syssock>0)
                    FD_SET(th->sock->syssock, &wfds);
                wfdscnt++;
                }
            }
            }
        }
        if(noadv==0)
        {
            par=th;
            th=th->next;
        }
    }
   
    if(sockat > sockit) sockat=sockit;

    int dns_fdcount = p_dns_fds(&rfds, &wfds);   
    if (dns_fdcount + fdscnt == 0)
    {
        sleep(1);
        return 0x0;
    }

    if(nodelays > 20)
    {
        usleep(10);
        nodelays=0;
    }

    /* TODO: psyBNC does not mind waiting for 1 second, but ares might want a response faster */

    tv.tv_usec = 0;
    tv.tv_sec = 1;
       
    //if(wfdscnt>0)
        ln=select(sockit + dns_fdcount + 1, &rfds, &wfds, NULL, &tv);
    //else
    //  ln=select(sockit +1, &rfds, NULL,NULL,&tv);

    /* ares: Process dns responses */

    p_dns_process(&rfds, &wfds);   

    time(&em);
    if(ln<=0) {

    if(ln<0) /* ouch, socket-error. check every single socket, do a garbage collection */
    {
        for(sck=sockit;sck>=sockat;sck--)
        {
        if(socketdatawaiting(sck)<0)
        {
            killsocket(sck);
        }       
        }
    }
    return em-tm;
    }
    th=socketnode;
    par=th;
    if(sockit<=0) sockit=1;
    /* reading, connecting done, errorhandling */
    for(sck=sockit;sck>=sockat;sck--)
    {
    noadv=0;
    ssck=sck;
    th=getpsocketbysock(sck);
    if(th!=NULL)
    {
        currentsocket=th;
#ifdef HAVE_SSL
        if(th->sock->ssl==SSL_ON && th->sock->sslfd!=NULL)
        ssck=SSL_get_fd(th->sock->sslfd);
        if(ssck<=0) ssck=sck;
#endif
        altsock=ssck;
        nowf=th->sock->nowfds;
        if(th->sock->flag==SOC_SYN && ssck>0)
        {
        if(FD_ISSET(ssck,&rfds) || FD_ISSET(ssck,&wfds))
        {
                opt=sizeof(optbuf);
                if (getsockopt(ssck, SOL_SOCKET, SO_ERROR, &optbuf,&opt) >=0) 
            {
            if(optbuf==0)
            {
                /* connected */
                altsock=th->sock->syssock;
#ifdef HAVE_SSL
                if(th->sock->ssl==SSL_ON)
                {
                if(th->sock->type==ST_CONNECT)
                    th->sock->sslfd=SSL_new(clnctx);
                else
                    th->sock->sslfd=SSL_new(srvctx);
                if(th->sock->sslfd==0)
                {
                    p_log(LOG_ERROR,-1,lngtxt(817),th->sock->syssock,th->sock->param);
                    optbuf=-1;
                }
                }
#endif
                if(optbuf==0)
                {
                if(th->sock->type==ST_CONNECT)
                    rc=socket_connect();
                else
                    rc=socket_accept();
                if(rc==0)
                {   
                    if(th->sock->type==ST_CONNECT)
                    th->sock->flag=SOC_CONN;
                    th->sock->delay=300;
                    if(th->sock->constructed!=NULL)
                    {
                    pcontext;
                    writesock_DELAY(th->sock->syssock,"",5);
                    rc=(*th->sock->constructed)(th->sock->param);
                    pcontext;
                    }
                }
                }
            }
            } else {
                optbuf = -1;
            }
            if(optbuf!=0) {
            /* error */
            th=getpsocketbysock(altsock);
            if(th!=NULL)
            {
                if(th->sock->errorhandler!=NULL)
                {
                if(th->sock->sockgroup==0 || (th->sock->sockgroup>0 && getpsocketbygroup(socketnode,th->sock->sockgroup,th->sock->syssock)==NULL))
                {
                    pcontext;
                    rc=(*th->sock->errorhandler)(th->sock->param,SERR_REFUSED);
                    pcontext;
                }
                }
                goterr=1;
                if(getpsocketbysock(altsock)!=NULL)
                {
                killsocket(th->sock->syssock);
                }
            }
            }   
        } else {
            if(th->sock->flag==SOC_SYN && th->sock->type==ST_CONNECT)
            {
            th->sock->delay+=delayinc;
            if(th->sock->delay>SOC_TIMEOUT)
            {
                altsock=th->sock->syssock;
                /* timed out, terminating socket and calling error */
                if(th->sock->errorhandler!=NULL)
                {
                pcontext;
                rc=(*th->sock->errorhandler)(th->sock->param,SERR_TIMEOUT);
                pcontext;
                }
                goterr=1;
                if(getpsocketbysock(altsock)!=NULL)
                {
                killsocket(th->sock->syssock);
                }
            }
            }
        }
        } else 
        if (th->sock->flag==SOC_CONN) {
        noadv=0;
        if(FD_ISSET(ssck,&rfds))
        {
            if (th->sock->flag==SOC_CONN)
            {
            altsock=th->sock->syssock;
            rc=receivesock(th->sock);
            th=par->next;
            if (getpsocketbysock(altsock)==NULL) rc=-1;
            if (rc<=0)
            {
                killsocket(altsock);
                noadv=1;
            }
            }
        } else {
            /* disconnection sensing at outgoing sockets */
            if(th->sock->flag==SOC_CONN && th->sock->type==ST_CONNECT && th->sock->dataflow!=SD_STREAM)
            {
            th->sock->delay-=delayinc;
            if(th->sock->delay<=0)
            {
                writesock_URGENT(th->sock->syssock,"\r\n");
                th->sock->delay=300;
            }
            }
        }
        if(FD_ISSET(ssck,&wfds) && noadv==0 && th->sock->serverstoned==0)
        {
#ifdef HAVE_SSL
            if(th->sock->ssl==SSL_OFF)
            flushsendq(sck,Q_NEXT);
            else
                if(th->sock->ssl==SSL_ON && th->sock->sslfd!=NULL)
            {
                c=SSL_get_current_cipher(th->sock->sslfd);
                SSL_CIPHER_get_bits(c,&bits);
                if(bits!=0) /* if handshake is done.. */
                flushsendq(sck,Q_NEXT);
            }
#else
            flushsendq(sck,Q_NEXT);
#endif
        }
        }
    }
    if (goterr==1) break;
    }

    return em-tm;
}

/**
 * Get the (real) source IP for a connected socket.
 * Returns NULL on error
 */
char *get_sourceip(int fd)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    char *ip = NULL;
    
    if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) != 0)
    {
        return NULL;
    }

    #ifdef IPV6
    if (addr.ss_family == AF_INET6)
    {
        ip = calloc(1, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&addr)->sin6_addr), ip, INET6_ADDRSTRLEN);
    }
    #endif

    if (addr.ss_family == AF_INET)
    {
        ip = calloc(1, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(((struct sockaddr_in *)&addr)->sin_addr.s_addr), ip, INET_ADDRSTRLEN);
    }     

    return ip;
}

/**
 * Get the (real) source port for a connected socket.
 * Returns 0 on error
 */
int get_sourceport(int fd)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int port = 0;
    
    if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) != 0)
    {
        return 0;
    }

    #ifdef IPV6
    if (addr.ss_family == AF_INET6)
    {
        port = ((struct sockaddr_in6*)&addr)->sin6_port;
    }
    #endif

    if (addr.ss_family == AF_INET)
    {
        port = ((struct sockaddr_in*)&addr)->sin_port;
    }     

    return ntohs(port);
}
