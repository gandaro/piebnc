/************************************************************************
 *   psybnc, src/p_peer.c
 *   Copyright (C) 2003 the most psychoid  and
 *                      the cool lam3rz IRC Group, IRCnet
 *			http://www.psychoid.lam3rz.de
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

#define P_PEER

#include <p_global.h>

/* MySQL for IP check */
#ifdef MYSQL_IPCHECK
#ifdef HAVE_MYSQL
#include <mysql.h>
int dbconnect();
unsigned int mysqltimeout = MYSQL_TIMEOUT;
void dbquery(char *query);

MYSQL mysql, *sock = NULL;
MYSQL_RES *res = NULL;
MYSQL_ROW row;
int dbconnect() 
{
    mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&mysqltimeout);
    if (!(sock = mysql_real_connect(&mysql,MYSQL_SERVER,MYSQL_USER,MYSQL_PASS,MYSQL_DB,MYSQL_PORT,NULL,0)))
    {
        p_log(LOG_ERROR,-1,"[MySQL] Could not connect to to %s@%s using %s: %s", MYSQL_USER, MYSQL_SERVER, MYSQL_DB, mysql_error(&mysql));
        return 0;
    } else {
/*		p_log(LOG_INFO,-1,"[MySQL] Connected to %s@%s using %s", MYSQL_USER, MYSQL_SERVER, MYSQL_DB); */
        return 1;
    }
}

void dbquery(char *query) 
{
	if(mysql_query(sock, query))
	{
		p_log(LOG_ERROR,-1,"[MySQL] Query (%s) failed (%s)", query, mysql_error(sock));
        res = NULL;
	} else {
/*		p_log(LOG_INFO,-1,"[MySQL] Query: %s", query); */
		res = mysql_store_result(sock);
	}
}

void EndDbQuery(void) {
/* p_log(LOG_INFO,-1,"Cleaning up..."); */
    if (res != NULL) {
        mysql_free_result(res);
        res = NULL;
    }

    if (sock != NULL) {
        mysql_close(sock);
        sock = NULL;
    }
}

char *escapequery (char *query) {
  char *escaped = malloc(2*strlen(query)+1);

  mysql_real_escape_string(&mysql, escaped, query, strlen(query));

  return escaped;
}

#endif
#endif

/* check, if host is already connected */

jmp_buf peertimeout;

void peeralarm(int sig)
{
    longjmp(peertimeout,0x0);
}

int checkpeerhostname (char *hostname)
{
   int apeer;
   int cnt=0;
   struct peernodes *th;
   pcontext;
   th=peernode;
   while (th!=NULL)
   {
       apeer=th->uid;
       if (newpeer(apeer)->state > STD_NOUSE) {
          if (strmcmp(newpeer(apeer)->host,hostname)) {
	     cnt++;
	     if(cnt>2) 
	         return -1;
          }
       }
       th=th->next;
   }
   return 0;
}

/* get a free peer descriptor */

int getnewpeer ()
{
   int apeer;
   pcontext;
   apeer = 1;
   P_CREATE=1;
   while (apeer < 255) 
   {
       if (newpeer(apeer)->state == STD_NOUSE) {
	  clearpeer(apeer);    
          return apeer;
       }
       apeer++;
   }
   return -1;
}

/* erase a connected peer */

int erasepeer(int npeer)
{
    pcontext;
    killsocket(newpeer(npeer)->insock);
    clearpeer(npeer);
    return 0x0;
}

#ifdef LINKAGE

/* linking a link (...) */

int linklink(int npeer)
{
    int lnk;
    char buf[200];
    struct socketnodes *lkm;
    char *pt;
    pcontext;
    lnk=getlink(npeer);
    if (lnk==0) return -1;
    if (getlinkbyname(newpeer(npeer)->name)!=lnk && newpeer(npeer)->type!=NP_RELAY) return -1;
    /* hostname, name of the bouncer, and port are correct */
    pcontext;
    if (*datalink(lnk)->pass==0 && newpeer(npeer)->type!=NP_RELAY)
    {
	strmncpy(datalink(lnk)->pass,newpeer(npeer)->pass,sizeof(datalink(lnk)->pass));
	writelink(lnk);
    }
    if (strmcmp(datalink(lnk)->pass,newpeer(npeer)->pass)==0) return -1;
    /* password is correct */	
    if (newpeer(npeer)->type==NP_LINK) 
    {
	if (datalink(lnk)->type!=LI_ALLOW)
	{
	    return -1; /* invalid link type, only 'allowed' links get accepted */
	}
#ifdef HAVE_SSL
	if(datalink(lnk)->cert[0]==0)
	{
	    lkm=getpsocketbysock(newpeer(npeer)->insock);
	    if(lkm!=NULL)
	    {
		if(lkm->sock->sslfd!=NULL)
		{
		    pt=sslgetcert(lkm->sock->sslfd);
		    if(pt!=NULL)
		    {
			strmncpy(datalink(lnk)->cert,pt,sizeof(datalink(lnk)->cert));
			p_log(LOG_INFO,-1,lngtxt(664),lnk);
		    }
		}
	    }
	} else {
	    ap_snprintf(buf,sizeof(buf),lngtxt(665),lnk);
	    if(sslcheckcert(newpeer(npeer)->insock,datalink(lnk)->cert,buf)==0)
		return -1;	    
	}
#endif
	ssnprintf(newpeer(npeer)->insock,lngtxt(666),me,me);
#ifdef PARTYCHANNEL
	ssnprintf(newpeer(npeer)->insock,lngtxt(667)); /* getting the 'WHO' */
	ap_snprintf(buf,sizeof(buf),"%s%s%s",lngtxt(668),PARTYCHAN,lngtxt(669));
	ssnprintf(newpeer(npeer)->insock,buf,me,me,partytopic);
#endif
	ssnprintf(newpeer(npeer)->insock,lngtxt(670)); /* getting the 'WHO' */
	/* found by fighter: dynamic ip links never timed out on dead ifs */
	if(datalink(lnk)->instate==STD_CONN)
	{
	    lkm=getpsocketbysock(datalink(lnk)->insock);
	    if(lkm)
	    {
		/* destroy the socket silently */
		lkm->sock->errorhandler=NULL;
		lkm->sock->destructor=NULL;
		killsocket(lkm->sock->syssock);
	    }	    
	}
	/* go on as usual */
	datalink(lnk)->insock=newpeer(npeer)->insock;
	datalink(lnk)->instate=STD_CONN;
	datalink(lnk)->outsock=0;
	datalink(lnk)->outsock=0;
	clearpeer(npeer);
#ifdef INTNET
	joinintnettolink(lnk);
#endif
	lkm=getpsocketbysock(datalink(lnk)->insock);
        pcontext;
	if(lkm!=NULL)
	{
	    lkm->sock->param=lnk;
	    lkm->sock->handler=checklinkdata;
	    lkm->sock->errorhandler=checklinkerror;
	    lkm->sock->destructor=checklinkkill;
	}
	p_log(LOG_INFO,-1,lngtxt(671),datalink(lnk)->name);
	sysparty(lngtxt(672),datalink(lnk)->name);
	addtopology(datalink(lnk)->name,me);
	return 0x0; /* done, linked */
    }
    pcontext;
    if (newpeer(npeer)->type==NP_RELAY)
    {
	if(datalink(lnk)->allowrelay!=1)
	{
	    ssnprintf(newpeer(npeer)->insock,lngtxt(673));
	    return -1;
	}
	return linkrelay(npeer,lnk);
    }
    return 0x0;
}

#endif

int userinboundsocket(int usern, int newsock)
{
    user(usern)->insock=newsock;
    return 0x0;
}

/* linking the new peer */

int linkpeer(int npeer)
{
    int rc;
    struct usernodes *th;
    struct socketnodes *lkm;
    char buf[200];
    char *pt;
    pcontext;
#ifdef ANONYMOUS
#ifdef MULTIUSER
    rc=checkuser(newpeer(npeer)->login);
#else
    rc=1;
#endif
    if (rc==0x0) nousers=1;
#endif
    if (nousers==1) {
       nousers = 0;
       rc = firstuser(npeer);
       pcontext;
       if(rc==-1) return -1;
       if (rc) {
	  strmncpy(user(rc)->nick,newpeer(npeer)->nick,sizeof(user(rc)->nick));
	  strmncpy(user(rc)->wantnick,newpeer(npeer)->nick,sizeof(user(rc)->wantnick));
	  strmncpy(user(rc)->user,newpeer(npeer)->user,sizeof(user(rc)->user));
	  strmncpy(user(rc)->host,newpeer(npeer)->host,sizeof(user(rc)->host));
          user(rc)->insock = newpeer(npeer)->insock;
	  user(rc)->instate = STD_CONN;
	  lkm=getpsocketbysock(user(rc)->insock);
	  pcontext;
	  if(lkm!=NULL)
	  {
	    lkm->sock->param=rc;
	    lkm->sock->handler=userinbound;
	    lkm->sock->errorhandler=userinerror;
	    lkm->sock->destructor=userinkill;
	    lkm->sock->sockgroup=SGR_USERINBOUND+rc;
	    lkm->sock->remapper=userinboundsocket;
	  }
#ifdef PARTYCHANNEL
	  joinparty(rc);
#endif
	  writeuser(rc);
          clearpeer(npeer);
	  pcontext;
	  memset(nulluser,0x0,sizeof(struct usert));
	  memset(dummyuser,0x0,sizeof(struct usert));
          return 0x0;
       }
    }
#ifdef MULTIUSER
    rc=checkuser(newpeer(npeer)->login);
#else
    rc=1;
#endif
    pcontext;
    if (rc==0x0) return -1;
    ap_snprintf(buf,sizeof(buf),"%s%s",slt1,slt2);
    pt=BLOW_stringencrypt(buf,newpeer(npeer)->pass);
    pcontext;
    ap_snprintf(newpeer(npeer)->pass,sizeof(newpeer(npeer)->pass),"=%s",pt);
    free(pt);
    if (strmcmp(newpeer(npeer)->pass,user(rc)->pass)==0x0) {
	user(rc)->penalty++;
	user(rc)->pentime=time(NULL);
	return -1;
    }
    /* this should annoy all those funny scriptkids, who are trying to
       bruteforce psybnc-passwords remotely. If more than 2 false logins are
       given, psybnc will lockup any login from that user for 10 minutes
       plus random seconds of a 60 second maximum. Host lockout just would
       lead to let them change the host.
    */
    if(user(rc)->penalty>2 && user(rc)->pentime+600+(rand()%120)>time(NULL))
	return -1;
    else 
    {
	user(rc)->penalty=0;
	user(rc)->pentime=0;
    }
#ifdef HAVE_SSL
    if(user(rc)->cert[0]==0)
    {
	lkm=getpsocketbysock(newpeer(npeer)->insock);	
	if(lkm!=NULL)
	{
	    if(lkm->sock->sslfd!=NULL)
	    {
		pt=sslgetcert(lkm->sock->sslfd);
		if(pt!=NULL)
		{
		    strmncpy(user(rc)->cert,pt,sizeof(user(rc)->cert));
		    p_log(LOG_INFO,-1,lngtxt(674),user(rc)->login);
		    writeuser(rc);
		    flushconfig();
		}
	    }
	}
    } else {
	ap_snprintf(buf,sizeof(buf),lngtxt(675),user(rc)->login);
	if(sslcheckcert(newpeer(npeer)->insock,user(rc)->cert,buf)==0)
	    return -1;	
    }
#endif
#ifndef PARTYCHANNEL
    sysparty(lngtxt(676),newpeer(npeer)->login);
#endif
    p_log(LOG_INFO,-1,lngtxt(677),newpeer(npeer)->login,currentsocket->sock->source);
    lkm=getpsocketbysock(newpeer(npeer)->insock);
    pcontext;
    if(lkm!=NULL)
    {
	lkm->sock->param=rc;
	lkm->sock->handler=userinbound;
	lkm->sock->errorhandler=userinerror;
	lkm->sock->destructor=userinkill;
    }
    /* authentification proceeded */
#ifdef NOMULTICLIENT
    if (user(rc)->insock > 0) {
       ssnprintf(user(rc)->insock,lngtxt(678),user(rc)->nick,newpeer(npeer)->host);
       killsocket(user(rc)->insock);	
    }
#endif
#ifdef PARTYCHANNEL
    if(user(rc)->sysmsg==0)
	ap_snprintf(buf,sizeof(buf),lngtxt(679),newpeer(npeer)->login);
#else
    if(user(rc)->sysmsg==0)
	ap_snprintf(buf,sizeof(buf),lngtxt(680),newpeer(npeer)->login);
#endif
    pcontext;
    th=usernode;
    while (th!=NULL)
    {
	if (th->user!=NULL)
	{
	    if (th->user->parent==rc || th->uid==rc)
	    {
#ifdef DYNAMIC
		cmdbconnect(th->uid);
#endif
		user(th->uid)->delayed=0; /* if a user is not connected, he will get an addserver message at login */
		user(th->uid)->insock = newpeer(npeer)->insock;
#ifdef SCRIPTING
		startdialogues(th->uid);
#endif
		strmncpy(user(th->uid)->host,newpeer(npeer)->host,sizeof(user(th->uid)->host));
		strmncpy(user(th->uid)->wantnick,newpeer(npeer)->nick,sizeof(user(th->uid)->wantnick));
		if (user(th->uid)->outstate == STD_CONN) {
		    user(th->uid)->instate = STD_CONN;
		    if (user(th->uid)->parent==0) 
		    {
			repeatserverinit(rc);
			ssnprintf(user(rc)->insock,lngtxt(681),user(rc)->firstnick,user(rc)->login,user(rc)->host,user(rc)->nick);
		    }
		    if(user(th->uid)->welcome==1)
		    {
			if(user(th->uid)->leavequit==1)
			    rejoinchannels(th->uid);
			else
			    rejoinclient(th->uid);
		    }
#ifdef PARTYCHANNEL
		    if(user(th->uid)->sysmsg==1 || th->user->parent==0)
		    {
			user(th->uid)->sysmsg=0;
			strmncpy(irccontent,PARTYCHAN,sizeof(irccontent));
			cmdjoin(th->uid);
			user(th->uid)->sysmsg=1;
		    }
#endif
		    ap_snprintf(buf,sizeof(buf),lngtxt(682),user(th->uid)->wantnick);
		    writesock_URGENT(user(th->uid)->outsock,buf);
		} else {
		    strmncpy(user(th->uid)->nick,newpeer(npeer)->nick,sizeof(user(th->uid)->nick));
		    user(th->uid)->instate = STD_CONN;
		    if (user(th->uid)->parent==0)
		    {
			if (checkforlog(th->uid))
                           ssnprintf(user(th->uid)->insock,lngtxt(683),user(th->uid)->nick);
			else
                           ssnprintf(user(th->uid)->insock,lngtxt(684),user(th->uid)->nick);
		    }
#ifdef PARTYCHANNEL
		    if(user(th->uid)->sysmsg==1 || th->user->parent==0)
		    {
			user(th->uid)->sysmsg=0;
			strmncpy(irccontent,PARTYCHAN,sizeof(irccontent));
			cmdjoin(th->uid);
			user(th->uid)->sysmsg=1;
		    }
#endif
		}
	    }
	}
	th=th->next;
    }
    clearpeer(npeer);
#ifdef INTNET
    rejoinintchannels(rc);
#endif
    /* allocate to users group, and set the remapper */
    lkm=getpsocketbysock(user(rc)->insock);
    if(lkm)
	if(lkm->sock)
	{
	    lkm->sock->sockgroup=SGR_USERINBOUND+rc;
	    lkm->sock->remapper=userinboundsocket;
	}
    return 0x0;
}

/* if an new peer gets killed */

int killoldlistener(int npeer)
{
    pcontext;
    if(npeer==0) return 0x0;
    p_log(LOG_WARNING,-1,lngtxt(685),newpeer(npeer)->host,newpeer(npeer)->login);
    erasepeer(npeer);
    return 0x0;	  
}

/* if an new peer gets killed */

int erroroldlistener(int npeer,int errn)
{
    pcontext;
    if(npeer==0) return 0x0;
    p_log(LOG_ERROR,-1,lngtxt(686),newpeer(npeer)->host,newpeer(npeer)->login);
    currentsocket->sock->destructor=NULL;
    erasepeer(npeer);
    return 0x0;	  
}

/* checking data coming on a peer */

int checkoldlistener(int npeer)
{
    char *po;
    pcontext;
    if (newpeer(npeer)->state != STD_NOUSE) {
          newpeer(npeer)->delayed++;
	  if (newpeer(npeer)->delayed > 8) {
	     /* all your bases are belong to us */
	     writesock(newpeer(npeer)->insock,lngtxt(687));
	     erasepeer(npeer);
	     return 0x0;
	  }
          pcontext;
	  parse();
	  pcontext;
	  if (ifcommand("USER")) {
	     strmncpy(newpeer(npeer)->user,irccontent,sizeof(newpeer(npeer)->user));
	     po=ircto;
	     po=strchr(ircto,' ');
	     if (po==NULL) return 0x0;
	     *po=0;
	     strmncpy(newpeer(npeer)->login,ircto,sizeof(newpeer(npeer)->login));
	  }
	  pcontext;
#ifdef LINKAGE
	  if (ifcommand(lngtxt(688))) {
	     newpeer(npeer)->lnkport=atoi(irccontent);
	     strmncpy(newpeer(npeer)->name,ircto,sizeof(newpeer(npeer)->name));
	     newpeer(npeer)->type=NP_LINK; /* this is a bouncer */
	  }
	  if (ifcommand(lngtxt(689))) {
	     strmncpy(newpeer(npeer)->vhost,irccontent,sizeof(newpeer(npeer)->vhost));
	  }
	  if (ifcommand(lngtxt(690))) {
	     strmncpy(newpeer(npeer)->server,ircto,sizeof(newpeer(npeer)->server));	    
	     newpeer(npeer)->port=atoi(irccontent);
	  }
	  if (ifcommand(lngtxt(691))) {
	     newpeer(npeer)->lnkport=atoi(irccontent);
	     strmncpy(newpeer(npeer)->name,ircto,sizeof(newpeer(npeer)->name));
	     newpeer(npeer)->type=NP_RELAY; /* this is a relay */
	  }
#endif
	  pcontext;
	  if (ifcommand("NICK")) {
	     strmncpy(newpeer(npeer)->nick,irccontent,sizeof(newpeer(npeer)->nick));
	     if (strlen(newpeer(npeer)->pass)==0 && newpeer(npeer)->type==0) {
	         ssnprintf(newpeer(npeer)->insock,lngtxt(692),newpeer(npeer)->nick);
	     }
	  }
	  pcontext;
	  if (ifcommand("PASS")) {
	     if (*irccontent=='+') *irccontent='-';
	     strmncpy(newpeer(npeer)->pass,irccontent,sizeof(newpeer(npeer)->pass));
#ifdef LINKAGE
	     if (newpeer(npeer)->type!=NP_USER)
	     {
	         if (linklink(npeer)==-1)
		 {
		     p_log(LOG_ERROR,-1,lngtxt(693),newpeer(npeer)->host,newpeer(npeer)->name);
	         erasepeer(npeer);
		     pcontext;
		     return 0x0;		     
		 }
		 return 0x0;
	     }
#endif
	  }
	  pcontext;
	  if ((strlen(newpeer(npeer)->nick) != 0) && (strlen(newpeer(npeer)->login) != 0) && (strlen(newpeer(npeer)->pass) != 0)) {
#ifdef MYSQL_IPCHECK
#ifdef HAVE_MYSQL
        /* This is the MySQL IP Check.
            It uses a shared table for banning and for IP restricting an account. If an entry has a comment it is a ban, if not it is an IP restriction.
            The comment is provided as is for the client when being rejected. The 'server' field is so a shared database can be used for multiple psyBNC instances.
            The 'server' matches the PSYBNC.SYSTEM.ME name (can be undefined, empty). Using a * (star) in the table makes the entry match any psyBNC connected to that table.

            We connect to the database every time to make sure we have a valid working connection. It could be optimized to keep-alive the connection, but guess performance wise it is not that big an issue,
            unless you have a very high amount of users (re-)connecting constantly.
        */
        pcontext;
        if (dbconnect() == 1) {
            char tmpvar[300] = "";
            int mysqlcount;
				/* Check for banned IP or banned ident */
				ap_snprintf(tmpvar, sizeof(tmpvar), "SELECT ip, ident, comments FROM `%s` WHERE (`server` = '%s' OR `server` = '*') AND (`ident` = '%s' OR `ip` = '%s') AND comments <> '' LIMIT 1", MYSQL_TABLE, me, escapequery(newpeer(npeer)->login), currentsocket->sock->source);
				dbquery(tmpvar);
                if (res != NULL) {
                    if ((mysqlcount = mysql_num_rows(res)) != 0) { /* User matches some kind of ban. We kick them off */
                        row = mysql_fetch_row(res);
                        pcontext;
                        ssnprintf(newpeer(npeer)->insock,lngtxt(2000),newpeer(npeer)->nick,row[2]);
                        p_log(LOG_WARNING,-1,"User rejected by filter: %s from host %s (%s) (%s)", newpeer(npeer)->login, newpeer(npeer)->host, currentsocket->sock->source, row[2]);
                        erasepeer(npeer);
                        EndDbQuery();
                        return 0x0;
                    }
                    /* Check if user has IP check enabled */
                    ap_snprintf(tmpvar, sizeof(tmpvar), "SELECT ip FROM `%s` WHERE (`server` = '%s' OR `server` = '*') AND `ident` = '%s' AND comments = ''", MYSQL_TABLE, me, escapequery(newpeer(npeer)->login));
                    dbquery(tmpvar);
                    if ((mysqlcount = mysql_num_rows(res)) != 0) { /* User has IP check */
                        ap_snprintf(tmpvar, sizeof(tmpvar), "SELECT ip FROM `%s` WHERE (`server` = '%s' OR `server` = '*') AND `ident` = '%s' AND `ip` = '%s' AND comments = '' LIMIT 1", MYSQL_TABLE, me, escapequery(newpeer(npeer)->login), currentsocket->sock->source);
                        dbquery(tmpvar);
                        if ((mysqlcount = mysql_num_rows(res)) != 0) { /* User has IP check and user matches */
                            pcontext;
                            p_log(LOG_INFO,-1,"[MySQL_IPCHECK] Successful match for ident %s. IP: %s", newpeer(npeer)->login, currentsocket->sock->source);
                        } else { /* User has IP check and user mismatched */
                            pcontext;
                            ssnprintf(newpeer(npeer)->insock,lngtxt(694),newpeer(npeer)->nick,newpeer(npeer)->login);
                            p_log(LOG_WARNING,-1,"Failed Authentification for %s from host %s (User IP %s did not match database)", newpeer(npeer)->login, newpeer(npeer)->host, currentsocket->sock->source);
                            erasepeer(npeer);
                            EndDbQuery();
                            return 0x0;
                        }
                    }
                } else { /* MySQL query failed or somehow bugged up, so we wipe off the user */
                    pcontext;
                    ssnprintf(newpeer(npeer)->insock,":-psyBNC!psyBNC@psyBNC.dk PRIVMSG %s :Failed to handle the incoming connection. Please try again in a while", newpeer(npeer)->nick);
                    p_log(LOG_ERROR,-1,"Failed to handle the incoming connection from %s@%s. MySQL query failed. See previous log entry for details", newpeer(npeer)->login,newpeer(npeer)->host);
                    erasepeer(npeer);
                    EndDbQuery();
                    return 0x0;
                }
                EndDbQuery();
            } else { /* Connection to MySQL failed or somehow bugged up, so we wipe off the user */
                pcontext;
                ssnprintf(newpeer(npeer)->insock,":-psyBNC!psyBNC@psyBNC.dk PRIVMSG %s :Failed to handle the incoming connection. Please try again in a while", newpeer(npeer)->nick);
                p_log(LOG_ERROR,-1,"Failed to handle the incoming connection from %s@%s. MySQL failed to connect", newpeer(npeer)->login,newpeer(npeer)->host);
                erasepeer(npeer);
                return 0x0;
            }
#endif
#endif
            if (linkpeer(npeer) ==-1) {
            ssnprintf(newpeer(npeer)->insock,lngtxt(694),newpeer(npeer)->nick,newpeer(npeer)->login);
            p_log(LOG_ERROR,-1,lngtxt(695),newpeer(npeer)->login,newpeer(npeer)->host);
            erasepeer(npeer);
#ifdef MYSQL_IPCHECK
#ifdef HAVE_MYSQL
				 EndDbQuery();
#endif
#endif
		  }
      }
    }
    pcontext;
    return 0x0;
}

/* checking a hosts allow */

int checkhostallows(char *host)
{
    char buf[350];
    char buf2[350];
    struct stringarray *th;
    char *pt;
    ap_snprintf(buf,sizeof(buf),lngtxt(696),host);
    th=hostallows;
    while(th!=NULL)
    {
	ap_snprintf(buf2,sizeof(buf2),lngtxt(697),th->entry);
	pt=strchr(buf2,';');
	if(pt!=NULL) *pt=0;
	if(wild_match(buf2,buf)) return 1;
	th=th->next;
    }
    return -1;
}

/* check a connected peer structure */

int checknewlistener(int i)
{
    int asocket;
    int npeer;
    int dummy;
    pcontext;
    asocket = currentsocket->sock->syssock;
    if (checkpeerhostname(accepthost) == -1) {
    	dummy = write(asocket,lngtxt(698),39);
	    killsocket(asocket);
    	return 0x0;
    }
    npeer=getnewpeer();
    if (npeer == -1) {
    	p_log(LOG_ERROR,-1,lngtxt(699),accepthost);
        writesock(asocket,lngtxt(700));
    	killsocket(asocket);
	    return 0x0;
    }
    ssnprintf(asocket,"%s%s%s",lngtxt(701),APPNAME,APPVER);
    currentsocket->sock->param=npeer;
    clearpeer(npeer);	
    pcontext;
    newpeer(npeer)->insock = asocket;
    strmncpy(newpeer(npeer)->host,accepthost,sizeof(newpeer(npeer)->host));
    newpeer(npeer)->state = STD_NEWCON;
    newpeer(npeer)->delayed = 0;
    return 0x0;
}
/* create listening sock */

void killed ()
{
   p_log(LOG_ERROR,-1,lngtxt(702));
   exit(0x0);
}

/* error routine */

void errored ()
{
   errn = 1;
   return; /* Not needed? */
}

/* creating listening ports on the hosts given in the config for the demon */

int createlisteners ()
{
  struct sigaction sv;
  struct sigaction sx;
  int proto;
  int rc;
  char entry[40];
  char host[200];
  int listenport;
  int cntlisten;
  int successes=0;
  char *ho;
#ifdef IPV6
  unsigned char ip6[16];
#ifdef SUNOS
    int ernu;
#endif
#endif
#ifdef SUNOS
  struct hostent *hesun=NULL;
#endif
  struct sockaddr_in sin;
  struct hostent *he;
  dcchost[0]=0;
  dcc6host[0]=0;
  sigemptyset(&sv.sa_mask);
  sv.sa_handler = killed;
  sigemptyset(&sx.sa_mask);
  sx.sa_handler = errored;
  sigaction( SIGTERM, &sv, NULL);
  sigaction( SIGINT, &sx, NULL);
  sigaction( SIGKILL, &sv, NULL);
  sigaction( SIGHUP, &sx, NULL);
  sigaction( SIGUSR1, &sx, NULL);
  sigaction( SIGPIPE, &sx, NULL);
  umask( ~S_IRUSR & ~S_IWUSR );
  srand( time( NULL) ); /* here we randomize to the timer (for randstring) */
  srandom(rand()); /* salt of random bases on rand of time */

  if(getini(lngtxt(703),lngtxt(704),lngtxt(705))==0)
  {
      if(inet_addr(value)<=0)
      {
          p_log(LOG_ERROR,0,lngtxt(706));
      } else {
	  if(strstr(value,"S=")==value)
              strmncpy(dcchost,value+2,sizeof(dcchost));
	  else	  
              strmncpy(dcchost,value,sizeof(dcchost));
      }	
  }
  /* limited to 10 listeners to turn down startup processor usage */
  for(cntlisten=0;cntlisten<10;cntlisten++)
  {
      ap_snprintf(entry,sizeof(entry),lngtxt(707),cntlisten);
      if(getini(lngtxt(708),entry,lngtxt(709))==0)
      {
	  listenport=atoi(value);
	  ap_snprintf(entry,sizeof(entry),lngtxt(710),cntlisten);
	  rc=getini(lngtxt(711),entry,lngtxt(712));
	  if(rc==0)
	  {
	      strmncpy(host,value,sizeof(host));
	  } else {
	      strcpy(host,"*");
	  }
	  if(strmcmp(host,"*"))
	  {
	      proto = AF_INET;
	  } else {
	      /* at startup, always blocking dns will be used. */
	      he=NULL;
#ifdef IPV6
	      proto=AF_INET6;
#else
	      proto=AF_INET;
#endif
	      if(strstr(host,"S=")==host)
	          ho=host+2;
	      else
	          ho=host;  
#ifdef IPV6
#ifdef SUNOS

	      he=getipnodebyname(ho,AF_INET6,0,&ernu);
	      hesun=he;
#else
	      he=gethostbyname2(ho,AF_INET6);
#endif	   
#endif   	      		      
	      if(he==NULL)
	      {
	          he=gethostbyname(ho);
		  proto=AF_INET;
	      }
	      if(he)
	      {
#ifdef IPV6
	          if(proto==AF_INET6)
		  {
		    memcpy(&ip6[0],he->h_addr,16);
		    if(ho==host)
		       ap_snprintf(host,199,"%01x:%01x:%01x:%01x:%01x:%01x:%01x:%01x",
			    ((((unsigned short)ip6[0]) << 8) + (unsigned short)ip6[1]),
			    ((((unsigned short)ip6[2]) << 8) + (unsigned short)ip6[3]),
			    ((((unsigned short)ip6[4]) << 8) + (unsigned short)ip6[5]),
			    ((((unsigned short)ip6[6]) << 8) + (unsigned short)ip6[7]),
			    ((((unsigned short)ip6[8]) << 8) + (unsigned short)ip6[9]),
			    ((((unsigned short)ip6[10]) << 8) + (unsigned short)ip6[11]),
			    ((((unsigned short)ip6[12]) << 8) + (unsigned short)ip6[13]),
			    ((((unsigned short)ip6[14]) << 8) + (unsigned short)ip6[15]));
		    else	    
		       ap_snprintf(host,199,"S=%01x:%01x:%01x:%01x:%01x:%01x:%01x:%01x",
			    ((((unsigned short)ip6[0]) << 8) + (unsigned short)ip6[1]),
			    ((((unsigned short)ip6[2]) << 8) + (unsigned short)ip6[3]),
			    ((((unsigned short)ip6[4]) << 8) + (unsigned short)ip6[5]),
			    ((((unsigned short)ip6[6]) << 8) + (unsigned short)ip6[7]),
			    ((((unsigned short)ip6[8]) << 8) + (unsigned short)ip6[9]),
			    ((((unsigned short)ip6[10]) << 8) + (unsigned short)ip6[11]),
			    ((((unsigned short)ip6[12]) << 8) + (unsigned short)ip6[13]),
			    ((((unsigned short)ip6[14]) << 8) + (unsigned short)ip6[15]));
		  } 
		  else 
#endif	          
		  {
		     memcpy(&sin.sin_addr,he->h_addr,4);
		     if(ho!=host)
		     {
		        ap_snprintf(host,sizeof(host),"S=%s",inet_ntoa(sin.sin_addr));
		     } else 
		        strmncpy(host,inet_ntoa(sin.sin_addr),sizeof(host));
		  }
	      } else {
		  if(ho!=host && strmcmp(ho,"*"))
		  {
		      proto=AF_INET;
		  }
		  else
	              host[0]=0;
	      }
#ifdef SUNOS
	      if(hesun)
	      {
	          freehostent(hesun);
	      }
#endif
	  }      
	  if(host[0]!=0)
	      if(createlistener(host,listenport,proto,0,checknewlistener,erroroldlistener,checkoldlistener,killoldlistener)>0) successes++;
      }	
  }
  if(successes!=0)
  {
      if(dcchost[0]==0)
          p_log(LOG_ERROR,-1,lngtxt(713));
  }
  return successes; /* success */
}
