/************************************************************************
 *   psybnc, src/p_client.c
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

#define P_CLIENT

#include <p_global.h>

int cmdaddlink(int usern, int type);
int quitclient(int usern);

/* the partychannel commands */

#ifdef PARTYCHANNEL

int ipartychan()
{
    char *pt,*pt2;
    char sbuf[200];
    char ebuf[4096];
    strmncpy(sbuf,PARTYCHAN,sizeof(sbuf));
    ucase(sbuf);
    pt=strstr(irccontent,PARTYCHAN);
    if(pt==NULL) pt=strstr(irccontent,sbuf);
    if(pt==NULL) return 0;
    pt2=pt+strlen(sbuf);
    *pt=0;
    if(*pt2==',')
    {
	pt2++;
	ap_snprintf(ebuf,sizeof(ebuf),"%s%s",irccontent,pt2);
	strmncpy(irccontent,ebuf,sizeof(irccontent));
	return 2;
    }
    if(pt!=irccontent) return 2;
    return 1;
}

int cmdjoin(int usern)
{
    int rc;
    char siccont[1024];
    rc=ipartychan();
    strmncpy(siccont,irccontent,sizeof(siccont));
    if(rc>0)
    {
	if(user(usern)->sysmsg==0)
	{
	    user(usern)->sysmsg=1;
	    joinparty(usern);
	}
	ap_snprintf(ircbuf,sizeof(ircbuf),lngtxt(3),siccont);
	if(rc==1) return 0;
    }
    return 1;
}


/* the partychannel commands */
int cmdtopic(int usern)
{
    struct usernodes *th;
    char buf[400];
    int rc;
    if(strmncasecmp(ircto,PARTYCHAN))
	{
	    th=usernode;
	    while(th!=NULL)
	    {
		rc=th->uid;
		if(user(rc)->instate>STD_NOCON && user(rc)->sysmsg==1)
		{
		    ap_snprintf(buf,sizeof(buf),"%s%s%s",lngtxt(4),PARTYCHAN,lngtxt(5));
		    ssnprintf(user(rc)->insock,buf,
			    user(usern)->login,me,user(usern)->login,me,irccontent);
		}
		th=th->next;
	    }
	    ap_snprintf(buf,sizeof(buf),"%s%s%s",lngtxt(6),PARTYCHAN,lngtxt(7));
	    ap_snprintf(ircbuf,sizeof(ircbuf),buf,
		        user(usern)->login,me,irccontent);
	    strmncpy(partytopic,irccontent,sizeof(partytopic));
	    broadcast(0);
	    return 0;
	}
    return 1;
}

int cmdpart(int usern)
{
    char siccont[1024];
    char buf[400];
    int rc;
    rc=ipartychan();
    strmncpy(siccont,irccontent,sizeof(siccont));
    if(rc>0)
    {
	if(user(usern)->sysmsg==1)
	{
	    user(usern)->sysmsg=0;
	    ap_snprintf(buf,sizeof(buf),"%s%s%s",lngtxt(8),PARTYCHAN,lngtxt(9));
	    ssnprintf(user(usern)->insock,buf,user(usern)->nick,user(usern)->login,user(usern)->host,user(usern)->nick);
	    sysparty(lngtxt(10),user(usern)->login);
	}
	ap_snprintf(ircbuf,sizeof(ircbuf),lngtxt(11),siccont);
	if(rc==1) return 0;
    }
    return 1;
}

#endif

/* display a help to a topic or an overview */
int printhelp(int ausern)
{
    int usern=0;
    char buf[250];
    pcontext;
    if (user(usern)->parent!=0) usern=user(usern)->parent; else usern=ausern;

    if(*irccontent==0 || ausern==0)
    {
	ap_snprintf(buf,sizeof(buf),lngtxt(156),user(usern)->nick);
	ssnprintf(user(usern)->insock,"%s" APPNAME APPVER "%s",buf, lngtxt(157));
	ssnprintf(user(usern)->insock,lngtxt(158),user(usern)->nick);
	userhelp(usern,NULL);
	ssnprintf(user(usern)->insock,lngtxt(159),user(usern)->nick);
	pcontext;
    } else {
	userhelp(usern,irccontent);
	ssnprintf(user(usern)->insock,lngtxt(160),user(usern)->nick);
    }
    return 0x0;
}

/* printing server banner */
int repeatserverinit(int usern)
{
    FILE *userb;
    struct linknodes *dcc;
    char buf[1024];
    char fname[40];
    char *zer;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ap_snprintf(fname,sizeof(fname),lngtxt(12),usern);
    if ((userb=fopen(fname,"r")) == NULL) {
	return -1;
    }
    while (fgets(buf,sizeof(buf),userb))
    {
	strmncpy(ircbuf,buf,sizeof(ircbuf));
	/* replacing the initial IP for DCC sessions */
	zer=strstr(ircbuf,lngtxt(13));
	if (zer!=NULL)
	{
	    zer=strchr(zer,'@');
	    if (zer!=NULL)
	    {
		zer++;
		*zer=0;
		if(strlen(ircbuf)+strlen(user(userp)->host)+2<sizeof(ircbuf))
		{
		    strcat(ircbuf,user(userp)->host);
		    strcat(ircbuf,"\n");
		}
	    }
	}
	/* done */
	parentnick(usern);
	writesock(user(usern)->insock,ircbuf);
    }
    fclose(userb);
    if (checkforlog(usern))
    {
	if(user(userp)->firstnick[0]!=0)
	    ssnprintf(user(usern)->insock,lngtxt(14),user(userp)->firstnick);
    }
    if (strlen(user(usern)->away)>0) {
	writesock(user(usern)->outsock,lngtxt(15));
	strmncpy(buf,lngtxt(16),sizeof(buf));
	dcc=user(usern)->dcc;
	while(dcc!=NULL)
	{
	    if (dcc->link!=NULL)
	    {
		if (dcc->link->outstate==STD_CONN)
		    writesock(dcc->link->outsock,buf);
	    }
	    dcc=dcc->next;
	}
    }
    user(usern)->gotop=0;
    return 0x0;
}

/* who is on the bounce ? */
int cmdbwho(usern)
{
    struct usernodes *th;
    int userl;
    char buf[400];
    char i;
    int userp;
    int last;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    th=usernode;
    while (th!=NULL)
    {
	 userl=th->uid;
	 last=0;
         if (strlen(user(userl)->login)) {
	    if (user(userl)->parent != 0) i='^'; else i='*';
	    if (*user(userl)->host==0) { i=' ';last=1; }
	    if (user(userl)->parent != 0) last=0;
	    if (user(usern)->rights == RI_USER) {
	       if(last==1)
	           ap_snprintf(buf,sizeof(buf),lngtxt(17),user(userp)->nick,i,user(userl)->login,user(userl)->nick,user(userl)->network,user(userl)->server,user(userl)->user,user(userl)->last);
	       else
	           ap_snprintf(buf,sizeof(buf),lngtxt(18),user(userp)->nick,i,user(userl)->login,user(userl)->nick,user(userl)->network,user(userl)->server,user(userl)->user);
	    } else {
	       if(last==1)
	           ap_snprintf(buf,sizeof(buf),lngtxt(19),user(userp)->nick,i,user(userl)->login,user(userl)->nick,user(userl)->host,user(userl)->network,user(userl)->server,user(userl)->user,user(userl)->last);
	       else
	           ap_snprintf(buf,sizeof(buf),lngtxt(20),user(userp)->nick,i,user(userl)->login,user(userl)->nick,user(userl)->host,user(userl)->network,user(userl)->server,user(userl)->user);
	    }
	    writesock(user(usern)->insock,buf);
	 }
	 th=th->next;
    }
    ap_snprintf(ircbuf,sizeof(ircbuf),lngtxt(21),user(usern)->login,me);
    broadcast(0);
	return 0x0;
}


/* kill socket */
int cmdkillsock(int usern)
{
	char buf[400];
	struct socketnodes *lkm, *next;
	int socket_id = 0, match = 0;

    char *types[4];
	types[0]="Connect";
    types[1]="Listen";
    types[2]="Resolver";
    types[3]="Unknown?";	

	/* If they didn't supply a socketid/host shout at them */
    if (strlen(irccontent) == 0) { 
		ssnprintf(user(usern)->insock, lngtxt(1433), user(usern)->nick); 
		return 0x0; 
	}

	socket_id = atoi(irccontent);


	/* Loop through all the sockets */

	lkm = socketnode;
	while(lkm != NULL) {
	
		next = lkm->next;
		match = 0;

		if (socket_id > 0 && socket_id == lkm->sock->syssock) match = 1;
		if (!strcasecmp(lkm->sock->source, irccontent)) match = 1;
		if (!strcasecmp(lkm->sock->dest, irccontent)) match = 1;

		if (match) {
			ap_snprintf(buf, sizeof(buf), "Killing socket '%d' (%s:%d -> %s:%d) [%s]", lkm->sock->syssock, lkm->sock->source, lkm->sock->sport, lkm->sock->dest, lkm->sock->dport, types[lkm->sock->type]); 
			p_log(LOG_INFO, usern, buf);
			killsocket(lkm->sock->syssock);
		}
		
		lkm = next;
	}
	return 0x0;
}

/* fix listener */
int cmdfixlistener(int usern)
{
	struct socketnodes *lkm, *next;
	int foundsocket = 0;
	
    nolog = 666;
	

	p_log(LOG_INFO, -1, "Attempting to fix listening sockets..");

	/*
	p_log(LOG_INFO, -1, "Searching for active listeners..");

    lkm = socketnode;
	while(lkm != NULL) {
		next = lkm->next;

		if (lkm->sock->type == ST_LISTEN && lkm->sock->constructed==checknewlistener) {
			
			p_log(LOG_INFO, -1, "Killing static listener '%d' (%s:%d)", lkm->sock->syssock, lkm->sock->source, lkm->sock->sport); 
			
			shutdown(lkm->sock->syssock, 2);
		    close(lkm->sock->syssock);

			foundsocket = 1;
		}

		lkm = next;
	}

	if (foundsocket == 0) {
		p_log(LOG_INFO, -1, "- No static listening sockets found!");
	}*/

	p_log(LOG_INFO, -1, "Reactivating listeners..");
	createlisteners();
	p_log(LOG_INFO, -1, "Searching for active listeners..");
	
	foundsocket = 0;
	lkm = socketnode;
	while(lkm != NULL) {
		next = lkm->next;

		if (lkm->sock->type == ST_LISTEN && lkm->sock->constructed==checknewlistener) {
			p_log(LOG_INFO, -1, "- Found static listener '%d' (%s:%d)", lkm->sock->syssock, lkm->sock->source, lkm->sock->sport); 
			foundsocket = 1;
		}

		lkm = next;
	}

	if (foundsocket == 0) {
		p_log(LOG_INFO, -1, "- No static listening sockets found!");
		p_log(LOG_INFO, -1, "Sorry, wasn't able to recreate listeners :(");
	} else {
		p_log(LOG_INFO, -1, "Done, not disconnecting client that requested fixlistener..");
	}

	//killsocket(user(usern)->insock);
    return 0x0;	
}

/* socket stats */
int cmdsockstat(int usern)
{
    p_log(LOG_INFO,usern,lngtxt(22));
    usr1_error(31337);
    p_log(LOG_INFO,usern,lngtxt(23));
    return 0x0;
}

/* adding a user by an admin or the firstuser handling */
int cmdadduser(int usern)
{
    int uind;
    int userp;
    struct socketnodes *ps;
    char *pt;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(ircto) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(28),user(userp)->nick);
       return -1;
    }
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(29),user(userp)->nick);
       return -1;
    }
    if (checkuser(ircto) >0) {
       ssnprintf(user(usern)->insock,lngtxt(30),user(userp)->nick,ircto);
       return -1;
    }
    uind = 1;
    U_CREATE=1;
    while (uind<=MAX_USER)
    {
	if (*user(uind)->login == 0) {
	    strmncpy(user(uind)->wantnick,ircto,sizeof(user(uind)->wantnick));
	    strmncpy(user(uind)->nick,ircto,sizeof(user(uind)->nick));
	    strmncpy(user(uind)->login,ircto,sizeof(user(uind)->login));
	    strmncpy(user(uind)->user,irccontent,sizeof(user(uind)->user));
	    if (usern==0)
	    {
	       strmncpy(user(uind)->pass,user(0)->pass,sizeof(user(uind)->pass));
#ifdef HAVE_SSL
	       ps=getpsocketbysock(user(0)->insock);
	       if(ps!=NULL)
	       {
	           if(ps->sock->sslfd!=NULL)
		   {
		       /* copy cert */
		       pt=sslgetcert(ps->sock->sslfd);
		       if(pt!=NULL)
		           strmncpy(user(uind)->cert,pt,sizeof(user(uind)->cert));
		   }
	       }
#endif
	    }
	    else
	       strmncpy(user(uind)->pass,randstring(8),sizeof(user(uind)->pass));
	    user(uind)->outstate = STD_NOCON;
	    user(uind)->instate = STD_NOCON;
	    user(uind)->rights = 0;
	    user(uind)->dccenabled=1;
	    user(uind)->autorejoin=1;
	    user(uind)->sysmsg = 1;
	    #ifdef IPV6
	    user(uind)->preferipv6 = -1;
	    #endif

	    p_log(LOG_INFO,usern,lngtxt(31),user(uind)->login,user(uind)->user,user(usern)->login);
	    if(usern!=0)
		ssnprintf(user(usern)->insock,lngtxt(32),user(usern)->nick,user(uind)->login,user(uind)->pass);
	    writeuser(uind);
	    clearuser(uind);
	    loaduser(uind);
	    return uind;
	}
	uind++;
    }
    p_log(LOG_ERROR,usern,lngtxt(33));
    return -1;
}

/* delete a user */
int cmddeluser(int usern)
{
    int uind;
    int userp;
    int duid;
    struct usernodes *uno,*nuno;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(34),user(userp)->nick);
       return -1;
    }
    if ((uind = checkuser(irccontent)) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(35),user(userp)->nick,irccontent);
       return -1;
    }
    if (uind==1)
    {
       ssnprintf(user(usern)->insock,lngtxt(36),user(userp)->nick,irccontent);
       return -1;
    }
    /* delete the networks of this user */
    uno=usernode;
    while(uno)
    {
	nuno=uno->next;
	if(uno->user)
	{
	    if(uno->user->parent==uind && uno->uid>1 && uno->uid!=uind)
	    {
		duid=uno->uid;
		deluser(duid);
		loaduser(duid);
	    }
	}
	uno=nuno;
    }
    /* delete the root user */
    deluser(uind);
    p_log(LOG_INFO,usern,lngtxt(37),user(uind)->nick,user(userp)->login);
    loaduser(uind);
    return 0x0;
}

/* printing out the welcome text */
int firstwelcome(void)
{
    char buf[1];
    pcontext;
    ssnprintf(user(0)->insock,lngtxt(24),user(0)->nick,user(0)->nick);
#ifdef ANONYMOUS
    ssnprintf(user(0)->insock,lngtxt(25),user(0)->nick);
#else
    ssnprintf(user(0)->insock,lngtxt(26),user(0)->nick);
    ssnprintf(user(0)->insock,lngtxt(27),user(0)->nick);
#endif
    *buf=*ircto;
    *ircto=0;
    printhelp(0);
    *ircto=*buf;
    return 0x0;
}

/* first user connects */
int firstuser(npeer)
{
    int linkto;
    pcontext;
    user(0)->rights = RI_ADMIN;
    strmncpy(irccontent,newpeer(npeer)->user,sizeof(irccontent));
    strmncpy(ircto,newpeer(npeer)->login,sizeof(ircto));
    strmncpy(user(0)->nick,newpeer(npeer)->nick,sizeof(user(0)->nick));
    strmncpy(user(0)->login,newpeer(npeer)->login,sizeof(user(0)->login));
    strmncpy(user(0)->pass,newpeer(npeer)->pass,sizeof(user(0)->pass));
    user(0)->insock = newpeer(npeer)->insock;
    user(0)->instate = STD_CONN;
    firstwelcome();
    linkto=cmdadduser(0);
    if(linkto==-1)
    {
	return -1;
    }
    if(linkto==1) user(linkto)->rights=RI_ADMIN;
    writeuser(linkto);
    return linkto;
}

#ifdef NETWORK
/* adding a network-user by an user */
int cmdaddnetwork(int usern)
{
    int uind;
    pcontext;
    if (user(usern)->parent!=0)
    {
       ssnprintf(user(usern)->insock,lngtxt(38),user(user(usern)->parent)->nick);
       return -1;
    }
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(39),user(usern)->nick);
       return -1;
    }
    if (strlen(irccontent) > 10) {
       ssnprintf(user(usern)->insock,lngtxt(40),user(usern)->nick);
       return -1;
    }
    if (checkusernetwork(usern) >0) {
       ssnprintf(user(usern)->insock,lngtxt(41),user(usern)->nick,irccontent);
       return -1;
    }
    uind = 1;
    U_CREATE=1;
    while (uind<MAX_USER)
    {
	if (strlen(user(uind)->login) == 0) {
	    strmncpy(user(uind)->wantnick,user(usern)->nick,sizeof(user(uind)->wantnick));
	    strmncpy(user(uind)->nick,user(usern)->nick,sizeof(user(uind)->nick));
	    strmncpy(user(uind)->login,user(usern)->login,sizeof(user(uind)->login));
	    strmncpy(user(uind)->user,user(usern)->user,sizeof(user(uind)->user));
	    strmncpy(user(uind)->pass,user(usern)->pass,sizeof(user(uind)->pass));
	    user(uind)->outstate = STD_NOCON;
	    user(uind)->instate = user(usern)->instate;
	    user(uind)->insock = user(usern)->insock;
	    user(uind)->rights = user(usern)->rights;
	    user(uind)->parent = usern;
	    strmncpy(user(uind)->network,irccontent,sizeof(user(uind)->network));
	    writeuser(uind);
	    clearuser(uind);
	    loaduser(uind);
	    p_log(LOG_INFO,usern,lngtxt(42),user(uind)->network,user(usern)->login);
	    return uind;
	}
	uind++;
    }
    p_log(LOG_ERROR,usern,lngtxt(43));
    return -1;
}

/* delete a network */
int cmddelnetwork(int usern)
{
    int uind;
    pcontext;
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(44),user(usern)->nick);
       return -1;
    }
    if ((uind = checkusernetwork(usern)) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(45),user(usern)->nick,irccontent);
       return -1;
    }
    deluser(uind);
    p_log(LOG_INFO,usern,lngtxt(46),user(uind)->network,user(uind)->login);
    loaduser(uind);
    return 0x0;
}

/* switch to another network */
int cmdswitchnet(int usern)
{
    int uind;
    char ocont[400];
    struct uchannelt *chan;
    struct usernodes *und;
    struct usert *un,*un1;
    if(user(usern)->parent!=0) return 0x0;
    pcontext;
    if (strlen(irccontent) == 0)
    {
       ssnprintf(user(usern)->insock,lngtxt(47),user(usern)->nick);
       return -1;
    }
    if (strlen(ircto) == 0)
    {
       ssnprintf(user(usern)->insock,lngtxt(48),user(usern)->nick);
       return -1;
    }
    if ((uind = checkusernetwork(usern)) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(49),user(usern)->nick,irccontent);
       return -1;
    }
    strmncpy(ocont,irccontent,sizeof(ocont));
    strmncpy(irccontent,ircto,sizeof(irccontent));
    if(checkusernetwork(usern)!=0)
    {
       ssnprintf(user(usern)->insock,lngtxt(50),user(usern)->nick,irccontent);
       return -1;
    }
    strmncpy(irccontent,ocont,sizeof(irccontent));
    /* part channels of main and network
       main */
    chan=user(usern)->channels;
    while(chan!=NULL)
    {
	if(chan->ison!=0)
	{
	    ssnprintf(user(usern)->insock,lngtxt(51),chan->name,user(usern)->nick);
	}
	chan=chan->next;
    }
    chan=user(uind)->channels;
    while(chan!=NULL)
    {
	if(chan->ison!=0)
	{
	    ssnprintf(user(usern)->insock,lngtxt(52),user(uind)->network,chan->name,user(usern)->nick);
	}
	chan=chan->next;
    }
    /* parted all channels, setting new network and parent */
    un=user(usern);
    un1=user(uind);
    und=usernode;
    while(und!=NULL)
    {
	if(und->user!=NULL)
	{
	    if(und->user==un1)
	    {
		und->user=un;
		und->uid=usern;
	    }
	    else if(und->user==un)
	    {
		und->user=un1;
		und->uid=uind;
	    } else
	    if(und->user->parent==usern)
		und->user->parent=uind;
	}
	und=und->next;
    }
    user(uind)->network[0]=0;
    user(uind)->parent=0;
    strmncpy(user(usern)->network,ircto,sizeof(user(usern)->network));
    user(usern)->parent=uind;
    writeuser(uind);
    writeuser(usern);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(53),user(usern)->nick,user(usern)->login,user(usern)->host,user(uind)->nick);
    rejoinclient(uind);
    rejoinclient(usern);
    return 0x0;
}
#endif

/* change password */
int cmdpassword(int usern)
{
    char fname[20];
    char buf[400];
    struct usernodes *unode;
    int uind;
    char *pw;
    pcontext;
    uind=usern;
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(54),user(usern)->nick);
       return -1;
    }
    if (strlen(ircto)) {
       uind = checkuser(ircto);
       if (uind==0) {
           ssnprintf(user(usern)->insock,lngtxt(55),user(usern)->nick,ircto);
           return -1;
       }
    } else
       strmncpy(ircto,user(usern)->login,sizeof(ircto));
    if(uind!=usern && user(usern)->rights!=RI_ADMIN)
    {
           ssnprintf(user(usern)->insock,lngtxt(56),user(usern)->nick);
           return -1;
    }
    unode=usernode;
    ap_snprintf(buf,sizeof(buf),"%s%s",slt1,slt2);
    pw=BLOW_stringencrypt(buf,irccontent);
    while(unode)
    {
	if(unode->user)
	{
	    if(unode->uid==uind || unode->user->parent==uind)
	    {
		ap_snprintf(fname,sizeof(fname),lngtxt(57),unode->uid);
		ap_snprintf(user(unode->uid)->pass,sizeof(user(unode->uid)->pass),"=%s",pw);
		/* reset penalty */
		user(unode->uid)->pentime=0;
		user(unode->uid)->penalty=0;
		writeini("USER","PASS",fname,user(unode->uid)->pass);
	    }
	}
	unode=unode->next;
    }
    if(pw) free(pw);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(58),user(usern)->nick,ircto,irccontent);
    return 0x0;
}

int cmdnick(int usern)
{
    pcontext;
    strmncpy(user(usern)->wantnick,irccontent,sizeof(user(usern)->wantnick));
    return 0x0;
}

/* jumping servers */
int cmdjump(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (user(usern)->outstate == STD_CONN) {
	if(*irccontent!=0)
	{
	    if(atoi(irccontent)>0 && atoi(irccontent)<21)
	    {
		user(usern)->currentserver=atoi(irccontent)-1;
	    }
	}
	ssnprintf(user(usern)->insock,lngtxt(59),user(userp)->nick);
	p_log(LOG_INFO,usern,lngtxt(60),user(usern)->login);
	user(usern)->afterquit=1;
	writesock(user(usern)->outsock,lngtxt(61));
	killsocket(user(usern)->outsock);
    } else {
	ssnprintf(user(usern)->insock,lngtxt(62),user(userp)->nick);
    }
    return 0x0;
}

int findnet(int usern, char *name)
{
    struct usernodes *th;
    th = usernode;
	for (th = usernode; th != NULL; th = th->next) {
		if (user(th->uid)->parent == usern && strmcmp(user(th->uid)->network,name) == 1) return th->uid;
	}
	return 0x0;
}

/* Quitting a user from a network */
int cmdbquitn(int usern)
{
	int userp;
	int victim_uid;
	int victim_net_uid;

	pcontext;
	
	if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;

	/* If they didn't supply a user/network shout at them */
    if (strlen(irccontent) == 0) { ssnprintf(user(usern)->insock,lngtxt(1413),user(userp)->nick); return 0x0; }
    if (strlen(ircto) == 0)	{ ssnprintf(user(usern)->insock,lngtxt(1413),user(userp)->nick); return 0x0; }

	/* Check if the user exists */
	victim_uid = checkuser(ircto);
	if (!victim_uid) { ssnprintf(user(usern)->insock, lngtxt(35), user(userp)->nick, ircto); return 0x0; }

	/* Check if the network exists for that user */
	victim_net_uid = findnet(victim_uid, irccontent);
	if (!victim_net_uid) { ssnprintf(user(usern)->insock, lngtxt(1414), user(userp)->nick, irccontent, ircto); return 0x0; }
	
	/* If the user already quitted, there is not much to do */
	if (user(victim_net_uid)->quitted ==1) {
		ssnprintf(user(usern)->insock,lngtxt(1415), user(userp)->nick, ircto, irccontent);
		return 0x0;
	}
	
	/* Quit the user and send them a message. */
	user(victim_net_uid)->quitted = 1;
	ssnprintf(user(victim_net_uid)->insock, lngtxt(1416), user(victim_net_uid)->nick, irccontent);
	writeuser(victim_net_uid);

	if (user(victim_net_uid)->outstate == STD_CONN) {
	   writesock(user(victim_net_uid)->outsock,lngtxt(264));
	   killsocket(user(victim_net_uid)->outsock);
	   user(victim_net_uid)->outstate = STD_NOCON;
	   user(victim_net_uid)->instate=STD_CONN;
	   user(victim_net_uid)->outsock=0;
	   user(victim_net_uid)->server[0]=0;
	}
	
	/* Tell admin we killed the user */
	ssnprintf(user(usern)->insock,lngtxt(1417), user(userp)->nick, ircto, irccontent);
	return 0x0;
}

/* Connecting a user to a specific network */
int cmdbconnectn(int usern)
{
	int userp;
	int victim_uid;
	int victim_net_uid;

	pcontext;
	
	if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;

	/* If they didn't supply a user/network shout at them */
    if (strlen(irccontent) == 0) { ssnprintf(user(usern)->insock,lngtxt(1423),user(userp)->nick); return 0x0; }
    if (strlen(ircto) == 0)	{ ssnprintf(user(usern)->insock,lngtxt(1423),user(userp)->nick); return 0x0; }

	/* Check if the user exists */
	victim_uid = checkuser(ircto);
	if (!victim_uid) { ssnprintf(user(usern)->insock, lngtxt(35), user(userp)->nick, ircto); return 0x0; }

	/* Check if the network exists for that user */
	victim_net_uid = findnet(victim_uid, irccontent);
	if (!victim_net_uid) { ssnprintf(user(usern)->insock, lngtxt(1424), user(userp)->nick, irccontent, ircto); return 0x0; }
	
	/* If the user is already connecting, there is not much to do */
	if (user(victim_net_uid)->quitted == 0) {
		ssnprintf(user(usern)->insock,lngtxt(1425), user(userp)->nick, ircto, irccontent);
		return 0x0;
	}
	
	/* Connect the user and send them a message. */
	ssnprintf(user(victim_net_uid)->insock, lngtxt(1426), user(victim_net_uid)->nick, irccontent);
	user(victim_net_uid)->quitted = 0;
	user(victim_net_uid)->delayed = 0;
	writeuser(victim_net_uid);
	
	/* Tell admin we are attempting to connect the user */
	ssnprintf(user(usern)->insock,lngtxt(1427), user(userp)->nick, ircto, irccontent);
	return 0x0;
}

/* Setting a VHOST for a user on a network */
int cmdbvhostn(int usern)
{
	char fname[20];
	char buf[100];

	int userp;
	char *network;
	char *vhost;
	char oldvhost[100];

	int victim_uid;
	int victim_net_uid;

    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;

	/* If they didn't supply a user/network/vhost shout at them */
    if (strlen(irccontent) == 0 || strchr(irccontent,' ') == NULL) { ssnprintf(user(usern)->insock,lngtxt(1403),user(userp)->nick); return 0x0; }
    if (strlen(ircto) == 0)	{ ssnprintf(user(usern)->insock,lngtxt(1403),user(userp)->nick); return 0x0; }

	/* If they did, we should split the stuff up */
	network = strtok(irccontent, " ");
	vhost = strtok(NULL, " ");
	if (vhost == NULL || network == NULL) { ssnprintf(user(usern)->insock,lngtxt(1403),user(userp)->nick); return 0x0; }
	
	/* Check if the user exists */
	victim_uid = checkuser(ircto);
	if (!victim_uid) { ssnprintf(user(usern)->insock, lngtxt(35), user(userp)->nick, ircto); return 0x0; }

	/* Check if the network exists for that user */
	victim_net_uid = findnet(victim_uid, network);
	if (!victim_net_uid) { ssnprintf(user(usern)->insock, lngtxt(1404), user(userp)->nick, network, ircto); return 0x0; }

	snprintf(oldvhost, 100, "%s", user(victim_net_uid)->vhost);
	
	/* Write the new vhost in the user's struct */
	user(victim_net_uid)->vlink = 0;
	strmncpy(user(victim_net_uid)->vhost, vhost, sizeof(user(victim_net_uid)->vhost));
	
	/* And write the new vhost to the config file */
    ap_snprintf(fname,sizeof(fname),lngtxt(64),victim_net_uid);
    writeini("USER", lngtxt(65), fname, user(victim_net_uid)->vhost);
    ap_snprintf(buf, sizeof(buf),"%d", user(victim_net_uid)->vlink);
    writeini("USER", lngtxt(66), fname, buf);
    flushconfig();

	ssnprintf(user(usern)->insock, lngtxt(1405), user(userp)->nick, ircto, network, oldvhost, vhost);
	return 0x0;
}

/* setting vhost */
int cmdvhost(int usern)
{
    char fname[20];
    char buf[100];
    int vl;
    int userp;
    int fuid=0;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    vl=atoi(ircto);
    if (vl!=0)
    {
	if (datalink(vl)->type!=1 && datalink(vl)->type!=2)
	{
	    ssnprintf(user(usern)->insock,lngtxt(63),user(usern)->nick,vl);
	    return 0x0;
	}
    } else {
	if(user(userp)->rights==RI_ADMIN && *ircto)
	{
	    fuid=checkuser(ircto);
	    if(!fuid)
	    {
		ssnprintf(user(usern)->insock,lngtxt(35),user(userp)->nick,ircto);
		return 0x0;
	    }
	}
	vl=0;
    }
    if(!fuid) fuid=usern;
    user(fuid)->vlink=vl;
    strmncpy(user(fuid)->vhost,irccontent,sizeof(user(fuid)->vhost));
    ap_snprintf(fname,sizeof(fname),lngtxt(64),fuid);
    writeini("USER",lngtxt(65),fname,user(fuid)->vhost);
    ap_snprintf(buf,sizeof(buf),"%d",vl);
    writeini("USER",lngtxt(66),fname,buf);
    flushconfig();
    if (vl!=0)
        ssnprintf(user(usern)->insock,lngtxt(67),user(userp)->nick,user(usern)->vhost,vl);
    else
        ssnprintf(user(usern)->insock,lngtxt(68),user(userp)->nick,user(fuid)->vhost);
    return 0x0;
}

#ifdef PROXYS
/* setting proxy */
int cmdproxy(int usern)
{
    char fname[20];
    char buf[100];
    char grnf[400];
    char *pt,*ept,*dpt;
    int userp;
    pcontext;
    ap_snprintf(grnf,sizeof(grnf),lngtxt(69),ircto,irccontent);
    pt=grnf;
    ept=pt;
    while(*ept==' ') ept++;
    pt=ept;
    dpt=ept;
    while(ept!=NULL)
    {
	 ept=strchr(ept+1,':');
         if(ept!=NULL) dpt=ept;
    }
    if(dpt==ept) return 0x0;
    if(dpt==NULL || pt==NULL) return 0x0;
    *dpt=0;
    dpt++;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    strmncpy(user(usern)->proxy,pt,sizeof(user(usern)->proxy));
    user(usern)->pport=atoi(dpt);
    ap_snprintf(fname,sizeof(fname),lngtxt(70),usern);
    writeini("USER",lngtxt(71),fname,user(usern)->proxy);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->pport);
    writeini("USER",lngtxt(72),fname,buf);
    flushconfig();
    if(user(usern)->pport==0)
	ssnprintf(user(usern)->insock,lngtxt(73),user(userp)->nick);
    else
	ssnprintf(user(usern)->insock,lngtxt(74),user(userp)->nick,user(usern)->proxy,user(usern)->pport);
    return 0x0;
}
#endif

/* setting antiidle */
int cmdaidle(int usern)
{
    char fname[20];
    char buf[10];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (atoi(irccontent) != 0 && atoi(irccontent) != 1) {
	ssnprintf(user(usern)->insock,lngtxt(75),user(userp)->nick);
	return 0x0;
    }
    user(usern)->antiidle=atoi(irccontent);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->antiidle);
    ap_snprintf(fname,sizeof(fname),lngtxt(76),usern);
    writeini("USER",lngtxt(77),fname,buf);
    flushconfig();
    if (user(usern)->antiidle==1) {
       ssnprintf(user(usern)->insock,lngtxt(78),user(userp)->nick);
    } else {
       ssnprintf(user(usern)->insock,lngtxt(79),user(userp)->nick);
    }
    return 0x0;
}

/* setting autojoin */
int cmdautorejoin(int usern)
{
    char fname[20];
    char buf[10];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (atoi(irccontent) != 0 && atoi(irccontent) != 1) {
	ssnprintf(user(usern)->insock,lngtxt(80),user(userp)->nick);
	return 0x0;
    }
    user(usern)->autorejoin=atoi(irccontent);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->autorejoin);
    ap_snprintf(fname,sizeof(fname),lngtxt(81),usern);
    writeini("USER",lngtxt(82),fname,buf);
    flushconfig();
    if (user(usern)->autorejoin==1) {
       ssnprintf(user(usern)->insock,lngtxt(83),user(userp)->nick);
    } else {
       ssnprintf(user(usern)->insock,lngtxt(84),user(userp)->nick);
    }
    return 0x0;
}

/* setting leavequit */
int cmdleavequit(int usern)
{
    char fname[20];
    char buf[10];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (atoi(irccontent) != 0 && atoi(irccontent) != 1) {
	ssnprintf(user(usern)->insock,lngtxt(85),user(userp)->nick);
	return 0x0;
    }
    user(usern)->leavequit=atoi(irccontent);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->leavequit);
    ap_snprintf(fname,sizeof(fname),lngtxt(86),usern);
    writeini("USER",lngtxt(87),fname,buf);
    flushconfig();
    if (user(usern)->leavequit==1) {
       ssnprintf(user(usern)->insock,lngtxt(88),user(userp)->nick);
    } else {
       ssnprintf(user(usern)->insock,lngtxt(89),user(userp)->nick);
    }
    return 0x0;
}

/* cmddccenable - setting if dccs are allowed to the bouncer */
int cmddccenable(int usern)
{
    char fname[20];
    char buf[10];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (atoi(irccontent) != 0 && atoi(irccontent) != 1) {
	ssnprintf(user(usern)->insock,lngtxt(90),user(userp)->nick);
	return 0x0;
    }
    user(usern)->dccenabled=atoi(irccontent);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->dccenabled);
    ap_snprintf(fname,sizeof(fname),lngtxt(91),usern);
    writeini("USER",lngtxt(92),fname,buf);
    flushconfig();
    if (user(usern)->dccenabled==1) {
       ssnprintf(user(usern)->insock,lngtxt(93),user(userp)->nick);
    } else {
       ssnprintf(user(usern)->insock,lngtxt(94),user(userp)->nick);
    }
    return 0x0;
}

/* setting away parameter */
int cmdsetaway(int usern)
{
    char fname[20];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    strmncpy(user(usern)->away,irccontent,sizeof(user(usern)->away));
    ap_snprintf(fname,sizeof(fname),lngtxt(95),usern);
    writeini("USER","AWAY",fname,user(usern)->away);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(96),user(userp)->nick,user(usern)->away);
    return 0x0;
}

/* setting leavemsg parameter */
int cmdsetleavemsg(int usern)
{
    char fname[20];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    strmncpy(user(usern)->leavemsg,irccontent,sizeof(user(usern)->leavemsg));
    ap_snprintf(fname,sizeof(fname),lngtxt(97),usern);
    writeini("USER",lngtxt(98),fname,user(usern)->leavemsg);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(99),user(userp)->nick,user(usern)->leavemsg);
    return 0x0;
}

/* setting away nick */
int cmdsetawaynick(int usern)
{
    char fname[20];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    strmncpy(user(usern)->awaynick,irccontent,sizeof(user(usern)->awaynick));
    ap_snprintf(fname,sizeof(fname),lngtxt(100),usern);
    writeini("USER",lngtxt(101),fname,user(usern)->awaynick);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(102),user(userp)->nick,user(usern)->awaynick);
    return 0x0;
}


/* setting username */
int cmdsetusername(int usern)
{
    char fname[20];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    strmncpy(user(usern)->user,irccontent,sizeof(user(usern)->user));
    ap_snprintf(fname,sizeof(fname),lngtxt(103),usern);
    writeini("USER","USER",fname,user(usern)->user);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(104),user(userp)->nick,user(usern)->user);
    return 0x0;
}

int cmdaddserver(int usern)
{
    char fname[20];
    char buf[400];
    char gsrv[400];
    char *pt,*dpt,*ept;
    char *pw;
    char *dpw=lngtxt(1316);
    int nmsrv;
    int rc;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(ircto) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(105),user(userp)->nick);
       return -1;
    }
	/* Deny adding a server with 'eushells.com' in it to prevent connecting to the bouncer itself */
	if (strmwildcmp(ircto, "*.eushells.com")!=0) {
		ssnprintf(user(usern)->insock,lngtxt(1380),user(userp)->nick);
		return -1;
	}
    ap_snprintf(fname,sizeof(fname),lngtxt(106),usern);
    nmsrv=1;
    while (nmsrv < 10)
    {
	  ap_snprintf(gsrv,sizeof(gsrv),lngtxt(107),ircto,irccontent);
	  pt=gsrv;
	  ept=pt;
          while(*ept==' ') ept++;
	  pt=ept;
          dpt=ept;
	  while(ept!=NULL)
	  {
	     ept=strchr(ept+1,':');
	     if(ept!=NULL) dpt=ept;
          }
          if(dpt==ept) return 0x0;
          if(dpt==NULL || pt==NULL) return 0x0;
          *dpt=0;
          dpt++;

          rc=getserver(nmsrv,usern);
	  if (rc<0) {
              pw=strchr(dpt,' ');
	      if(pw!=NULL)
	      {
	          *pw=0;
		  pw++;
		  ap_snprintf(buf,sizeof(buf),lngtxt(108),nmsrv);
		  writeini(lngtxt(109),buf,fname,pw);
	      } else {
	          pw=dpw;
	      }
	      if (strlen(dpt)==0) {
	         ap_snprintf(irccontent,sizeof(irccontent),"6667");
	      } else {
	         strmncpy(irccontent,dpt,sizeof(irccontent));
	      }
	      ap_snprintf(buf,sizeof(buf),lngtxt(110),nmsrv);
	      writeini(lngtxt(111),buf,fname,irccontent);
	      ap_snprintf(buf,sizeof(buf),lngtxt(112),nmsrv);
	      writeini(lngtxt(113),buf,fname,pt);
	      flushconfig();
              ssnprintf(user(usern)->insock,lngtxt(114),user(userp)->nick,pt,irccontent,pw);
	      user(usern)->delayed=0;
	      return 0x0;
	  }
	  nmsrv++;
    }
    ssnprintf(user(usern)->insock,lngtxt(115),user(userp)->nick);
    return -1;
}

int cmddelserver(int usern)
{
    char fname[20];
    char buf[400];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(116),user(userp)->nick);
       return -1;
    }
    ap_snprintf(fname,sizeof(fname),lngtxt(117),usern);
    ap_snprintf(buf,sizeof(buf),lngtxt(118),irccontent);
    writeini(lngtxt(119),buf,fname,NULL);
    ap_snprintf(buf,sizeof(buf),lngtxt(120),irccontent);
    writeini(lngtxt(121),buf,fname,NULL);
    ap_snprintf(buf,sizeof(buf),lngtxt(122),irccontent);
    writeini(lngtxt(123),buf,fname,NULL);
    flushconfig();
    ssnprintf(user(usern)->insock,lngtxt(124),user(userp)->nick,irccontent);
    return -1;
}

int cmdlistservers(int usern)
{
    char fname[20];
    char sicsrv[400];
    int sicport;
    int nmsrv;
    int rc;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    sicport=user(usern)->port;
    strmncpy(sicsrv,user(usern)->server,sizeof(sicsrv));
    ap_snprintf(fname,sizeof(fname),lngtxt(125),usern);
    nmsrv=1;
    while (nmsrv < 10)
    {
          rc=getserver(nmsrv,usern);
	  if (rc==0) {
              ssnprintf(user(usern)->insock,lngtxt(126),user(userp)->nick,nmsrv,user(usern)->server,user(usern)->port);
	  }
	  nmsrv++;
    }
    ssnprintf(user(usern)->insock,lngtxt(127),user(userp)->nick);
    strmncpy(user(usern)->server,sicsrv,sizeof(user(usern)->server));
    user(usern)->port = sicport;
    return -1;
}

#ifdef LINKAGE

int cmdlinkfrom(int usern)
{
    cmdaddlink(usern,LI_ALLOW);
    return 0x0;
}

int cmdlinkto(int usern)
{
    cmdaddlink(usern,LI_LINK);
    return 0x0;
}

int cmdaddlink(int usern,int type)
{
    int newlink = 0;
    char *pt,*ept,*dpt;
    char *fr=lngtxt(1317);
    char *tr=lngtxt(1318);
    char *tp;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (*me==0) {
       ssnprintf(user(usern)->insock,lngtxt(128),user(userp)->nick);
       return -1;
    }
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(129),user(userp)->nick,irccommand);
       return -1;
    }
    if (strlen(ircto) == 0 && type!=LI_LINK) {
       ssnprintf(user(usern)->insock,lngtxt(130),user(userp)->nick,irccommand);
       return -1;
    }
    if (strchr(irccontent,':')==NULL) {
       ssnprintf(user(usern)->insock,lngtxt(131),user(userp)->nick,irccommand);
       return -1;
    }
    pt=strchr(irccontent,':');
    ept=pt;
    dpt=pt;
    while(ept!=NULL)
    {
	ept=strchr(ept+1,':');
	if(ept!=NULL) dpt=ept;
    }
    pt=dpt;
    *pt=0;pt++;
    if (atoi(pt)==0) {
       ssnprintf(user(usern)->insock,lngtxt(132),user(userp)->nick,irccommand);
       return -1;
    }
    if (type==LI_LINK)
    {
	strmncpy(ircto,me,sizeof(ircto));
	strmncpy(datalink(newlink)->pass,randstring(15),sizeof(datalink(newlink)->pass));
	tp=tr;
    } else
	tp=fr;
    newlink=getlinkbyname(ircto);
    if (newlink!=0 && type!=LI_LINK) {
       ssnprintf(user(usern)->insock,lngtxt(133),user(userp)->nick,ircto);
       return -1;
    }
    newlink=getnewlink();
    if (newlink==0) {
       ssnprintf(user(usern)->insock,lngtxt(134),user(userp)->nick);
       return -1;
    }
    clearlink(newlink);
    strmncpy(datalink(newlink)->host,irccontent,sizeof(datalink(newlink)->host));
    datalink(newlink)->port=atoi(pt);
    datalink(newlink)->allowrelay=0;
    strmncpy(datalink(newlink)->name,ircto,sizeof(datalink(newlink)->name));
    datalink(newlink)->type=type;
    if (type==LI_ALLOW)
	 strmncpy(datalink(newlink)->iam,ircto,sizeof(datalink(newlink)->iam));
    writelink(newlink);
    p_log(LOG_INFO,usern,lngtxt(135),datalink(newlink)->name,tp,datalink(newlink)->host,datalink(newlink)->port,user(usern)->login);
    return 0x0;
}

/* set / unset the relay flag */
int cmdrelaylink(int usern)
{
    char *yo=lngtxt(1319);
    char *nes=lngtxt(1320);
    int lnk;
    char *pt;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0 || (atoi(irccontent)!=0 && atoi(irccontent)!=1)) {
       ssnprintf(user(usern)->insock,lngtxt(136),user(userp)->nick);
       return -1;
    }
    if (strlen(ircto)==0) {
       ssnprintf(user(usern)->insock,lngtxt(137),user(userp)->nick);
       return -1;
    }
    lnk=atoi(ircto);
    if (datalink(lnk)->type==0) lnk=0;
    if (lnk==0)
    {
       ssnprintf(user(usern)->insock,lngtxt(138),user(userp)->nick,ircto);
       return -1;
    }
    datalink(lnk)->allowrelay=atoi(irccontent);
    writelink(lnk);
    if (datalink(lnk)->allowrelay==0)
	pt=nes;
    else
	pt=yo;
    p_log(LOG_INFO,usern,lngtxt(139),ircto,pt,user(usern)->login);
    return 0x0;
}

int cmddellink(int usern)
{
    int lnk=0;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
       ssnprintf(user(usern)->insock,lngtxt(140),user(userp)->nick);
       return -1;
    }
    if (datalink(atoi(irccontent))->type!=0)
	lnk=atoi(irccontent);
    if (lnk==0)
    {
       ssnprintf(user(usern)->insock,lngtxt(141),user(userp)->nick,irccontent);
       return -1;
    }
    p_log(LOG_INFO,usern,lngtxt(142),lnk,user(usern)->login);
    if (datalink(lnk)->outstate==STD_CONN)
    {
	sysparty(lngtxt(143),datalink(lnk)->iam,user(usern)->login);
	killsocket(datalink(lnk)->outsock);
	removetopology(me,datalink(lnk)->iam,lostlink);
    }
    if (datalink(lnk)->instate==STD_CONN)
    {
	sysparty(lngtxt(144),datalink(lnk)->iam,user(usern)->login);
	killsocket(datalink(lnk)->insock);
	removetopology(me,datalink(lnk)->iam,lostlink);
    }
    clearlink(lnk);
    eraselinkini(lnk);
    return 0x0;
}

int iiusern;

/* listevent; */
int listsinglelink(char *dispbuf)
{
    ssnprintf(user(iiusern)->insock,lngtxt(145),user(iiusern)->nick,dispbuf);
    return 0x0;
}

/* list the links */
int cmdlistlinks(int usern)
{
    struct linknodes *th;
    int linkn=1;
    char o[]="->";
    char i[]="<-";
    char r[]="R ";
    char l;
    char *pt = NULL;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(146),user(usern)->nick);
    th=linknode;
    while (th!=NULL)
    {
	linkn=th->uid;
	l=' ';
	if (datalink(linkn)->type!=0)
	{
	    if (datalink(linkn)->type==LI_LINK)
	    {
		pt=o;
		if (datalink(linkn)->outstate==STD_CONN) l='*';
	    }
	    if (datalink(linkn)->type==LI_ALLOW)
	    {
		if (datalink(linkn)->instate==STD_CONN) l='*';
		pt=i;
	    }
	    if (datalink(linkn)->type==LI_RELAY) { pt=r; l='*';}
	    ssnprintf(user(usern)->insock,lngtxt(147),user(userp)->nick,l,linkn,pt,datalink(linkn)->iam,datalink(linkn)->host,datalink(linkn)->port);
	}
	th=th->next;
    }
    iiusern=usern;
    ssnprintf(user(usern)->insock,lngtxt(148),user(usern)->nick);
    displaytopology(listsinglelink);
    ssnprintf(user(usern)->insock,lngtxt(149),user(usern)->nick);
    return 0x0;
}

#endif

#ifdef DCCCHAT

int cmdadddcc(int usern)
{
    char *npt;
    char *upt;
    char *ppt;
    char *hpt;
    char *spt;
    char *tpt;
    int port;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    npt=strchr(ircbuf,' ');
    if (npt!=NULL)
    {
	*npt=0;
	npt++;
	upt=strchr(npt,' ');
	if (upt!=NULL)
	{
	    *upt=0;
	    upt++;
	    ppt=strchr(upt,' ');
	    if (ppt!=NULL)
	    {
		*ppt=0;
		ppt++;
		hpt=strchr(ppt,':');
		if (hpt!=NULL)
		{
		    *hpt=0;
		    hpt++;
		    spt=strchr(hpt,':');
		    tpt=spt;
		    while(tpt!=NULL)
		    {
			spt=tpt;
			tpt++;
			tpt=strchr(tpt,':'); /* stripping ipv6 addresses */
		    }
		    if (spt!=NULL)
		    {
			*spt=0;
			spt++;
			port=atoi(spt);
			if (port!=0)
			{
			    adddcc(usern,hpt,port,upt,ppt,npt,0);
			    return 0x0;
			}
		    }
		}
	    }
	}
    }
    ssnprintf(user(usern)->insock,lngtxt(150),user(userp)->nick);
    return 0x0;
}

int cmddeldcc(int usern)
{
    erasedcc(usern,atoi(irccontent));
    return 0x0;
}

int cmdlistdcc(int usern)
{
    listdccs(usern);
    return 0x0;
}

int cmddccchat(int usern)
{
    addpendingdcc(usern, PDC_CHATTORQ, NULL, 0, irccontent, NULL, NULL, 0L, AF_INET);
    return 0x0;
}

int cmddccanswer(int usern)
{
    addpendingdcc(usern, PDC_CHATFROM, NULL, 0, irccontent, NULL, NULL, 0L, AF_INET);
    return 0x0;
}

#endif

#ifdef DCCFILES

int cmddccsend(int usern)
{
    addpendingdcc(usern, PDC_SENDTORQ, NULL, 0, ircto, irccontent, NULL, 0L, AF_INET);
    return 0x0;
}

int cmddccget(int usern)
{
    char *pt;
    pt=strchr(irccontent,' ');
    if(pt!=NULL)
    {
	*pt=0;
	pt++;
	addpendingdcc(usern, PDC_RECVFROM, NULL,0, ircto, irccontent, pt, 0L, AF_INET);
    } else {
	addpendingdcc(usern, PDC_RECVFROM, NULL,0, ircto, irccontent, NULL, 0L, AF_INET);
    }
    return 0x0;
}

int cmddccsendme(int usern)
{
    addpendingdcc(usern, PDC_SENDTORQ, NULL, 0, user(usern)->nick,irccontent, NULL, 0L, AF_INET);
    return 0x0;
}

/* setting autogetdcc */
int cmdautogetdcc(int usern)
{
    char fname[20];
    char buf[10];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (atoi(irccontent) != 0 && atoi(irccontent) != 1) {
	ssnprintf(user(usern)->insock,lngtxt(151),user(userp)->nick);
	return 0x0;
    }
    user(usern)->autogetdcc=atoi(irccontent);
    ap_snprintf(buf,sizeof(buf),"%d",user(usern)->autogetdcc);
    ap_snprintf(fname,sizeof(fname),lngtxt(152),usern);
    writeini("USER",lngtxt(153),fname,buf);
    flushconfig();
    if (user(usern)->autogetdcc==1) {
       ssnprintf(user(usern)->insock,lngtxt(154),user(userp)->nick);
    } else {
       ssnprintf(user(usern)->insock,lngtxt(155),user(userp)->nick);
    }
    return 0x0;
}
#endif

int cmddcccancel(int usern)
{
    if(ircto[0]==0)
	canceldcc(usern,irccontent,NULL);
    else
	canceldcc(usern,ircto,irccontent);
    return 0x0;
}

/* add an op */
int cmdaddop(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(161),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(162),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(163),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(164),usern);
    user(usern)->ops=writelist(irccontent,cryptit(ircto),cfile,user(usern)->ops);
    ssnprintf(user(usern)->insock,lngtxt(165),user(userp)->nick,irccontent,ircto);
    return 0x0;
}

/* add an autoop */
int cmdaddautoop(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(166),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(167),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(168),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(169),usern);
    user(usern)->aops=writelist(irccontent,cryptit(ircto),cfile,user(usern)->aops);
    ssnprintf(user(usern)->insock,lngtxt(170),user(userp)->nick,irccontent,ircto);
    return 0x0;
}

/* add an askop */
int cmdaddask(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(171),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(172),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(173),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(174),usern);
    user(usern)->askops=writelist(irccontent,cryptit(ircto),cfile,user(usern)->askops);
    ssnprintf(user(usern)->insock,lngtxt(175),user(userp)->nick,irccontent,ircto);
    return 0x0;
}

/* add a hostallow */
int cmdaddallow(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(176),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(177),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(178),usern);
    hostallows=writelist(irccontent,"*",cfile,hostallows);
    ssnprintf(user(usern)->insock,lngtxt(179),user(userp)->nick,irccontent);
    return 0x0;
}

/* add a ban */
int cmdaddban(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(180),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(181),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(182),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(183),usern);
    user(usern)->bans=writelist(irccontent,ircto,cfile,user(usern)->bans);
    ssnprintf(user(usern)->insock,lngtxt(184),user(userp)->nick,irccontent,ircto);
    return 0x0;
}

/* add an ignore */
int cmdaddignore(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(1332),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(1333),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(1334),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(1335),usern);
    user(usern)->ignores=writelist(irccontent,ircto,cfile,user(usern)->ignores);
    ssnprintf(user(usern)->insock,lngtxt(1336),user(userp)->nick,irccontent,ircto);
    return 0x0;
}

#ifndef DYNAMIC
/* add a logmask */
int cmdaddlog(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(185),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(186),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(187),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(188),usern);
    user(usern)->logs=writelist(irccontent,ircto,cfile,user(usern)->logs);
    ssnprintf(user(usern)->insock,lngtxt(189),user(userp)->nick,ircto,irccontent);
    return 0x0;
}
#endif

#ifdef LINKAGE
int cmdrelink(int usern)
{
    int vl;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    vl=atoi(irccontent);
    if (vl!=0)
    {
	if (datalink(vl)->type!=1 && datalink(vl)->type!=2)
	{
	    ssnprintf(user(usern)->insock,lngtxt(190),user(usern)->nick,vl);
	    return 0x0;
	}
    }
    if(datalink(vl)->type==LI_LINK && datalink(vl)->outstate==STD_CONN)
	killsocket(datalink(vl)->outsock);
    if(datalink(vl)->type==LI_ALLOW && datalink(vl)->instate==STD_CONN)
	killsocket(datalink(vl)->insock);
    ssnprintf(user(usern)->insock,lngtxt(191),user(usern)->nick,vl);
    return 0x0;
}
#endif

#ifdef CRYPT
/* add an encryption */
int cmdencrypt(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(192),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(193),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(194),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(195),usern);
    ucase(irccontent);
    user(usern)->encrypt=writelist(irccontent,cryptit(ircto),cfile,user(usern)->encrypt);
    ssnprintf(user(usern)->insock,lngtxt(196),user(userp)->nick,irccontent,ircto);
    return 0x0;
}
#endif

#ifdef TRANSLATE
/* add a translator */
int cmdtranslate(int usern)
{
    char cfile[40];
    char *pt;
    int userp;
    char *langs[19];
    char buf[100];
    int ec;
    int isa=0,isb=0;
    langs[0]= "en_de";
    langs[1]= "en_fr";
    langs[2]= "en_it";
    langs[3]= "en_pt";
    langs[4]= "de_en";
    langs[5]= "fr_en";
    langs[6]= "it_en";
    langs[7]= "pt_en";
    langs[8]= "en_zh";
    langs[9]= "en_ja";
    langs[10]="en_ko";
    langs[11]="en_es";
    langs[12]="en_ru";
    langs[13]="fr_de";
    langs[14]="de_fr";
    langs[15]="ja_en";
    langs[16]="ko_en";
    langs[17]="ru_en";
    langs[18]="es_en";
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(197),user(userp)->nick);
	return 0x0;
    }
    if (strlen(ircto) == 0 || *ircto=='+') {
        ssnprintf(user(usern)->insock,lngtxt(198),user(userp)->nick);
	return 0x0;
    }
    if (strchr(irccontent,';')) {
        ssnprintf(user(usern)->insock,lngtxt(199),user(userp)->nick);
	return 0x0;
    }
    strmncpy(buf,irccontent,sizeof(buf));
    pt=strchr(buf,' ');
    if(pt==NULL)
    {
        ssnprintf(user(usern)->insock,lngtxt(200),user(userp)->nick);
	return 0x0;
    }
    *pt++=0;
    if(strlen(pt)!=5 || strlen(buf)!=5)
    {
	ssnprintf(user(usern)->insock,lngtxt(201),user(userp)->nick);
	return 0x0;
    }
    ec=0;
    while(ec<19)
    {
	if(strstr(langs[ec],pt)!=NULL) isa=1;
	if(strstr(langs[ec],buf)!=NULL) isb=1;
	ec++;
    }
    if(isa==1 && isb==1)
    {
	ap_snprintf(cfile,sizeof(cfile),lngtxt(202),usern);
	ucase(ircto);
	user(usern)->translates=writelist(irccontent,ircto,cfile,user(usern)->translates);
	ssnprintf(user(usern)->insock,lngtxt(203),user(userp)->nick,ircto,irccontent);
    } else
	ssnprintf(user(usern)->insock,lngtxt(204),user(userp)->nick);
    return 0x0;
}
#endif

/* remove op entry */
int cmddelop(int usern)
{
    char cfile[40];
    int userp;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(205),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(206),usern);
    user(usern)->ops=eraselist(atoi(irccontent),cfile,user(usern)->ops);
    ssnprintf(user(usern)->insock,lngtxt(207),user(userp)->nick,irccontent);
    return 0x0;
}

/* remove autoop entry */
int cmddelautoop(int usern)
{
    char cfile[40];
    int userp;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(208),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(209),usern);
    user(usern)->aops=eraselist(atoi(irccontent),cfile,user(usern)->aops);
    ssnprintf(user(usern)->insock,lngtxt(210),user(userp)->nick,irccontent);
    return 0x0;
}

/* delete askop */
int cmddelask(int usern)
{
    char cfile[40];
    pcontext;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(211),user(usern)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(212),usern);
    user(usern)->askops=eraselist(atoi(irccontent),cfile,user(usern)->askops);
    ssnprintf(user(usern)->insock,lngtxt(213),user(usern)->nick,irccontent);
    return 0x0;
}

/* delete allow */
int cmddelallow(int usern)
{
    char cfile[40];
    pcontext;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(214),user(usern)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(215),usern);
    hostallows=eraselist(atoi(irccontent),cfile,hostallows);
    ssnprintf(user(usern)->insock,lngtxt(216),user(usern)->nick,irccontent);
    return 0x0;
}

/* delete a ban */
int cmddelban(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(217),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(218),usern);
    pcontext;
    user(usern)->bans=eraselist(atoi(irccontent),cfile,user(usern)->bans);
    pcontext;
    ssnprintf(user(usern)->insock,lngtxt(219),user(userp)->nick,irccontent);
    pcontext;
    return 0x0;
}

/* delete an ignore */
int cmddelignore(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(1337),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(1338),usern);
    pcontext;
    user(usern)->ignores=eraselist(atoi(irccontent),cfile,user(usern)->ignores);
    pcontext;
    ssnprintf(user(usern)->insock,lngtxt(1339),user(userp)->nick,irccontent);
    pcontext;
    return 0x0;
}

/* delete a log entry */
int cmddellog(int usern)
{
    char cfile[40];
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(220),user(userp)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(221),usern);
    user(usern)->logs=eraselist(atoi(irccontent),cfile,user(usern)->logs);
    ssnprintf(user(usern)->insock,lngtxt(222),user(userp)->nick,irccontent);
    return 0x0;
}

#ifdef CRYPT
/* delete encryption */
int cmddelencrypt(int usern)
{
    char cfile[40];
    pcontext;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(223),user(usern)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(224),usern);
    user(usern)->encrypt=eraselist(atoi(irccontent),cfile,user(usern)->encrypt);
    ssnprintf(user(usern)->insock,lngtxt(225),user(usern)->nick,irccontent);
    return 0x0;
}
#endif

#ifdef TRANSLATE
/* delete encryption */
int cmddeltranslate(int usern)
{
    char cfile[40];
    pcontext;
    if (strlen(irccontent) == 0) {
        ssnprintf(user(usern)->insock,lngtxt(226),user(usern)->nick);
	return 0x0;
    }
    ap_snprintf(cfile,sizeof(cfile),lngtxt(227),usern);
    user(usern)->translates=eraselist(atoi(irccontent),cfile,user(usern)->translates);
    ssnprintf(user(usern)->insock,lngtxt(228),user(usern)->nick,irccontent);
    return 0x0;
}
#endif

/* list the ops */
int cmdlistops(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(229),user(userp)->nick);
    liststrings(user(usern)->ops,usern);
    ssnprintf(user(usern)->insock,lngtxt(230),user(userp)->nick);
    return 0x0;
}

/* list the autoops */
int cmdlistautoops(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(231),user(userp)->nick);
    liststrings(user(usern)->aops,usern);
    ssnprintf(user(usern)->insock,lngtxt(232),user(userp)->nick);
    return 0x0;
}

/* list the askops */
int cmdlistask(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(233),user(userp)->nick);
    liststrings(user(usern)->askops,usern);
    ssnprintf(user(usern)->insock,lngtxt(234),user(userp)->nick);
    return 0x0;
}

/* list the hostallows */
int cmdlistallow(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(235),user(userp)->nick);
    liststrings(hostallows,usern);
    ssnprintf(user(usern)->insock,lngtxt(236),user(userp)->nick);
    return 0x0;
}

/* list all bans */
int cmdlistbans(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(237),user(userp)->nick);
    liststrings(user(usern)->bans,usern);
    ssnprintf(user(usern)->insock,lngtxt(238),user(userp)->nick);
    return 0x0;
}

/* list all ignores */
int cmdlistignores(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(1340),user(userp)->nick);
    liststrings(user(usern)->ignores,usern);
    ssnprintf(user(usern)->insock,lngtxt(1341),user(userp)->nick);
    return 0x0;
}

#ifdef CRYPT
/* list all encryptions */
int cmdlistencrypt(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(239),user(userp)->nick);
    liststrings(user(usern)->encrypt,usern);
    ssnprintf(user(usern)->insock,lngtxt(240),user(userp)->nick);
    return 0x0;
}
#endif

#ifdef TRANSLATE
/* list all translators */
int cmdlisttranslate(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(241),user(userp)->nick);
    liststrings(user(usern)->translates,usern);
    ssnprintf(user(usern)->insock,lngtxt(242),user(userp)->nick);
    return 0x0;
}
#endif

#ifndef DYNAMIC
/* list all log-entrys */
int cmdlistlogs(int usern)
{
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(243),user(userp)->nick);
    liststrings(user(usern)->logs,usern);
    ssnprintf(user(usern)->insock,lngtxt(244),user(userp)->nick);
    return 0x0;
}
#endif

/* rehash the proxy */
int cmdrehash(int usern)
{
    struct socketnodes *sck,*psck;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    ssnprintf(user(usern)->insock,lngtxt(245),user(userp)->nick);
    p_log(LOG_WARNING,usern,lngtxt(246),user(usern)->login);
    sck=socketnode;
    /* bug found by syzop - thanks :) */
    while(sck!=NULL)
    {
	psck=sck->next;
	if(sck->sock!=NULL)
	    if(sck->sock->type!=ST_LISTEN || strmcmp(sck->sock->dest,"DCC")==1)
		killsocket(sck->sock->syssock);
	sck=psck;
    }
/* reloading all users */
    loadusers();
    loadlinks();
    return 0x0;
}

#ifdef MULTIUSER
/* crown an admin */
int cmdadmin(int usern)
{
    int rc;
    int userp;
    int brem=0;
    struct usernodes *th;
    pcontext;
    th=usernode;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent)==0) {
       ssnprintf(user(usern)->insock,lngtxt(247),user(userp)->nick);
       return 0x0;
    }
    rc=checkuser(irccontent);
    if (rc) {
       if(user(rc)->parent!=0) rc=user(rc)->parent;
       while(th)
       {
    	    if(th->user!=NULL)
	    {
		if(th->uid==rc || th->user->parent==rc)
		{
		    th->user->rights=RI_ADMIN;
		    writeuser(th->uid);
		    brem=1;
		}
	    }
	    th=th->next;
       }
       if(brem)
       {
	    p_log(LOG_INFO,usern,lngtxt(248),user(userp)->nick,irccontent);
       }
    } else {
       ssnprintf(user(usern)->insock,lngtxt(249),user(userp)->nick,irccontent);
    }
    return 0x0;
}

/* remove the crown */

int cmdunadmin(int usern)
{
    int rc;
    int userp;
    int brem=0;
    struct usernodes *th;
    pcontext;
    th=usernode;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent)==0) {
       ssnprintf(user(usern)->insock,lngtxt(250),user(userp)->nick);
       return 0x0;
    }
    rc=checkuser(irccontent);
    if (rc) {
       if(user(rc)->parent!=0) rc=user(rc)->parent;
       while(th)
       {
	    if(th->user!=NULL)
	    {
		if(th->uid==rc || th->user->parent==rc)
		{
		    th->user->rights=RI_USER;
		    writeuser(th->uid);
		    brem=1;
		}
	    }
	    th=th->next;
       }
       if(brem)
       {
           p_log(LOG_INFO,usern,lngtxt(251),user(userp)->nick,irccontent);
       }
    } else {
       ssnprintf(user(usern)->insock,lngtxt(252),user(userp)->nick,irccontent);
    }
    return 0x0;
}

/* kill a user on the bounce */

int cmdbkill(int usern)
{
    struct socketnodes *sno=socketnode;
    int rc;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    if (strlen(irccontent)==0) {
       ssnprintf(user(usern)->insock,lngtxt(253),user(userp)->nick);
    }
    rc=checkuser(irccontent);
    if (rc) {
       if (user(rc)->instate != STD_CONN) {
           ssnprintf(user(usern)->insock,lngtxt(254),user(userp)->nick);
           return -1;
       }
       p_log(LOG_INFO,usern,lngtxt(255),user(userp)->nick,irccontent);
       ssnprintf(user(rc)->insock,lngtxt(256),user(rc)->nick,user(usern)->login);
       while((sno=getpsocketbygroup(sno,rc+SGR_USERINBOUND,-1)))
       {
	   if(sno->sock)
               killsocket(sno->sock->syssock);
	   sno=socketnode;
       }
       memset(user(usern)->host,0x0,sizeof(user(usern)->host));
       user(rc)->instate=STD_NOCON;
       user(rc)->insock=0;
    } else {
       ssnprintf(user(usern)->insock,lngtxt(257),user(userp)->nick,irccontent);
    }
    return 0x0;
}
#endif

#ifdef SCRIPTING
/* reload all scripts of a user and his networks */
int cmdreloadscript(int usern)
{
    struct usernodes *th;
    int userp;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    th=usernode;
    while (th!=NULL)
    {
	if (th->user!=NULL)
	{
	    if (th->uid==userp || th->user->parent==userp)
	    {
		stopdialogues(th->uid);
		clearuserscript(th->uid);
		loadscript(th->uid);
		startdialogues(th->uid);
	    }
	}
	th=th->next;
    }
    ssnprintf(user(userp)->insock,lngtxt(258),user(userp)->nick);
    return 0x0;
}

/* list the running tasks (if admin, all, if user, only his) */
int cmdlisttasks(int usern)
{
    int userp;
    struct subtask *stsk;
    stsk=subtasks;
    pcontext;
    if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
    p_log(LOG_INFO,usern,lngtxt(259));
    while(stsk!=NULL)
    {
	if(stsk->uid==usern || user(usern)->rights==RI_ADMIN)
	{
	    p_log(LOG_INFO,usern,lngtxt(260),stsk->pid,stsk->fdin,stsk->fdout,stsk->fderr,stsk->desc);
	}
	stsk=stsk->next;
    }
    p_log(LOG_INFO,usern,lngtxt(261));
    return 0x0;
}
#endif

/* BRAW - inject data into user's inboud buffer so bnc thinks user executed that command */
int cmdbraw(int usern)
{
	int target_user;
	pcontext;
	
	/* Check things */
    if (strlen(ircto)==0) {	ssnprintf(user(usern)->insock,lngtxt(1372),user(usern)->nick); return 0x0; }	
    if (strlen(irccontent)==0) { ssnprintf(user(usern)->insock,lngtxt(1379),user(usern)->nick);	return 0x0;	}
	if ((target_user = checkuser(ircto)) == 0) { ssnprintf(user(usern)->insock,lngtxt(1373),user(usern)->nick,ircto); return 0x0; }
	
	/* Rewrite buffer */
	ap_snprintf(ircbuf, sizeof(ircbuf), "%s", irccontent);

	/* Tell admin we're gonna send it */
	ssnprintf(user(usern)->insock,lngtxt(1375),user(usern)->nick,ircbuf,user(target_user)->login);

	/* Inject into inbound buffer */
	fakeinbound(target_user);
	return 0x0;
}

/* Return 'Done' or 'Done: <whatever provided to BDONE>' */
int cmdbdone(int usern)
{
	pcontext;
	if (strlen(irccontent)==0) ssnprintf(user(usern)->insock,lngtxt(1453));
	else ssnprintf(user(usern)->insock,lngtxt(1454), irccontent);
	return 0x0;
}

/* quit a connection */
int cmdbquit(int usern)
{
    int userp;
    int uind;
    pcontext;
    uind=usern;
	if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
	if (strlen(irccontent) == 0) {
		if (user(usern)->quitted ==1) {
		ssnprintf(user(usern)->insock,lngtxt(262),user(userp)->nick);
		return 0x0;
		}
		user(usern)->quitted = 1;
		ssnprintf(user(usern)->insock,lngtxt(263),user(userp)->nick);
		writeuser(usern);
		if (user(usern)->outstate == STD_CONN) {
		   writesock(user(usern)->outsock,lngtxt(264));
		   killsocket(user(usern)->outsock);
		   user(usern)->outstate = STD_NOCON;
		   ssnprintf(user(usern)->insock,lngtxt(265),user(userp)->nick);
		   user(usern)->instate=STD_CONN;
		   user(usern)->outsock=0;
		   user(usern)->server[0]=0;
		}
	} else {
       uind = checkuser(irccontent);
       if (uind==0) {
           ssnprintf(user(usern)->insock,lngtxt(1363),user(usern)->nick,irccontent);
           return -1;
       } else
		strmncpy(irccontent,user(usern)->login,sizeof(irccontent));
		if(uind!=usern && user(usern)->rights!=RI_ADMIN) {
			ssnprintf(user(usern)->insock,lngtxt(1362),user(usern)->nick);
			return -1;
		} else {
			usern=uind;
			if (user(usern)->quitted==1) {
			ssnprintf(user(userp)->insock,lngtxt(1360),user(userp)->nick,user(usern)->nick);
			return 0x0;
			}
			user(usern)->quitted = 1;
			ssnprintf(user(usern)->insock,lngtxt(1365),user(usern)->nick,user(userp)->nick);
			ssnprintf(user(userp)->insock,lngtxt(1361),user(userp)->nick,user(usern)->nick);
			writeuser(usern);
			if (user(usern)->outstate == STD_CONN) {
			   writesock(user(usern)->outsock,lngtxt(1364));
			   killsocket(user(usern)->outsock);
			   user(usern)->outstate = STD_NOCON;
			   ssnprintf(user(usern)->insock,lngtxt(1366),user(usern)->nick,user(userp)->nick);
			   user(usern)->instate=STD_CONN;
			   user(usern)->outsock=0;
			   user(usern)->server[0]=0;
			}
		}
	}
    return 0x0;
}

/* connect a bquitted a connection */
int cmdbconnect(int usern)
{
    int userp;
    int uind;
    pcontext;
    uind=usern;
	if (user(usern)->parent!=0) userp=user(usern)->parent; else userp=usern;
	
	if (strlen(irccontent) == 0) {
		if (user(usern)->quitted==0) {
		ssnprintf(user(usern)->insock,lngtxt(266),user(userp)->nick);
		return 0x0;
		}
		user(usern)->quitted = 0;
		user(usern)->delayed = 0;
		writeuser(usern);
		return 0x0;
	} else {
       uind = checkuser(irccontent);
       if (uind==0) {
           ssnprintf(user(usern)->insock,lngtxt(1370),user(usern)->nick,irccontent);
           return -1;
       } else
		strmncpy(irccontent,user(usern)->login,sizeof(irccontent));
		if(uind!=usern && user(usern)->rights!=RI_ADMIN) {
			ssnprintf(user(usern)->insock,lngtxt(1371),user(usern)->nick);
			return -1;
		} else {
			usern=uind;
			if (user(usern)->quitted==0) {
			ssnprintf(user(userp)->insock,lngtxt(1367),user(userp)->nick,irccontent);
			return 0x0;
			}
			user(usern)->quitted = 0;
			user(usern)->delayed = 0;
			ssnprintf(user(usern)->insock,lngtxt(1369),user(usern)->nick,user(userp)->nick);
			ssnprintf(user(userp)->insock,lngtxt(1368),user(userp)->nick,user(usern)->nick);
			writeuser(usern);
			return 0x0;
		}
	}
}

/* setconnectdelay - set the connection delay of users */
int cmdsetconnectdelay(int usern)
{
    int rc;
	int olddelay;
	char olddelay2[5] = "";
    pcontext;
    if(*irccontent==0)
    {
	ssnprintf(user(usern)->insock,lngtxt(1463),user(usern)->nick);
	return -1;
    }
    rc=getini(lngtxt(267),"CONNECTDELAY",INIFILE);
    if(rc==0) {
		if ((strcmp(value, "0") != 0) && (atoi(value) <= 0 || atoi(irccontent)>600)) {
			olddelay = 30;
			if ((strcmp(irccontent, "0")) != 0 && (atoi(irccontent) <= 0 || atoi(irccontent)>600)) {
				p_log(LOG_INFO,-1,lngtxt(1467),olddelay,"System");
				snprintf(olddelay2, sizeof(olddelay2), "%d", olddelay);
				writeini(lngtxt(267),lngtxt(1468),INIFILE,olddelay2);
				flushconfig();
			}
		} else {
			olddelay = atoi(value);
		}
	} else {
		olddelay = 30;
		if ((strcmp(irccontent, "0")) != 0 && (atoi(irccontent) <= 0 || atoi(irccontent)>600)) {
			p_log(LOG_INFO,-1,lngtxt(1467),olddelay,"System");
			snprintf(olddelay2, sizeof(olddelay2), "%d", olddelay);
			writeini(lngtxt(267),lngtxt(1468),INIFILE,olddelay2);
			flushconfig();
		}
	}
	if ((strcmp(irccontent, "0")) != 0 && (atoi(irccontent) <= 0 || atoi(irccontent)>600)) {
		ssnprintf(user(usern)->insock,lngtxt(1465),user(usern)->nick);
		return -1;
	}
	writeini(lngtxt(267),lngtxt(1468),INIFILE,irccontent);
	flushconfig();
	ssnprintf(user(usern)->insock,lngtxt(1464),user(usern)->nick,olddelay,atoi(irccontent));
	p_log(LOG_INFO,-1,lngtxt(1466),olddelay,atoi(irccontent),user(usern)->login);
    return -1;
}

#ifdef IPV6

/* default ipv6 - tell the dns resolver whether or not to prefer ipv6 addresses by default when resolving vhosts/servers, can be overriden by prefer ipv6 */

int cmddefaultipv6(int usern)
{
    int newvalue = atoi(irccontent);
    int userp = user(usern)->parent;

    if (userp == 0)
    {
        userp = usern;
    }

    // Handle incorrect syntax by allowing only 0/1 and giving an error if atoi() returned 0 and
    // they wrote something other than "0" (in which case atoi() simply failed to convert it to
    // an integer).

    if ((newvalue == 0 && strcmp(irccontent, "0") != 0) || (newvalue != 0 && newvalue != 1))
    {
        ssnprintf(user(usern)->insock, lngtxt(1483), user(userp)->nick);
    }
    else
    {
        // Update the setting.

        defaultipv6 = newvalue;
        writeini("SYSTEM", "DEFAULTIPV6", INIFILE, (newvalue == 0 ? "0" : "1"));
        flushconfig();

        // Write an entry to the logfile and notify all admins.

        if (newvalue == 0)
        {
            p_log(LOG_INFO, -1, lngtxt(1484), "IPv4", user(userp)->login);
        }
        else
        {
            p_log(LOG_INFO, -1, lngtxt(1484), "IPv6", user(userp)->login);
        }
    }

    return 0x0;
}

/* prefer ipv6 - tell the dns resolver whether or not to prefer ipv6 addresses when resolving vhosts/servers */

int cmdpreferipv6(int usern)
{
    char field[20] = "";
    char addmsg[512] = "";
    int newvalue = atoi(irccontent);
    int effuser = usern;
    int userp = usern;

    // Determine if the user (or its parent, when using networking) is an administrator.
    // If they are, then they are allowed to set the preference for other users.

    int is_admin = (user(usern)->rights == RI_ADMIN);
    if (user(usern)->parent != 0)
    {
        userp = user(usern)->parent;
        is_admin = (user(userp)->rights == RI_ADMIN);
    }

    if (is_admin && *ircto)
    {
        // An admin is trying to set the preference for a user. Update the effective user to
        // reflect the new user and abort if that user does not exist.

        effuser = checkuser(ircto);
        if (effuser == 0)
        {
            ssnprintf(user(usern)->insock, lngtxt(35), user(userp)->nick, ircto);
            return -1;
        }
    }

    // Prepare some additional messages to append to all future messages.

    if (effuser == usern && strlen(user(usern)->network) != 0)
    {
        // The user is setting the preference for themselves in a network, add the
        // name of the network to messages.

        ap_snprintf(addmsg, sizeof(addmsg), lngtxt(1497), user(usern)->network);
    }
    else if (effuser != usern)
    {
        // The user is setting the preference for someone else, add the name of the
        // user to messages.

        ap_snprintf(addmsg, sizeof(addmsg), lngtxt(1498), ircto);
    }

    // TODO: Set for different user in one of their networks (CMDPREFERIPV6N-like?)

    // Handle incorrect syntax by allowing only 0/1 and giving an error if atoi() returned 0 and
    // they wrote something other than "0" (in which case atoi() simply failed to convert it to
    // an integer).

    if ((newvalue == 0 && strcmp(irccontent, "0") != 0) || (newvalue != 0 && newvalue != 1))
    {
        // Show a different error message for admins as it also shows the correct syntax which
        // is slightly different for admins (because they can specify an additional username).

        if (!is_admin)
        {
            ssnprintf(user(usern)->insock, lngtxt(1493), user(userp)->nick);
        }
        else
        {
            ssnprintf(user(usern)->insock, lngtxt(1494), user(userp)->nick);
        }
    }
    else
    {
        // Update the preference in memory to reflect the new change. Also store the preference in the
        // configuration file under 'USER<id>.PREFERIPV6=0/1'.

        user(effuser)->preferipv6 = newvalue;

        ap_snprintf(field, sizeof(field), "USER%d", effuser);
        writeini("USER", "PREFERIPV6", field, (newvalue == 0 ? "0" : "1"));
        flushconfig();

        // The change has been committed. Now we can notify the user that did the change that the change
        // was successful.

        if (newvalue == 0)
        {
            ssnprintf(user(usern)->insock, lngtxt(1495), user(userp)->nick, addmsg);
        }
        else
        {
            ssnprintf(user(usern)->insock, lngtxt(1496), user(userp)->nick, addmsg);
        }
    }

    return 0x0;
}
#endif

/* mysqlipcheck - enable/disable mysqlipcheck */
#ifdef MYSQL_IPCHECK
#ifdef HAVE_MYSQL
int cmdmysqlipcheck(int usern)
{
    int rc;
	char oldvalue2[1] = "";
    pcontext;
    if(*irccontent==0)
    {
	ssnprintf(user(usern)->insock,lngtxt(2004),user(usern)->nick);
	return -1;
    }
    rc=getini(lngtxt(267),"MYSQLIPCHECK",INIFILE);
    if(rc==0) {
		if (strcmp(value, "0") != 0 && atoi(value) != 1) {
			if (strcmp(irccontent, "0") != 0 && atoi(irccontent) != 1) {
				p_log(LOG_INFO,usern,lngtxt(2007));
				snprintf(oldvalue2, sizeof(oldvalue2), "%d", 0);
				writeini(lngtxt(267),lngtxt(2008),INIFILE,oldvalue2); /* It is broken, so we silently fix (off), as the user is not smart enough to provide either 1 or 0 */
				flushconfig();
			}
		}
	} else {
		if (strcmp(irccontent, "0") != 0 && atoi(irccontent) != 1) {
			p_log(LOG_INFO,usern,lngtxt(2007));
			snprintf(oldvalue2, sizeof(oldvalue2), "%d", 0);
			writeini(lngtxt(267),lngtxt(2008),INIFILE,oldvalue2); /* Not present, and user is not smart enough to provide either 1 or 0 */
			flushconfig();
		}
	}
	if (strcmp(irccontent, "0") != 0 && atoi(irccontent) != 1) {
		ssnprintf(user(usern)->insock,lngtxt(2007),user(usern)->nick); /* This time we tell the user, they aren't that smart */
		return -1;
	}
	writeini(lngtxt(267),lngtxt(2008),INIFILE,irccontent);
	flushconfig();
	if (strcmp(irccontent, "0") == 0) {
		ssnprintf(user(usern)->insock,lngtxt(2006),user(usern)->nick);
		p_log(LOG_INFO,-1,lngtxt(2010),user(usern)->login);
	}
	if (atoi(irccontent) == 1) {
		ssnprintf(user(usern)->insock,lngtxt(2005),user(usern)->nick);
		p_log(LOG_INFO,-1,lngtxt(2009),user(usern)->login);
	}
    return -1;
}
#endif
#endif

#ifdef LINKAGE

int cmdname(int usern)
{
    char *pt;
    pcontext;
    if (strlen(me)==0) {
	pt=strchr(irccontent,' '); /* filtering space */
	if (pt!=NULL) *pt=0;
	strmncpy(me,irccontent,sizeof(me));
	writeini(lngtxt(267),"ME",INIFILE,me);
	flushconfig();
	p_log(LOG_INFO,usern,lngtxt(268),me);
	return -1;
    }
    return 0x0;
}

#endif

int cmdquit(int usern)
{
    pcontext;
    if (user(usern)->parent !=0) usern=user(usern)->parent;
    p_log(LOG_INFO,-1,lngtxt(269),user(usern)->login,currentsocket->sock->source);
    if(getpsocketbygroup(socketnode,currentsocket->sock->sockgroup,currentsocket->sock->syssock))
    {
	killsocket(currentsocket->sock->syssock);
    } else {
	ssnprintf(user(usern)->insock,lngtxt(270),user(usern)->nick,user(usern)->login,user(usern)->host);
	quitclient(usern);
    }
    return -1;
}

/* setlang - set the language of the bouncer */

int cmdsetlang(int usern)
{
    int rc;
    char oldlang[100];
    pcontext;
    if(*irccontent==0)
    {
	ssnprintf(user(usern)->insock,lngtxt(1345),user(usern)->nick);
	return -1;
    }
    rc=getini(lngtxt(267),"LANGUAGE",INIFILE);
    if(rc==0)
	strmncpy(oldlang,value,sizeof(oldlang));
    else
	strcpy(oldlang,"english");
    rc=loadlanguage(irccontent);
    if(rc!=0)
    {
	rc=loadlanguage(oldlang);
	if(rc!=0)
	    rc=loadlanguage("english");
	ssnprintf(user(usern)->insock,lngtxt(1347),user(usern)->nick,irccontent);
    } else {
	writeini(lngtxt(267),"LANGUAGE",INIFILE,irccontent);
	flushconfig();
	ssnprintf(user(usern)->insock,lngtxt(1346),user(usern)->nick,irccontent);
	p_log(LOG_INFO,usern,lngtxt(1348),irccontent,user(usern)->nick);
    }
    return -1;
}

#ifdef CRYPT

/* Brian Rhea says: It could be spoofed.
   psychoid says: Until now. Lets give a checksum to this */

unsigned int keyhash(char *key)
{
    unsigned int hsh=0;
    char *pt;
    for(pt=key;*pt;pt++) hsh+=*pt;
    return hsh;
}

int checkcrypt(int usern)
{
    struct stringarray *lkm;
    int decr=0,valid=0;
    char buf[800],buf1[200];
    char chkbuf[30];
    char *tomatch;
    char *prefx;
    char *pt,*pt1,*pt2;
    char *b[3];
    char act[]="\x01" "ACTION ";
    char nt[]="\x00";
#ifdef BLOWFISH
    char bx[]="[B]";
#endif
#ifdef IDEA
    char bx[]="[I]";
#endif
    b[0]="[B]";
    b[1]="[I]";
    b[2]="[N]";
    prefx=nt;
    lkm=user(usern)->encrypt;
    if(strstr(irccontent,b[2])==irccontent) return 0x0;
    if(*ircbuf==':')
    {
        decr=1;
        if(strchr(user(usern)->chantypes,*ircto))
        {
	    tomatch=ircto;
	} else {
	    tomatch=ircnick;
	}
    } else {
	decr=0;
	tomatch=ircto;
    }
    strmncpy(buf,tomatch,sizeof(buf));
    ucase(buf);
    while(lkm!=NULL)
    {
	strmncpy(buf1,lkm->entry,sizeof(buf1));
	pt=buf1;
	pt2=strchr(buf1,';');
	if(pt2==NULL) return 0x0;
	*pt2++=0;
	ucase(pt);
	if(strlen(pt)==strlen(buf))
	{
	    if(strstr(pt,buf)==pt)
	    {
		pt1=decryptit(pt2);
		if(decr==1)
		{
		    pt2=NULL;
		    if(*irccontent==1) /* actions, dccs, ctcps */
		    {
			if(strstr(irccontent,act)==irccontent)
			{
			    /* this was the match buffer.. a little bug */
			    pt=irccontent+strlen(act);
			    valid=1;
			} else {
			    /* we got another control msg, which will be ignored */
			}
		    } else {
		        pt=irccontent;
			valid=1;
		    }
		    if(valid)
		    {
			pt2=NULL;
			if(strstr(pt,b[0])==pt)
			    pt2=BLOW_stringdecrypt(pt+3,pt1);
			else if(strstr(pt,b[1])==pt)
			    pt2=IDEA_stringdecrypt(pt+3,pt1);
			if(pt2==NULL) return 0x0;
			pt=strstr(ircbuf,irccontent);
			if(pt==NULL) return 0x0;
			if(strstr(pt,act)==pt) pt+=strlen(act);
			pt+=3;
			*pt=0;
			strmncpy(buf,ircbuf,sizeof(buf));
			ap_snprintf(ircbuf,sizeof(ircbuf),lngtxt(271),buf,prefx,pt2);
			free(pt2);
			parse();
		    }
		    return 0x0;
		} else {
		    if(*irccontent==1)
		    {
			if(strstr(irccontent,act)==irccontent)
			{
			    valid=1;
			} else {
			    return 0x0; /* ignoring others */
			}
		    }
		    pt=strstr(ircbuf,irccontent);
		    if(pt==NULL) return 0x0;
		    if(valid==1) pt+=strlen(act);
		    *pt=0;
		    strmncpy(buf,ircbuf,sizeof(buf));
		    if(valid)
			ap_snprintf(chkbuf,sizeof(chkbuf)," <%lu>\x01",keyhash(pt1));
		    else
			ap_snprintf(chkbuf,sizeof(chkbuf)," <%lu>",keyhash(pt1));
		    if(valid) irccontent[strlen(irccontent)-1]=0;
		    if((strlen(irccontent)+strlen(chkbuf)+1)<sizeof(irccontent))
			strcat(irccontent,chkbuf);
		    pt2=irccontent;
		    if(valid==1) pt2+=strlen(act);
#ifdef BLOWFISH
		    pt=BLOW_stringencrypt(pt2,pt1);
#endif
#ifdef IDEA
		    pt=IDEA_stringencrypt(pt2,pt1);
#endif
		    if(pt==NULL) return 0x0;
		    ap_snprintf(ircbuf,sizeof(ircbuf),lngtxt(272),buf,bx,pt);
		    parse();
		    return 0x0;
		}
	    }
	}
	lkm=lkm->next;
    }
    return 0x0;
}

#endif

#ifdef TRANSLATE

int checktranslate(int usern)
{
    struct stringarray *lkm;
    int rc=0;
    int dest=0;
    char buf[200],buf1[200];
    char *tomatch;
    char *pt,*pt1,*pt2;
    lkm=user(usern)->translates;

    if(*ircbuf==':')
    {
        dest=TR_FROM;
        if(strchr(user(usern)->chantypes,*ircto))
        {
    	    tomatch=ircto;
	} else {
	    tomatch=ircnick;
	}
    } else {
	dest=TR_TO;
	tomatch=ircto;
    }
    strmncpy(buf,tomatch,sizeof(buf));
    ucase(buf);
    while(lkm!=NULL)
    {
	strmncpy(buf1,lkm->entry,sizeof(buf1));
	pt=buf1;
	pt2=strchr(buf1,';');
	if(pt2==NULL) return 0x1;
	*pt2++=0;
	ucase(pt2);
	if(strlen(pt2)==strlen(buf))
	{
	    if(strstr(pt2,buf)==pt2)
	    {
		pt1=strchr(pt,' ');
		if(pt1==NULL) return 0x1;
		*pt1++=0;
		if(dest==TR_TO)
		{
		    pt1=pt;
		}
		rc=addtranslate(usern,irccontent,ircfrom,ircto,dest,pt1,irccommand);
		return 0x0;
	    }
	}
	lkm=lkm->next;
    }
    return 0x1;
}

#endif

int cmdping(int usern)
{
    /* needs to send back a server pong (for some evil irc-scripts) */
    if(user(usern)->server[0]==0)
	ssnprintf(user(usern)->insock,lngtxt(273),user(usern)->nick);
    else
	ssnprintf(user(usern)->insock,lngtxt(274),user(usern)->server,user(usern)->server,user(usern)->nick);
    return 0x0;
}

int cmdprivmsg(int usern)
{
    char bc=')';
    int rc;
    pcontext;
#ifndef NOMULTICLIENT
    notsocket=user(usern)->insock;
    if(user(usern)->parent!=0)
    {
	if(strchr(user(usern)->chantypes,*ircto)!=NULL)
	    ssnprintf(user(usern)->insock,":%s!%s@%s %s #%s~%s :%s",user(usern)->nick,user(usern)->login,user(usern)->host,irccommand,user(usern)->network,ircto,irccontent);
	else
	    ssnprintf(user(usern)->insock,":%s~%s!%s@%s %s %s :<- <%s> %s",user(usern)->network,ircto,user(usern)->login,user(usern)->host,irccommand,user(usern)->nick,user(usern)->nick,irccontent);
    } else {
	if(strchr(user(usern)->chantypes,*ircto)!=NULL)
	    ssnprintf(user(usern)->insock,":%s!%s@%s %s %s :%s",user(usern)->nick,user(usern)->login,user(usern)->host,irccommand,ircto,irccontent);
	else
	    ssnprintf(user(usern)->insock,":%s!%s@%s %s %s :<- <%s> %s",ircto,user(usern)->login,user(usern)->host,irccommand,user(usern)->nick,user(usern)->nick,irccontent);
    }
    notsocket=0;
#endif
    if(strmncasecmp(ircto,"-psyBNC")==1)
    {
	strmncpy(ircbuf,irccontent,sizeof(ircbuf));
	userinbound(usern);
	return 0x0;
    }
#ifdef SCRIPTING
    if(senddialoguequery(usern)==1) return 0x0;
#else
#ifdef DCCCHAT
    if(ircto[0]=='(')
    {
	if(querydccchat(usern,ircto+1)==1) return 0x0;
    }
#endif
#endif
#ifdef PARTYCHANNEL
    if (strmncasecmp(ircto,PARTYCHAN))
    {
	strcpy(ircto,"$$"); /* ... old clients, compatibility */
    }
#endif
    if (*ircto == '$') {
         querybounce(usern);
	 return 0;
    }
    if (*ircto == bc) {
         querybot(usern);
	 return 0;
    }
    rc=1;
#ifdef TRANSLATE
    rc=checktranslate(usern);
#endif
#ifdef CRYPT
    checkcrypt(usern);
#endif
    return rc;
}

int cmdwho(int usern)
{
    pcontext;
    user(usern)->triggered++;
    return -1;
}

int cmduser(int usern)
{
    return -1;
}

int quitclient(int usern)
{
    struct linknodes *dcc;
    struct usernodes *th;
    struct socketnodes *thn;
    time_t tm;
    pcontext;
    time( &tm );
    strmncpy(user(usern)->last,ctime( &tm ),sizeof(user(usern)->last));
    th=usernode;
    while (th!=NULL)
    {
	if (th->user!=NULL)
	{
	    if (th->uid==usern || th->user->parent==usern)
	    {
	        user(th->uid)->instate = STD_NOCON;
	        if (user(th->uid)->parent!=0) user(th->uid)->insock = 0;
#ifdef INTNET
		cmdintquit(usern,0);
#endif
#ifdef SCRIPTING
		stopdialogues(usern);
#endif
#ifdef DYNAMIC
		cmdbquit(th->uid);
		dcc=user(th->uid)->dcc;
		while(dcc!=NULL)
		{
		    if (dcc->link!=NULL)
		    {
		        if (dcc->link->outstate==STD_CONN)
			    killsocket(dcc->link->outsock);
		    }
		    dcc=dcc->next;
		}
#else
		if (user(th->uid)->leavequit!=0)
		{
		    partleavemsg(th->uid);
		} else
		if (*user(th->uid)->leavemsg!=0)
		{
		    sendleavemsg(th->uid);
		}
	        if (strlen(user(th->uid)->away) >0) {
	            ssnprintf(user(usern)->outsock,lngtxt(275),user(th->uid)->away);
		    dcc=user(th->uid)->dcc;
		    while(dcc!=NULL)
		    {
			if (dcc->link!=NULL)
			{
			    if (dcc->link->outstate==STD_CONN)
				ssnprintf(dcc->link->outsock,lngtxt(276),user(th->uid)->away);
			}
			dcc=dcc->next;
		    }
	        }
#endif
		user(th->uid)->triggered=0;
		user(th->uid)->afterquit=1;
	        memset(user(th->uid)->host,0x0,sizeof(user(th->uid)->host));
		if(*user(th->uid)->awaynick!=0)
		    ssnprintf(user(th->uid)->outsock,lngtxt(277),user(th->uid)->awaynick);
		else
		    ssnprintf(user(th->uid)->outsock,lngtxt(278),user(th->uid)->wantnick);
	    }
	}
	th=th->next;
    }
    thn=getpsocketbysock(user(usern)->insock);
    if (thn!=NULL)
	thn->sock->destructor=NULL;
    killsocket(user(usern)->insock);
    user(usern)->insock=0;
    flushconfig();
#ifdef PARTYCHANNEL
    if(user(usern)->sysmsg==1)
    {
	strmncpy(irccontent,PARTYCHAN,sizeof(irccontent));
	cmdpart(usern);
	user(usern)->sysmsg=1;
    }
#else
    sysparty(lngtxt(279),user(usern)->login);
#endif
    return 0x0;
}

int userinerror(int usern,int errn)
{
    pcontext;
    p_log(LOG_ERROR,-1,lngtxt(280),user(usern)->login,currentsocket->sock->source);
    if (user(usern)->rights!=RI_ADMIN) systemnotice(usern,lngtxt(281),user(usern)->login,currentsocket->sock->source);
    strmncpy(irccontent,lngtxt(282),sizeof(irccontent));
    quitclient(usern);
    return -1;
}

int userinkill(int usern)
{
    pcontext;
    p_log(LOG_WARNING,-1,lngtxt(283),user(usern)->login,currentsocket->sock->source);
    if (user(usern)->rights!=RI_ADMIN) systemnotice(usern,lngtxt(284),user(usern)->login,currentsocket->sock->source);
    strmncpy(irccontent,lngtxt(285),sizeof(irccontent));
    quitclient(usern);
    return -1;
}

