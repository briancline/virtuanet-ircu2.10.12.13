/*
 * IRC - Internet Relay Chat, ircd/mute.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Implementation of Mute manipulation functions.
 * @version $Id: mute.c 1936 2010-01-07 02:55:33Z entrope $
 */
#include "config.h"

#include "mute.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK_APPROVED	   0	/**< Mask is acceptable */
#define CHECK_OVERRIDABLE  1	/**< Mask is acceptable, but not by default */
#define CHECK_REJECTED	   2	/**< Mask is totally unacceptable */

#define MASK_WILD_0	0x01	/**< Wildcards in the last position */
#define MASK_WILD_1	0x02	/**< Wildcards in the next-to-last position */

#define MASK_WILD_MASK	0x03	/**< Mask out the positional wildcards */

#define MASK_WILDS	0x10	/**< Mask contains wildcards */
#define MASK_IP		0x20	/**< Mask is an IP address */
#define MASK_HALT	0x40	/**< Finished processing mask */

/** List of user mutes. */
struct Mute* GlobalMuteList  = 0;

/** Iterate through \a list of mutes.  Use this like a for loop,
 * i.e., follow it with braces and use whatever you passed as \a mt
 * as a single mute to be acted upon.
 *
 * @param[in] list List of mutes to iterate over.
 * @param[in] mt Name of a struct Mute pointer variable that will be made to point to the mutes in sequence.
 * @param[in] next Name of a scratch struct Mute pointer variable.
 */
/* There is some subtlety here with the boolean operators:
 * (x || 1) is used to continue in a logical-and series even when !x.
 * (x && 0) is used to continue in a logical-or series even when x.
 */
#define mtiter(list, mt, next)				\
  /* Iterate through the mutes in the list */		\
  for ((mt) = (list); (mt); (mt) = (next))		\
    /* Figure out the next pointer in list... */	\
    if ((((next) = (mt)->mt_next) || 1) &&		\
	/* Then see if it's expired */			\
	(mt)->mt_lifetime <= CurrentTime)		\
      /* Record has expired, so free the mute */	\
      mute_free((mt), 1);					\
    /* See if we need to expire the mute */		\
    else if ((((mt)->mt_expire > CurrentTime) ||        \
	      (((mt)->mt_flags &= ~MUTE_ACTIVE) && 0) ||	\
	      ((mt)->mt_state = MLOCAL_GLOBAL)) && 0)	\
      ; /* empty statement */				\
    else

/** Find canonical user and host for a string.
 * If \a userhost starts with '$', assign \a userhost to *user_p and NULL to *host_p.
 * Otherwise, if \a userhost contains '@', assign the earlier part of it to *user_p and the rest to *host_p.
 * Otherwise, assign \a def_user to *user_p and \a userhost to *host_p.
 *
 * @param[in] userhost Input string from user.
 * @param[out] user_p Gets pointer to user (or realname) part of hostmask.
 * @param[out] host_p Gets point to host part of hostmask (may be assigned NULL).
 * @param[in] def_user Default value for user part.
 */
static void
canon_userhost(char *userhost, char **user_p, char **host_p, char *def_user)
{
  char *tmp;

  if (*userhost == '$') {
    *user_p = userhost;
    *host_p = NULL;
    return;
  }

  if (!(tmp = strchr(userhost, '@'))) {
    *user_p = def_user;
    *host_p = userhost;
  } else {
    *user_p = userhost;
    *(tmp++) = '\0';
    *host_p = tmp;
  }
}

/** Create a Mute structure.
 * @param[in] user User part of mask.
 * @param[in] host Host part of mask (NULL if not applicable).
 * @param[in] reason Reason for mute.
 * @param[in] expire Expiration timestamp.
 * @param[in] lastmod Last modification timestamp.
 * @param[in] flags Bitwise combination of MUTE_* bits.
 * @return Newly allocated mute.
 */
static struct Mute *
make_mute(char *user, char *host, char *reason, time_t expire, time_t lastmod,
	   time_t lifetime, unsigned int flags)
{
  struct Mute *mute;

  assert(0 != expire);

  mute = (struct Mute *)MyMalloc(sizeof(struct Mute)); /* alloc memory */
  assert(0 != mute);

  DupString(mute->mt_reason, reason); /* initialize mute... */
  mute->mt_expire = expire;
  mute->mt_lifetime = lifetime;
  mute->mt_lastmod = lastmod;
  mute->mt_flags = flags & MUTE_MASK;
  mute->mt_state = MLOCAL_GLOBAL; /* not locally modified */

  DupString(mute->mt_user, user); /* remember them... */
  if (*user != '$')
    DupString(mute->mt_host, host);
  else
    mute->mt_host = NULL;

  if (*user != '$' && ipmask_parse(host, &mute->mt_addr, &mute->mt_bits))
    mute->mt_flags |= MUTE_IPMASK;

  mute->mt_next = GlobalMuteList; /* then link it into list */
  mute->mt_prev_p = &GlobalMuteList;
  if (GlobalMuteList)
    GlobalMuteList->mt_prev_p = &mute->mt_next;
  GlobalMuteList = mute;

  return mute;
}

/** Check local clients against a new mute.
 * If the mute is inactive, return immediately.
 * Otherwise, if any users match it, disconnect them.
 * @param[in] cptr Peer connect that sent the mute.
 * @param[in] sptr Client that originated the mute.
 * @param[in] mute New mute to check.
 * @return Zero, unless \a sptr muted himself, in which case CPTR_KILLED.
 */
static int
do_mute(struct Client *cptr, struct Client *sptr, struct Mute *mute)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (feature_bool(FEAT_DISABLE_MUTES))
    return 0; /* mutes are disabled */

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
	continue;

      if (MuteIsRealName(mute)) { /* Realname Mute */
	Debug((DEBUG_DEBUG,"Realname Mute: %s %s",(cli_info(acptr)),
					mute->mt_user+2));
        if (match(mute->mt_user+2, cli_info(acptr)) != 0)
            continue;
        Debug((DEBUG_DEBUG,"Matched!"));
      } else { /* Host/IP mute */
        if (cli_user(acptr)->username &&
            match(mute->mt_user, (cli_user(acptr))->username) != 0)
          continue;

        if (MuteIsIpMask(mute)) {
          if (!ipmask_check(&cli_ip(acptr), &mute->mt_addr, mute->mt_bits))
            continue;
        }
        else {
          if (match(mute->mt_host, cli_sockhost(acptr)) != 0)
            continue;
        }
      }

      /* here's an affected client -- modify his mute flag accordingly */
      if (MuteIsActive(mute))
        SetMute(acptr);
      else
        ClearMute(acptr);

      /* let the ops know about it */
      sendto_opmask_butone(0, SNO_GLINE, "Mute %s for %s",
                           MuteIsActive(mute) ? "active" : "inactive",
                           get_client_name(acptr, SHOW_IP));
    }
  }
  return retval;
}

/**
 * Implements the mask checking applied to local mutes.
 * Basically, host masks must have a minimum of two non-wild domain
 * fields, and IP masks must have a minimum of 16 bits.  If the mask
 * has even one wild-card, OVERRIDABLE is returned, assuming the other
 * check doesn't fail.
 * @param[in] mask mute mask to check.
 * @return One of CHECK_REJECTED, CHECK_OVERRIDABLE, or CHECK_APPROVED.
 */
static int
mute_checkmask(char *mask)
{
  unsigned int flags = MASK_IP;
  unsigned int dots = 0;
  unsigned int ipmask = 0;

  for (; *mask; mask++) { /* go through given mask */
    if (*mask == '.') { /* it's a separator; advance positional wilds */
      flags = (flags & ~MASK_WILD_MASK) | ((flags << 1) & MASK_WILD_MASK);
      dots++;

      if ((flags & (MASK_IP | MASK_WILDS)) == MASK_IP)
	ipmask += 8; /* It's an IP with no wilds, count bits */
    } else if (*mask == '*' || *mask == '?')
      flags |= MASK_WILD_0 | MASK_WILDS; /* found a wildcard */
    else if (*mask == '/') { /* n.n.n.n/n notation; parse bit specifier */
      ++mask;
      ipmask = strtoul(mask, &mask, 10);

      /* sanity-check to date */
      if (*mask || (flags & (MASK_WILDS | MASK_IP)) != MASK_IP)
	return CHECK_REJECTED;
      if (!dots) {
        if (ipmask > 128)
          return CHECK_REJECTED;
        if (ipmask < 128)
          flags |= MASK_WILDS;
      } else {
        if (dots != 3 || ipmask > 32)
          return CHECK_REJECTED;
        if (ipmask < 32)
	  flags |= MASK_WILDS;
      }

      flags |= MASK_HALT; /* Halt the ipmask calculation */
      break; /* get out of the loop */
    } else if (!IsIP6Char(*mask)) {
      flags &= ~MASK_IP; /* not an IP anymore! */
      ipmask = 0;
    }
  }

  /* Sanity-check quads */
  if (dots > 3 || (!(flags & MASK_WILDS) && dots < 3)) {
    flags &= ~MASK_IP;
    ipmask = 0;
  }

  /* update bit count if necessary */
  if ((flags & (MASK_IP | MASK_WILDS | MASK_HALT)) == MASK_IP)
    ipmask += 8;

  /* Check to see that it's not too wide of a mask */
  if (flags & MASK_WILDS &&
      ((!(flags & MASK_IP) && (dots < 2 || flags & MASK_WILD_MASK)) ||
       (flags & MASK_IP && ipmask < 16)))
    return CHECK_REJECTED; /* to wide, reject */

  /* Ok, it's approved; require override if it has wildcards, though */
  return flags & MASK_WILDS ? CHECK_OVERRIDABLE : CHECK_APPROVED;
}

/** Forward a mute to other servers.
 * @param[in] cptr Client that sent us the mute.
 * @param[in] sptr Client that originated the mute.
 * @param[in] mute mute to forward.
 * @return Zero.
 */
static int
mute_propagate(struct Client *cptr, struct Client *sptr, struct Mute *mute)
{
  if (MuteIsLocal(mute))
    return 0;

  assert(mute->mt_lastmod);

  sendcmdto_serv_butone(sptr, CMD_MUTE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
			MuteIsRemActive(mute) ? '+' : '-', mute->mt_user,
			mute->mt_host ? "@" : "",
			mute->mt_host ? mute->mt_host : "",
			mute->mt_expire - CurrentTime, mute->mt_lastmod,
			mute->mt_lifetime, mute->mt_reason);

  return 0;
}

/** Count number of users who match \a mask.
 * @param[in] mask user\@host or user\@ip mask to check.
 * @param[in] flags Bitmask possibly containing the value MUTE_LOCAL, to limit searches to this server.
 * @return Count of matching users.
 */
static int
count_users(char *mask, int flags)
{
  struct irc_in_addr ipmask;
  struct Client *acptr;
  int count = 0;
  int ipmask_valid;
  char namebuf[USERLEN + HOSTLEN + 2];
  char ipbuf[USERLEN + SOCKIPLEN + 2];
  unsigned char ipmask_len;

  ipmask_valid = ipmask_parse(mask, &ipmask, &ipmask_len);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if ((flags & MUTE_LOCAL) && !MyConnect(acptr))
      continue;

    ircd_snprintf(0, namebuf, sizeof(namebuf), "%s@%s",
		  cli_user(acptr)->username, cli_user(acptr)->host);
    ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%s@%s", cli_user(acptr)->username,
		  ircd_ntoa(&cli_ip(acptr)));

    if (!match(mask, namebuf)
        || !match(mask, ipbuf)
        || (ipmask_valid && ipmask_check(&cli_ip(acptr), &ipmask, ipmask_len)))
      count++;
  }

  return count;
}

/** Count number of users with a realname matching \a mask.
 * @param[in] mask Wildcard mask to match against realnames.
 * @return Count of matching users.
 */
static int
count_realnames(const char *mask)
{
  struct Client *acptr;
  int minlen;
  int count;
  char cmask[BUFSIZE];

  count = 0;
  matchcomp(cmask, &minlen, NULL, mask);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if (strlen(cli_info(acptr)) < minlen)
      continue;
    if (!matchexec(cli_info(acptr), cmask, minlen))
      count++;
  }
  return count;
}

/** Create a new mute and add it to global lists.
 * \a userhost may be in one of four forms:
 * \li A string starting with $R and followed by a mask to match against their realname.
 * \li A user\@IP mask (user\@ part optional) to create an IP-based ban.
 * \li A user\@host mask (user\@ part optional) to create a hostname ban.
 *
 * @param[in] cptr Client that sent us the mute.
 * @param[in] sptr Client that originated the mute.
 * @param[in] userhost Text mask for the mute.
 * @param[in] reason Reason for mute.
 * @param[in] expire Expiration time of mute.
 * @param[in] lastmod Last modification time of mute.
 * @param[in] lifetime Lifetime of mute.
 * @param[in] flags Bitwise combination of MUTE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
mute_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, time_t lifetime,
	  unsigned int flags)
{
  struct Mute *amute;
  char uhmask[USERLEN + HOSTLEN + 2];
  char *user, *host;
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);
  assert(((flags & (MUTE_GLOBAL | MUTE_LOCAL)) == MUTE_GLOBAL) ||
         ((flags & (MUTE_GLOBAL | MUTE_LOCAL)) == MUTE_LOCAL));

  Debug((DEBUG_DEBUG, "mute_add(\"%s\", \"%s\", \"%s\", \"%s\", %Tu, %Tu "
	 "%Tu, 0x%04x)", cli_name(cptr), cli_name(sptr), userhost, reason,
	 expire, lastmod, lifetime, flags));

  if (*userhost == '$') {
    switch (userhost[1]) {
      case 'R': flags |= MUTE_REALNAME; break;
      default:
        /* uh, what to do here? */
        /* The answer, my dear Watson, is we throw a protocol_violation()
           -- hikari */
        if (IsServer(cptr))
          return protocol_violation(sptr,"%s has been smoking the sweet leaf and sent me a whacky mute",cli_name(sptr));
        sendto_opmask_butone(NULL, SNO_GLINE, "%s has been smoking the sweet leaf and sent me a whacky mute", cli_name(sptr));
        return 0;
    }
    user = userhost;
    host = NULL;
    if (MyUser(sptr) || (IsUser(sptr) && flags & MUTE_LOCAL)) {
      tmp = count_realnames(userhost + 2);
      if ((tmp >= feature_int(FEAT_MUTEMAXUSERCOUNT))
	  && !(flags & MUTE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  } else {
    canon_userhost(userhost, &user, &host, "*");
    if (sizeof(uhmask) <
	ircd_snprintf(0, uhmask, sizeof(uhmask), "%s@%s", user, host))
      return send_reply(sptr, ERR_LONGMASK);
    else if (MyUser(sptr) || (IsUser(sptr) && flags & MUTE_LOCAL)) {
      switch (mute_checkmask(host)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
	if (flags & MUTE_OPERFORCE)
	  break;
	/*FALLTHROUGH*/
      case CHECK_REJECTED:
	return send_reply(sptr, ERR_MASKTOOWIDE, uhmask);
	break;
      }

      if ((tmp = count_users(uhmask, flags)) >=
	  feature_int(FEAT_MUTEMAXUSERCOUNT) && !(flags & MUTE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than MUTE_MAX_EXPIRE.
   */
  if (!(flags & MUTE_FORCE) &&
      (expire <= CurrentTime || expire > CurrentTime + MUTE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  } else if (expire <= CurrentTime) {
    /* This expired mute was forced to be added, so mark it inactive. */
    flags &= ~MUTE_ACTIVE;
  }

  if (!lifetime) /* no lifetime set, use expiration time */
    lifetime = expire;

  /* lifetime is already an absolute timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
                       SNO_AUTO, "%s adding %s%s MUTE for %s%s%s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       (flags & MUTE_ACTIVE) ? "" : "deactivated ",
		       (flags & MUTE_LOCAL) ? "local" : "global", user,
		       (flags & MUTE_REALNAME) ? "" : "@",
		       (flags & MUTE_REALNAME) ? "" : host,
		       expire + TSoffset, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s MUTE for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & MUTE_LOCAL ? "local" : "global", user,
	    flags & MUTE_REALNAME ? "" : "@",
	    flags & MUTE_REALNAME ? "" : host,
	    expire + TSoffset, reason);

  /* make the mute */
  amute = make_mute(user, host, reason, expire, lastmod, lifetime, flags);

  /* since we've disabled overlapped mute checking, amute should
   * never be NULL...
   */
  assert(amute);

  mute_propagate(cptr, sptr, amute);

  return do_mute(cptr, sptr, amute); /* knock off users if necessary */
}

/** Activate a currently inactive mute.
 * @param[in] cptr Peer that told us to activate the mute.
 * @param[in] sptr Client that originally thought it was a good idea.
 * @param[in] mute mute to activate.
 * @param[in] lastmod New value for last modification timestamp.
 * @param[in] flags 0 if the activation should be propagated, MUTE_LOCAL if not.
 * @return Zero, unless \a sptr had a death wish (in which case CPTR_KILLED).
 */
int
mute_activate(struct Client *cptr, struct Client *sptr, struct Mute *mute,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != mute);

  saveflags = mute->mt_flags;

  if (flags & MUTE_LOCAL)
    mute->mt_flags &= ~MUTE_LDEACT;
  else {
    mute->mt_flags |= MUTE_ACTIVE;

    if (mute->mt_lastmod) {
      if (mute->mt_lastmod >= lastmod) /* force lastmod to increase */
	mute->mt_lastmod++;
      else
	mute->mt_lastmod = lastmod;
    }
  }

  if ((saveflags & MUTE_ACTMASK) == MUTE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global MUTE for %s%s%s, "
                       "expiring at %Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       mute->mt_user, mute->mt_host ? "@" : "",
                       mute->mt_host ? mute->mt_host : "",
                       mute->mt_expire + TSoffset, mute->mt_reason);
  
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global MUTE for %s%s%s, expiring at %Tu: %s", sptr, mute->mt_user,
	    mute->mt_host ? "@" : "",
	    mute->mt_host ? mute->mt_host : "",
	    mute->mt_expire + TSoffset, mute->mt_reason);

  if (!(flags & MUTE_LOCAL)) /* don't propagate local changes */
    mute_propagate(cptr, sptr, mute);

  return do_mute(cptr, sptr, mute);
}

/** Deactivate a mute.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the deactivation.
 * @param[in] mute mute to deactivate.
 * @param[in] lastmod New value for mute last modification timestamp.
 * @param[in] flags MUTE_LOCAL to only deactivate locally, 0 to propagate.
 * @return Zero.
 */
int
mute_deactivate(struct Client *cptr, struct Client *sptr, struct Mute *mute,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != mute);

  saveflags = mute->mt_flags;

  if (MuteIsLocal(mute))
    msg = "removing local";
  else if (!mute->mt_lastmod && !(flags & MUTE_LOCAL)) {
    msg = "removing global";
    mute->mt_flags &= ~MUTE_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & MUTE_LOCAL)
      mute->mt_flags |= MUTE_LDEACT;
    else {
      mute->mt_flags &= ~MUTE_ACTIVE;

      if (mute->mt_lastmod) {
	if (mute->mt_lastmod >= lastmod)
	  mute->mt_lastmod++;
	else
	  mute->mt_lastmod = lastmod;
      }
    }

    if ((saveflags & MUTE_ACTMASK) != MUTE_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s MUTE for %s%s%s, expiring at %Tu: "
		       "%s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       msg, mute->mt_user, mute->mt_host ? "@" : "",
                       mute->mt_host ? mute->mt_host : "",
		       mute->mt_expire + TSoffset, mute->mt_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s MUTE for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    mute->mt_user,
	    mute->mt_host ? "@" : "",
	    mute->mt_host ? mute->mt_host : "",
	    mute->mt_expire + TSoffset, mute->mt_reason);

  if (!(flags & MUTE_LOCAL)) /* don't propagate local changes */
    mute_propagate(cptr, sptr, mute);

  /* deactivate mutedness on affected users */
  do_mute(cptr, sptr, mute);
  
  /* if it's a local mute or a Uworld mute (and not locally deactivated).. */
  if (MuteIsLocal(mute) || (!mute->mt_lastmod && !(flags & MUTE_LOCAL)))
    mute_free(mute, 0); /* get rid of it */

  return 0;
}

/** Modify a global mute.
 * @param[in] cptr Client that sent us the mute modification.
 * @param[in] sptr Client that originated the mute modification.
 * @param[in] mute mute being modified.
 * @param[in] action Resultant status of the mute.
 * @param[in] reason Reason for mute.
 * @param[in] expire Expiration time of mute.
 * @param[in] lastmod Last modification time of mute.
 * @param[in] lifetime Lifetime of mute.
 * @param[in] flags Bitwise combination of MUTE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
mute_modify(struct Client *cptr, struct Client *sptr, struct Mute *mute,
	     enum MuteAction action, char *reason, time_t expire,
	     time_t lastmod, time_t lifetime, unsigned int flags)
{
  char buf[BUFSIZE], *op = "";
  int pos = 0;

  assert(mute);
  assert(!MuteIsLocal(mute));

  Debug((DEBUG_DEBUG,  "mute_modify(\"%s\", \"%s\", \"%s%s%s\", %s, \"%s\", "
	 "%Tu, %Tu, %Tu, 0x%04x)", cli_name(cptr), cli_name(sptr),
	 mute->mt_user, mute->mt_host ? "@" : "",
	 mute->mt_host ? mute->mt_host : "",
	 action == MUTE_ACTIVATE ? "MUTE_ACTIVATE" :
	 (action == MUTE_DEACTIVATE ? "MUTE_DEACTIVATE" :
	  (action == MUTE_LOCAL_ACTIVATE ? "MUTE_LOCAL_ACTIVATE" :
	   (action == MUTE_LOCAL_DEACTIVATE ? "MUTE_LOCAL_DEACTIVATE" :
	    (action == MUTE_MODIFY ? "MUTE_MODIFY" : "<UNKNOWN>")))),
	 reason, expire, lastmod, lifetime, flags));

  /* First, let's check lastmod... */
  if (action != MUTE_LOCAL_ACTIVATE && action != MUTE_LOCAL_DEACTIVATE) {
    if (MuteLastMod(mute) > lastmod) { /* we have a more recent version */
      if (IsBurstOrBurstAck(cptr))
	return 0; /* middle of a burst, it'll resync on its own */
      return mute_resend(cptr, mute); /* resync the server */
    } else if (MuteLastMod(mute) == lastmod)
      return 0; /* we have that version of the mute... */
  }

  /* All right, we know that there's a change of some sort.  What is it? */
  /* first, check out the expiration time... */
  if ((flags & MUTE_EXPIRE) && expire) {
    if (!(flags & MUTE_FORCE) &&
	(expire <= CurrentTime || expire > CurrentTime + MUTE_MAX_EXPIRE)) {
      if (!IsServer(sptr) && MyConnect(sptr)) /* bad expiration time */
	send_reply(sptr, ERR_BADEXPIRE, expire);
      return 0;
    }
  } else
    flags &= ~MUTE_EXPIRE;

  /* Now check to see if there's any change... */
  if ((flags & MUTE_EXPIRE) && expire == mute->mt_expire) {
    flags &= ~MUTE_EXPIRE; /* no change to expiration time... */
    expire = 0;
  }

  /* Next, check out lifetime--this one's a bit trickier... */
  if (!(flags & MUTE_LIFETIME) || !lifetime)
    lifetime = mute->mt_lifetime; /* use mute lifetime */

  lifetime = IRCD_MAX(lifetime, expire); /* set lifetime to the max */

  /* OK, let's see which is greater... */
  if (lifetime > mute->mt_lifetime)
    flags |= MUTE_LIFETIME; /* have to update lifetime */
  else {
    flags &= ~MUTE_LIFETIME; /* no change to lifetime */
    lifetime = 0;
  }

  /* Finally, let's see if the reason needs to be updated */
  if ((flags & MUTE_REASON) && reason &&
      !ircd_strcmp(mute->mt_reason, reason))
    flags &= ~MUTE_REASON; /* no changes to the reason */

  /* OK, now let's take a look at the action... */
  if ((action == MUTE_ACTIVATE && (mute->mt_flags & MUTE_ACTIVE)) ||
      (action == MUTE_DEACTIVATE && !(mute->mt_flags & MUTE_ACTIVE)) ||
      (action == MUTE_LOCAL_ACTIVATE &&
       (mute->mt_state == MLOCAL_ACTIVATED)) ||
      (action == MUTE_LOCAL_DEACTIVATE &&
       (mute->mt_state == MLOCAL_DEACTIVATED)) ||
      /* can't activate an expired mute */
      IRCD_MAX(mute->mt_expire, expire) <= CurrentTime)
    action = MUTE_MODIFY; /* no activity state modifications */

  Debug((DEBUG_DEBUG,  "About to perform changes; flags 0x%04x, action %s",
	 flags, action == MUTE_ACTIVATE ? "MUTE_ACTIVATE" :
	 (action == MUTE_DEACTIVATE ? "MUTE_DEACTIVATE" :
	  (action == MUTE_LOCAL_ACTIVATE ? "MUTE_LOCAL_ACTIVATE" :
	   (action == MUTE_LOCAL_DEACTIVATE ? "MUTE_LOCAL_DEACTIVATE" :
	    (action == MUTE_MODIFY ? "MUTE_MODIFY" : "<UNKNOWN>"))))));

  /* If there are no changes to perform, do no changes */
  if (!(flags & MUTE_UPDATE) && action == MUTE_MODIFY)
    return 0;

  /* Now we know what needs to be changed, so let's process the changes... */

  /* Start by updating lastmod, if indicated... */
  if (action != MUTE_LOCAL_ACTIVATE && action != MUTE_LOCAL_DEACTIVATE)
    mute->mt_lastmod = lastmod;

  /* Then move on to activity status changes... */
  switch (action) {
  case MUTE_ACTIVATE: /* Globally activating mute */
    mute->mt_flags |= MUTE_ACTIVE; /* make it active... */
    mute->mt_state = MLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally activating mute");
    op = "+"; /* operation for mute propagation */
    break;

  case MUTE_DEACTIVATE: /* Globally deactivating mute */
    mute->mt_flags &= ~MUTE_ACTIVE; /* make it inactive... */
    mute->mt_state = MLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally deactivating mute");
    op = "-"; /* operation for mute propagation */
    break;

  case MUTE_LOCAL_ACTIVATE: /* Locally activating mute */
    mute->mt_state = MLOCAL_ACTIVATED; /* make it locally active */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally activating mute");
    break;

  case MUTE_LOCAL_DEACTIVATE: /* Locally deactivating mute */
    mute->mt_state = MLOCAL_DEACTIVATED; /* make it locally inactive */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally deactivating mute");
    break;

  case MUTE_MODIFY: /* no change to activity status */
    break;
  }

  /* Handle expiration changes... */
  if (flags & MUTE_EXPIRE) {
    mute->mt_expire = expire; /* save new expiration time */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing expiration time to %Tu",
			   pos ? ";" : "",
			   pos && !(flags & (MUTE_LIFETIME | MUTE_REASON)) ?
			   " and" : "", expire);
  }

  /* Next, handle lifetime changes... */
  if (flags & MUTE_LIFETIME) {
    mute->mt_lifetime = lifetime; /* save new lifetime */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s extending record lifetime to %Tu",
			   pos ? ";" : "", pos && !(flags & MUTE_REASON) ?
			   " and" : "", lifetime);
  }

  /* Now, handle reason changes... */
  if (flags & MUTE_REASON) {
    MyFree(mute->mt_reason); /* release old reason */
    DupString(mute->mt_reason, reason); /* store new reason */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing reason to \"%s\"",
			   pos ? ";" : "", pos ? " and" : "", reason);
  }

  /* All right, inform ops... */
  sendto_opmask_butone(0, SNO_GLINE, "%s modifying global MUTE for %s%s%s:%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       mute->mt_user, mute->mt_host ? "@" : "",
		       mute->mt_host ? mute->mt_host : "", buf);

  /* and log the change */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C modifying global MUTE for %s%s%s:%s", sptr, mute->mt_user,
	    mute->mt_host ? "@" : "", mute->mt_host ? mute->mt_host : "",
	    buf);

  /* We'll be simple for this release, but we can update this to change
   * the propagation syntax on future updates
   */
  if (action != MUTE_LOCAL_ACTIVATE && action != MUTE_LOCAL_DEACTIVATE)
    sendcmdto_serv_butone(sptr, CMD_MUTE, cptr,
			  "* %s%s%s%s%s %Tu %Tu %Tu :%s",
			  flags & MUTE_OPERFORCE ? "!" : "", op,
			  mute->mt_user, mute->mt_host ? "@" : "",
			  mute->mt_host ? mute->mt_host : "",
			  mute->mt_expire - CurrentTime, mute->mt_lastmod,
			  mute->mt_lifetime, mute->mt_reason);

  /* OK, let's do the mute... */
  return do_mute(cptr, sptr, mute);
}

/** Destroy a local mute.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the destruction.
 * @param[in] mute mute to destroy.
 * @return Zero.
 */
int
mute_destroy(struct Client *cptr, struct Client *sptr, struct Mute *mute)
{
  assert(mute);
  assert(MuteIsLocal(mute));

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s removing local MUTE for %s%s%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       mute->mt_user, mute->mt_host ? "@" : "",
		       mute->mt_host ? mute->mt_host : "");
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C removing local MUTE for %s%s%s", sptr, mute->mt_user,
	    mute->mt_host ? "@" : "", mute->mt_host ? mute->mt_host : "");

  mute_free(mute, 1); /* get rid of the mute */

  return 0; /* convenience return */
}

/** Find a mute for a particular mask, guided by certain flags.
 * Certain bits in \a flags are interpreted specially:
 * <dl>
 * <dt>MUTE_ANY</dt><dd>Search user mutes.</dd>
 * <dt>MUTE_GLOBAL</dt><dd>Only match global mutes.</dd>
 * <dt>MUTE_LOCAL</dt><dd>Only match local mutes.</dd>
 * <dt>MUTE_LASTMOD</dt><dd>Only match mutes with a last modification time.</dd>
 * <dt>MUTE_EXACT</dt><dd>Require an exact match of mute mask.</dd>
 * <dt>anything else</dt><dd>Search user mutes.</dd>
 * </dl>
 * @param[in] userhost Mask to search for.
 * @param[in] flags Bitwise combination of MUTE_* flags.
 * @return First matching mute, or NULL if none are found.
 */
struct Mute *
mute_find(char *userhost, unsigned int flags)
{
  struct Mute *mute = 0;
  struct Mute *smute;
  char *user, *host, *t_uh;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, "*");

  mtiter(GlobalMuteList, mute, smute) {
    if ((flags & (MuteIsLocal(mute) ? MUTE_GLOBAL : MUTE_LOCAL)) ||
	(flags & MUTE_LASTMOD && !mute->mt_lastmod))
      continue;
    else if (flags & MUTE_EXACT) {
      if (((mute->mt_host && host && ircd_strcmp(mute->mt_host, host) == 0)
           || (!mute->mt_host && !host)) &&
          (ircd_strcmp(mute->mt_user, user) == 0))
	break;
    } else {
      if (((mute->mt_host && host && match(mute->mt_host, host) == 0)
           || (!mute->mt_host && !host)) &&
	  (match(mute->mt_user, user) == 0))
	break;
    }
  }

  MyFree(t_uh);

  return mute;
}

/** Find a matching mute for a user.
 * @param[in] cptr Client to compare against.
 * @param[in] flags Bitwise combination of MUTE_GLOBAL and/or
 * MUTE_LASTMOD to limit matches.
 * @return Matching mute, or NULL if none are found.
 */
struct Mute *
mute_lookup(struct Client *cptr, unsigned int flags)
{
  struct Mute *mute;
  struct Mute *smute;

  mtiter(GlobalMuteList, mute, smute) {
    if ((flags & MUTE_GLOBAL && mute->mt_flags & MUTE_LOCAL) ||
        (flags & MUTE_LASTMOD && !mute->mt_lastmod))
      continue;

    if (MuteIsRealName(mute)) {
      Debug((DEBUG_DEBUG,"realname mute: '%s' '%s'",mute->mt_user,cli_info(cptr)));
      if (match(mute->mt_user+2, cli_info(cptr)) != 0)
        continue;
    }
    else {
      if (match(mute->mt_user, (cli_user(cptr))->username) != 0)
        continue;

      if (MuteIsIpMask(mute)) {
        if (!ipmask_check(&cli_ip(cptr), &mute->mt_addr, mute->mt_bits))
          continue;
      }
      else {
        if (match(mute->mt_host, (cli_user(cptr))->realhost) != 0)
          continue;
      }
    }
    if (MuteIsActive(mute))
      return mute;
  }
  /*
   * No Mutes matched
   */
  return 0;
}

/** Delink and free a mute.
 * @param[in] mute mute to free.
 */
void
mute_free(struct Mute *mute, int reapply)
{
  assert(0 != mute);

  if (reapply) {
    /* remove the active flag so we can re-apply muted-ness to any affected users */
    mute->mt_flags &= ~MUTE_ACTIVE;
    do_mute(NULL, NULL, mute); /* unmute anyone that this affected */
  }

  *mute->mt_prev_p = mute->mt_next; /* squeeze this mute out */
  if (mute->mt_next)
    mute->mt_next->mt_prev_p = mute->mt_prev_p;

  MyFree(mute->mt_user); /* free up the memory */
  if (mute->mt_host)
    MyFree(mute->mt_host);
  MyFree(mute->mt_reason);
  MyFree(mute);
}

/** Burst all known global mutes to another server.
 * @param[in] cptr Destination of burst.
 */
void
mute_burst(struct Client *cptr)
{
  struct Mute *mute;
  struct Mute *smute;

  mtiter(GlobalMuteList, mute, smute) {
    if (!MuteIsLocal(mute) && mute->mt_lastmod)
      sendcmdto_one(&me, CMD_MUTE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		    MuteIsRemActive(mute) ? '+' : '-', mute->mt_user,
                    mute->mt_host ? "@" : "",
                    mute->mt_host ? mute->mt_host : "",
		    mute->mt_expire - CurrentTime, mute->mt_lastmod,
                    mute->mt_lifetime, mute->mt_reason);
  }
}

/** Send a mute to another server.
 * @param[in] cptr Who to inform of the mute.
 * @param[in] mute mute to send.
 * @return Zero.
 */
int
mute_resend(struct Client *cptr, struct Mute *mute)
{
  if (MuteIsLocal(mute) || !mute->mt_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_MUTE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		MuteIsRemActive(mute) ? '+' : '-', mute->mt_user,
		mute->mt_host ? "@" : "",
                mute->mt_host ? mute->mt_host : "",
		mute->mt_expire - CurrentTime, mute->mt_lastmod,
		mute->mt_lifetime, mute->mt_reason);

  return 0;
}

/** Display one or all mutes to a user.
 * If \a userhost is not NULL, only send the first matching mute.
 * Otherwise send the whole list.
 * @param[in] sptr User asking for mute list.
 * @param[in] userhost mute mask to search for (or NULL).
 * @return Zero.
 */
int
mute_list(struct Client *sptr, char *userhost)
{
  struct Mute *mute;
  struct Mute *smute;

  if (userhost) {
    if (!(mute = mute_find(userhost, MUTE_ANY))) /* no such mute */
      return send_reply(sptr, ERR_NOSUCHMUTE, userhost);

    /* send mute information along */
    send_reply(sptr, RPL_MUTELIST, mute->mt_user,
               mute->mt_host ? "@" : "",
               mute->mt_host ? mute->mt_host : "",
	       mute->mt_expire + TSoffset, mute->mt_lastmod,
	       mute->mt_lifetime + TSoffset,
	       MuteIsLocal(mute) ? cli_name(&me) : "*",
	       mute->mt_state == MLOCAL_ACTIVATED ? ">" :
	       (mute->mt_state == MLOCAL_DEACTIVATED ? "<" : ""),
	       MuteIsRemActive(mute) ? '+' : '-', mute->mt_reason);
  } else {
    mtiter(GlobalMuteList, mute, smute) {
      send_reply(sptr, RPL_MUTELIST, mute->mt_user,
		 mute->mt_host ? "@" : "",
		 mute->mt_host ? mute->mt_host : "",
		 mute->mt_expire + TSoffset, mute->mt_lastmod,
		 mute->mt_lifetime + TSoffset,
		 MuteIsLocal(mute) ? cli_name(&me) : "*",
		 mute->mt_state == MLOCAL_ACTIVATED ? ">" :
		 (mute->mt_state == MLOCAL_DEACTIVATED ? "<" : ""),
		 MuteIsRemActive(mute) ? '+' : '-', mute->mt_reason);
    }
  }

  /* end of mute information */
  return send_reply(sptr, RPL_ENDOFMUTELIST);
}

/** Statistics callback to list mutes.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
mute_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Mute *mute;
  struct Mute *smute;

  mtiter(GlobalMuteList, mute, smute) {
    send_reply(sptr, RPL_STATSMUTE, 'M', mute->mt_user,
	       mute->mt_host ? "@" : "",
	       mute->mt_host ? mute->mt_host : "",
	       mute->mt_expire + TSoffset, mute->mt_lastmod,
	       mute->mt_lifetime + TSoffset,
	       mute->mt_state == MLOCAL_ACTIVATED ? ">" :
	       (mute->mt_state == MLOCAL_DEACTIVATED ? "<" : ""),
	       MuteIsRemActive(mute) ? '+' : '-',
	       mute->mt_reason);
  }
}

/** Calculate memory used by mutes.
 * @param[out] mt_size Number of bytes used by mutes.
 * @return Number of mutes in use.
 */
int
mute_memory_count(size_t *mt_size)
{
  struct Mute *mute;
  unsigned int mt = 0;

  for (mute = GlobalMuteList; mute; mute = mute->mt_next) {
    mt++;
    *mt_size += sizeof(struct Mute);
    *mt_size += mute->mt_user ? (strlen(mute->mt_user) + 1) : 0;
    *mt_size += mute->mt_host ? (strlen(mute->mt_host) + 1) : 0;
    *mt_size += mute->mt_reason ? (strlen(mute->mt_reason) + 1) : 0;
  }

  return mt;
}

/** Timer function to check for expired mutes.
 * @param[in] ev Expired timer event (ignored).
 */
void check_expired_mutes(struct Event* ev)
{
  struct Mute *mute, *smute;
  
  if(feature_bool(FEAT_DISABLE_MUTES))
    return;
  
  mtiter(GlobalMuteList, mute, smute) {
    /*
     * The mtiter macro automatically takes care of mute_free'ing
     * any expired mutes that it comes across. mute_free then
     * deactivates them and calls do_mute for each so that affected
     * local clients can have their mute flag cleared accordingly.
     */
  }
}