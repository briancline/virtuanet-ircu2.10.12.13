/*
 * IRC - Internet Relay Chat, ircd/m_mute.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 *
 * $Id: m_mute.c 1917 2009-07-06 02:02:31Z entrope $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "mute.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

#define PASTWATCH	157680000	/* number of seconds in 5 years */

/*
 * If the expiration value, interpreted as an absolute timestamp, is
 * more recent than 5 years in the past, we interpret it as an
 * absolute timestamp; otherwise, we assume it's relative and convert
 * it to an absolute timestamp.  Either way, the output of this macro
 * is an absolute timestamp--not guaranteed to be a *valid* timestamp,
 * but you can't have everything in a macro ;)
 */
#define abs_expire(exp)							\
  ((exp) >= CurrentTime - PASTWATCH ? (exp) : (exp) + CurrentTime)

/*
 * ms_mute - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<mute mask>
 *
 * For other parameters, see doc/readme.mute.
 */
int
ms_mute(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Mute *amute = 0;
  unsigned int flags = 0;
  enum MuteAction action = MUTE_MODIFY;
  time_t expire = 0, lastmod = 0, lifetime = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason", *tmp = 0;

  if (parc < 3)
    return need_more_params(sptr, "MUTE");

  if (IsServer(sptr))
    flags |= MUTE_FORCE;

  if (*mask == '!') {
    mask++;
    flags |= MUTE_OPERFORCE; /* assume oper had WIDE_MUTE */
  }

  switch (*mask) { /* handle +, -, <, and > */
  case '+': /* activate the mute */
    action = MUTE_ACTIVATE;
    mask++;
    break;

  case '-': /* deactivate the mute */
    action = MUTE_DEACTIVATE;
    mask++;
    break;

  case '>': /* locally activate the mute */
    action = MUTE_LOCAL_ACTIVATE;
    mask++;
    break;

  case '<': /* locally deactivate the mute */
    action = MUTE_LOCAL_DEACTIVATE;
    mask++;
    break;
  }

  /* Now, let's figure out if it's a local or global mute */
  if (action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE ||
      (target[0] == '*' && target[1] == '\0'))
    flags |= MUTE_GLOBAL;
  else
    flags |= MUTE_LOCAL;

  /* now figure out if we need to resolve a server */
  if ((action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE ||
       (flags & MUTE_LOCAL)) && !(acptr = FindNServer(target)))
    return 0; /* no such server, jump out */

  /* If it's a local activate/deactivate and server isn't me, propagate it */
  if ((action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE) &&
      !IsMe(acptr)) {
    Debug((DEBUG_DEBUG, "I am forwarding a local change to a global mute "
	   "to a remote server; target %s, mask %s, operforce %s, action %c",
	   target, mask, flags & MUTE_OPERFORCE ? "YES" : "NO",
	   action == MUTE_LOCAL_ACTIVATE ? '>' : '<'));

    sendcmdto_one(sptr, CMD_MUTE, acptr, "%C %s%c%s", acptr,
		  flags & MUTE_OPERFORCE ? "!" : "",
		  action == MUTE_LOCAL_ACTIVATE ? '>' : '<', mask);

    return 0; /* all done */
  }

  /* Next, try to find the mute... */
  if ((flags & MUTE_GLOBAL) || IsMe(acptr)) /* don't bother if it's not me! */
    amute = mute_find(mask, flags | MUTE_ANY | MUTE_EXACT);

  /* We now have all the pieces to tell us what we've got; let's put
   * it all together and convert the rest of the arguments.
   */

  /* Handle the local mutes first... */
  if (flags & MUTE_LOCAL) {
    assert(acptr);

    /* normalize the action, first */
    if (action == MUTE_LOCAL_ACTIVATE || action == MUTE_MODIFY)
      action = MUTE_ACTIVATE;
    else if (action == MUTE_LOCAL_DEACTIVATE)
      action = MUTE_DEACTIVATE;

    if (action == MUTE_ACTIVATE) { /* get expiration and reason */
      if (parc < 5) /* check parameter count... */
	return need_more_params(sptr, "MUTE");

      expire = atoi(parv[3]); /* get expiration... */
      expire = abs_expire(expire); /* convert to absolute... */
      reason = parv[parc - 1]; /* and reason */

      if (IsMe(acptr)) {
	if (amute) /* mute already exists, so let's ignore it... */
	  return 0;

	/* OK, create the local mute */
	Debug((DEBUG_DEBUG, "I am creating a local mute here; target %s, "
	       "mask %s, operforce %s, action %s, expire %Tu, reason: %s",
	       target, mask, flags & MUTE_OPERFORCE ? "YES" : "NO",
	       action == MUTE_ACTIVATE ? "+" : "-", expire, reason));

	return mute_add(cptr, sptr, mask, reason, expire, lastmod,
			 lifetime, flags | MUTE_ACTIVE);
      }
    } else if (IsMe(acptr)) { /* destroying a local mute */
      if (!amute) /* mute doesn't exist, so let's complain... */
	return send_reply(sptr, ERR_NOSUCHMUTE, mask);

      /* Let's now destroy the mute */;
      Debug((DEBUG_DEBUG, "I am destroying a local mute here; target %s, "
	     "mask %s, operforce %s, action %s", target, mask,
	     flags & MUTE_OPERFORCE ? "YES" : "NO",
	     action == MUTE_ACTIVATE ? "+" : "-"));

      return mute_destroy(cptr, sptr, amute);
    }

    /* OK, we've converted arguments; if it's not for us, forward */
    /* UPDATE NOTE: Once all servers are updated to u2.10.12.11, the
     * format string in this sendcmdto_one() may be updated to omit
     * <lastmod> for MUTE_ACTIVATE and to omit <expire>, <lastmod>,
     * and <reason> for MUTE_DEACTIVATE.
     */
    assert(!IsMe(acptr));

    Debug((DEBUG_DEBUG, "I am forwarding a local mute to a remote server; "
	   "target %s, mask %s, operforce %s, action %c, expire %Tu, "
	   "lastmod %Tu, reason: %s", target, mask,
	   flags & MUTE_OPERFORCE ? "YES" : "NO",
	   action == MUTE_ACTIVATE ? '+' :  '-', expire, CurrentTime,
	   reason));

    sendcmdto_one(sptr, CMD_MUTE, acptr, "%C %s%c%s %Tu %Tu :%s",
		  acptr, flags & MUTE_OPERFORCE ? "!" : "",
		  action == MUTE_ACTIVATE ? '+' : '-', mask,
		  expire - CurrentTime, CurrentTime, reason);

    return 0; /* all done */
  }

  /* can't modify a mute that doesn't exist, so remap to activate */
  if (!amute && action == MUTE_MODIFY)
    action = MUTE_ACTIVATE;

  /* OK, let's figure out what other parameters we may have... */
  switch (action) {
  case MUTE_LOCAL_ACTIVATE: /* locally activating a mute */
  case MUTE_LOCAL_DEACTIVATE: /* locally deactivating a mute */
    if (!amute) /* no mute to locally activate or deactivate? */
      return send_reply(sptr, ERR_NOSUCHMUTE, mask);
    lastmod = amute->mt_lastmod;
    break; /* no additional parameters to manipulate */

  case MUTE_ACTIVATE: /* activating a mute */
  case MUTE_DEACTIVATE: /* deactivating a mute */
    /* in either of these cases, we have at least a lastmod parameter */
    if (parc < 4)
      return need_more_params(sptr, "MUTE");
    else if (parc == 4) /* lastmod only form... */
      lastmod = atoi(parv[3]);
    /*FALLTHROUGH*/
  case MUTE_MODIFY: /* modifying a mute */
    /* convert expire and lastmod, look for lifetime and reason */
    if (parc > 4) { /* protect against fall-through from 4-param form */
      expire = atoi(parv[3]); /* convert expiration and lastmod */
      expire = abs_expire(expire);
      lastmod = atoi(parv[4]);

      flags |= MUTE_EXPIRE; /* we have an expiration time update */

      if (parc > 6) { /* no question, have a lifetime and reason */
	lifetime = atoi(parv[5]);
	reason = parv[parc - 1];

	flags |= MUTE_LIFETIME | MUTE_REASON;
      } else if (parc == 6) { /* either a lifetime or a reason */
	if (!amute || /* mute creation, has to be the reason */
	    /* trial-convert as lifetime, and if it doesn't fully convert,
	     * it must be the reason */
	    (!(lifetime = strtoul(parv[5], &tmp, 10)) && !*tmp)) {
	  lifetime = 0;
	  reason = parv[5];

	  flags |= MUTE_REASON; /* have a reason update */
	} else if (lifetime)
	  flags |= MUTE_LIFETIME; /* have a lifetime update */
      }
    }
  }

  if (!lastmod) /* must have a lastmod parameter by now */
    return need_more_params(sptr, "MUTE");

  Debug((DEBUG_DEBUG, "I have a global mute I am acting upon now; "
	 "target %s, mask %s, operforce %s, action %s, expire %Tu, "
	 "lastmod %Tu, lifetime %Tu, reason: %s; mute %s!  (fields "
	 "present: %s %s %s)", target, mask,
	 flags & MUTE_OPERFORCE ? "YES" : "NO",
	 action == MUTE_ACTIVATE ? "+" :
	 (action == MUTE_DEACTIVATE ? "-" :
	  (action == MUTE_LOCAL_ACTIVATE ? ">" :
	   (action == MUTE_LOCAL_DEACTIVATE ? "<" : "(MODIFY)"))),
	 expire, lastmod, lifetime, reason,
	 amute ? "EXISTS" : "does not exist",
	 flags & MUTE_EXPIRE ? "expire" : "",
	 flags & MUTE_LIFETIME ? "lifetime" : "",
	 flags & MUTE_REASON ? "reason" : ""));

  /* OK, at this point, we have converted all available parameters.
   * Let's actually do the action!
   */
  if (amute)
    return mute_modify(cptr, sptr, amute, action, reason, expire,
			lastmod, lifetime, flags);

  assert(action != MUTE_LOCAL_ACTIVATE);
  assert(action != MUTE_LOCAL_DEACTIVATE);
  assert(action != MUTE_MODIFY);

  if (!expire) { /* Cannot *add* a mute we don't have, but try hard */
    Debug((DEBUG_DEBUG, "Propagating mute %s for mute we don't have",
	   action == MUTE_ACTIVATE ? "activation" : "deactivation"));

    /* propagate the mute, even though we don't have it */
    sendcmdto_serv_butone(sptr, CMD_MUTE, cptr, "* %c%s %Tu",
			  action == MUTE_ACTIVATE ? '+' : '-',
			  mask, lastmod);

    return 0;
  }

  return mute_add(cptr, sptr, mask, reason, expire, lastmod, lifetime,
		   flags | ((action == MUTE_ACTIVATE) ? MUTE_ACTIVE : 0));
}

/*
 * mo_mute - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<mute mask>]
 *
 * For other parameters, see doc/readme.mute.
 */
int
mo_mute(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Mute *amute = 0;
  unsigned int flags = 0;
  enum MuteAction action = MUTE_MODIFY;
  time_t expire = 0;
  char *mask = parv[1], *target = 0, *reason = 0, *end;

  if (parc < 2)
    return mute_list(sptr, 0);

  if (*mask == '!') {
    mask++;

    if (HasPriv(sptr, PRIV_WIDE_MUTE))
      flags |= MUTE_OPERFORCE;
  }

  switch (*mask) { /* handle +, -, <, and > */
  case '+': /* activate the mute */
    action = MUTE_ACTIVATE;
    mask++;
    break;

  case '-': /* deactivate the mute */
    action = MUTE_DEACTIVATE;
    mask++;
    break;

  case '>': /* locally activate the mute */
    action = MUTE_LOCAL_ACTIVATE;
    mask++;
    break;

  case '<': /* locally deactivate the mute */
    action = MUTE_LOCAL_DEACTIVATE;
    mask++;
    break;
  }

  /* OK, let's figure out the parameters... */
  switch (action) {
  case MUTE_MODIFY: /* no specific action on the mute... */
    if (parc == 2) /* user wants a listing of a specific mute */
      return mute_list(sptr, mask);
    else if (parc < 4) /* must have target and expire, minimum */
      return need_more_params(sptr, "MUTE");

    target = parv[2]; /* get the target... */
    expire = strtol(parv[3], &end, 10) + CurrentTime; /* and the expiration */
    if (*end != '\0')
      return send_reply(sptr, SND_EXPLICIT | ERR_BADEXPIRE, "%s :Bad expire time", parv[3]);

    flags |= MUTE_EXPIRE; /* remember that we got an expire time */

    if (parc > 4) { /* also got a reason... */
      reason = parv[parc - 1];
      flags |= MUTE_REASON;
    }

    /* target is not global, interpolate action and require reason */
    if (target[0] != '*' || target[1] != '\0') {
      if (!reason) /* have to have a reason for this */
	return need_more_params(sptr, "MUTE");

      action = MUTE_ACTIVATE;
    }
    break;

  case MUTE_LOCAL_ACTIVATE: /* locally activate a mute */
  case MUTE_LOCAL_DEACTIVATE: /* locally deactivate a mute */
    if (parc > 2) { /* if target is available, pick it */
      target = parv[2];
      if (target[0] == '*' && target[1] == '\0')
        return send_reply(sptr, ERR_NOSUCHSERVER, target);
    }
    break;

  case MUTE_ACTIVATE: /* activating/adding a mute */
  case MUTE_DEACTIVATE: /* deactivating/removing a mute */
    if (parc < 3)
      return need_more_params(sptr, "MUTE");

    if (parc > 3) {
      /* get expiration and target */
      reason = parv[parc - 1];
      expire = strtol(parv[parc - 2], &end, 10) + CurrentTime;
      if (*end != '\0')
        return send_reply(sptr, SND_EXPLICIT | ERR_BADEXPIRE, "%s :Bad expire time", parv[parc - 2]);

      flags |= MUTE_EXPIRE | MUTE_REASON; /* remember that we got 'em */

      if (parc > 4) /* also have a target! */
	target = parv[2];
    } else {
      target = parv[2]; /* target has to be present, and has to be '*' */

      if (target[0] != '*' || target[1] != '\0')
	return need_more_params(sptr, "MUTE");
    }
    break;
  }

  /* Now let's figure out which is the target server */
  if (!target) /* no target, has to be me... */
    acptr = &me;
  /* if it's not '*', look up the server */
  else if ((target[0] != '*' || target[1] != '\0') &&
	   !(acptr = find_match_server(target)))
    return send_reply(sptr, ERR_NOSUCHSERVER, target);

  /* Now, is the mute local or global? */
  if (action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE ||
      !acptr)
    flags |= MUTE_GLOBAL;
  else /* it's some form of local mute */
    flags |= MUTE_LOCAL;

  /* If it's a local activate/deactivate and server isn't me, propagate it */
  if ((action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE) &&
      !IsMe(acptr)) {
    /* check for permissions... */
    if (!feature_bool(FEAT_CONFIG_OPERCMDS))
      return send_reply(sptr, ERR_DISABLED, "MUTE");
    else if (!HasPriv(sptr, PRIV_MUTE))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    Debug((DEBUG_DEBUG, "I am forwarding a local change to a global mute "
	   "to a remote server; target %s, mask %s, operforce %s, action %c",
	   cli_name(acptr), mask, flags & MUTE_OPERFORCE ? "YES" : "NO",
	   action == MUTE_LOCAL_ACTIVATE ? '>' : '<'));

    sendcmdto_one(sptr, CMD_MUTE, acptr, "%C %s%c%s", acptr,
                  flags & MUTE_OPERFORCE ? "!" : "",
                  action == MUTE_LOCAL_ACTIVATE ? '>' : '<', mask);

    return 0; /* all done */
  }

  /* Next, try to find the mute... */
  if ((flags & MUTE_GLOBAL) || IsMe(acptr)) /* don't bother if it's not me! */
    amute = mute_find(mask, flags | MUTE_ANY | MUTE_EXACT);

  /* We now have all the pieces to tell us what we've got; let's put
   * it all together and convert the rest of the arguments.
   */

  /* Handle the local mutes first... */
  if (flags & MUTE_LOCAL) {
    assert(acptr);

    /* normalize the action, first */
    if (action == MUTE_LOCAL_ACTIVATE || action == MUTE_MODIFY)
      action = MUTE_ACTIVATE;
    else if (action == MUTE_LOCAL_DEACTIVATE)
      action = MUTE_DEACTIVATE;

    /* If it's not for us, forward */
    /* UPDATE NOTE: Once all servers are updated to u2.10.12.11, the
     * format string in this sendcmdto_one() may be updated to omit
     * <lastmod> for MUTE_ACTIVATE and to omit <expire>, <lastmod>,
     * and <reason> for MUTE_DEACTIVATE.
     */

    if (!IsMe(acptr)) {
      /* check for permissions... */
      if (!feature_bool(FEAT_CONFIG_OPERCMDS))
	return send_reply(sptr, ERR_DISABLED, "MUTE");
      else if (!HasPriv(sptr, PRIV_MUTE))
	return send_reply(sptr, ERR_NOPRIVILEGES);

      Debug((DEBUG_DEBUG, "I am forwarding a local mute to a remote "
	     "server; target %s, mask %s, operforce %s, action %c, "
	     "expire %Tu, reason %s", target, mask,
	     flags & MUTE_OPERFORCE ? "YES" : "NO",
	     action == MUTE_ACTIVATE ? '+' : '-', expire, reason));

      sendcmdto_one(sptr, CMD_MUTE, acptr, "%C %s%c%s %Tu %Tu :%s",
		    acptr, flags & MUTE_OPERFORCE ? "!" : "",
		    action == MUTE_ACTIVATE ? '+' : '-', mask,
		    expire - CurrentTime, CurrentTime, reason);

      return 0; /* all done */
    }

    /* check local mute permissions... */
    if (!HasPriv(sptr, PRIV_LOCAL_MUTE))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    /* let's handle activation... */
    if (action == MUTE_ACTIVATE) {
      if (amute) /* mute already exists, so let's ignore it... */
	return 0;

      /* OK, create the local mute */
      Debug((DEBUG_DEBUG, "I am creating a local mute here; target %s, "
	     "mask %s, operforce %s, action  %s, expire %Tu, reason: %s",
	     target, mask, flags & MUTE_OPERFORCE ? "YES" : "NO",
	     action == MUTE_ACTIVATE ? "+" : "-", expire, reason));

      return mute_add(cptr, sptr, mask, reason, expire, 0, 0,
		       flags | MUTE_ACTIVE);
    } else { /* OK, it's a deactivation/destruction */
      if (!amute) /* mute doesn't exist, so let's complain... */
	return send_reply(sptr, ERR_NOSUCHMUTE, mask);

      /* Let's now destroy the mute */
      Debug((DEBUG_DEBUG, "I am destroying a local mute here; target %s, "
	     "mask %s, operforce %s, action %s", target, mask,
	     flags & MUTE_OPERFORCE ? "YES" : "NO",
	     action == MUTE_ACTIVATE ? "+" : "-"));

      return mute_destroy(cptr, sptr, amute);
    }
  }

  /* can't modify a mute that doesn't exist...
   * (and if we are creating a new one, we need a reason and expiration)
   */
  if (!amute &&
      (action == MUTE_MODIFY || action == MUTE_LOCAL_ACTIVATE ||
       action == MUTE_LOCAL_DEACTIVATE || !reason || !expire))
    return send_reply(sptr, ERR_NOSUCHMUTE, mask);

  /* check for mute permissions... */
  if (action == MUTE_LOCAL_ACTIVATE || action == MUTE_LOCAL_DEACTIVATE) {
    /* only need local privileges for locally-limited status changes */
    if (!HasPriv(sptr, PRIV_LOCAL_MUTE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
  } else { /* global privileges required */
    if (!feature_bool(FEAT_CONFIG_OPERCMDS))
      return send_reply(sptr, ERR_DISABLED, "MUTE");
    else if (!HasPriv(sptr, PRIV_MUTE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
  }

  Debug((DEBUG_DEBUG, "I have a global mute I am acting upon now; "
	 "target %s, mask %s, operforce %s, action %s, expire %Tu, "
	 "reason: %s; mute %s!  (fields present: %s %s)", target, 
	 mask, flags & MUTE_OPERFORCE ? "YES" : "NO",
	 action == MUTE_ACTIVATE ? "+" :
	 (action == MUTE_DEACTIVATE ? "-" :
	  (action == MUTE_LOCAL_ACTIVATE ? ">" :
	   (action == MUTE_LOCAL_DEACTIVATE ? "<" : "(MODIFY)"))),
	 expire, reason, amute ? "EXISTS" : "does not exist",
	 flags & MUTE_EXPIRE ? "expire" : "",
	 flags & MUTE_REASON ? "reason" : ""));

  if (amute) /* modifying an existing mute */
    return mute_modify(cptr, sptr, amute, action, reason, expire,
			CurrentTime, 0, flags);

  assert(action != MUTE_LOCAL_ACTIVATE);
  assert(action != MUTE_LOCAL_DEACTIVATE);
  assert(action != MUTE_MODIFY);

  /* create a new mute */
  return mute_add(cptr, sptr, mask, reason, expire, CurrentTime, 0,
		   flags | ((action == MUTE_ACTIVATE) ? MUTE_ACTIVE : 0));
}

/*
 * m_mute - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_mute(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHMUTE, "");

  return mute_list(sptr, parv[1]);
}
