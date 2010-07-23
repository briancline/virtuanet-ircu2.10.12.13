#ifndef INCLUDED_mute_h
#define INCLUDED_mute_h
/*
 * IRC - Internet Relay Chat, include/mute.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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
 * @brief Structures and APIs for mute manipulation.
 * @version $Id: mute.h 1913 2009-07-04 22:46:00Z entrope $
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_res_h
#include "res.h"
#endif

struct Client;
struct StatDesc;
struct Event;

#define MUTE_MAX_EXPIRE 604800	/**< max expire: 7 days */

/** Local state of a mute. */
enum MuteLocalState {
  MLOCAL_GLOBAL,		/**< mute state unmodified locally. */
  MLOCAL_ACTIVATED,		/**< mute state locally activated. */
  MLOCAL_DEACTIVATED		/**< mute state locally deactivated. */
};

/** Description of a mute. */
struct Mute {
  struct Mute *mt_next;	/**< Next mute in linked list. */
  struct Mute**mt_prev_p;	/**< Previous pointer to this mute. */
  char	       *mt_user;	/**< Username mask (or realname mask). */
  char	       *mt_host;	/**< Host portion of mask. */
  char	       *mt_reason;	/**< Reason for mute. */
  time_t	mt_expire;	/**< Expiration timestamp. */
  time_t	mt_lastmod;	/**< Last modification timestamp. */
  time_t	mt_lifetime;	/**< Record expiration timestamp. */
  struct irc_in_addr mt_addr;	/**< IP address (for IP-based mutes). */
  unsigned char mt_bits;	/**< Bits in mt_addr used in the mask. */
  unsigned int	mt_flags;	/**< mute status flags. */
  enum MuteLocalState mt_state;/**< mute local state. */
};

/** Action to perform on a mute. */
enum MuteAction {
  MUTE_ACTIVATE,		/**< mute should be activated. */
  MUTE_DEACTIVATE,		/**< mute should be deactivated. */
  MUTE_LOCAL_ACTIVATE,		/**< mute should be locally activated. */
  MUTE_LOCAL_DEACTIVATE,	/**< mute should be locally deactivated. */
  MUTE_MODIFY			/**< mute should be modified. */
};

#define MUTE_ACTIVE	0x0001  /**< mute is active. */
#define MUTE_IPMASK	0x0002  /**< mt_addr and mt_bits fields are valid. */
#define MUTE_LOCAL	0x0008  /**< mute only applies to this server. */
#define MUTE_ANY	0x0010  /**< Search flag: Find any mute. */
#define MUTE_FORCE	0x0020  /**< Override normal limits on mutes. */
#define MUTE_EXACT	0x0040  /**< Exact match only (no wildcards). */
#define MUTE_LDEACT	0x0080	/**< Locally deactivated. */
#define MUTE_GLOBAL	0x0100	/**< Find only global mutes. */
#define MUTE_LASTMOD	0x0200	/**< Find only mutes with non-zero lastmod. */
#define MUTE_OPERFORCE	0x0400	/**< Oper forcing mute to be set. */
#define MUTE_REALNAME  0x0800  /**< mute matches only the realname field. */

#define MUTE_EXPIRE	0x1000	/**< Expiration time update */
#define MUTE_LIFETIME	0x2000	/**< Record lifetime update */
#define MUTE_REASON	0x4000	/**< Reason update */

/** Controllable flags that can be set on an actual mute. */
#define MUTE_MASK	(MUTE_ACTIVE | MUTE_LOCAL | MUTE_REALNAME)
/** Mask for mute activity flags. */
#define MUTE_ACTMASK	(MUTE_ACTIVE | MUTE_LDEACT)

/** Mask for mute update flags. */
#define MUTE_UPDATE	(MUTE_EXPIRE | MUTE_LIFETIME | MUTE_REASON)

/** Test whether \a m is active. */
#define MuteIsActive(m)	((((m)->mt_flags & MUTE_ACTIVE) &&	  \
				  (m)->mt_state != MLOCAL_DEACTIVATED) || \
				 (m)->mt_state == MLOCAL_ACTIVATED)
/** Test whether \a m is remotely (globally) active. */
#define MuteIsRemActive(m)	((m)->mt_flags & MUTE_ACTIVE)
/** Test whether \a m is an IP-based mute. */
#define MuteIsIpMask(m)	((m)->mt_flags & MUTE_IPMASK)
/** Test whether \a m is a realname-based mute. */
#define MuteIsRealName(m)      ((m)->mt_flags & MUTE_REALNAME)
/** Test whether \a m is local to this server. */
#define MuteIsLocal(m)		((m)->mt_flags & MUTE_LOCAL)
/** Test whether \a c has a matching mute. */
#define MuteLookup(c)     (!feature_bool(FEAT_DISABLE_MUTES) && mute_lookup((c), 0))

/** Return user mask of a mute. */
#define MuteUser(m)		((m)->mt_user)
/** Return host mask of a mute. */
#define MuteHost(m)		((m)->mt_host)
/** Return reason/message of a mute. */
#define MuteReason(m)		((m)->mt_reason)
/** Return last modification time of a mute. */
#define MuteLastMod(m)		((m)->mt_lastmod)

extern int mute_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     time_t lifetime, unsigned int flags);
extern int mute_activate(struct Client *cptr, struct Client *sptr,
			  struct Mute *mute, time_t lastmod,
			  unsigned int flags);
extern int mute_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Mute *mute, time_t lastmod,
			    unsigned int flags);
extern int mute_modify(struct Client *cptr, struct Client *sptr,
			struct Mute *mute, enum MuteAction action,
			char *reason, time_t expire, time_t lastmod,
			time_t lifetime, unsigned int flags);
extern int mute_destroy(struct Client *cptr, struct Client *sptr,
			 struct Mute *mute);
extern struct Mute *mute_find(char *userhost, unsigned int flags);
extern struct Mute *mute_lookup(struct Client *cptr, unsigned int flags);
extern void mute_free(struct Mute *mute, int reapply);
extern void mute_burst(struct Client *cptr);
extern int mute_resend(struct Client *cptr, struct Mute *mute);
extern int mute_list(struct Client *sptr, char *userhost);
extern void mute_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern int mute_memory_count(size_t *mt_size);
void check_expired_mutes(struct Event* ev);

#endif /* INCLUDED_mute_h */
