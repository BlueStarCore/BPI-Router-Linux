/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nf_conntrack_ml.h - per-flow ML feature vector carried on the conntrack
 * entry (Stargazer NGFW).
 *
 * Stored as a conntrack extension (NF_CT_EXT_ML). Packet/byte counts come from
 * the ACCT extension; this holds the features ACCT/TSTAMP do not (timing,
 * packet-length spread, accumulated TCP flags) plus the score the ML daemon
 * writes back. Populated per-packet by the pkt_forward hook; exported on flow
 * teardown via ctnetlink. Fields are indexed by direction:
 * [IP_CT_DIR_ORIGINAL]=0, [IP_CT_DIR_REPLY]=1.
 */
#ifndef _NF_CONNTRACK_ML_H
#define _NF_CONNTRACK_ML_H

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

struct nf_conn_ml {
	u64	first_ns;	/* ktime of the first packet (flow start)   */
	u64	last_ns;	/* ktime of the last packet (IAT + duration) */
	u64	iat_sum_ns;	/* sum of inter-arrival gaps (both dirs)     */
	u32	iat_count;	/* number of gaps accumulated                */
	u16	tcp_flags[2];	/* OR of TCP flag bits seen, per direction   */
	u16	len_min[2];	/* smallest L3 packet length, per direction  */
	u16	len_max[2];	/* largest  L3 packet length, per direction  */
	s32	ml_score;	/* score written back by the ML daemon       */
};

static inline struct nf_conn_ml *nf_conn_ml_find(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_ML);
}

/* Allocate the ML extension on a not-yet-confirmed conntrack and prime the
 * per-direction minimum-length fields so the first packet sets them. */
static inline struct nf_conn_ml *nf_ct_ml_ext_add(struct nf_conn *ct, gfp_t gfp)
{
	struct nf_conn_ml *ml = nf_ct_ext_add(ct, NF_CT_EXT_ML, gfp);

	if (ml) {
		ml->len_min[0] = U16_MAX;
		ml->len_min[1] = U16_MAX;
	}
	return ml;
}

#endif /* _NF_CONNTRACK_ML_H */
