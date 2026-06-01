/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nf_conntrack_ml.h - per-flow ML feature vector carried on the conntrack
 * entry (Stargazer NGFW).
 *
 * Stored as a conntrack extension (NF_CT_EXT_ML). Packet/byte counts come from
 * the ACCT extension; this holds the features ACCT/TSTAMP do not: inter-arrival
 * timing (sum, sum-of-squares and min, plus a forward-direction split),
 * packet-length sum/sum-of-squares and per-direction min/max, accumulated TCP
 * flags and per-flag packet counts, and the flow's in/out interface — plus the
 * score the ML daemon writes back. Sums and sums-of-squares let the consumer
 * compute mean/variance/std without floating point in the kernel. Populated
 * per-packet by the pkt_forward hook; exported as CTA_ML on the ctnetlink dump
 * path (GET/DUMP), so CONFIG_NF_CONNTRACK_EVENTS is not required. Two-element
 * arrays are indexed by direction: [IP_CT_DIR_ORIGINAL]=0, [IP_CT_DIR_REPLY]=1.
 */
#ifndef _NF_CONNTRACK_ML_H
#define _NF_CONNTRACK_ML_H

#include <linux/ktime.h>
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
	u16	iif;		/* ingress ifindex, original direction (0=unset) */
	u16	oif;		/* egress  ifindex, original direction (0=unset) */

	/* Inter-arrival-time variance/min. Gaps are in microseconds; the mean
	 * is iat_sum_ns/iat_count, the variance derives from flow_iat_sq_sum. */
	u64	flow_iat_sq_sum;  /* sum of squared inter-arrival gaps (us^2) */

	/* Forward-direction (IP_CT_DIR_ORIGINAL) inter-arrival times (us). */
	ktime_t	last_seen_fwd;	  /* ktime of the last forward packet (0=none) */
	u64	fwd_iat_sum;	  /* sum of forward gaps (us)                 */
	u64	fwd_iat_sq_sum;	  /* sum of squared forward gaps (us^2)        */

	/* L3 packet-length sum and sum-of-squares, both directions (bytes). */
	u64	pktlen_sum;	  /* sum of L3 packet lengths                 */
	u64	pktlen_sq_sum;	  /* sum of squared L3 packet lengths         */

	u32	flow_iat_min;	  /* smallest inter-arrival gap (us; primed U32_MAX) */
	u32	fwd_iat_count;	  /* number of forward gaps accumulated       */
	u32	syn_count;	  /* TCP packets seen with SYN set            */
	u32	ack_count;	  /* TCP packets seen with ACK set            */
	u32	psh_count;	  /* TCP packets seen with PSH set            */
	u32	urg_count;	  /* TCP packets seen with URG set            */
};

static inline struct nf_conn_ml *nf_conn_ml_find(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_ML);
}

/* Allocate the ML extension on a not-yet-confirmed conntrack and prime the
 * minimum fields so the first packet/gap sets them. */
static inline struct nf_conn_ml *nf_ct_ml_ext_add(struct nf_conn *ct, gfp_t gfp)
{
	struct nf_conn_ml *ml = nf_ct_ext_add(ct, NF_CT_EXT_ML, gfp);

	if (ml) {
		ml->len_min[0] = U16_MAX;
		ml->len_min[1] = U16_MAX;
		ml->flow_iat_min = U32_MAX;
	}
	return ml;
}

#endif /* _NF_CONNTRACK_ML_H */
