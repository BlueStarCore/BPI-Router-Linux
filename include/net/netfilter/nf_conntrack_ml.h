/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nf_conntrack_ml.h - per-flow ML feature vector carried on the conntrack
 * entry (Stargazer NGFW).
 *
 * Stored as a conntrack extension (NF_CT_EXT_ML). The per-direction packet
 * counts the ML daemon needs for ratios come from the ACCT extension; this
 * holds what ACCT does not, the CICFlowMeter-style features: inter-arrival
 * timing (sum, sum-of-squares and min, plus a forward-direction split),
 * L4-payload-length sum/sum-of-squares with a sample count, per-direction
 * min/max and per-direction payload byte totals, the OR of the TCP flag bits
 * and per-flag packet counts, and the flow's in/out interface — plus the score
 * the ML daemon writes back. Lengths follow CICFlowMeter: the L4 payload only,
 * never the IP/transport headers. Sums and sums-of-squares let the consumer
 * compute mean/variance/std without floating point in the kernel; all
 * inter-arrival times are kept in microseconds. Populated per-packet by the
 * pkt_forward hook; exported as CTA_ML on the ctnetlink dump path (GET/DUMP),
 * so CONFIG_NF_CONNTRACK_EVENTS is not required. Two-element arrays are indexed
 * by direction: [IP_CT_DIR_ORIGINAL]=0, [IP_CT_DIR_REPLY]=1.
 */
#ifndef _NF_CONNTRACK_ML_H
#define _NF_CONNTRACK_ML_H

#include <linux/ktime.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

struct nf_conn_ml {
	u64	first_ns;	/* ktime of the first packet (flow start)    */
	u64	last_ns;	/* ktime of the last packet (IAT + duration) */
	u64	iat_sum_us;	/* sum of inter-arrival gaps, both dirs (us)  */
	u32	iat_count;	/* number of gaps accumulated                 */
	u16	tcp_flags[2];	/* OR of TCP flag bits seen, per direction    */
	u16	len_min[2];	/* smallest L4 payload length, per direction  */
	u16	len_max[2];	/* largest  L4 payload length, per direction  */
	s32	ml_score;	/* score written back by the ML daemon        */
	u16	iif;		/* ingress ifindex, original direction (0=unset) */
	u16	oif;		/* egress  ifindex, original direction (0=unset) */

	/* Flow inter-arrival-time variance source. Mean is iat_sum_us/iat_count;
	 * variance derives from flow_iat_sq_sum and iat_count (microseconds). */
	u64	flow_iat_sq_sum;  /* sum of squared inter-arrival gaps (us^2) */

	/* Forward-direction (IP_CT_DIR_ORIGINAL) inter-arrival times (us). */
	ktime_t	last_seen_fwd;	  /* ktime of the last forward packet (0=none) */
	u64	fwd_iat_sum;	  /* sum of forward gaps (us)                 */
	u64	fwd_iat_sq_sum;	  /* sum of squared forward gaps (us^2)        */

	/* L4-payload-length sums (bytes). pktlen_* cover both directions for the
	 * flow length variance (pktlen_count is its sample count N);
	 * bytes_fwd/bytes_bwd give the per-direction payload totals for the
	 * forward/backward length means. */
	u64	pktlen_sum;	  /* sum of payload lengths, both directions */
	u64	pktlen_sq_sum;	  /* sum of squared payload lengths           */
	u64	bytes_fwd;	  /* sum of forward  payload lengths          */
	u64	bytes_bwd;	  /* sum of backward payload lengths          */

	u32	flow_iat_min;	  /* smallest inter-arrival gap (us; primed U32_MAX) */
	u32	fwd_iat_count;	  /* number of forward gaps accumulated       */
	u32	syn_count;	  /* TCP packets seen with SYN set            */
	u32	ack_count;	  /* TCP packets seen with ACK set            */
	u32	psh_count;	  /* TCP packets seen with PSH set            */
	u32	urg_count;	  /* TCP packets seen with URG set            */
	u32	pktlen_count;	  /* number of payload samples (both dirs)    */
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
