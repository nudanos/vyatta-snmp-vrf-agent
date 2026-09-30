/*
 *  Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>

#ifdef HAVE_ROUTING_DOMAIN
#include <linux/rtg_domains.h>
#endif

#define RCVBUF_SIZE (32768)
#define SNDBUF_SIZE (512)

static int nlseq;

/*
 * Returns 0 if the vrf names are the same, 1 if not.
 * Checks for corner cases around defaults.
 */
int
vrf_compare(const char *vrf1, const char *vrf2)
{
    /* If both are default (null/empty string/default) it's a match */
    if ((!vrf1 || strlen(vrf1) == 0 || !strcmp(vrf1, "default")) &&
            (!vrf2 || strlen(vrf2) == 0 || !strcmp(vrf2, "default")))
        return 0;

    /* Guard against undefined behaviour */
    if (vrf1 && vrf2)
        return !!strcmp(vrf1, vrf2);

    return 1;
}

/*
 * Check if a vrf id and a name refer to the same vrf.
 * Returns 0 if yes, 1 if no.
 */
int
match_vrf_to_id(const char *vrf, const uint32_t vrf_table_id)
{
#ifdef HAVE_ROUTING_DOMAIN
    if (!vrf && vrf_table_id != RD_DEFAULT)
        return 1;
    if (!vrf && vrf_table_id == RD_DEFAULT)
        return 0;
    if (vrf_table_id != atoi(vrf))
        return 1;
    return 0;
#endif

    /* Shortcut - if one is not set or is default, easy to check for a non-match */
    if ((!vrf || !strcmp(vrf, "default")) &&
            (vrf_table_id == RT_TABLE_MAIN || vrf_table_id == RT_TABLE_LOCAL))
        return 0;
    if ((!vrf || !strcmp(vrf, "default")) &&
            vrf_table_id != RT_TABLE_MAIN && vrf_table_id != RT_TABLE_LOCAL)
        return 1;
    if (vrf && strcmp(vrf, "default") &&
            (vrf_table_id == RT_TABLE_MAIN || vrf_table_id == RT_TABLE_LOCAL))
        return 1;

    /* Bad luck, both are set, check what name corresponds to the vrf_table_id */
    int             nlsk;
    unsigned char rcvbuf[RCVBUF_SIZE];
    int rcvbuf_size = RCVBUF_SIZE;
    unsigned char sndbuf[SNDBUF_SIZE];
    struct nlmsghdr *hdr;
    struct ifinfomsg *ifihdr;
    int count;
    int end_of_message = 0;
    int rc = 1;

    /*
     * Open a netlink socket
     */
    nlsk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nlsk < 0) {
        snmp_log_perror("socket netlink");
        return 1;
    }

    if (setsockopt(nlsk, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        snmp_log_perror("setsockopt netlink rcvbuf");
        close(nlsk);
        return 1;
    }

    memset(sndbuf, 0, SNDBUF_SIZE);
    hdr = (struct nlmsghdr *)sndbuf;
    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    hdr->nlmsg_type = RTM_GETLINK;
    hdr->nlmsg_flags = NLM_F_ROOT|NLM_F_REQUEST;
    hdr->nlmsg_seq = ++nlseq;

    ifihdr = (struct ifinfomsg *)NLMSG_DATA(hdr);
    ifihdr->ifi_family = AF_UNSPEC;

    /*
     * Send a request to the kernel to dump the routing table to us
     */
    count = send(nlsk, sndbuf, hdr->nlmsg_len, 0);
    if (count < 0) {
        snmp_log_perror("send netlink");
        close(nlsk);
        return 1;
    }

    /*
     * Now listen for response
     */
    do {
        struct nlmsghdr *n;

        /*
         * Get the message
         */
        count = recv(nlsk, rcvbuf, sizeof(rcvbuf), MSG_DONTWAIT);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            snmp_log_perror("recv netlink");
            break;
        }

        /*
         * Walk all of the returned messages
         */
        for (n = (struct nlmsghdr *)rcvbuf; NLMSG_OK(n, count);
             n = NLMSG_NEXT(n, count)) {
            struct nlmsghdr *ifim;
            struct rtattr *rta;
            int32_t len;
            char *name;
            int match = 0;

            /*
             * Make sure the message is ok
             */
            if (n->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(n);
                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    snmp_log(LOG_ERR, "kernel netlink error truncated\n");
                else
                    snmp_log(LOG_ERR, "kernel netlink error %s\n",
                             strerror(-err->error));
                break;
            }
            /*
             * End of message, we're done
             */
            if (n->nlmsg_type & NLMSG_DONE) {
                end_of_message = 1;
                break;
            }

            if (n->nlmsg_type != RTM_NEWLINK) {
                snmp_log(LOG_ERR, "unexpected message of type %d in nlmsg\n",
                         n->nlmsg_type);
                continue;
            }

            ifim = NLMSG_DATA(n);

            rta = IFLA_RTA(ifim);
            len = IFLA_PAYLOAD(ifim);
            for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                if (rta->rta_type == IFLA_VRF_TABLE &&
                        vrf_table_id == *(uint32_t *) RTA_DATA(rta)) {
                    match = 1;
                }
                if (rta->rta_type == IFLA_IFNAME) {
                    name = (char *)RTA_DATA(rta);
                }
            }

            if (match && !strcmp(name, vrf)) {
                rc = 0;
                break;
            }
        }

        if (rc == 0)
            break;

    } while (!end_of_message);

    close(nlsk);

    return rc;
}
