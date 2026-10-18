#ifndef OD_SOCKS_H
#define OD_SOCKS_H

#include <stdint.h>

#include "od_socket.h"
#include "od_types.h"

#define OD_SOCKS_VERSION 0x05u

/* Methods */
#define OD_SOCKS_METHOD_NOAUTH 0x00u
#define OD_SOCKS_METHOD_USERPASS 0x02u
#define OD_SOCKS_METHOD_NO_ACCEPTABLE 0xFFu

/* Commands */
#define OD_SOCKS_CMD_CONNECT 0x01u

/* Address types */
#define OD_SOCKS_ATYP_IPV4 0x01u
#define OD_SOCKS_ATYP_DOMAIN 0x03u
#define OD_SOCKS_ATYP_IPV6 0x04u

/* Reply codes */
#define OD_SOCKS_REP_SUCCEEDED 0x00u
#define OD_SOCKS_REP_GENERAL_FAILURE 0x01u
#define OD_SOCKS_REP_RULESET_DENIED 0x02u
#define OD_SOCKS_REP_NETWORK_UNREACHABLE 0x03u
#define OD_SOCKS_REP_HOST_UNREACHABLE 0x04u
#define OD_SOCKS_REP_CONNECTION_REFUSED 0x05u
#define OD_SOCKS_REP_TTL_EXPIRED 0x06u
#define OD_SOCKS_REP_COMMAND_NOT_SUPPORTED 0x07u
#define OD_SOCKS_REP_ATYP_NOT_SUPPORTED 0x08u

/*
 * SOCKS5 negotiation.
 * - If username/password are NULL: NO AUTH (0x00).
 * - If username/password are provided: USER/PASS auth (0x02, RFC 1929).
 * Returns 0 on success, -1 on protocol/auth/I-O failure.
 */
int od_socks_negotiate(socket_t fd, const char *username, const char *password);

/*
 * Parses a SOCKS5 CONNECT request and fills out_target with HOST:PORT.
 * On success returns 0 and sets out_rep_code to OD_SOCKS_REP_SUCCEEDED.
 * On failure returns -1 and sets out_rep_code to an RFC 1928 reply code.
 */
int od_socks_read_connect(socket_t fd, endpoint_t *out_target, uint8_t *out_rep_code);

/*
 * Sends a SOCKS5 reply with an IPv4 zero bind address (0.0.0.0:0).
 * Returns 0 on success, -1 on I/O error.
 */
int od_socks_send_reply(socket_t fd, uint8_t rep_code);

#endif
