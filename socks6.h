/*-
 * Copyright (c) 2018 University Politehnica of Bucharest
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SOCKS6_H
#define SOCKS6_H

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stdint.h>
#include <endian.h>

#define SOCKS6_VERSION_MAJOR 6
/**
 * @brief VERSION_MINOR
 * < 100 standardized
 * 100 + draft revision: accurately represents draft revision
 * 200 + draft revision: builds upon draft revision (subject to heavy API change)
 * 255: no particular draft revision
 * currently: post-draft-02 (202)
 */
#define SOCKS6_VERSION_MINOR 202

#define SOCKS6_PWAUTH_VERSION 0x01

struct SOCKS6Version
{
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

struct SOCKS6Request
{
	uint8_t commandCode;
	uint16_t port;
	uint8_t address[0];
} __attribute__((packed));

struct SOCKS6Address
{
	uint8_t type;
	uint8_t address[0];
} __attribute__((packed));

struct SOCKS6IPv4Address
{
	uint8_t type;
	uint32_t ipv4Address;
} __attribute__((packed));

struct SOCKS6IPv6Address
{
	uint8_t type;
	uint8_t ipv6Address[16];
} __attribute__((packed));

struct SOCKS6DomainAddress
{
	uint8_t type;
	uint8_t len;
	uint8_t domain[0];
} __attribute__((packed));

enum SOCKS6RequestCode
{
	SOCKS6_REQUEST_NOOP       = 0x00,
	SOCKS6_REQUEST_CONNECT    = 0x01,
	SOCKS6_REQUEST_BIND       = 0x02,
	SOCKS6_REQUEST_UDP_ASSOC  = 0x03,
	/* for future revisions */
//	SOCKS6_REQUEST_TCP_ASSOC  = 0x04,
//	SOCKS6_REQUEST_DTLS_ASSOC = 0x05,
//	SOCKS6_REQUEST_TLS_ASSOC  = 0x06,
};

enum SOCKS6AddressType
{
	SOCKS6_ADDR_IPV4   = 0x01,
	SOCKS6_ADDR_DOMAIN = 0x03,
	SOCKS6_ADDR_IPV6   = 0x04,
};

struct SOCKS6Options
{
	uint8_t optionCount;
	uint8_t options[0];
} __attribute__((packed));

struct SOCKS6InitialData
{
	uint16_t initialDataLen;
	uint8_t initialData[0];
} __attribute__((packed));

struct SOCKS6AuthReply
{
	uint8_t type;
	uint8_t method;
} __attribute__((packed));

enum SOCKS6AuthReplyCode
{
	SOCKS6_AUTH_REPLY_SUCCESS = 0x00,
	SOCKS6_AUTH_REPLY_MORE    = 0x01,
};

/**
 * @brief The SOCKS6Method enum
 * Taken from https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
 */
enum SOCKS6Method
{
	SOCKS6_METHOD_NOAUTH       = 0x00,
	SOCKS6_METHOD_GSSAPI       = 0x01,
	SOCKS6_METHOD_USRPASSWD    = 0x02,
	SOCKS6_METHOD_CHAP         = 0x03,
	SOCKS6_METHOD_CRAM         = 0x05,
	SOCKS6_METHOD_SSL          = 0x06,
	SOCKS6_METHOD_NDS          = 0x07,
	SOCKS6_METHOD_MAF          = 0x08,
	SOCKS6_METHOD_JPB          = 0x09,
	SOCKS6_METHOD_UNACCEPTABLE = 0xff,
};

struct SOCKS6OperationReply
{
	uint8_t code;
	uint16_t initialDataOffset;
	uint16_t bindPort;
	uint8_t bindAddress[0];
} __attribute__((packed));

enum SOCKS6OperationReplyCode
{
	SOCKS6_OPERATION_REPLY_SUCCESS            = 0x00,
	SOCKS6_OPERATION_REPLY_FAILURE            = 0x01, /* general SOCKS server failure */
	SOCKS6_OPERATION_REPLY_NOT_ALLOWED        = 0x02, /* connection not allowed by ruleset */
	SOCKS6_OPERATION_REPLY_NET_UNREACH        = 0x03, /* network unreachable */
	SOCKS6_OPERATION_REPLY_HOST_UNREACH       = 0x04, /* host unreachable */
	SOCKS6_OPERATION_REPLY_REFUSED            = 0x05, /* connection refused */
	SOCKS6_OPERATION_REPLY_TTL_EXPIRED        = 0x06, /* TTL expired */
	SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED  = 0x07, /* command not supported */
	SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED = 0x08, /* address type not supported */
};

struct SOCKS6Option
{
	uint8_t kind;
	uint8_t len;
	uint8_t data[0];
} __attribute__((packed));

enum SOCKS6OptionKind
{
	SOCKS6_OPTION_SOCKET      = 0x01,
	SOCKS6_OPTION_AUTH_METHOD = 0x02,
	SOCKS6_OPTION_AUTH_DATA   = 0x03,
	SOCKS6_OPTION_IDEMPOTENCE = 0x04,
};

struct SOCKS6SocketOption
{
	struct SOCKS6Option optionHead;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t level: 6,
		leg: 2;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t leg: 2,
		level: 6;
#else
#error Fix BYTE_ORDER
#endif
	uint8_t code;
	uint8_t data[0];
} __attribute__((packed));

enum SOCKS6SocketOptionLeg
{
	SOCKS6_SOCKOPT_LEG_CLIENT_PROXY = 0x01,
	SOCKS6_SOCKOPT_LEG_PROXY_SERVER = 0x02,
	SOCKS6_SOCKOPT_LEG_BOTH         = 0x03,
};

enum SOCKS6SocketOptionLevel
{
	SOCKS6_SOCKOPT_LEVEL_SOCKET = 0x01,
	SOCKS6_SOCKOPT_LEVEL_IPV4   = 0x02,
	SOCKS6_SOCKOPT_LEVEL_IPV6   = 0x03,
	SOCKS6_SOCKOPT_LEVEL_TCP    = 0x04,
	SOCKS6_SOCKOPT_LEVEL_UDP    = 0x05,
};

enum SOCKS6SocketOptionCode
{
	/* socket */
	/* ipv4 */
	/* ipv6 */
	/* tcp */
	SOCKS6_SOCKOPT_CODE_TFO      = 0x17,
	SOCKS6_SOCKOPT_CODE_MPTCP    = 0x2a,
	SOCKS6_SOCKOPT_CODE_MP_SCHED = 0x2b,
	/* udp */
};

struct SOCKS6MPTCPSchedulerOption
{
	struct SOCKS6SocketOption socketOptionHead;
	uint8_t scheduler;
} __attribute__((packed));

enum SOCKS6MPTCPScheduler
{
	SOCKS6_MPTCP_SCHEDULER_DEFAULT   = 0x01,
	SOCKS6_MPTCP_SCHEDULER_RR        = 0x02,
	SOCKS6_MPTCP_SCHEDULER_REDUNDANT = 0x03,
};

struct SOCKS6AuthMethodOption
{
	struct SOCKS6Option optionHead;
	uint8_t methods[0];
} __attribute__((packed));

struct SOCKS6AuthDataOption
{
	struct SOCKS6Option optionHead;
	uint8_t method;
	uint8_t methodData[0];
} __attribute__((packed));

struct SOCKS6IdempotenceOption
{
	struct SOCKS6Option optionHead;
	uint8_t type;
	uint8_t idempotenceData[0];
} __attribute__((packed));

enum SOCKS6IDempotenceType
{
	SOCKS6_IDEMPOTENCE_WND_REQ          = 0x00,
	SOCKS6_IDEMPOTENCE_WND_ADVERT       = 0x01,
	SOCKS6_IDEMPOTENCE_TOK_EXPEND       = 0x02,
	SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY = 0x03,
};

struct SOCKS6WindowRequestOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t windowSize;
} __attribute__((packed));

struct SOCKS6WindowAdvertOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t windowBase;
	uint32_t windowSize;
} __attribute__((packed));

struct SOCKS6TokenExpenditureOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t token;
} __attribute__((packed));

struct SOCKS6TokenExpenditureReplyOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint8_t code;
} __attribute__((packed));

enum SOCKS6TokenExpenditureCode
{
	SOCKS6_TOK_EXPEND_SUCCESS    = 0x00,
	SOCKS6_TOK_EXPEND_NO_WND     = 0x01,
	SOCKS6_TOK_EXPEND_OUT_OF_WND = 0x02,
	SOCKS6_TOK_EXPEND_DUPLICATE  = 0x03,
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6_H
