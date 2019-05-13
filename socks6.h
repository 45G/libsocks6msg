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
 * 100 + draft revision: accurately represents draft revision (subject to API changes; not subject to protocol changes)
 * 200 + draft revision: builds upon draft revision (subject to API and protocol changes)
 * 255: no particular draft revision
 * currently: post-draft-06 (206)
 */
#define SOCKS6_VERSION_MINOR 206

#define SOCKS6_PWAUTH_VERSION 0x01

struct SOCKS6Version
{
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

struct SOCKS6Request
{
	uint8_t  commandCode;
	uint16_t port;
	uint8_t  address[0];
} __attribute__((packed));

struct SOCKS6Address
{
	uint8_t type;
	uint8_t address[0];
} __attribute__((packed));

struct SOCKS6IPv4Address
{
	uint8_t  type;
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
};

enum SOCKS6AddressType
{
	SOCKS6_ADDR_IPV4   = 0x01,
	SOCKS6_ADDR_DOMAIN = 0x03,
	SOCKS6_ADDR_IPV6   = 0x04,
};

struct SOCKS6Options
{
	uint16_t optionsLength;
	uint8_t  options[0];
} __attribute__((packed));

#define SOCKS6_OPTIONS_LENGTH_MAX (1 << 14)

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
	uint8_t  code;
	uint16_t bindPort;
	uint8_t  bindAddress[0];
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
	SOCKS6_OPERATION_REPLY_TIMEOUT            = 0x09, /* connection attempt timed out */
};

struct SOCKS6Option
{
	uint8_t  kind;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

enum SOCKS6OptionKind
{
	SOCKS6_OPTION_STACK       = 0x01,
	SOCKS6_OPTION_AUTH_METHOD = 0x02,
	SOCKS6_OPTION_AUTH_DATA   = 0x03,
	SOCKS6_OPTION_SESSION     = 0x04,
	SOCKS6_OPTION_IDEMPOTENCE = 0x05,

	SOCKS6_OPTION_VENDOR_MIN  = 0xe0,
	SOCKS6_OPTION_VENDOR_MAX  = 0xff,
};

struct SOCKS6StackOption
{
	struct SOCKS6Option optionHead;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t             level: 6,
			    leg: 2;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t             leg: 2,
			    level: 6;
#else
#error Fix BYTE_ORDER
#endif
	uint8_t             code;
	uint8_t             data[0];
} __attribute__((packed));

enum SOCKS6StackLeg
{
	SOCKS6_STACK_LEG_CLIENT_PROXY = 0x01,
	SOCKS6_STACK_LEG_PROXY_REMOTE = 0x02,
	SOCKS6_STACK_LEG_BOTH         = 0x03,
};

enum SOCKS6StackLevel
{
	SOCKS6_STACK_LEVEL_IP   = 0x01,
	SOCKS6_STACK_LEVEL_IPV4 = 0x02,
	SOCKS6_STACK_LEVEL_IPV6 = 0x03,
	SOCKS6_STACK_LEVEL_TCP  = 0x04,
	SOCKS6_STACK_LEVEL_UDP  = 0x05,
	/* for future revisions */
	//SOCKS6_STACK_LEVEL_TLS  = 0x06,
};

enum SOCKS6StackOptionCode
{
	/* IP */
	SOCKS6_STACK_CODE_TOS      = 0x01,

	/* IPv4 */

	/* IPv6 */

	/* TCP */
	SOCKS6_STACK_CODE_TFO      = 0x01,
	SOCKS6_STACK_CODE_MP       = 0x02,
	SOCKS6_STACK_CODE_BACKLOG  = 0x03,

	/* UDP */

	/* TLS */
};

struct SOCKS6TOSOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint8_t                  tos;
} __attribute__((packed));

struct SOCKS6TFOOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint16_t                 payloadLen;
} __attribute__((packed));

struct SOCKS6MPOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint8_t                  availability;
} __attribute__((packed));

struct SOCKS6BacklogOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint16_t                 backlog;
} __attribute__((packed));

#define SOCKS6_BACKLOG_MIN 1

struct SOCKS6AuthMethodOption
{
	struct SOCKS6Option optionHead;
	uint16_t            initialDataLen;
	uint8_t             methods[0];
} __attribute__((packed));

#define SOCKS6_INITIAL_DATA_MAX (1 << 14)

struct SOCKS6AuthDataOption
{
	struct SOCKS6Option optionHead;
	uint8_t             method;
	uint8_t             methodData[0];
} __attribute__((packed));

struct SOCKS6SessionOption
{
	struct SOCKS6Option optionHead;
	uint8_t             type;
	uint8_t             sessionData[0];
} __attribute__((packed));

enum SOCKS6SessionType
{
	SOCKS6_SESSION_REQUEST   = 0x01,
	SOCKS6_SESSION_ID        = 0x02,
	SOCKS6_SESSION_TEARDOWN  = 0x03,
	SOCKS6_SESSION_OK        = 0x04,
	SOCKS6_SESSION_INVALID   = 0x05,
	SOCKS6_SESSION_UNTRUSTED = 0x06,
	
};

struct SOCKS6SessionIDOption
{
	struct SOCKS6SessionOption sessionOptionHead;
	uint8_t                    ticket[0];
};

#define SOCKS6_ID_LENGTH_MAX (SOCKS6_OPTIONS_LENGTH_MAX - sizeof(struct SOCKS6SessionIDOption))

struct SOCKS6IdempotenceOption
{
	struct SOCKS6Option optionHead;
	uint8_t             type;
	uint8_t             idempotenceData[0];
} __attribute__((packed));

enum SOCKS6IDempotenceType
{
	SOCKS6_IDEMPOTENCE_WND_REQ          = 0x01,
	SOCKS6_IDEMPOTENCE_WND_ADVERT       = 0x02,
	SOCKS6_IDEMPOTENCE_TOK_EXPEND       = 0x03,
	SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY = 0x04,
};

struct SOCKS6WindowRequestOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t                       windowSize;
} __attribute__((packed));

struct SOCKS6WindowAdvertOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t                       windowBase;
	uint32_t                       windowSize;
} __attribute__((packed));

#define SOCKS6_TOKEN_WINDOW_MIN 1
#define SOCKS6_TOKEN_WINDOW_MAX ((1UL << 31) - 1)

struct SOCKS6TokenExpenditureOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint32_t                       token;
} __attribute__((packed));

struct SOCKS6TokenExpenditureReplyOption
{
	struct SOCKS6IdempotenceOption idempotenceOptionHead;
	uint8_t                        code;
} __attribute__((packed));

enum SOCKS6TokenExpenditureCode
{
	SOCKS6_TOK_EXPEND_SUCCESS = 0x01,
	SOCKS6_TOK_EXPEND_FAILURE = 0x02,
};

struct SOCKS6AssocInit
{
	uint32_t assocID;
} __attribute__((packed));

struct SOCKS6AssocConfirmation
{
	uint8_t status;
} __attribute__((packed));

struct SOCKS6DatagramHeader
{
	struct SOCKS6Version version;
	uint32_t             assocID;
	uint16_t             port;
	uint8_t              address[0];
} __attribute__((packed));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6_H
