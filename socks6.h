#ifndef SOCKS6_H
#define SOCKS6_H

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stdint.h>
#include <endian.h>

/**
 * @brief SOCKS6_VERSION
 * This value will be 6 when standardized.
 * It gets modified when the wire format changes, to avoid having different versions of this library speak to each other.
 * 100 + draft revision: accurately represents draft revision (subject to API changes; not subject to protocol changes)
 * 200 + draft revision: builds upon draft revision (subject to API and protocol changes)
 * 255: no particular draft revision
 * currently: post-draft-06 (206)
 */
#define SOCKS6_VERSION (206)

#define SOCKS6_PWAUTH_VERSION (1)

#define SOCKS6_ALIGNMENT (4)

struct SOCKS6Version
{
	uint8_t version;
} __attribute__((packed));

struct SOCKS6Request
{
	uint8_t  version;
	uint8_t  commandCode;
	uint16_t optionsLength;
	uint16_t port;
	uint8_t  padding;
	uint8_t  addressType;
	uint8_t  address[0];
} __attribute__((packed));

struct SOCKS6IPv4Address
{
	uint32_t ipv4Address;
} __attribute__((packed));

struct SOCKS6IPv6Address
{
	uint8_t ipv6Address[16];
} __attribute__((packed));

struct SOCKS6DomainAddress
{
	uint8_t len;
	uint8_t domain[0];
} __attribute__((packed));

enum SOCKS6RequestCode
{
	SOCKS6_REQUEST_NOOP      = 0,
	SOCKS6_REQUEST_CONNECT   = 1,
	SOCKS6_REQUEST_BIND      = 2,
	SOCKS6_REQUEST_UDP_ASSOC = 3,
};

enum SOCKS6AddressType
{
	SOCKS6_ADDR_IPV4   = 1,
	SOCKS6_ADDR_DOMAIN = 3,
	SOCKS6_ADDR_IPV6   = 4,
};

#define SOCKS6_OPTIONS_LENGTH_MAX (1 << 14)

struct SOCKS6AuthReply
{
	uint8_t  version;
	uint8_t  type;
	uint16_t optionsLength;
} __attribute__((packed));

enum SOCKS6AuthReplyCode
{
	SOCKS6_AUTH_REPLY_SUCCESS = 0,
	SOCKS6_AUTH_REPLY_FAILURE = 1,
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
	uint8_t  version;
	uint8_t  code;
	uint16_t optionsLength;
	uint16_t bindPort;
	uint8_t  padding;
	uint8_t  addressType;
	uint8_t  bindAddress[0];
} __attribute__((packed));

enum SOCKS6OperationReplyCode
{
	SOCKS6_OPERATION_REPLY_SUCCESS            = 0,
	SOCKS6_OPERATION_REPLY_FAILURE            = 1, /* general SOCKS server failure */
	SOCKS6_OPERATION_REPLY_NOT_ALLOWED        = 2, /* connection not allowed by ruleset */
	SOCKS6_OPERATION_REPLY_NET_UNREACH        = 3, /* network unreachable */
	SOCKS6_OPERATION_REPLY_HOST_UNREACH       = 4, /* host unreachable */
	SOCKS6_OPERATION_REPLY_REFUSED            = 5, /* connection refused */
	SOCKS6_OPERATION_REPLY_TTL_EXPIRED        = 6, /* TTL expired */
	SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED  = 7, /* command not supported */
	SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED = 8, /* address type not supported */
	SOCKS6_OPERATION_REPLY_TIMEOUT            = 9, /* connection attempt timed out */
};

struct SOCKS6Option
{
	uint16_t kind;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

enum SOCKS6OptionKind
{
	SOCKS6_OPTION_STACK              = 1,

	SOCKS6_OPTION_AUTH_METHOD_ADVERT = 2,
	SOCKS6_OPTION_AUTH_METHOD_SELECT = 3,

	SOCKS6_OPTION_AUTH_DATA          = 4,

	SOCKS6_OPTION_SESSION_REQUEST    = 5,
	SOCKS6_OPTION_SESSION_ID         = 6,
	SOCKS6_OPTION_SESSION_UNTRUSTED  = 7,
	SOCKS6_OPTION_SESSION_OK         = 8,
	SOCKS6_OPTION_SESSION_INVALID    = 9,
	SOCKS6_OPTION_SESSION_TEARDOWN   = 10,

	SOCKS6_OPTION_IDEMPOTENCE_REQ    = 11,
	SOCKS6_OPTION_IDEMPOTENCE_WND    = 12,
	SOCKS6_OPTION_IDEMPOTENCE_EXPEND = 13,
	SOCKS6_OPTION_IDEMPOTENCE_ACCEPT = 14,
	SOCKS6_OPTION_IDEMPOTENCE_REJECT = 15,

	SOCKS6_OPTION_RESOLVE_REQ        = 16,
	SOCKS6_OPTION_RESOLVE_IPv4       = 17,
	SOCKS6_OPTION_RESOLVE_IPv6       = 18,
	SOCKS6_OPTION_RESOLVE_DOMAIN     = 19,

	SOCKS6_OPTION_VENDOR_MIN         = 64512,
	SOCKS6_OPTION_VENDOR_MAX         = 65535,
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
	SOCKS6_STACK_LEG_CLIENT_PROXY = 1,
	SOCKS6_STACK_LEG_PROXY_REMOTE = 2,
	SOCKS6_STACK_LEG_BOTH         = 3,
};

enum SOCKS6StackLevel
{
	SOCKS6_STACK_LEVEL_IP   = 1,
	SOCKS6_STACK_LEVEL_IPV4 = 2,
	SOCKS6_STACK_LEVEL_IPV6 = 3,
	SOCKS6_STACK_LEVEL_TCP  = 4,
	SOCKS6_STACK_LEVEL_UDP  = 5,
};

enum SOCKS6StackOptionCode
{
	/* IP */
	SOCKS6_STACK_CODE_TOS      = 1,

	/* IPv4 */

	/* IPv6 */

	/* TCP */
	SOCKS6_STACK_CODE_TFO      = 1,
	SOCKS6_STACK_CODE_MP       = 2,
	SOCKS6_STACK_CODE_BACKLOG  = 3,

	/* UDP */

	/* TLS */
};

struct SOCKS6TOSOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint8_t                  tos;
	uint8_t                  padding[1];
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
	uint8_t                  padding[1];
} __attribute__((packed));

enum SOCKS6MPAvailability
{
	SOCKS6_MP_AVAILABLE   = 1,
	SOCKS6_MP_UNAVAILABLE = 2,
};

struct SOCKS6BacklogOption
{
	struct SOCKS6StackOption stackOptionHead;
	uint16_t                 backlog;
} __attribute__((packed));

struct SOCKS6AuthMethodAdvertOption
{
	struct SOCKS6Option optionHead;
	uint16_t            initialDataLen;
	uint8_t             methods[0];
} __attribute__((packed));

#define SOCKS6_INITIAL_DATA_MAX (1 << 14)

struct SOCKS6AuthMethodSelectOption
{
	struct SOCKS6Option optionHead;
	uint8_t             method;
	uint8_t             padding[3];
} __attribute__((packed));

struct SOCKS6AuthDataOption
{
	struct SOCKS6Option optionHead;
	uint8_t             method;
	uint8_t             methodData[0];
} __attribute__((packed));

struct SOCKS6SessionIDOption
{
	struct SOCKS6Option optionHead;
	uint8_t             ticket[0];
};

#define SOCKS6_ID_LENGTH_MAX (SOCKS6_OPTIONS_LENGTH_MAX - sizeof(struct SOCKS6SessionIDOption))

struct SOCKS6WindowRequestOption
{
	struct SOCKS6Option optionHead;
	uint32_t            windowSize;
} __attribute__((packed));

struct SOCKS6WindowAdvertOption
{
	struct SOCKS6Option optionHead;
	uint32_t            windowBase;
	uint32_t            windowSize;
} __attribute__((packed));

#define SOCKS6_TOKEN_WINDOW_MIN (1)
#define SOCKS6_TOKEN_WINDOW_MAX ((1UL << 31) - 1)

struct SOCKS6TokenExpenditureOption
{
	struct SOCKS6Option optionHead;
	uint32_t            token;
} __attribute__((packed));

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
	uint8_t  version;
	uint8_t  addressType;
	uint16_t port;
	uint64_t assocID;
	uint8_t  address[0];
} __attribute__((packed));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6_H
