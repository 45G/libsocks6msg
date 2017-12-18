#ifndef SOCKS6_HH
#define SOCKS6_HH

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stdint.h>

#define SOCKS6_VERSION_MAJOR 6
/**
 * @brief VERSION_MINOR
 * < 100 standardized
 * 100 + draft revision: accurately represents draft revision
 * 255: no particular draft revision
 */
#define SOCKS6_VERSION_MINOR 255

struct SOCKS6Version
{
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

struct SOCKS6Request
{
	uint8_t address[16];
	uint16_t port;
	uint16_t initialDataLen;
	uint8_t commandCode;
	uint8_t optionCount;
	uint8_t options[0];
} __attribute__((packed));

enum SOCKS6RequestCode
{
	SOCKS6_REQUEST_NOOP       = 0x00,
	SOCKS6_REQUEST_CONNECT    = 0x01,
	SOCKS6_REQUEST_BIND       = 0x02,
	SOCKS6_REQUEST_UDP_ASSOC  = 0x03,
//	SOCKS6_REQUEST_TCP_ASSOC  = 0x04,
//	SOCKS6_REQUEST_DTLS_ASSOC = 0x05,
//	SOCKS6_REQUEST_TLS_ASSOC  = 0x06,
};

struct SOCKS6AuthReply
{
	uint8_t type;
	uint8_t method;
	uint8_t optionCount;
	uint8_t options[0];
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
	uint8_t bindAddress[16];
	uint16_t bindPort;
	uint16_t initialDataOffset;
	uint8_t code;
	uint8_t optionCount;
	uint8_t options[0];
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
	SOCKS6_OPTION_AUTH_METHOD = 0x01,
	SOCKS6_OPTION_AUTH_DATA   = 0x02,
	SOCKS6_OPTION_IDEMPOTENCE = 0x03,
	SOCKS6_OPTION_DOMAIN_RES  = 0x04,
	SOCKS6_OPTION_FEATURE     = 0x05,
};

struct SOCKS6AuthMethodOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t methods[0];
} __attribute__((packed));

struct SOCKS6AuthDataOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t method;
	uint8_t methodData[0];
} __attribute__((packed));

struct SOCKS6IdempotenceOption
{
	uint8_t kind;
	uint8_t len;
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
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint32_t windowSize;
} __attribute__((packed));

struct SOCKS6WindowAdvertOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint32_t windowBase;
	uint32_t windowSize;
} __attribute__((packed));

struct SOCKS6TokenExpenditureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint32_t token;
} __attribute__((packed));

struct SOCKS6TokenExpenditureReplyOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t code;
} __attribute__((packed));

struct SOCKS6DomainResolutionOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t preferedIPVer;
	uint8_t domain[0];
} __attribute__((packed));

struct SOCKS6FeatureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t data[0];
} __attribute__((packed));

enum SOCKS6FeatureType
{
	SOCKS6_FEATURE_NODELAY = 0x00,
	SOCKS6_FEATURE_IPTOS   = 0x01,
	SOCKS6_FEATURE_TCPOPT  = 0x02,
	SOCKS6_FEATURE_MPSCHED = 0x03,
};

struct SOCKS6NoDelayFeatureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t nodelayFlags;
} __attribute__((packed));

enum SOCKS6NoDelayFlags
{
	SOCKS6_NODELAY_CLIENT_PROXY = 0x01,
	SOCKS6_NODELAY_PROXY_SERVER = 0x02,
	SOCKS6_NODELAY_BOTH         = 0x03,
};

struct SOCKS6IPTOSFeatureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t clientProxyTOS;
	uint8_t proxyServerTOS;
} __attribute__((packed));

struct SOCKS6TCPOptionFeatureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t options[0];
} __attribute__((packed));

struct SOCKS6MPSchedFeatureOption
{
	uint8_t kind;
	uint8_t len;
	uint8_t type;
	uint8_t clientProxySched;
	uint8_t proxyServerSched;
} __attribute__((packed));

enum SOCKS6MPSched
{
	SOCKS6_MP_SCHED_INDIFFERENT    = 0x00,
	SOCKS6_MP_SCHED_MAX_THROUGHPUT = 0x01,
	SOCKS6_MP_SCHED_MIN_DELAY      = 0x02,
	SOCKS6_MP_SCHED_MIN_COST       = 0x03,
} __attribute__((packed));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6_WIRE_HH
