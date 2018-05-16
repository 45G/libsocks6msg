#ifndef SOCKS6MSG_OPTION_HH
#define SOCKS6MSG_OPTION_HH

#include <set>
#include <vector>
#include <string>
#include "socks6msg_config.hh"
#include "socks6.h"
#include "socks6msg_bytebuffer.hh"
#include "socks6msg_usrpasswd.hh"

namespace S6M
{

class OptionSet;

class Option
{
	SOCKS6OptionKind kind;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	SOCKS6OptionKind getKind() const
	{
		return kind;
	}
	
	virtual size_t packedSize() const = 0;
	
	void pack(ByteBuffer *bb) const
	{
		uint8_t *buf = bb->get<uint8_t>(packedSize());
		
		forcedPack(buf);
	}
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const = 0;
	
	Option(SOCKS6OptionKind kind)
		: kind(kind) {}
	
	virtual ~Option();
};

#if SOCKS6MSG_CONFIG_RAW_OPTION
class RawOption: public Option
{
	std::vector<uint8_t> data;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	RawOption(SOCKS6OptionKind kind, const uint8_t *data, size_t dataLen);
};
#endif /* SOCKS6MSG_CONFIG_RAW_OPTION */

class SocketOption: public Option
{
	SOCKS6SocketOptionLeg leg;
	SOCKS6SocketOptionLevel level;
	SOCKS6SocketOptionCode code;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	SOCKS6SocketOptionLeg getLeg() const
	{
		return leg;
	}
	
	SOCKS6SocketOptionLevel getLevel() const
	{
		return level;
	}
	
	SOCKS6SocketOptionCode getCode() const
	{
		return code;
	}
	
	static Option *parse(void *buf);
	
	SocketOption(SOCKS6SocketOptionLeg leg, SOCKS6SocketOptionLevel level, SOCKS6SocketOptionCode code)
		: Option(SOCKS6_OPTION_SOCKET), leg(leg), level(level), code(code) {}
};

class TFOOption: public SocketOption
{
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TFOOption()
		: SocketOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_TFO) {}
};

class MPTCPOption: public SocketOption
{
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	MPTCPOption()
		: SocketOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_MPTCP) {}
};

class MPScehdOption: public SocketOption
{
	SOCKS6MPTCPScheduler sched;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	MPScehdOption(SOCKS6SocketOptionLeg leg, SOCKS6MPTCPScheduler sched);
};

class AuthMethodOption: public Option
{
	std::set<SOCKS6Method> methods;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	AuthMethodOption(std::set<SOCKS6Method> methods);
};

class AuthDataOption: public Option
{
	SOCKS6Method method;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	SOCKS6Method getMethod() const
	{
		return method;
	}
	
	static Option *parse(void *buf);
	
	AuthDataOption(SOCKS6Method method)
		: Option(SOCKS6_OPTION_AUTH_DATA), method(method) {}
};

#if SOCKS6MSG_CONFIG_RAW_AUTH_DATA
class RawAuthDataOption: public AuthDataOption
{
	std::vector<uint8_t> data;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	RawAuthDataOption(SOCKS6Method method, uint8_t *data, size_t dataLen);
};
#endif /* SOCKS6MSG_CONFIG_RAW_METHOD_DATA */

class UsernamePasswdOption: public AuthDataOption
{
	UserPasswordRequest req;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	UsernamePasswdOption(std::string username, std::string passwd);
};

class IdempotenceOption: public Option
{
	SOCKS6IDempotenceType type;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	static Option *parse(void *buf);
	
	IdempotenceOption(SOCKS6IDempotenceType type)
		: Option(SOCKS6_OPTION_IDEMPOTENCE), type(type) {}
};

class TokenWindowRequestOption: public IdempotenceOption
{
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenWindowRequestOption()
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_REQ) {}
};

class TokenWindowAdvertOption: public IdempotenceOption
{
	uint32_t winBase;
	uint32_t winSize;
	
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize);
};

class TokenExpenditureRequestOption: public IdempotenceOption
{
	uint32_t token;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenExpenditureRequestOption(uint32_t token)
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND), token(token) {}
};

class TokenExpenditureReplyOption: public IdempotenceOption
{
	SOCKS6TokenExpenditureCode code;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code);
};

}

#endif // SOCKS6MSG_OPTION_HH
