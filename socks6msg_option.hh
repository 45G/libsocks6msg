#ifndef SOCKS6MSG_OPTION_HH
#define SOCKS6MSG_OPTION_HH

#include <set>
#include <vector>
#include <string>
#include "socks6msg_base.hh"

namespace S6M
{

class OptionSet;

class Option
{
	SOCKS6OptionKind kind;
	
public:
	SOCKS6OptionKind getKind() const
	{
		return kind;
	}
	
	virtual size_t packedSize() const = 0;
	
	virtual void pack(uint8_t *buf) const;
	
	void pack(ByteBuffer *bb) const
	{
		uint8_t *buf = bb->get<uint8_t>(packedSize());
		
		pack(buf);
	}
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const = 0;
	
	Option(SOCKS6OptionKind kind)
		: kind(kind) {}
	
	virtual ~Option();
};

class RawOption: public Option
{
	std::vector<uint8_t> data;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	RawOption(SOCKS6OptionKind kind, const uint8_t *data, size_t dataLen);
};

class SocketOption: public Option
{
	SOCKS6SocketOptionLeg leg;
	SOCKS6SocketOptionLevel level;
	SOCKS6SocketOptionCode code;
	
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
	
	virtual void pack(uint8_t *buf) const;
	
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
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	MPScehdOption(SOCKS6SocketOptionLeg leg, SOCKS6MPTCPScheduler sched);
};

class AuthMethodOption: public Option
{
	std::set<SOCKS6Method> methods;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	AuthMethodOption(std::set<SOCKS6Method> methods);
};

class AuthDataOption: public Option
{
	SOCKS6Method method;
	
public:
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	AuthDataOption(SOCKS6Method method)
		: Option(SOCKS6_OPTION_AUTH_DATA), method(method) {}
};

class RawAuthDataOption: public AuthDataOption
{
	std::vector<uint8_t> data;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	RawAuthDataOption(SOCKS6Method method, uint8_t *data, size_t dataLen);
};

//TODO: sanity checks in constructor
class UsernamePasswdOption: public AuthDataOption
{
	std::string username;
	std::string passwd;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	UsernamePasswdOption(std::string username, std::string passwd);
};

class IdempotenceOption: public Option
{
	SOCKS6IDempotenceType type;
	
public:
	virtual void pack(uint8_t *buf) const;
	
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
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize);
};

class TokenExpenditureRequestOption: public IdempotenceOption
{
	uint32_t token;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenExpenditureRequestOption(uint32_t token)
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND), token(token) {}
};

class TokenExpenditureReplyOption: public IdempotenceOption
{
	SOCKS6TokenExpenditureCode code;
	
public:
	virtual size_t packedSize() const;
	
	virtual void pack(uint8_t *buf) const;
	
	static Option *parse(void *buf);
	
	virtual void apply(OptionSet *optSet) const;
	
	TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code);
};

}

#endif // SOCKS6MSG_OPTION_HH
