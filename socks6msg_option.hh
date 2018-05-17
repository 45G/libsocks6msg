#ifndef SOCKS6MSG_OPTION_HH
#define SOCKS6MSG_OPTION_HH

#include <set>
#include <vector>
#include <string>
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
	
	static void parse(void *buf, OptionSet *optionSet);
	
	Option(SOCKS6OptionKind kind)
		: kind(kind) {}
	
	virtual ~Option();
};

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
	
	static void parse(void *buf, OptionSet *optionSet);
	
	SocketOption(SOCKS6SocketOptionLeg leg, SOCKS6SocketOptionLevel level, SOCKS6SocketOptionCode code)
		: Option(SOCKS6_OPTION_SOCKET), leg(leg), level(level), code(code) {}
};

class TFOOption: public SocketOption
{
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
	TFOOption()
		: SocketOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_TFO) {}
};

class MPTCPOption: public SocketOption
{
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
	MPTCPOption()
		: SocketOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_MPTCP) {}
};

class MPSchedOption: public SocketOption
{
	SOCKS6MPTCPScheduler sched;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
	MPSchedOption(SOCKS6SocketOptionLeg leg, SOCKS6MPTCPScheduler sched)
		: SocketOption(leg, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_MP_SCHED), sched(sched) {}
};

class AuthMethodOption: public Option
{
	std::set<SOCKS6Method> methods;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
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
	
	static void parse(void *buf, OptionSet *optionSet);
	
	AuthDataOption(SOCKS6Method method)
		: Option(SOCKS6_OPTION_AUTH_DATA), method(method) {}
};

class UsernamePasswdOption: public AuthDataOption
{
	UserPasswordRequest req;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
	UsernamePasswdOption(boost::shared_ptr<std::string> username, boost::shared_ptr<std::string> passwd);
};

class IdempotenceOption: public Option
{
	SOCKS6IDempotenceType type;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	static void parse(void *buf, OptionSet *optionSet);
	
	IdempotenceOption(SOCKS6IDempotenceType type)
		: Option(SOCKS6_OPTION_IDEMPOTENCE), type(type) {}
};

class TokenWindowRequestOption: public IdempotenceOption
{
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
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
	
	static void parse(void *buf, OptionSet *optionSet);
	
	TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize);
};

class TokenExpenditureRequestOption: public IdempotenceOption
{
	uint32_t token;
	
protected:
	virtual void forcedPack(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void parse(void *buf, OptionSet *optionSet);
	
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
	
	static void parse(void *buf, OptionSet *optionSet);
	
	TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code)
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY), code(code) {}
};

}

#endif // SOCKS6MSG_OPTION_HH
