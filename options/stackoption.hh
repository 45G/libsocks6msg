#ifndef SOCKS6MSG_STACKOPTION_HH
#define SOCKS6MSG_STACKOPTION_HH

#include "option.hh"

namespace S6M
{

class StackOption: public Option
{
	SOCKS6StackLeg leg;
	SOCKS6StackLevel level;
	SOCKS6StackOptionCode code;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SOCKS6StackLeg getLeg() const
	{
		return leg;
	}
	
	SOCKS6StackLevel getLevel() const
	{
		return level;
	}
	
	SOCKS6StackOptionCode getCode() const
	{
		return code;
	}
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	StackOption(SOCKS6StackLeg leg, SOCKS6StackLevel level, SOCKS6StackOptionCode code)
		: Option(SOCKS6_OPTION_STACK), leg(leg), level(level), code(code) {}
};

class TOSOption: public StackOption
{
	uint8_t tos;

protected:
	virtual void fill(uint8_t *buf) const;

public:
	virtual size_t packedSize() const;

	static void incementalParse(void *buf, OptionSet *optionSet);

	TOSOption(SOCKS6StackLeg leg, uint8_t tos)
		: StackOption(leg, SOCKS6_STACK_LEVEL_IP, SOCKS6_STACK_CODE_TOS), tos(tos) {}
};

class TFOOption: public StackOption
{
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	TFOOption()
		: StackOption(SOCKS6_STACK_LEG_PROXY_REMOTE, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_TFO) {}
};

class MPTCPOption: public StackOption
{
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	MPTCPOption()
		: StackOption(SOCKS6_STACK_LEG_PROXY_REMOTE, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MPTCP) {}
};

class MPSchedOption: public StackOption
{
	SOCKS6MPTCPScheduler sched;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	MPSchedOption(SOCKS6StackLeg leg, SOCKS6MPTCPScheduler sched)
		: StackOption(leg, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MP_SCHED), sched(sched) {}
};

class BacklogOption: public StackOption
{
	uint16_t backlog;

protected:
	virtual void fill(uint8_t *buf) const;

public:
	virtual size_t packedSize() const;

	static void incementalParse(void *buf, OptionSet *optionSet);

	BacklogOption(uint16_t backlog)
		: StackOption(SOCKS6_STACK_LEG_PROXY_REMOTE, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_BACKLOG), backlog(backlog) {}
};

}

#endif // SOCKS6MSG_STACKOPTION_HH
