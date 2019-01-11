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
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
	
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

	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);

	TOSOption(SOCKS6StackLeg leg, uint8_t tos)
		: StackOption(leg, SOCKS6_STACK_LEVEL_IP, SOCKS6_STACK_CODE_TOS), tos(tos) {}

	uint8_t getTOS() const
	{
		return tos;
	}
};

class TFOOption: public StackOption
{
	uint16_t payloadSize;

public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
	
	TFOOption(uint16_t payloadSize)
		: StackOption(SOCKS6_STACK_LEG_PROXY_REMOTE, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_TFO), payloadSize(payloadSize) {}

	uint16_t getPayloadSize() const
	{
		return payloadSize;
	}
};

class MPTCPOption: public StackOption
{
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
	
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
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
	
	MPSchedOption(SOCKS6StackLeg leg, SOCKS6MPTCPScheduler sched)
		: StackOption(leg, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MP_SCHED), sched(sched) {}

	SOCKS6MPTCPScheduler getScheduler() const
	{
		return sched;
	}
};

class BacklogOption: public StackOption
{
	uint16_t backlog;

protected:
	virtual void fill(uint8_t *buf) const;

public:
	virtual size_t packedSize() const;

	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);

	BacklogOption(uint16_t backlog);

	uint16_t getBacklog() const
	{
		return backlog;
	}
};

}

#endif // SOCKS6MSG_STACKOPTION_HH
