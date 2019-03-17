#ifndef SOCKS6MSG_STACKOPTION_HH
#define SOCKS6MSG_STACKOPTION_HH

#include "option.hh"
#include "byteorder.hh"

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
	
	static void incrementalParse(void *buf, OptionSet *optionSet);
	
	StackOption(SOCKS6StackLeg leg, SOCKS6StackLevel level, SOCKS6StackOptionCode code)
		: Option(SOCKS6_OPTION_STACK), leg(leg), level(level), code(code) {}
};

template <SOCKS6StackLevel LVL, SOCKS6StackOptionCode CODE> class SimpleStackOptionBase: public StackOption
{
public:
	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6StackOption);
	}

	SimpleStackOptionBase(SOCKS6StackLeg leg)
		: StackOption(leg, LVL, CODE) {}
};

template <SOCKS6StackLevel LVL, SOCKS6StackOptionCode CODE, typename V> class IntStackOptionBase: public StackOption
{
	V value;
	
protected:
	struct RawOption
	{
		SOCKS6StackOption stackOptionHead;
		V value;
	} __attribute__((packed));
	
	virtual void fill(uint8_t *buf) const
	{
		StackOption::fill(buf);
		RawOption *opt = reinterpret_cast<RawOption *>(buf);
		opt->value = hton(value);
	}
	
	V getValue() const 
	{
		return value;
	}
	
public:
	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6StackOption) + sizeof(V);
	}

	IntStackOptionBase(SOCKS6StackLeg leg, V value)
		: StackOption(leg, LVL, CODE), value(value) {}
};

class TOSOption: public IntStackOptionBase<SOCKS6_STACK_LEVEL_IP, SOCKS6_STACK_CODE_TOS, uint8_t>
{
public:
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet);

	TOSOption(SOCKS6StackLeg leg, uint8_t tos)
		: IntStackOptionBase(leg, tos) {}

	uint8_t getTOS() const
	{
		return getValue();
	}
};

class TFOOption: public IntStackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_TFO, uint16_t>
{
public:
	static void incrementalParse(void *buf, OptionSet *optionSet);
	
	TFOOption(uint16_t payloadSize)
		: IntStackOptionBase(SOCKS6_STACK_LEG_PROXY_REMOTE, payloadSize) {}

	uint16_t getPayloadSize() const
	{
		return getValue();
	}
};

class MPTCPOption: public SimpleStackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MPTCP>
{
public:
	static void incrementalParse(void *buf, OptionSet *optionSet);
	
	MPTCPOption()
		: SimpleStackOptionBase(SOCKS6_STACK_LEG_PROXY_REMOTE) {}
};

class MPSchedOption: public IntStackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MP_SCHED, uint8_t>
{
	SOCKS6MPTCPScheduler sched;
	
public:
	static void incrementalParse(void *buf, OptionSet *optionSet);
	
	MPSchedOption(SOCKS6StackLeg leg, SOCKS6MPTCPScheduler sched)
		: IntStackOptionBase(leg, sched) {}

	SOCKS6MPTCPScheduler getScheduler() const
	{
		return (SOCKS6MPTCPScheduler)getValue();
	}
};

class BacklogOption: public IntStackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_BACKLOG, uint16_t>
{
public:
	static void incrementalParse(void *buf, OptionSet *optionSet);

	BacklogOption(uint16_t backlog);

	uint16_t getBacklog() const
	{
		return getValue();
	}
};

}

#endif // SOCKS6MSG_STACKOPTION_HH
