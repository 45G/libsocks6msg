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

	static void incrementalParse(SOCKS6Option *baseOpt, OptionSet *optionSet);

	StackOption(SOCKS6StackLeg leg, SOCKS6StackLevel level, SOCKS6StackOptionCode code)
		: Option(SOCKS6_OPTION_STACK), leg(leg), level(level), code(code) {}
};

template <SOCKS6StackLevel LVL, SOCKS6StackOptionCode CODE, typename V, typename RAW, SOCKS6StackLeg LEG_RESTRICT = SOCKS6_STACK_LEG_BOTH>
class StackOptionBase: public StackOption
{
	V value;

protected:
	struct RawOption
	{
		SOCKS6StackOption stackOptionHead;
		RAW value;
	} __attribute__((packed));

	virtual void fill(uint8_t *buf) const
	{
		StackOption::fill(buf);
		RawOption *opt = reinterpret_cast<RawOption *>(buf);
		opt->value = hton((RAW)value);
	}

public:
	typedef V Value;
	
	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6StackOption) + sizeof(V);
	}

	StackOptionBase(SOCKS6StackLeg leg, V value)
		: StackOption(leg, LVL, CODE), value(value)
	{
		if (LEG_RESTRICT != SOCKS6_STACK_LEG_BOTH && leg != LEG_RESTRICT)
			throw std::invalid_argument("Bad leg");
	}

	V getValue() const
	{
		return value;
	}
};

class TOSOption: public StackOptionBase<SOCKS6_STACK_LEVEL_IP, SOCKS6_STACK_CODE_TOS, uint8_t, uint8_t>
{
public:
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class TFOOption: public StackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_TFO, uint16_t, uint16_t, SOCKS6_STACK_LEG_PROXY_REMOTE>
{
public:
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class MPTCPOption: public StackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MP, bool, uint8_t>
{
public:
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class BacklogOption: public StackOptionBase<SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_BACKLOG, uint16_t, uint16_t, SOCKS6_STACK_LEG_PROXY_REMOTE>
{
public:
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet);

	BacklogOption(SOCKS6StackLeg leg, uint16_t backlog);
};

}

#endif // SOCKS6MSG_STACKOPTION_HH
