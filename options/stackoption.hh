#ifndef SOCKS6MSG_STACKOPTION_HH
#define SOCKS6MSG_STACKOPTION_HH

#include "option.hh"
#include "byteorder.hh"
#include "padded.hh"
#include "sanity.hh"
#include "restrictedint.hh"

namespace S6M
{

class StackOption: public Option
{
	Enum<SOCKS6StackLeg>  leg;
	SOCKS6StackLevel      level;
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

template <typename T, SOCKS6StackLevel LVL, SOCKS6StackOptionCode C, typename V, typename RAW, SOCKS6StackLeg LR = SOCKS6_STACK_LEG_BOTH>
class StackOptionBase: public StackOption
{
	V value;

protected:
	struct RawOption
	{
		SOCKS6StackOption stackOptionHead;
		RAW               value;
		uint8_t           padding[paddingOf(sizeof(SOCKS6StackOption) + sizeof(RAW))];
	} __attribute__((packed));

	virtual void fill(uint8_t *buf) const
	{
		StackOption::fill(buf);
		RawOption *opt = reinterpret_cast<RawOption *>(buf);
		opt->value = hton((RAW)value);
		memset(opt->padding, 0, sizeof(opt->padding));
	}

public:
	static constexpr SOCKS6StackLevel      LEVEL        = LVL;
	static constexpr SOCKS6StackOptionCode CODE         = C;
	static constexpr SOCKS6StackLeg        LEG_RESTRICT = LR;
	
	typedef V Value;
	
	virtual size_t packedSize() const
	{
		return sizeof(RawOption);
	}

	StackOptionBase(SOCKS6StackLeg leg, V value)
		: StackOption(leg, LVL, C), value(value)
	{
		if (LR != SOCKS6_STACK_LEG_BOTH && leg != LR)
			throw std::invalid_argument("Bad leg");
	}
	
	static void incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
	{
		RawOption *opt = rawOptCast<RawOption>(optBase, false);
		
		T::stackParse(opt, optionSet);
	}

	V getValue() const
	{
		return value;
	}
};

class TOSOption: public StackOptionBase<TOSOption, SOCKS6_STACK_LEVEL_IP, SOCKS6_STACK_CODE_TOS, uint8_t, uint8_t>
{
public:
	static void stackParse(RawOption *opt, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class TFOOption: public StackOptionBase<TFOOption, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_TFO, uint16_t, uint16_t, SOCKS6_STACK_LEG_PROXY_REMOTE>
{
public:
	static void stackParse(RawOption *opt, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class MPOption: public StackOptionBase<MPOption, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_MP, Enum<SOCKS6MPAvailability>, uint8_t, SOCKS6_STACK_LEG_PROXY_REMOTE>
{
public:
	static void stackParse(RawOption *opt, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

class BacklogOption: public StackOptionBase<BacklogOption, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_BACKLOG, uint16_t, uint16_t, SOCKS6_STACK_LEG_PROXY_REMOTE>
{
public:
	static void stackParse(RawOption *opt, OptionSet *optionSet);

	using StackOptionBase::StackOptionBase;
};

}

#endif // SOCKS6MSG_STACKOPTION_HH
