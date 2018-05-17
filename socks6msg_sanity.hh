#ifndef SOCKS6MSG_SANITY_HH
#define SOCKS6MSG_SANITY_HH

#pragma GCC diagnostic error "-Wswitch

#include "socks6.h"
#include "socks6msg_exception.hh"

namespace S6M
{

template <typename ENUM>
ENUM enumSanity(int val)
{
	/* fail if instantiated */
	switch ((ENUM)val) {}
}

SOCKS6MPTCPScheduler enumSanity<SOCKS6MPTCPScheduler>(int val)
{
	SOCKS6MPTCPScheduler sched = SOCKS6MPTCPScheduler(val);
	
	switch (sched)
	{
	case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
	case SOCKS6_MPTCP_SCHEDULER_RR:
	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		return sched;
	}
	
	throw InvalidFieldException();
}

}

#endif // SOCKS6MSG_SANITY_HH
