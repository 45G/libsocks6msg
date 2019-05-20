#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include "optionset.hh"


using namespace std;
using namespace boost;

namespace S6M
{

template <typename T>
void ensureVacant(const std::unique_ptr<T> &ptr)
{
	if (ptr.get() != nullptr)
		throw std::logic_error("Option already in place");
}

template <typename T>
void ensureVacant(const std::shared_ptr<T> &ptr)
{
	if (ptr.get() != nullptr)
		throw std::logic_error("Option already in place");
}

#define COMMIT(FIELD, WHAT) \
	ensureVacant(FIELD); \
	(FIELD).reset(WHAT); \
	owner->registerOption((FIELD).get());

#define COMMIT2(FIELD1, FIELD2, WHAT) \
	ensureVacant(FIELD1); \
	ensureVacant(FIELD2); \
	(FIELD1).reset(WHAT); \
	(FIELD2) = (FIELD1); \
	owner->registerOption((FIELD1).get());

void OptionSetBase::enforceMode(OptionSet::Mode mode1) const
{
	if (mode != mode1)
		throw logic_error("Option not available");
}

void OptionSetBase::enforceMode(OptionSet::Mode mode1, OptionSet::Mode mode2) const
{
	if (mode != mode1 && mode != mode2)
		throw logic_error("Option not available");
}

OptionSet::OptionSet(ByteBuffer *bb, Mode mode)
	: OptionSetBase(this, mode)
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	uint16_t optsLen = ntohs(optsHead->optionsLength);
	if (optsLen > SOCKS6_OPTIONS_LENGTH_MAX)
		throw invalid_argument("Bad options length");
	ByteBuffer optsBB(bb->get<uint8_t>(optsLen), optsLen);
	
	while (optsBB.getUsed() < optsBB.getTotalSize())
	{
		SOCKS6Option *opt;
		size_t optLen;

		try
		{
			opt = bb->get<SOCKS6Option>();

			/* bad option length wrecks remaining options */
			optLen = ntohs(opt->len);
			if (optLen < sizeof(SOCKS6Option))
				throw length_error("Option too short");
			if (optLen % 4 != 0)
				throw length_error("Option not aligned");

			bb->get<uint8_t>(optLen - sizeof(SOCKS6Option));
		}
		catch (length_error &)
		{
			break;
		}
		
		try
		{
			Option::incrementalParse(opt, optLen, this);
		}
		catch (invalid_argument &) {}
	}
}

static void cram(const Option &option, SOCKS6Options *optionsHead, ByteBuffer *bb)
{
	option.pack(bb);
	optionsHead->optionsLength += option.packedSize();
}

void OptionSet::pack(ByteBuffer *bb) const
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	optsHead->optionsLength = 0;
	
	BOOST_FOREACH(Option *option, options)
	{
		cram(*option, optsHead, bb);
	}
}

size_t OptionSet::packedSize() const
{
	size_t size = sizeof(SOCKS6Options);
	
	size += optionsSize;
	
	return size;
}

SessionOptionSet::SessionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void SessionOptionSet::request()
{
	enforceMode(M_REQ);
	COMMIT(mandatoryOpt, new SessionRequestOption());
}

void SessionOptionSet::tearDown()
{
	enforceMode(M_REQ);
	if (mandatoryOpt == nullptr)
		throw logic_error("Request must be part of session");
	COMMIT(teardownOpt, new SessionTeardownOption());
}

void SessionOptionSet::setID(const std::vector<uint8_t> &ticket)
{
	enforceMode(M_REQ, M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionIDOption(ticket));
}

void SessionOptionSet::signalOK()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionOKOption());
}

void SessionOptionSet::signalReject()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionInvalidOption());
}

void SessionOptionSet::setUntrusted()
{
	enforceMode(M_REQ);
	if (reinterpret_cast<SessionIDOption *>(mandatoryOpt.get()) == nullptr)
		throw logic_error("Must advertise a session ID");
	COMMIT(untrustedOpt, new SessionUntrustedOption());
}

IdempotenceOptionSet::IdempotenceOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void IdempotenceOptionSet::request(uint32_t size)
{
	enforceMode(M_REQ);
	COMMIT(requestOpt, new TokenWindowRequestOption(size));
}

void IdempotenceOptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	COMMIT(expenditureOpt, new TokenExpenditureRequestOption(token));
}

void IdempotenceOptionSet::advertise(uint32_t base, uint32_t size)
{
	enforceMode(M_AUTH_REP);
	COMMIT(windowOpt, new TokenWindowAdvertOption(base, size));
}

void IdempotenceOptionSet::setReply(SOCKS6TokenExpenditureCode code)
{
	enforceMode(M_AUTH_REP);
	COMMIT(replyOpt, new TokenExpenditureReplyOption(code));
}

template<typename T>
StackOptionPair<T>::StackOptionPair(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

template<typename T>
void StackOptionPair<T>::set(SOCKS6StackLeg leg, typename T::Value value)
{
	enforceMode(M_REQ, M_AUTH_REP);
	switch(leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		COMMIT(clientProxy, new T(leg, value));
		return;
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		COMMIT(proxyRemote, new T(leg, value));
		return;
	case SOCKS6_STACK_LEG_BOTH:
		COMMIT2(clientProxy, proxyRemote, new T(leg, value));
		return;
	}
}

template<typename T>
boost::optional<typename T::Value> StackOptionPair<T>::get(SOCKS6StackLeg leg) const
{
	enforceMode(M_REQ, M_AUTH_REP);
	switch(leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		if (clientProxy.get() == nullptr)
			return {};
		return clientProxy->getValue();
		
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		if (proxyRemote.get() == nullptr)
			return {};
		return clientProxy->getValue();
		
	case SOCKS6_STACK_LEG_BOTH:
		throw logic_error("Bad leg");
	}
	return {};
}

StackOptionSet::StackOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

template class StackOptionPair<TOSOption>;
template class StackOptionPair<TFOOption>;
template class StackOptionPair<MPOption>;
template class StackOptionPair<BacklogOption>;

UserPasswdOptionSet::UserPasswdOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void UserPasswdOptionSet::setCredentials(const string &user, const string &passwd)
{
	enforceMode(M_REQ);
	COMMIT(req, new UsernamePasswdReqOption(user, passwd));
}

void UserPasswdOptionSet::setReply(bool success)
{
	enforceMode(M_AUTH_REP);
	COMMIT(reply, new UsernamePasswdReplyOption(success));
}

void AuthMethodOptionSet::advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
{
	enforceMode(M_REQ);
	COMMIT(advertOption, new AuthMethodAdvertOption(initialDataLen, methods));
}

void AuthMethodOptionSet::select(SOCKS6Method method)
{
	enforceMode(M_AUTH_REP);
	COMMIT(selectOption, new AuthMethodSelectOption(method));
}

}
