#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <boost/shared_ptr.hpp>
#include "socks6msg_base.hh"
#include "socks6msg_option.hh"

namespace S6M
{

class OptionSet
{
	bool tfo;
	bool mptcp;
	
	struct Scheds
	{
		SOCKS6MPTCPScheduler clientProxy;
		SOCKS6MPTCPScheduler proxyServer;
		
		Scheds()
			: clientProxy((SOCKS6MPTCPScheduler) 0), proxyServer((SOCKS6MPTCPScheduler) 0) {}
		
	} mptcpSched;
	
	struct Idem
	{
		bool request;
		bool spend;
		uint32_t token;
		
		bool advertise;
		uint32_t base;
		uint32_t windowSize;
		
		bool reply;
		SOCKS6TokenExpenditureCode replyCode;
		
		Idem()
			: request(false), spend(false), advertise(false), reply(false) {}
	} idempotence;
	
	std::set<SOCKS6Method> knownMethods;
	
	struct
	{
		std::string username;
		std::string passwd;
	} userPasswdAuth;
	
	std::list<boost::shared_ptr<Option> > opts;
	
public:
	OptionSet();
	
	~OptionSet();
	
	void parse(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
