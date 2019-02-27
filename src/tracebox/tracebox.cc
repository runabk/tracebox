/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "config.h"
#include "tracebox.h"
#include "crafter/Utils/IPResolver.h"
#include "script.h"
#include "PacketModification.h"
#include "PartialHeader.h"


#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>

#ifdef HAVE_LIBJSON
#include <json/json.h>
#endif
#ifdef HAVE_JSONC
#include <json-c/json.h>
#endif

extern "C" {
#include <pcap.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/resource.h>
#include <fcntl.h>

};

#define PCAP_IPv4 "1.1.1.1"
#define PCAP_IPv6 "dead::beef"

#ifndef IN_LOOPBACK
#define	IN_LOOPBACK(a)		((ntohl((long int) (a)) & 0xff000000) == 0x7f000000)
#endif

#define IN6_LOOPBACK(a) \
        (((__const uint32_t *) (a))[0] == 0                                   \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == htonl (1))

using namespace Crafter;
using namespace std;

static bool skip_suid_check = false;

static uint8_t hops_max = 64;
static uint8_t hops_min = 1;
static uint8_t hops_max_dscp = 30;
static int global_pktid = 500;

static string destination;
static string iface;
static bool resolve = true;
static bool verbose = false;
bool print_debug = false;
static json_object * jobj = NULL;
static json_object *j_results = NULL;
static bool dscp_flag = false;

static string mymac;
static string neighbormac;

//struct ifreq ifr_iface;

double tbx_default_timeout = 1;

template<int n> void BuildNetworkLayer(Packet *) { }
template<int n> void BuildTransportLayer(Packet *, int,int, const char *,int) { }

template<>
void BuildNetworkLayer<IP::PROTO>(Packet *pkt)
{
        
	IP ip = IP();
	ip.SetIdentification(rand());
	pkt->PushLayer(ip);
}

template<>
void BuildNetworkLayer<IPv6::PROTO>(Packet *pkt)
{
	IPv6 ip = IPv6();
	ip.SetFlowLabel(rand());
	pkt->PushLayer(ip);
}

template<>
void BuildTransportLayer<TCP::PROTO>(Packet *pkt, int dport, int sport,const char *in_str, int flag)
{
	TCP tcp = TCP();
	tcp.SetSrcPort(sport);
	tcp.SetDstPort(dport);
	tcp.SetSeqNumber(rand());
	tcp.SetFlags(0x2);
	pkt->PushLayer(tcp);
	
	TCPOptionMaxSegSize mss = TCPOptionMaxSegSize();
	mss.SetMaxSegSize(1460);
	pkt->PushLayer(mss);

	TCPOptionSACKPermitted toption = TCPOptionSACKPermitted();
	pkt->PushLayer(toption);

	TCPOptionTimestamp tstamp = TCPOptionTimestamp();
	tstamp.SetValue(25001005);
	tstamp.SetEchoReply(0);
	pkt->PushLayer(tstamp);

	TCPOptionPad tnop = TCPOptionPad();
        pkt->PushLayer(tnop);

	TCPOptionWindowScale tcpwscale = TCPOptionWindowScale();
	tcpwscale.SetShift(7);
	pkt->PushLayer(tcpwscale);
	
	
}

template<>
void BuildTransportLayer<UDP::PROTO>(Packet *pkt, int dport,int sport,const char *in_str,int flag)
{
	UDP udp = UDP();
	udp.SetSrcPort(sport);
	udp.SetDstPort(dport);
	if (flag==0)
	    udp.SetCheckSum(0x0);
	pkt->PushLayer(udp);

	if(sport==dport && dport==9899)
        {
            SCTP sctp = SCTP();
            sctp.SetSrcPort(50000);
            sctp.SetDstPort(443);
            sctp.SetTag(0);
            pkt->PushLayer(sctp);
	}
	if(sport==dport && dport==6511)
	{
	    DCCP dccp = DCCP();
            dccp.SetSrcPort(50000);
            dccp.SetDstPort(443);
            dccp.SetSeqNumberH(rand());
            dccp.SetSeqNumberL(rand());
            //pkt->Print();
            pkt->PushLayer(dccp);
	}

	if(in_str)
        {
                int len_str = strlen(in_str) / 2;
                byte payload[len_str];
                for (int i = 0; i < len_str; i++)
                  sscanf(in_str + 2*i, "%02x",&payload[i]);
                pkt->PushLayer(RawLayer(payload,len_str));
        }
        else if(sport==dport && dport==9899)
	{
           byte payload[] ={0x01,0x00,0x00,0x24,0xf6,0x70,0x4b,0xce,0x00,0x01,0xa0,0x00,0x00,0x0a,0xff,0xff,0xdd,0x54,0x9a,0x89,0x00,0x0c,0x00,0x06,0x00,0x05,0x00,0x00,0x80,0x00,0x00,0x04,0xc0,0x00,0x00,0x04};
           pkt->PushLayer(RawLayer(payload,36));
	}else if (sport==dport && dport==6511)
	{
	  //Do nothing
	}else
        {  
            
            char sample_str[]="0123456789abcdef";
            char *tmp = NULL;
            byte payload[1472];
            
            struct timeval  tv;
            gettimeofday(&tv, NULL);
            srand((tv.tv_sec) * 1000 + (tv.tv_usec) / 1000);
            //srand(time(NULL));
            for(int i=0; i< 1472; i++)
            {
                asprintf(&tmp, "%c%c", sample_str[rand()%16],sample_str[rand()%16]);
                sscanf(tmp, "%02x",&payload[i]);
            }
        
            pkt->PushLayer(RawLayer(payload,1472));
        }
}

template<>
void BuildTransportLayer<SCTP::PROTO>(Packet *pkt, int dport,int sport,const char *in_str, int flag)
{
        SCTP sctp = SCTP();
        sctp.SetSrcPort(sport);
        sctp.SetDstPort(dport);
        sctp.SetTag(0);
        pkt->PushLayer(sctp);

        if(in_str)
        {
                int len_str = strlen(in_str) / 2;
                byte payload[len_str];
                for (int i = 0; i < len_str; i++)
                  sscanf(in_str + 2*i, "%02x", &payload[i]);
                pkt->PushLayer(RawLayer(payload,len_str));
        }
        else
        {
                byte payload[] ={0x01,0x00,0x00,0x24,0xf6,0x70,0x4b,0xce,0x00,0x01,0xa0,0x00,0x00,0x0a,0xff,0xff,0xdd,0x54,0x9a,0x89,0x00,0x0c,0x00,0x06,0x00,0x05,0x00,0x00,0x80,0x00,0x00,0x04,0xc0,0x00,0x00,0x04};
		pkt->PushLayer(RawLayer(payload,36));
        }
}

template<>
void BuildTransportLayer<DCCP::PROTO>(Packet *pkt, int dport,int sport,const char *in_str,int flag)
{
        DCCP dccp = DCCP();
        dccp.SetSrcPort(sport);
        dccp.SetDstPort(dport);
        dccp.SetSeqNumberH(rand());
        dccp.SetSeqNumberL(rand());
        //pkt->Print();
        pkt->PushLayer(dccp);
}

template<>
void BuildTransportLayer<UDPLite::PROTO>(Packet *pkt, int dport,int sport,const char *in_str,int flag)
{
        UDPLite udplite = UDPLite();
        udplite.SetSrcPort(sport);
        udplite.SetDstPort(dport);
        pkt->PushLayer(udplite);

        if(in_str)
        {
                int len_str = strlen(in_str) / 2;
                byte payload[len_str];
                for (int i = 0; i < len_str; i++)
                  sscanf(in_str + 2*i, "%02x", &payload[i]);
                pkt->PushLayer(RawLayer(payload,len_str));
        }
        else
	{

            char sample_str[]="0123456789abcdef";
            char *tmp = NULL;
            byte payload[1472];

            struct timeval  tv;
            gettimeofday(&tv, NULL);
            srand((tv.tv_sec) * 1000 + (tv.tv_usec) / 1000);
            //srand(time(NULL));
            for(int i=0; i< 1472; i++)
            {
                asprintf(&tmp, "%c%c", sample_str[rand()%16],sample_str[rand()%16]);
                sscanf(tmp, "%02x",&payload[i]);
            }

            pkt->PushLayer(RawLayer(payload,1472));
        }
}

template<>
void BuildTransportLayer<IPSec::PROTO>(Packet *pkt, int dport,int sport,const char *in_str, int flag)
{
        IPSec ipsec = IPSec();
        ipsec.SetSpi(sport);
        ipsec.SetSeq(dport);
        pkt->PushLayer(ipsec);

        if(in_str)
        {
                int len_str = strlen(in_str) / 2;
                byte payload[len_str];
                for (int i = 0; i < len_str; i++)
                  sscanf(in_str + 2*i, "%02x", &payload[i]);
                pkt->PushLayer(RawLayer(payload,len_str));
        }
        else
       {

        byte payload[] ={0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x1a, 0x17, 0x0e, 0x16, 0xad, 0x78, 0xe0, 0xee, 0xc6, 0x52, 0x1a, 0x1c, 0xa0, 0x1c, 0x2f, 0x49, 0x08, 0xfb, 0xfd, 0x3f, 0xa3, 0xae, 0x1b, 0xfa, 0xbf, 0x4a, 0xe9, 0x4a, 0x56, 0x2a, 0x78, 0xc3, 0x65, 0xdd, 0xf7, 0x2f, 0xce, 0x9d, 0xd0, 0x06, 0x6c, 0xbf, 0xac, 0xe9, 0xa9, 0x63, 0x53, 0x5a, 0xde, 0xc1, 0x76, 0xf5, 0x77, 0xc1, 0x8a, 0xd9, 0x00, 0xda, 0xbc, 0x8e, 0xfc, 0x6a, 0x95, 0xde, 0x54, 0x13, 0x39, 0xde, 0xa0, 0x3d, 0x7a, 0x1d, 0xca, 0x5f, 0x51, 0x76, 0xfc, 0x0c, 0xed, 0xf5, 0x5f, 0x86, 0xfa, 0x96, 0x76, 0xca, 0xf4, 0xe0, 0x32, 0x69, 0x2d, 0x91, 0x42, 0x08, 0x68, 0x85, 0x04, 0x5e, 0x6a, 0x73, 0x47, 0x5f, 0x9f, 0xd8, 0xe9, 0xb9, 0x53, 0xaf, 0xa7, 0x9c, 0x17, 0x1d, 0x6b, 0x88, 0xd8, 0x4a, 0x7b, 0x51, 0x72, 0x56, 0x0c, 0x57, 0xcf, 0xea, 0x87};
        pkt->PushLayer(RawLayer(payload,132));
        }
}

Packet *BuildProbe(int net, int tr, int dport, int sport,const char *in_str, int flag)
{
	Packet *pkt = new Packet();
	switch(net) {
	case IP::PROTO:
		BuildNetworkLayer<IP::PROTO>(pkt);
		break;
	case IPv6::PROTO:
		BuildNetworkLayer<IPv6::PROTO>(pkt);
		break;
	}
	
	switch(tr) {
	case IPSec::PROTO:
                BuildTransportLayer<IPSec::PROTO>(pkt, dport,sport,in_str,flag);
                break;
	case TCP::PROTO:
		BuildTransportLayer<TCP::PROTO>(pkt, dport,sport,in_str,flag);
		break;
	case UDP::PROTO:
		BuildTransportLayer<UDP::PROTO>(pkt, dport,sport,in_str,flag);
		break;
	case SCTP::PROTO:
                BuildTransportLayer<SCTP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case DCCP::PROTO:
                BuildTransportLayer<DCCP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case UDPLite::PROTO:
                BuildTransportLayer<UDPLite::PROTO>(pkt, dport,sport,in_str,flag);
                break;
	}
	return pkt;
}

Packet *FloodProbe(Packet *pkt,int net, int tr, int dport, int sport,const char *in_str, int flag)
{
        //Packet *pkt = new Packet();

        switch(net) {
        case IP::PROTO:
                BuildNetworkLayer<IP::PROTO>(pkt);
                break;
        case IPv6::PROTO:
                BuildNetworkLayer<IPv6::PROTO>(pkt);
                break;
        }

        switch(tr) {
        case IPSec::PROTO:
                BuildTransportLayer<IPSec::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case TCP::PROTO:
                BuildTransportLayer<TCP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case UDP::PROTO:
                BuildTransportLayer<UDP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case SCTP::PROTO:
                BuildTransportLayer<SCTP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case DCCP::PROTO:
                BuildTransportLayer<DCCP::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        case UDPLite::PROTO:
                BuildTransportLayer<UDPLite::PROTO>(pkt, dport,sport,in_str,flag);
                break;
        }
        return pkt;
}


string GetDefaultIface(bool ipv6, const string &addr)
{
	struct sockaddr_storage sa;
	int fd, af = ipv6 ? AF_INET6 : AF_INET;
	socklen_t n;
	size_t sa_len;
	struct ifaddrs *ifaces, *ifa;

	memset(&sa, 0, sizeof(sa));
	if (ipv6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
		sin6->sin6_family = af;
		sa_len = sizeof(*sin6);
		inet_pton(af, addr.c_str(), &sin6->sin6_addr);
		sin6->sin6_port = htons(666);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		sin->sin_family = af;
		sa_len = sizeof(*sin);
		inet_pton(af, addr.c_str(), &sin->sin_addr);
		sin->sin_port = htons(666);
	}

	if ((fd = socket(af, SOCK_DGRAM, 0)) < 0)
		goto out;

	if (connect(fd, (struct sockaddr *)&sa, sa_len) < 0) {
		perror("connect");
		goto error;
	}

	n = sa_len;
	if (getsockname(fd, (struct sockaddr *)&sa, &n) < 0)
		goto error;

	if (getifaddrs(&ifaces) < 0)
		goto error;

	for (ifa = ifaces; ifa != 0; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == af) {
			void *ifa_addr, *saddr;
			char name[IF_NAMESIZE];
			size_t len = ipv6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
			ifa_addr = ipv6 ? (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr :
					(void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			saddr = ipv6 ? (void *)&((struct sockaddr_in6 *)&sa)->sin6_addr :
					(void *)&((struct sockaddr_in *)&sa)->sin_addr;
			if (!memcmp(ifa_addr, saddr, len)) {
				memcpy(name, ifa->ifa_name, IF_NAMESIZE);
				freeifaddrs(ifaces);
				close(fd);
				return name;
			}
		}
	}

	freeifaddrs(ifaces);
error:
	close(fd);
out:
	return "";
}

bool isPcap(const string& iface)
{
	return iface.compare(0, 5, "pcap:") == 0;
}

bool pcapParse(const string& name, string& output, string& input)
{
	string s = name;
	string delimiter = ":";
	vector<string> tokens;
	size_t pos = 0;

	while ((pos = s.find(delimiter)) != string::npos) {
	    string token = s.substr(0, pos);
	    s.erase(0, pos + 1);
		tokens.push_back(token);
	}
	tokens.push_back(s);

	if (tokens.size() != 3 || tokens[0] != "pcap")
		return false;

	output = tokens[1];
	input = tokens[2];

	return true;
}

static pcap_t *pd = NULL, *save_d = NULL;
static int rfd;
static pcap_t *rd = NULL;
static pcap_dumper_t *pdumper, *save_dumper = NULL;
static const char *pcap_filename = DEFAULT_PCAP_FILENAME;
#ifdef HAVE_CURL
static const char * upload_url = DEFAULT_URL;
static bool upload = false;
#endif

int openPcap(){
	OpenPcapDumper(DLT_RAW, pcap_filename, save_d, save_dumper);
	if(save_dumper == NULL){
		cerr << "Error while opening pcap file : " << pcap_geterr(save_d) << endl;
		return -1;
	}
	return 0;
}

void writePcap(Packet* p){
	struct pcap_pkthdr hdr;
	hdr.len = p->GetSize();
	hdr.caplen = p->GetSize();
	hdr.ts = p->GetTimestamp();
	pcap_dump(reinterpret_cast<u_char*>(save_dumper), &hdr, p->GetRawPtr());
}

void closePcap(){
	pcap_dump_flush(save_dumper);
	pcap_close(save_d);
	pcap_dump_close(save_dumper);
#ifdef HAVE_CURL
	if (upload) {
		std::cerr << "Uploading pcap to " << upload_url << std::endl;
		curlPost(pcap_filename, upload_url);
	}
#endif
}


Packet* PcapSendRecv(Packet *probe, const string& iface)
{
	struct pcap_pkthdr hdr1, hdr2;
	uint8_t *packet;
	Packet* reply = NULL;
	string in_file, out_file;

	if (!pd && !rd)
		pcapParse(iface, out_file, in_file);

	memset(&hdr1, 0, sizeof(hdr2));
	if (gettimeofday(&hdr2.ts, NULL) < 0)
		return NULL;
	hdr2.len = probe->GetSize();
	hdr2.caplen = probe->GetSize();

	/* Write packet to pcap and wait for reply */
	if (!pd)
		OpenPcapDumper(DLT_RAW, out_file, pd, pdumper);

#ifdef __APPLE__
	/* if MAC OSX -> IP total len must be changed */
	byte copy[probe->GetSize()];
	memcpy(copy, probe->GetRawPtr(), probe->GetSize());

	if (probe->GetLayer<IPLayer>()->GetID() == IP::PROTO) {
		byte tmp = copy[2];
		copy[2] = copy[3];
		copy[3] = tmp;
	}
	DumperPcap(pdumper, &hdr2, copy);
#else
	DumperPcap(pdumper, &hdr2, probe->GetRawPtr());
#endif
	pcap_dump_flush(pdumper);
	if (!rd) {
		char pcap_errbuf[PCAP_ERRBUF_SIZE];

		rd = pcap_open_offline(in_file.c_str(), pcap_errbuf);
		if (rd == NULL) {
			goto error;
		}

		rfd = pcap_get_selectable_fd(rd);
		if (rfd < 0) {
			goto error;
		}
	}

	/* Retrieve the reply from MB or server*/
	packet = (uint8_t *)pcap_next(rd, &hdr1);

	reply = new Packet;
	switch((packet[0] & 0xf0) >> 4) {
	case 4:
		reply->PacketFromIP(packet, hdr1.len);
		break;
	case 6:
		reply->PacketFromIPv6(packet, hdr1.len);
		break;
	default:
		delete reply;
		return NULL;
	}

error:
	return reply;
}

string resolve_name(int proto, string& name)
{
	switch (proto) {
	case IP::PROTO:
		return GetIP(name);
	case IPv6::PROTO:
		return GetIPv6(name);
	default:
		return "";
	}
}

string iface_address(int proto, string& iface)
{
	try {
		switch (proto) {
		case IP::PROTO:
			if (isPcap(iface))
				return PCAP_IPv4;
			return GetMyIP(iface);
		case IPv6::PROTO:
			if (isPcap(iface))
				return PCAP_IPv6;
			return GetMyIPv6(iface, false);
		default:
			return "";
		}
	} catch (std::runtime_error &ex) { return ""; }
}

static unsigned long timeval_diff(const struct timeval a, const struct timeval b)
{
	return (a.tv_sec - b.tv_sec) * 10e6L + a.tv_usec - b.tv_usec;
}

static int Callback(void *ctx, uint8_t ttl, string& router,
		PacketModifications *mod,Packet *r_pkt)
{
	(void)ctx;
	const Packet *probe = mod->orig.get();
	const Packet *rcv = mod->modif.get();
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1)
		cout << "tracebox to " <<
			ip->GetDestinationIP() << " (" << destination << "): " <<
			(int)hops_max << " hops max" << endl;

	if (rcv) {
		ip = rcv->GetLayer<IPLayer>();
		if (!resolve)
			cout << +(int)ttl << ": " << router << " ";
		else
			cout << (int)ttl << ": " << GetHostname(router) << " (" << router << ") ";
		IPLayer *ip_l = r_pkt->GetLayer<IPLayer>();

                switch (ip_l->GetID()) {
                case IP::PROTO:

                        IP *r_ip = reinterpret_cast<IP *>(ip_l);
                        if ( (int)r_ip->GetProtocol() == 1)
                        {
                                ICMP *icmp = r_pkt->GetLayer<ICMP>();
                                cout << (int)icmp->GetType() << " " << (int)icmp->GetCode() << " ";
                        }
                        break;
                /*case IPv6::PROTO:
                        IPv6 *r_ip = reinterpret_cast<IPv6 *>(ip_l);
                        if ( (int)r_ip->GetNextHeader() == 58)
                        {
                                ICMPv6 *icmp = r_pkt->GetLayer<ICMPv6>();
                                cout << (int)icmp->GetType() << " " << icmp->GetCode() << " ";
                        }
                        break;*/
                }
		cout << timeval_diff(rcv->GetTimestamp(), probe->GetTimestamp()) / 1000 << "ms ";
		if (mod) {
			mod->Print(cout, verbose);
			delete mod;
		}
		cout << endl;
	} 

	return 0;
}

static int Callback_JSON(void *ctx, uint8_t ttl, string& router,
		PacketModifications *mod,Packet *r_pkt)
{
	(void)ctx;
	const Packet *probe = mod->orig.get();
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1){
		json_object_object_add(jobj,"addr", json_object_new_string(ip->GetDestinationIP().c_str()));
		json_object_object_add(jobj,"name", json_object_new_string(destination.c_str()));
		json_object_object_add(jobj,"max_hops", json_object_new_int(hops_max));
	}

	json_object * hop = json_object_new_object();

	const Packet *rcv = mod->modif.get();
	if (rcv) {
			ip = rcv->GetLayer<IPLayer>();
			IPLayer *ip_l = r_pkt->GetLayer<IPLayer>();

                        switch (ip_l->GetID()) {
                        case IP::PROTO:
                                IP *r_ip = reinterpret_cast<IP *>(ip_l);
                                if ( (int)r_ip->GetProtocol() == 1)
                                {
                                        ICMP *icmp = r_pkt->GetLayer<ICMP>();
                                        json_object_object_add(hop,"icmp_type", json_object_new_int(icmp->GetType()));
                                        json_object_object_add(hop,"icmp_code", json_object_new_int(icmp->GetCode()));
                                        
                                }
                                break;
                        /*case IPv6::PROTO:
                                IPv6 *r_ip = GetIPv6(*r_pkt);
                                //IPv6 *r_ip = reinterpret_cast<IPv6 *>(ip_l);
                                if ( (int)r_ip->GetNextHeader() == 58)
                                {
                                        ICMPv6 *icmp = r_pkt->GetLayer<ICMPv6>();
                                        json_object_object_add(hop,"icmp_type", json_object_new_int(icmp->GetType()));
                                        json_object_object_add(hop,"icmp_code", json_object_new_int(icmp->GetCode()));
                                }
                                break;*/
                                }

                        /*
                        IPLayer *ip_l = r_pkt->GetLayer<IPLayer>();
                        IP *r_ip = reinterpret_cast<IP *>(ip_l);
                        if ( (int)r_ip->GetProtocol() == 1)
                        {
                                ICMP *icmp = r_pkt->GetLayer<ICMP>();
                                json_object_object_add(hop,"icmp_type", json_object_new_int(icmp->GetType()));
                                json_object_object_add(hop,"icmp_code", json_object_new_int(icmp->GetCode()));
                        
                        }
                        */

                        json_object_object_add(hop,"DSTMAC", json_object_new_string(mymac.c_str()));
                        json_object_object_add(hop,"SRCMAC", json_object_new_string(neighbormac.c_str())); 
                        
			json_object_object_add(hop,"hop", json_object_new_int(ttl));
			json_object_object_add(hop,"from", json_object_new_string(router.c_str()));
			json_object_object_add(hop,"delay", json_object_new_int(timeval_diff(rcv->GetTimestamp(), probe->GetTimestamp())));
			if (resolve)
				json_object_object_add(hop,"name", json_object_new_string(GetHostname(router).c_str()));
			if (mod){
				json_object *modif = json_object_new_array();
				json_object *add = json_object_new_array();
				json_object *del = json_object_new_array();
				json_object *ext = NULL;

				mod->Print_JSON(modif, add, del, &ext, verbose);

				json_object_object_add(hop,"Modifications", modif);
				json_object_object_add(hop,"Additions", add);
				json_object_object_add(hop,"Deletions", del);
				if (ext != NULL)
					json_object_object_add(hop, "ICMPExtensions", ext);
				delete mod;
			}
	}
	else{
		json_object_object_add(hop,"hop", json_object_new_int(ttl));
		json_object_object_add(hop,"from", json_object_new_string("*"));
                json_object_object_add(hop,"DSTMAC", json_object_new_string(mymac.c_str()));
                json_object_object_add(hop,"SRCMAC", json_object_new_string(neighbormac.c_str())); 
	}

	json_object_array_add(j_results,hop);
        
        if(dscp_flag)
        {
         json_object *dscp_modification = NULL;
         json_object_object_foreach(hop, key, val) {
            if(strcmp(key,"Modifications") == 0)
            {
                dscp_modification = json_object_object_get(hop,"Modifications");
                
                json_object *element_dscp,*element_dscp_name,*element_dscp_name_exp,*element_dscp_name_rcv;
                int len_modification = json_object_array_length(dscp_modification);
                for (int i = 0; i < len_modification; i++) 
                {
                   element_dscp = json_object_array_get_idx(dscp_modification, i);
                   json_object_object_foreach(element_dscp, key1, val1) {
                    if (strcmp(key1,"IP::DiffServicesCP") == 0)
                    {
                        element_dscp_name = json_object_object_get(element_dscp,"IP::DiffServicesCP");
                        element_dscp_name_exp = json_object_object_get(element_dscp_name, "Expected");
                        element_dscp_name_rcv = json_object_object_get(element_dscp_name, "Received");
                            if(json_object_get_int(element_dscp_name_exp)!=json_object_get_int(element_dscp_name_rcv))
                                return 1;
                    }
                
                    }
                }
            }
           }
        }
            

        
        
	return 0;
}

bool validIPAddress(bool ipv6, const string& ipAddress)
{
	if (ipv6)
		return validateIpv6Address(ipAddress);
	else
		return validateIpv4Address(ipAddress);
}

IPLayer* probe_sanity_check(const Packet *pkt, string& err, string& iface)
{
	IPLayer *ip = pkt->GetLayer<IPLayer>();
	string sourceIP;
	string destinationIP;

	if (!ip) {
		err = "You need to specify at least an IPv4 or IPv6 header";
		return NULL;
	}

	destinationIP = ip->GetDestinationIP();
	sourceIP = ip->GetSourceIP();
	if ((destinationIP == "0.0.0.0" || destinationIP == "::") && destination != "")
		destinationIP = resolve_name(ip->GetID(), destination);

	if (destinationIP == "" || destinationIP == "0.0.0.0" || destinationIP == "::") {
		err = "You need to specify a destination";
		return NULL;
	}

	if (!validIPAddress(ip->GetID() == IPv6::PROTO, destinationIP)) {
		err = "The specified destination address is not valid";
		return NULL;
	}

	iface = iface == "" ? GetDefaultIface(ip->GetID() == IPv6::PROTO, destinationIP) : iface;
	if (iface == "") {
		err = "You need to specify an interface as there is no default one";
		return NULL;
	}

	if (sourceIP == "" || sourceIP == "0.0.0.0" || sourceIP == "::") {
		sourceIP = iface_address(ip->GetID(), iface);
		if (sourceIP == "") {
			err = "There is no source address for the specified protocol";
			return NULL;
		}
		ip->SetSourceIP(sourceIP);
	} else if (!validIPAddress(ip->GetID() == IPv6::PROTO, sourceIP)) {
		err = "The specified source address is not valid";
		return NULL;
	}

	ip->SetDestinationIP(destinationIP);
	return ip;
}

int doTracebox(std::shared_ptr<Packet> pkt_shrd,uint8_t dscp, tracebox_cb_t *callback,
		string& err, void *ctx)
{
	Packet* rcv = NULL;
	PacketModifications *mod = NULL;
	string sIP;
	Packet new_pkt=Packet();
	Packet *pkt = pkt_shrd.get();
	IPLayer *ip = probe_sanity_check(pkt, err, iface);
	if (!ip)
		return -1;

        //int pkt_id=1000;
	for (uint8_t ttl = hops_min; ttl <= hops_max; ++ttl) {
		switch (ip->GetID()) {
		case IP::PROTO:
			reinterpret_cast<IP *>(ip)->SetTTL(ttl);
                        reinterpret_cast<IP *>(ip)->SetIdentification(global_pktid);
			reinterpret_cast<IP *>(ip)->SetDiffServicesCP(dscp);
                        
                        //pkt_id++;
                        //if(pkt_id>20000)
                        //    pkt_id=1000;
			break;
		case IPv6::PROTO:
			reinterpret_cast<IPv6 *>(ip)->SetHopLimit(ttl);
			reinterpret_cast<IPv6 *>(ip)->SetTrafficClass(dscp*4);
			break;
		default:
			std::cerr << "Could not access the IPLayer from the probe, "
				"aborting." << std::endl;
			return 1;
		}
		pkt->PreCraft();
		if (print_debug) {
			std::cerr << "Filter used at hop " << (int) ttl << ": ";
			pkt->GetFilter(std::cerr);
			std::cerr << std::endl;
		}

		if (isPcap(iface))
			rcv = PcapSendRecv(pkt, iface);
		else{ // Write both pkt & rcv to pcap file
			rcv = pkt->SendRecv(iface, tbx_default_timeout, 1.0);
			if(!isPcap(iface))
				writePcap(pkt);
		}

		/* If we have a reply then compute the differences */
		if (rcv) {
                        Packet eth_all = rcv->SubPacket(0,1);
                        Ethernet *eth=eth_all.GetLayer<Ethernet>();
                        mymac = eth->GetDestinationMAC();
                        neighbormac = eth->GetSourceMAC();
                        
			if(!isPcap(iface)){
				Packet p;
				/* Removing Ethernet Layer for storage */
				p = rcv->SubPacket(1,rcv->GetLayerCount());
				writePcap(&p);
			}
			sIP = rcv->GetLayer<IPLayer>()->GetSourceIP();
		} else {
			sIP = "";
		}
		if(rcv) 
		  new_pkt = *rcv;
		mod = PacketModifications::ComputeModifications(pkt_shrd, rcv);

                hops_max_dscp = ttl;
                
		/* The callback can stop the iteration */
		if (callback && callback(ctx, ttl, sIP, mod,&new_pkt))
			return 0;

		/* Stop if we reached the server */
		if (rcv && sIP == ip->GetDestinationIP())
			return 1;
		
	}
	return 0;
}


int doFloodbox(int dport, int sport,uint8_t dscp_val, int n_pkts, int k_interval,int times_pktbuff, char *seq_rand,string& err)
{
    int k_round = n_pkts/k_interval;
    if (k_round * k_interval < n_pkts)
    {
        k_round++;
        n_pkts = k_round * k_interval;
    }
	
	unsigned int data_byte = 1472;
        //int bufsize = (k_interval)*data_byte;
	int *seq_rand_int = (int*)malloc(times_pktbuff*sizeof(int));
	int fix_pktbuff;
	if (seq_rand == NULL)
	   fix_pktbuff = times_pktbuff;
	else
	{
	    seq_rand_int = (int*)realloc(seq_rand_int, strlen(seq_rand)*sizeof(int));
	    int maximum=0;
	    char tmp[2];
	    tmp[1]='\0';
	    for(unsigned int ij=0;ij < strlen(seq_rand);ij++ )
	      {
		tmp[0] = seq_rand[ij];
		seq_rand_int[ij] = atoi(tmp);
		if (seq_rand_int[ij] > maximum)
		    maximum = seq_rand_int[ij];
	      }
	    fix_pktbuff = maximum + 1;
	}
	char buffinal[data_byte*(fix_pktbuff+1)+1];
	//std::cerr << fix_pktbuff << "OK" << strlen(buffinal) <<endl;	
	int i;
        for(i=0; i< data_byte*(fix_pktbuff+1); i++)
	  	buffinal[i]=(rand()%26)+65;
	buffinal[i]='\0';
	

	int flood_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);		
	int flags, newflags;
	flags = fcntl(flood_socket, F_GETFL, 0);
    	if (flags < 0) {
       	     std::cerr << "fcntl(F_GETFL)" << std::endl;
    		}
	newflags = flags | (int) O_NONBLOCK;
    	if (newflags != flags)
		if (fcntl(flood_socket, F_SETFL, newflags) < 0) {
	    	    std::cerr << "fcntl(F_SETFL)" << std::endl;
		}
	
    	struct sockaddr_in my_addr, server_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
 	my_addr.sin_port = htons(sport);
	my_addr.sin_addr.s_addr = inet_addr(iface_address(IP::PROTO,iface).c_str());
	
	if(bind(flood_socket,(struct sockaddr *) &my_addr, sizeof(my_addr))<0)
                {
                   std::cerr << "cannot bind socket" << std::endl;
                   return 0;
                }

	int buffersize= 9000000;
    	const int* valone = &buffersize;
    	if(setsockopt(flood_socket, SOL_SOCKET, SO_SNDBUF, valone, sizeof(buffersize)) < 0) {
        std::cerr<<"Unable to set send buffer size, continuing with default size"<<std::endl;
    	}
	
	int ipttl = hops_max_dscp+2;
	if(setsockopt(flood_socket, IPPROTO_IP,IP_TTL,&ipttl, sizeof(ipttl)) < 0)
		{
			std::cerr << "IP TTL Setting in Flood packets" << std::endl;
		}

	int iptos = 0;
	if (setsockopt(flood_socket,IPPROTO_IP,IP_TOS,&iptos, sizeof(iptos)) < 0)
		{
			std::cerr << "IP TOS Setting in Flood packets" << std::endl;
		}
	/*int pathMTU = IP_PMTUDISC_WANT;
	if ( setsockopt(flood_socket,IPPROTO_IP,IP_MTU_DISCOVER, &pathMTU,sizeof(pathMTU)) < 0)
	  {
             std::cerr << "Setting DF in packets" << std::endl;
          }
	*/
 	memset(&server_addr, 0, sizeof(server_addr));
 	server_addr.sin_port=htons(dport);
 	server_addr.sin_family = AF_INET;
 	server_addr.sin_addr.s_addr=inet_addr(destination.c_str());
	

    Packet **pktArryBE = new Packet * [(hops_max_dscp+1-hops_min) * k_round];
    Packet **pktArry = new Packet * [(hops_max_dscp+1-hops_min) * k_round];
    
    Packet *pkt = new Packet();
    IPLayer *ip;
  
    int pktno;
    int pkt_id=30000;
    int ntimes=0;
    
    Ethernet ethernet = Ethernet();
    ethernet.SetSourceMAC(mymac);
    ethernet.SetDestinationMAC(neighbormac);
    
    pkt->PushLayer(ethernet);
    
    for (int i = 0; i < k_round; i++) {
    
        pktno=0;
        
        for (uint8_t ttl = hops_min; ttl <= hops_max_dscp; ++ttl) {
        
            Packet *pkt_gen = new Packet(*pkt);
            pkt_gen = FloodProbe(pkt_gen,IP::PROTO, UDP::PROTO, dport,sport+ntimes,NULL,10);
            ip = probe_sanity_check(pkt_gen, err, iface);
        
            switch (ip->GetID()) {
                case IP::PROTO:
                    reinterpret_cast<IP *>(ip)->SetTTL(ttl);
                    reinterpret_cast<IP *>(ip)->SetIdentification(pkt_id);
                    reinterpret_cast<IP *>(ip)->SetDiffServicesCP(dscp_val);
                    break;
            }
            pkt_gen->PreCraft();
            pktArry[(hops_max_dscp+1-hops_min) * i + pktno]=new Packet(*pkt_gen);
        
            pkt_id++;
            if(pkt_id>60000)
                pkt_id=30000;
        
            pkt_gen = new Packet(*pkt);
            pkt_gen=FloodProbe(pkt_gen,IP::PROTO, UDP::PROTO, dport,sport+ntimes,NULL,10);
            ip = probe_sanity_check(pkt_gen, err, iface);
        
            switch (ip->GetID()) {
                case IP::PROTO:
                    reinterpret_cast<IP *>(ip)->SetTTL(ttl);
                    reinterpret_cast<IP *>(ip)->SetIdentification(pkt_id);
                    break;
            }
            pkt_gen->PreCraft();
            pktArryBE[(hops_max_dscp+1-hops_min) * i + pktno]=new Packet(*pkt_gen);
        
            pktno++;
        
            pkt_id++;
            if(pkt_id>60000)
                pkt_id=30000;
        }    
    }
    
   
    int s = socket(PF_PACKET, SOCK_RAW,htons (ETH_P_IP));
    
    struct sockaddr_ll iface_device;
    memset (&iface_device, 0, sizeof (iface_device));
    if ((iface_device.sll_ifindex = if_nametoindex (iface.c_str())) == 0) {
      std::cerr << "if_nametoindex() failed to obtain interface index " << endl;
    
    }
     
    uint8_t MyMac_Addr[6];
    if (sscanf(mymac.c_str(), "%x:%x:%x:%x:%x:%x",&MyMac_Addr[0],&MyMac_Addr[1],&MyMac_Addr[2],&MyMac_Addr[3],&MyMac_Addr[4],&MyMac_Addr[5]) < 6)
    {
        std::cerr << "could not parse" << std::endl;
    }

    
   iface_device.sll_family = AF_PACKET;
   memcpy (iface_device.sll_addr, MyMac_Addr, 6 * sizeof (uint8_t));
   iface_device.sll_halen = 6;
   
    int one = 1;
    const int* val = &one;
    
    if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, val, sizeof(one)) < 0)
         {
                std::cerr << "2. Errro "<<std::endl;
        }


    if(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.size()) < 0)
       {
                std::cerr << "3. Errro "<<std::endl;
        }
        
  /*  if (setsockopt(s, SOL_PACKET, PACKET_QDISC_BYPASS, val, sizeof(one)) <0 )
    {
        std::cerr << "4. Errro "<<std::endl;
    }
    
    */
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, val, sizeof(one)) <0)
       {
        std::cerr << "5. Errro "<<std::endl;
    } 
    /*
    int optval=7;
    if(setsockopt(s, SOL_SOCKET, SO_PRIORITY, &optval, sizeof(optval)) < 0)
       {
        std::cerr << "6. Errro "<<std::endl;
    } */ 

    
    int buffer_size= 500000;
    const int* val_one = &buffer_size;
    if(setsockopt(s, SOL_SOCKET, SO_SNDBUF, val_one, sizeof(buffer_size)) < 0) {
        std::cerr<<"Unable to set send buffer size, continuing with default size"<<std::endl;
    }
   
    const byte *data = pktArry[0]->GetRawPtr();
    size_t datasize = pktArry[0]->GetSize();
    
    int sent=0;
    //int amount_left;
    char *partly;
    size_t max_size = k_interval * data_byte;
    size_t total_send = 0;    
    size_t tmp_size=0;

    int one_two;
    for (int i = 0; i < k_round; i++) {
   	
	total_send = 0;
	partly = buffinal;
	if (seq_rand == NULL)
	   one_two=(int)rand() % fix_pktbuff;
	else
	   one_two = seq_rand_int[i];
	while (total_send < max_size)
	{
	   tmp_size = max_size - total_send;
	   if (tmp_size > data_byte)
		tmp_size = data_byte;
	
	if (strlen(partly) < tmp_size)
	    partly = buffinal;

	sent = sendto (flood_socket,partly,(one_two+1)*tmp_size,0, (struct sockaddr *) &server_addr, sizeof (struct sockaddr));
        if (sent==-1)
	   break;
	total_send += sent;
	partly +=sent;
        
	}
        
	pktno=0;
        for (uint8_t ttl = hops_min; ttl <= hops_max_dscp; ++ttl) {
            
             datasize = pktArry[(hops_max_dscp+1-hops_min) * i + pktno]->GetSize();
             data = pktArry[(hops_max_dscp+1-hops_min) * i + pktno]->GetRawPtr();
             if (sendto (s, data, datasize, 0, (struct sockaddr *) &iface_device, sizeof (iface_device)) <= 0) {
                std::cerr <<  "DSCP" <<datasize<< std::endl;
    		   }
                 
             datasize = pktArryBE[(hops_max_dscp+1-hops_min) * i + pktno]->GetSize();
             data = pktArryBE[(hops_max_dscp+1-hops_min) * i + pktno]->GetRawPtr();
             if (sendto (s, data, datasize, 0, (struct sockaddr *) &iface_device, sizeof (iface_device)) <= 0) {
                std::cerr << "0DSCP" <<datasize<< std::endl;
                }
        
        pktno++;
        
        }
    }
    delete[] pktArry;
    delete[] pktArryBE;
    close(s);
    close(flood_socket);
    return 0;
}

int set_tracebox_ttl_range(uint8_t ttl_min, uint8_t ttl_max)
{
	if(!(ttl_min > 0 && (ttl_min <= ttl_max)))
		return -1;

	hops_min = ttl_min;
	hops_max = ttl_max;
	return 0;
}

uint8_t get_min_ttl() { return hops_min; };
uint8_t get_max_ttl() { return hops_max; };

int main(int argc, char *argv[])
{
	int c;
	int ret = EXIT_SUCCESS;
	int dport = 80;
	int sport = 48001;
	int flag = 10;
	int net_proto = IP::PROTO, tr_proto = TCP::PROTO;
	const char *script = NULL;
	const char *probe = NULL;
	const char *extra_payload = NULL;
	Packet *pkt = NULL;
	string err;
	bool inline_script = false;
	PartialTCP::register_type();
        
        int tcpdump_cmd = 0;
	
	tracebox_cb_t *callback = Callback;

	int npkts=0;
	int kinterval=0;
        uint8_t dscp=0;
	int times_pktbuff=1;
	char *seq_rand=NULL;
	/* disable libcrafter warnings */
	ShowWarnings = 0;
        
        
        /*cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(-1, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask))
		std::cerr << "Error in setting affinity" << std::endl;
        
        */
        int rc = setpriority(PRIO_PROCESS, 0, -15);

    if (rc < 0) {
        std::cerr << "setpriority:"<<std::endl;
        rc = setpriority(PRIO_PROCESS, 0, 0);
    }
        
	while ((c = getopt(argc, argv, "e:Sl:i:A:B:M:m:s:N:K:F:P:T:L:p:d:I:x:f:hnzv6uwjabqyto:VD"
#ifdef HAVE_CURL
					"Cc:"
#endif
					)) != -1) {
		switch (c) {
			case 'N':
				npkts = strtol(optarg, NULL, 10);
                                break;
			case 'K':
                                kinterval = strtol(optarg, NULL, 10);
                                break;
			case 'F':
                                dscp = strtol(optarg, NULL, 10);
                                break;
                        case 'P':
				tcpdump_cmd = strtol(optarg, NULL, 10);
				break;
			case 'T':
                                times_pktbuff = strtol(optarg, NULL, 10);
                                break;
			case 'L':
                                seq_rand = optarg;
                                break;
			case 'o':
                                flag = strtol(optarg, NULL, 10);
                                break;
			case 'e':
                                extra_payload = strdup(optarg);
                                break;
			case 'S':
				skip_suid_check = true;
				break;
			case 'i':
				iface = optarg;
				break;
                        case 'A':
                                mymac=optarg;
                                break;
                        case 'B':
                                neighbormac=optarg;
                                break;
			case 'M':
				hops_min = strtol(optarg, NULL, 10);
				break;
			case 'm':
				hops_max = strtol(optarg, NULL, 10);
				break;
			case 'n':
				resolve = false;
				break;
                        case 'z':
				dscp_flag = true;
				break;
			case '6':
				net_proto = IPv6::PROTO;
				break;
			case 'd':
				dport = strtol(optarg, NULL, 10);
				break;
		        case 'I':
                                global_pktid = strtol(optarg, NULL, 10);
                                break;
			case 'x':
                                sport = strtol(optarg, NULL, 10);
                                break;
			case 'u':
				tr_proto = UDP::PROTO;
				break;
			case 'q':
                                tr_proto = IPSec::PROTO;;
                                break;
			case 'a':
                                tr_proto = SCTP::PROTO;
                                break;
                        case 'b':
                                tr_proto = DCCP::PROTO;
                                break;
                        case 'y':
                                tr_proto = UDPLite::PROTO;
                                break;
			case 's':
				script = optarg;
				break;
			case 'p':
				probe = optarg;
				break;
			case 'v':
				verbose = true;
				break;
			case 'j':
				callback = Callback_JSON;
				jobj = json_object_new_object();
				j_results = json_object_new_array();
				break;
#ifdef HAVE_CURL
			case 'c':
				upload_url = optarg;
				upload = true;
				break;
			case 'C':
				upload = true;
				break;
#endif
			case 'f' :
				pcap_filename = optarg;
				break;
			case 'h':
				ret = 0;
				goto usage;
			case 'w':
				ShowWarnings = 1;
				break;
			case 'l':
				script = optarg;
				inline_script = true;
				break;
			case 't':
				tbx_default_timeout = strtod(optarg, NULL);
				break;
			case 'V':
				std::cerr << _REV_PARSE << std::endl;
				return 0;
			case 'D':
				print_debug = true;
				break;
			case ':':
				std::cerr << "Option `-" << (char)optopt
							<< "' requires an argument!" << std::endl;
				goto usage;
				break;
			case '?':
				std::cerr << "Unknown option `-" << (char)optopt
							<< "'." << std::endl;
			default:
				goto usage;
		}
	}
    
    
    
    if (mymac == "")
        mymac = GetMyMAC(iface);
    if (neighbormac == "")
        neighbormac = "ff:ff:ff:ff:ff:ff";
    
    if (set_tracebox_ttl_range(hops_min, hops_max) < 0) {
		cerr << "Cannot use the specified TTL range: [" << hops_min << ", " << hops_max << "]" << std::endl;
		goto usage;
	}

	if (!skip_suid_check && getuid() != 0) {
		cerr << "tracebox requires superuser permissions!" << endl;
		goto usage;
	}

	if (optind < argc) {
		destination = argv[optind];
	} else if (!inline_script && ! script) {
		cerr << "You must specify a destination host" << endl;
		goto usage;
	}

	if(openPcap()){
		return EXIT_FAILURE;
	}

	if (!probe && !script) {
		pkt = BuildProbe(net_proto, tr_proto, dport,sport,extra_payload,flag);
	} else if (probe && !script) {
		string cmd = probe;
		pkt = script_packet(cmd);
	} else if (script && !probe) {
		int rem_argc = argc - optind;
		char **rem_argv = rem_argc ? &argv[optind] : NULL;
		if (inline_script)
			ret = script_exec(script, rem_argc, rem_argv);
		else
			ret = script_execfile(script, rem_argc, rem_argv);
		goto out;
	} else {
		cerr << "You cannot specify a script and a probe at the same time" << endl;
		goto usage;
	}

	if (!pkt)
		return EXIT_FAILURE;

	if (npkts == 0 && kinterval == 0){
	    if (doTracebox(std::shared_ptr<Packet>(pkt),dscp,callback,err) < 0)
		{
		cerr << "Error: " << err << endl;
                goto usage;
        	}
	}
	
	if (npkts > 0 && kinterval > 0){
            
            if(tcpdump_cmd)
            {
                char command[120];
                sprintf(command,"ps -p %d > /dev/null 2>&1;",tcpdump_cmd);
                while(true)
                {
                    if(0==system(command))
                        break;
                }

            }
            
            if(dscp_flag)
            {
                if (doTracebox(std::shared_ptr<Packet>(pkt),dscp,callback,err) < 0)
                    {
                        cerr << "Error: " << err << endl;
                        goto usage;
                    }
            }else{
                
                hops_max_dscp = hops_max;
                
            }

	 if (doFloodbox(dport,sport,dscp,npkts,kinterval,times_pktbuff,seq_rand,err) < 0) {
		cerr << "Error: " << err << endl;
		goto usage;
	  }
	  
	  sleep(3.0);
          
          if(tcpdump_cmd)
            {
                char command[120];
                sprintf(command,"kill -2 %d",tcpdump_cmd);
                while(true)
                {
                    if(0==system(command))
                        break;
                }

            }
	}
    
	if (jobj != NULL) {
		json_object_object_add(jobj,"Hops", j_results);
		std::cout << json_object_to_json_string(jobj) << std::endl;
	}
out:
	closePcap();
	return ret;

usage:
	cerr << "Usage:\n"
"  " << argv[0] << " [ OPTIONS ] {host | [Lua argument list]}\n"
"Options are:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -6                          Use IPv6 for static probe generated\n"
"  -u                          Use UDP for static probe generated\n"
"  -d port                     Use the specified port for static probe\n"
"                              generated. Default is 80.\n"
"  -i device                   Specify a network interface to operate with\n"
"  -I packet_id                Specify a packet id number for IPv4 headdr\n"
"  -m hops_max                 Set the max number of hops (max TTL to be reached).\n"
"                              Default is 30.\n"
"  -M hops_min                 Set the min number of hops (min TTL to be reached).\n"
"                              Default is 1. \n"
"  -z                          If it is used, then we stop tracebox where we observe a DSCP change\n"
"  -v                          Print more information.\n"
"  -j                          Change the format of the output to JSON.\n"
"  -t timeout                  Timeout to wait for a reply after sending a packet.\n"
"                              Default is 1 sec, accepts decimals.\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script_file              Run a script file.\n"
"  -l inline_script            Run a script.\n"
"  -w                          Show warnings when crafting packets.\n"
"  -x sport                    Use the specified port for sport\n"
"  -e                          Extra payload (input=hexstring, eg -e 011011ef). Payload just after SCTP header,UDP, UDPLite, or IP (for IPSec)\n"
"  -a                          Use SCTP INIT for static probe generated\n"
"  -b                          Use DCCP Request for static probe generated\n"
"  -y                          Use UDPLite for static probe generated\n"
"  -q                          Use IPSec for static probe generated\n"
"  -o			       :0 for UDP with zero checksum and QUIC header\n"
"  -A	SRCMAC		       My MAC address of the interface\n"
"  -B	DSTMAC		       Neighbor MAC address of the interface\n"
"  -N	X		       Total X number of UDP packets with DSCP CS0 to be sent\n"
"  -K	Y		       Y Number of UDP packets interval after which we send TTL-limited UDP with CS0 and other codepoints all at once\n"
"  -F	N		       DSCP value N (in integer) to be set in tracebox packets\n"
"  -T   N                      Network stack generates faster than the Raw socket. Smaller value means smaller buffer passed to sendto(). N (in integer, >= 1)\n"
"  -L	sequence	       The sequence of values passed for T, For example, -T 4320 means -N N -K K where length(4320)=4=ceiling(N/K) and on 1st round, it sends 5 times of maximum packet size buffer is passed to sendto() and likewise\n"
#ifdef HAVE_LIBCURL
"  -c server_url               Specify a server where captured packets will be sent.\n"
"  -C                          Same than -c, but use the server at " DEFAULT_URL ".\n"
#endif
"  -f filename                 Specify the name of the pcap file.\n"
"                              Default is " DEFAULT_PCAP_FILENAME ".\n"
"  -S                          Skip the privilege check at the start.\n"
"                              To be used mainly for testing purposes,\n"
"	                           as it will cause tracebox to crash for some\n"
"							   of its features!.\n"
"  -V                          Print tracebox version and exit.\n"
"  -D                          Print debug information.\n"
"\n"
"Every argument passed after the options in conjunction with -s or -l will be passed\n"
"to the lua interpreter and available in a global vector of strings named 'argv',\n"
"in the order they appeared on the command-line.\n"
"\n\nVersion: " _REV_PARSE "\n"
	<< endl;
	return ret;
}
