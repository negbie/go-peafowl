package main

/*
#cgo CFLAGS: -I peafowl_lib/lib
#cgo LDFLAGS: peafowl_lib/lib/libdpi.a

#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include "peafowl_lib/src/api.h"

#ifdef WIN32
#define gopacket_time_secs_t long
#define gopacket_time_usecs_t long
#elif __APPLE__
#define gopacket_time_secs_t __darwin_time_t
#define gopacket_time_usecs_t __darwin_suseconds_t
#elif __ANDROID__
#define gopacket_time_secs_t __kernel_time_t
#define gopacket_time_usecs_t __kernel_suseconds_t
#elif __GLIBC__
#define gopacket_time_secs_t __time_t
#define gopacket_time_usecs_t __suseconds_t
#else  // Some form of linux/bsd/etc...
#include <sys/param.h>
#ifdef __OpenBSD__
#define gopacket_time_secs_t u_int32_t
#define gopacket_time_usecs_t u_int32_t
#else
#define gopacket_time_secs_t time_t
#define gopacket_time_usecs_t suseconds_t
#endif
#endif

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

dpi_library_state_t* state; // the state
struct pcap_pkthdr* header;
const u_char* packet;

uint ip_offset=0;
u_int32_t unknown=0;
u_int32_t http_matches=0;
u_int32_t dns_matches=0;
u_int32_t bgp_matches=0;
u_int32_t smtp_matches=0;
u_int32_t pop3_matches=0;
u_int32_t mdns_matches=0;
u_int32_t ntp_matches=0;
u_int32_t dhcp_matches=0;
u_int32_t dhcpv6_matches=0;
u_int32_t rtp_matches=0;
u_int32_t sip_matches=0;



// init state
int init()
{
	state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
	ip_offset=sizeof(struct ether_header);

	if(state == NULL) {
	  return -1;
	}

	return 0;
  }

  // identify protocols l7
  int get_protocol(const u_char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	int ID_protocol = -1;

	r = dpi_stateful_identify_application_protocol(state, packet+ip_offset,
													header->caplen-ip_offset, time(NULL));

	if(r.protocol.l4prot==IPPROTO_TCP){
		switch(r.protocol.l7prot){
			case DPI_PROTOCOL_TCP_BGP:
				++bgp_matches;
				break;
			case DPI_PROTOCOL_TCP_HTTP:
				++http_matches;
				break;
			case DPI_PROTOCOL_TCP_SMTP:
				++smtp_matches;
				break;
			case DPI_PROTOCOL_TCP_POP3:
				++pop3_matches;
				break;
			default:
				++unknown;
				break;
		}
	}else if(r.protocol.l4prot==IPPROTO_UDP){
		switch(r.protocol.l7prot){
			case DPI_PROTOCOL_UDP_DHCP:
				++dhcp_matches;
				break;
			case DPI_PROTOCOL_UDP_DHCPv6:
				++dhcpv6_matches;
				break;
			case DPI_PROTOCOL_UDP_DNS:
				++dns_matches;
				break;
			case DPI_PROTOCOL_UDP_MDNS:
				++mdns_matches;
				break;
			case DPI_PROTOCOL_UDP_NTP:
				++ntp_matches;
				break;
			case DPI_PROTOCOL_UDP_RTP:
				++rtp_matches;
				break;
			case DPI_PROTOCOL_UDP_SIP:
				++sip_matches;
				break;
			default:
				++unknown;
				break;
		}
	}else{
		++unknown;
	}


	if(r.protocol.l4prot == IPPROTO_UDP){
	  if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
		return r.protocol.l7prot;
	  }
	} else if(r.protocol.l4prot == IPPROTO_TCP){
	  if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
		return DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
	  }
	}
	return ID_protocol;
  }

  // identify protocols pairs [l7,l4]
  char * get_protocol_pair(const u_char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	char * res;
	res = malloc(2 * sizeof(char));
	memset(res,-1,2);

	r = dpi_stateful_identify_application_protocol(state, packet+ip_offset,
		                                        	header->caplen-ip_offset, time(NULL));
	if(r.protocol.l4prot == IPPROTO_UDP){
	  res[0] = IPPROTO_UDP;
	  if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
		res[1] = r.protocol.l7prot;
		return res;
	  }
	} else if(r.protocol.l4prot == IPPROTO_TCP){
	  res[0] = IPPROTO_TCP;
	  if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
		res[1] = DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
		return res;
	  }
	}
	return res;
  }

  // terminate
  void terminate()
  {
	dpi_terminate(state);
  }
*/
import "C"
import (
	"flag"
	"io"
	"log"
	"os"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

var (
	pcapFile = flag.String("rf", "", "PCAP file")
)

type PcapgoHandle struct {
	reader     *pcapgo.Reader
	fileReader io.ReadCloser
}

func NewPcapgoHandle(f string) (*PcapgoHandle, error) {
	fileReader, err := os.Open(f)
	if err != nil {
		return nil, err
	}

	reader, err := pcapgo.NewReader(fileReader)
	if err != nil {
		return nil, err
	}
	return &PcapgoHandle{
		reader:     reader,
		fileReader: fileReader,
	}, nil
}

func (a *PcapgoHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := a.reader.ReadPacketData()
	return data, ci, err
}

func (a *PcapgoHandle) Close() error {
	return a.fileReader.Close()
}

func main() {
	flag.Parse()

	state := C.init()
	if state == -1 {
		log.Fatal("dpi_init_stateful ERROR")
	}
	defer C.terminate()

	h, err := NewPcapgoHandle(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	for {

		data, ci, err := h.ReadPacketData()
		if err == io.EOF {
			log.Println("-------------------------------------")
			log.Printf("Unknown:\t%d\n", C.unknown)
			log.Printf("HTTP:\t%d\n", C.http_matches)
			log.Printf("BGP:\t%d\n", C.bgp_matches)
			log.Printf("POP3:\t%d\n", C.pop3_matches)
			log.Printf("SMTP:\t%d\n", C.smtp_matches)
			log.Printf("NTP:\t%d\n", C.ntp_matches)
			log.Printf("DNS:\t%d\n", C.dns_matches)
			log.Printf("MDNS:\t%d\n", C.mdns_matches)
			log.Printf("DHCP:\t%d\n", C.dhcp_matches)
			log.Printf("DHCPv6:\t%d\n", C.dhcpv6_matches)
			log.Printf("RTP:\t%d\n", C.rtp_matches)
			log.Printf("SIP:\t%d\n", C.sip_matches)
			log.Println("-------------------------------------")
			log.Fatal("reached end of file")
		} else if err != nil {
			log.Fatal(err)
		}

		var hdr C.struct_pcap_pkthdr
		hdr.ts.tv_sec = C.gopacket_time_secs_t(ci.Timestamp.Unix())
		hdr.ts.tv_usec = C.gopacket_time_usecs_t(ci.Timestamp.Nanosecond() / 1000)
		hdr.caplen = C.bpf_u_int32(len(data)) // Trust actual length over ci.Length.
		hdr.len = C.bpf_u_int32(ci.Length)

		dataptr := (*C.u_char)(unsafe.Pointer(&data[0]))

		C.get_protocol(dataptr, &hdr)
		C.get_protocol_pair(dataptr, &hdr)
	}

}
