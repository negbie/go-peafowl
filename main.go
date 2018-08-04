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

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

dpi_library_state_t* state; // the state

struct pcap_pkthdr* header;

// init state
int init()
{
	state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);

	if(state == NULL) {
	  fprintf(stderr, "dpi_init_stateful ERROR\n");
	  return -1; // ERROR
	}

	return 0;
  }

  // identify protocols l7
  int get_protocol(char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	int ID_protocol = -1;

	r = dpi_stateful_identify_application_protocol(state, (const u_char*) packet+sizeof(struct ether_header),
						   header->len-sizeof(struct ether_header), time(NULL));
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
  char * get_protocol_pair(char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	char * res;
	res = calloc(2,  sizeof(char));
	memset(res,0,2);

	r = dpi_stateful_identify_application_protocol(state, (const u_char*) packet+sizeof(struct ether_header),
						   header->len-sizeof(struct ether_header), time(NULL));
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
	C.init()

	flag.Parse()
	h, err := NewPcapgoHandle(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	for {

		data, ci, err := h.ReadPacketData()
		if err != nil {
			log.Fatal(err)
		}

		var hdr C.struct_pcap_pkthdr
		hdr.ts.tv_sec = C.long(ci.Timestamp.Unix())
		hdr.ts.tv_usec = C.long(ci.Timestamp.Nanosecond() / 1000)
		hdr.caplen = C.bpf_u_int32(len(data)) // Trust actual length over ci.Length.
		hdr.len = C.bpf_u_int32(ci.Length)
		dataptr := (*C.char)(unsafe.Pointer(&data[0]))

		log.Println(C.get_protocol(dataptr, &hdr))

		proto := C.GoString(C.get_protocol_pair(dataptr, &hdr))
		log.Println(proto)

	}
}
