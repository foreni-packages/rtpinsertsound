//-------------------------------------------------------------------------------
//
// rtpinsertsound.h - Command line tool to insert the
//               content of a sound (i.e. audio) file into a call.
//
//               Please refer to rtpinsertsound.c for an
//               overview of the functionality of the tool.
//               
//    Copyright (C) 2006  Mark D. Collier/Mark O'Brien
//
//    This program is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program; if not, write to the Free Software
//    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
//    Authors:
//        v3.0 : 01/03/2007
//            Mark D. Collier <mark.collier@securelogix.com>, SecureLogix
//            Mark O'Brien, SecureLogix
//            Dustin D. Trammell <dtrammell@tippingpoint.com>, TippingPoint
//        v2.0 : 10/10/2006
//        v1.0 : 08/14/2006
//            Mark D. Collier <mark.collier@securelogix.com>, SecureLogix
//            Mark O'Brien, SecureLogix
//
//        SecureLogix: http://www.securelogix.com
//        TippingPoint: http://www.tippingpoint.com
//        Hacking Exposed VoIP: http://www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

#ifndef __RTPINSERTSOUND_H
#define __RTPINSERTSOUND_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h> 
#include <unistd.h>

#define __RTPINSERTSOUND_VERSION  "rtpinsertsound - Version 2.0"
#define __RTPINSERTSOUND_DATE     "                 October 10, 2006"

#define __RTPINSERTSOUND_PROMISCOUS_MODE 1

#define __RTPINSERTSOUND_LIBNET_IP         3
#define __RTPINSERTSOUND_LIBNET_ETHERNET   2

#define __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER __RTPINSERTSOUND_LIBNET_IP

#define __RTPINSERTSOUND_G711_PAYLOAD_TYPE         0

#define __RTPINSERTSOUND_G711_PAYLOAD_LEN          160

#define __RTPINSERTSOUND_G711_CODEC_RATE_HZ        50

#define __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC  20000

#define __RTPINSERTSOUND_G711_AUDIO_TO_INSERT_SEC  30

#define __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT __RTPINSERTSOUND_G711_CODEC_RATE_HZ * __RTPINSERTSOUND_G711_AUDIO_TO_INSERT_SEC

#define __RTPINSERTSOUND_PCM_UNCOMPRESSED_COMPRESSION_CODE  1

char libnet_errbuf        [LIBNET_ERRBUF_SIZE];

int opt;
int optind;
int deltaTSec;
int deltaTUsec;
int sockfd                       = 0;
int rc                           = 0;

unsigned int jitterDelayUsec     = 0;
unsigned int jitterProximityUsec = 0;

//unsigned int numPackets      = 0;

bool bVerbose                = false;

const u_char *packet         = NULL;

pcap_t *h_pcap_live_rtp                 = NULL;  //  libpcap "handle"

struct pcap_pkthdr *ppcap_pkthdr        = NULL;
struct pcap_pkthdr pcap_header;
    
struct libnet_ethernet_hdr *eth_hdr     = NULL;
struct libnet_ipv4_hdr *ip_hdr          = NULL;
struct libnet_udp_hdr *udp_hdr          = NULL;
    
struct rfc1889_rtp_hdr {
    
    //  byte 0 - uppermost byte of header
    //  bit fields are defined starting from rightmost bits and
    //  encountering higher order bits as you proceed down the page.
    //  for example: cc occupies the low-order 4 bits of the byte.

    unsigned int cc : 4;                    // CSRC Count (i.e. # of CSRC hdrs following fixed hdr)
    unsigned int bExtensionIncluded : 1;    // if RTP hdr includes 1 extension hdr 
    unsigned int bPaddingIncluded : 1;      // if the RTP payload is padded
    unsigned int version : 2;               // should always equal version 2
    
    //  byte 1
    //  bits are defined from rightmost bits first and leftmost bits as you proceed down the page
    
    unsigned int payloadType : 7;
    unsigned int bMarker : 1;               // Mark

    //  bytes 3 & 2 (i.e. network order)
    
    unsigned short sequenceNumber;          // Should inc by 1.
    
    //  bytes 7, 6, 5, 4 (i.e. network order)
    
    unsigned int timestamp;                 // For G.711 should inc by 160.
    
    //  bytes 11, 10, 9, 8 (i.e. network order)
        
    unsigned int ssrc;                      // Synchronization Source - fixed for a stream
}; 

struct rfc1889_rtp_hdr *rtp_hdr = NULL;
    
unsigned int offset_to_ip_hdr  = LIBNET_ETH_H;
unsigned int offset_to_udp_hdr = LIBNET_ETH_H + LIBNET_IPV4_H;
unsigned int offset_to_rtp_msg = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H;
unsigned int offset_to_rtp_payload = 
                LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H +
                sizeof ( struct rfc1889_rtp_hdr );

unsigned int g711_rtp_msg_len = __RTPINSERTSOUND_G711_PAYLOAD_LEN +
                                sizeof ( struct rfc1889_rtp_hdr );

struct bpf_program compiled_pcap_filter;
    
libnet_t *l                     = NULL;

libnet_ptag_t udp_tag           = 0;
libnet_ptag_t ip_tag            = 0;
libnet_ptag_t ether_tag         = 0;

struct timeval time_of_day;

struct ifreq ifreq;
unsigned char deviceMAC[IFHWADDRLEN];

//    
//  Each PCMU value is an 8-bit, non-linear, unsigned datum
//

typedef struct pcmu {    
    unsigned char pcmu_value[ __RTPINSERTSOUND_G711_PAYLOAD_LEN ]; 
} pcmuG711;

struct pcmu pcmuSamplesToInsert[ __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT ];

typedef struct rtp_msg {
    struct rfc1889_rtp_hdr rtp_hdr;
    unsigned char          rtp_payload[ __RTPINSERTSOUND_G711_PAYLOAD_LEN ];
} rtpG711Msg;

bool  preloadWavAudio ( char *psInputAudioFile,
                        struct pcmu pcmuSamplesToInsert[], 
                        unsigned int *numG711PacketEquivalents );

bool  preloadTCPdumpAudio ( char *psInputAudioFile,
                            struct pcmu pcmuSamplesToInsert[], 
                            unsigned int *numG711PacketEquivalents );                                         

void  delayTransmitOfSpoofedPacket ( unsigned int codecIntervalUsec );
void  decodeAndPrintRTPMsg( const u_char *packet );
void  catch_signals  ( int signo  );
void  CleanupAndExit ( int status );
void  usage          ( int status );

#endif  //  __RTPINSERTSOUND_H
