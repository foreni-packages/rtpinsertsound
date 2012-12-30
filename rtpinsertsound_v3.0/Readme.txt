A tool to insert audio into a specified audio (i.e. RTP) stream was created in
the August - September 2006 timeframe. The tool is named rtpinsertsound. It 
was tested on a Linux Red Hat Fedora Core 4 platform (Pentium IV, 2.5 GHz),
but it is expected this tool will successfully build and execute on a variety
of Linux distributions. The first distribution of the tool is: v1.1.

v3.0 is an upgrade produced in January 2007 to support the auto-detection
of RTP session endpoint addresses and ports via libfindrtp.

v2.0 is an upgrade produced in October 2006 to directly support the input
of certain wave (i.e. .wav) files into the tool as the source of audio
to insert, in addition to the input of audio in the form of a tcpdump
formatted file (i.e. G.711 RTP/UDP/IP/ETHERNET captures) which was
supported in v1.1.

    Copyright (c)  2006  Mark D. Collier/Mark O'Brien
    Permission is granted to copy, distribute and/or modify this document
    under the terms of the GNU Free Documentation License, Version 1.2
    or any later version published by the Free Software Foundation;
    with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
    A copy of the license is included in the section entitled "GNU
    Free Documentation License".
 
Authors:
    v3.0 : 01/03/2007
        Mark D. Collier <mark.collier@securelogix.com>, SecureLogix
	     Mark O'Brien, SecureLogix
        Dustin D. Trammell <dtrammell@tippingpoint.com>, TippingPoint
    v2.0 : 10/10/2006
    v1.0 : 08/14/2006
        Mark D. Collier <mark.collier@securelogix.com>, SecureLogix
	     Mark O'Brien, SecureLogix

    SecureLogix: http://www.securelogix.com
    TippingPoint: http://www.tippingpoint.com
    HackingExposed VoIP: http://www.hackingexposedvoip.com

This tool was produced with honorable intentions, which are:

  o To aid owners of VoIP infrastructure to test, audit, and uncover security
    vulnerabilities in their deployments.

  o To aid 3rd parties to test, audit, and uncover security vulnerabilities
    in the VoIP infrastructure of owners of said infrastructure who contract
    with or otherwise expressly approve said 3rd parties to assess said
    VoIP infrastructure.

  o To aid producers of VoIP infrastructure to test, audit, and uncover security
    vulnerabilities in the VoIP hardware/software/systems they produce.

  o For use in collective educational endeavors or use by individuals for
    their own intellectual curiosity, amusement, or aggrandizement - absent
    nefarious intent.
   
Unlawful use of this tool is strictly prohibited.

The following open-source libraries of special note were used to build
rtpinsertsound:

1) libnet v1.1.2.1 (tool requires at least this version)
2) libpcap v0.9.4  (tool will probably work with some earlier versions)
3) libfindrtp [ e.g. utility routine - libfindrtp_find_rtp( ) to sniff out RTP sessions ]
4) hack_library [ e.g. utility routine - Str2IP( ) ]

    Note: The Makefile for the rtpinsertsound presumes
          that hack_library.o and hack_library.h reside in
          a folder at ../hack_library relative to the Makefile
          within the rtpinsertsound directory.

5) a G.711 codec conversion library based upon open-source code
    from SUN published in the early 1990's and updated by 
    Borge Lindberg on 12/30/1994.

    Note: The Makefile for the rtpinsertsound tool presumes
          that the original g711.c file has been renamed
          g711conversions.c and a g711conversions.h file
          has been added. The rtpinsertsound tool Makefile
          presumes the header and object for this library
          reside in a folder at ../g711conversions relative
          to the folder where rtpinsertsound is built. The
          following comment is extracted from the source for
          your information:

    /*
     * December 30, 1994:
     * Functions linear2alaw, linear2ulaw have been updated to correctly
     * convert unquantized 16 bit values.
     * Tables for direct u- to A-law and A- to u-law conversions have been
     * corrected.
     * Borge Lindberg, Center for PersonKommunikation, Aalborg University.
     * bli@cpk.auc.dk
     *
     */

Install and build the libraries in accordance with their respective
instructions. Then change to the rtpinsertsound_v3.0 directory and simply
type: make

then:

[root@localhost rtpinsertsound_v3.0]# ./rtpinsertsound
 
Error: 1 command line parameter is mandatory

rtpinsertsound - Version 2.0
                 October 10, 2006
 Usage:
 Mandatory -
        pathname of file whose audio is to be mixed into the
            targeted live audio stream. If the file extension is
            .wav, then the file must be a standard Microsoft
            RIFF formatted WAVE file meeting these constraints:
              1) header 'chunks' must be in one of two sequences:
                   RIFF, fmt, fact, data
                     or
                   RIFF, fmt, data
              2) Compression Code = 1 (PCM/Uncompressed)
              3) Number of Channels = 1 (mono)
              4) Sample Rate (Hz) = 8000
              5) Significant Bits/Sample =
                      signed,   linear 16-bit or
                      unsigned, linear  8-bit
            If the file name does not specify a .wav extension,
            then the file is presumed to be a tcpdump formatted
            file with a sequence of, exclusively, G.711 u-law
            RTP/UDP/IP/ETHERNET messages
            Note: Yep, the format is referred to as 'tcpdump'
                  even though this file must contain udp messages
 Optional -
        -a source RTP IPv4 addr
        -A source RTP port
        -b destination RTP IPv4 addr
        -B destination RTP port
        -f spoof factor - amount by which to:
             a) increment the RTP hdr sequence number obtained
                from the ith legitimate packet to produce the
                RTP hdr sequence number for the ith spoofed packet
             b) multiply the RTP payload length and add that
                product to the RTP hdr timestamp obtained from
                the ith legitimate packet to produce the RTP hdr
                timestamp for the ith spoofed packet
             c) increment the IP hdr ID number obtained from the
                ith legitimate packet to produce the IP hdr ID
                number for the ith spoofed packet
           [ range: +/- 1000, default: 2 ]
        -i interface (e.g. eth0)
        -j jitter factor - the reception of a legitimate RTP
             packet in the target audio stream enables the output
             of the next spoofed packet. This factor determines
             when that spoofed packet is actually transmitted.
             The factor relates how close to the next legitimate
             packet you'd actually like the enabled spoofed packet
             to be transmitted. For example, -j 10 means 10% of
             the codec's transmission interval. If the transmission
             interval = 20,000 usec (i.e. G.711), then delay the
             output of the spoofed RTP packet until the time-of-day
             is within 2000 usec (i.e. 10%) of the time the next
             legitimate RTP packet is expected. In other words,
             delay 100% minus the jitter factor, or 18,000 usec
             in this example. The smaller the jitter factor, the
             greater the risk you run of not outputting the current
             spoofed packet before the next legitimate RTP packet
             is received. Therefore, a factor > 10 is advised.
           [ range: 0 - 80, default: 80 = output spoof ASAP ]
        -p seconds to pause between setup and injection
        -h help - print this usage
        -v verbose output mode

Note: If you are running the tool from a host with multiple
      ethernet interfaces which are up, be forewarned that
      the order those interfaces appear in your route table
      and the networks accessible from those interfaces might
      compel Linux to output spoofed audio packets to an
      interface different than the one stipulated by you on
      command line. This should not affect the tool unless
      those spoofed packets arrive back at the host through
      the interface you have specified on the command line
      (e.g. the interfaces have connectivity through a hub).
[root@EquinoxLX rtpinsertsound_v3.0]#

This tool does NOT presume it is running as Man-In-The-Middle
(MITM), however, it does presume that target audio (i.e. RTP) packet
streams of interest can be received by the specified Ethernet interface
in promiscuous mode (e.g. the host running the tool is connected to
a hub through which target audio packet streams are flowing).

The tool presently supports inserting audio into an audio stream
(i.e. RTP/UDP/IP/Ethernet) bearing G.711 u-law payloads only.
The RTP header of the target audio packets must be a standard
RFC 3550 12-byte RTP header. The tool does NOT automatically
detect and compensate for audio session modifications. The tool
does NOT presently support 802.1q (i.e. layer 2 VLAN/priority
tagging) within the 802.3 IEEE Ethernet header. The tool presumes
it is running on a little-endian platform.

Use Ethereal/Wireshark or some appropriate sniffer to determine the 
stream into which you'd like to insert an audio playback. You must
know the source IPv4 address, source UDP port, destination IPv4
address, and destination UDP port of the stream into which you'd like
to insert audio. This tool is unidirectional. If the insertion of the
audio is successful, the targeted destination will be persuaded to
accept the RTP packets inserted by this tool and reject the legitimate
audio packets that continue to stream from the legitimate source to the
target destination. In other words, audio from the legitimate source
will be muted during the duration of the playback. Perhaps it is more
technically correct to state that the pre-recorded bogus audio being
played back by the tool is being "interlaced" into the target audio
stream. 

Playback is rather arbitrarily limited to 30 seconds. You may change
the source code if you require a longer playback interval. 

The sound (i.e. audio) to insert into an audio stream must be in
one of two forms as stipulated by the usage printout appearing
above.

If a wave file you'd like to input to the tool does not comply with
the constraints imposed by the tool, you will need to use an audio
conversion utility to massage the file into a form acceptable by the
tool. For example, many wave files on the Net are in this format:

Compression Code:        1
Channels:                1
Sample Rate (Hz):        11025
Avg. Bytes/sec:          11025
Block Align:             1
Significant Bits/sample: 8
 
A sample rate of 11025 is not presently supported by the tool.
The Linux sox command might be used to convert the file to 
the required 8000 Hz sample rate. If the file is named
swclear.wav then:

sox -V swclear.wav -r 8000 swclear_resample.wav resample -ql

converts swclear.wav to swclear_resample.wav with the
following format:

Compression Code:        1
Channels:                1
Sample Rate (Hz):        8000
Avg. Bytes/sec:          8000
Block Align:             1
Significant Bits/sample: 8

The sox command can also be used to convert multi-channel
audio to mono, covert different compression codes to the
PCM/uncompressed format required by the tool, and convert
the number of significant bits/sample, among many other
conversions.

Unfortunately, sox does not support the conversion of wave files
from MPEG format to the format required by the tool. If you 
attempted a similar sox command to the one above for the a
MPEG Layer 3 formatted file you'd get this error:

sox: Failed reading khan.wav: Sorry, this WAV file is in MPEG Layer 3 format.

For tcpdump formatted input files, the file must be composed of
sequential RTP/UDP/IP/Ethernet messages, where the RTP payloads
are encoded using the G.711 u-law codec (i.e. PCMU). Our sound
files were produced using the Asterisk open-source IP PBX. Asterisk
“call files” were used to call a VoIP phone that was configured
with a preference to receive audio processed by the G.711 u-law
codec. The call file stipulated the sound file to play once the
call was connected. The Ethereal/Wireshark network analyzer tool
was used to capture the G.711 packets flowing from the Asterisk
IP PBX to the phone. These were saved into a standard tcpdump
file. There are, no doubt, many other mechanisms to produce such
a file.

Note: For operation of the open-source Asterisk IP PBX and 
         an explanation of "call files", see: Asterisk: The Future of
         Telephony, by Jim Van Meggelen, Jared Smith, and Leif Madsen.
         Copyright 2005 O’Reilly Media, Inc., 0-596-00962-3.
 
         A softcopy of that book is available on-line as a legitimately
         free download.

A later version of the tool might be capable of inputting a
greater variety of audio file formats.
 
When the tool is executed, it first loads the pre-recorded audio into 
memory. Then it attempts to detect a packet from the audio stream
designated on the command line. The output of bogus audio interlaced
into the legitimate audio stream is close-looped with the reception of
legitimate audio packets.

The optional spoof factor value might be specified on the command line
(i.e. default = 2). As reported by the tool's usage printout, the
spoof factor is used to adjust key RTP header and IP header values
in an inserted audio packet relative to those values in the legitimate
audio packet triggering the insertion of that bogus audio packet.
Adjusting those key header values slightly higher (or lower) relative
to the last legitimate packet may persuade the target destination to
accept the inserted packets and reject the legitimate packets it
continues to receive.

The optional jitter factor value might be specified on the command line
(i.e. default 80% = ASAP). The jitter factor determines exactly when
the next bogus audio packet is inserted relative to the received audio
packet triggering the output of the bogus packet. The default value
outputs the bogus packet ASAP. A value less than 80% requires the
bogus packet to be output closer to when the next legitimate packet
is expected. The factor is expressed as a percentage of the ideal
codec transmission interval, which is every 20 ms for G.711 u-law.
So, for G.711:

jitter factor       how close to the next legitimate packet
      %             the bogus packet is transmitted
-------------       -------------------------------------------
      80            close to 20 ms (i.e. ASAP - within a couple
                    of hundred usec after the trigger packet)

      70            14 ms (i.e.  6 ms after the trigger packet)
      60            12 ms (i.e.  8 ms after the trigger packet)
      50            10 ms (i.e. 10 ms after the trigger packet)
      40             8 ms (i.e. 12 ms after the trigger packet)
      30             6 ms (i.e. 14 ms after the trigger packet)                   
      20             4 ms (i.e. 16 ms after the trigger packet)
      10             2 ms (i.e. 18 ms after the trigger packet)
       5             1 ms (i.e. 19 ms after the trigger packet)

When a jitter factor other than 80 is specified, the execution priority
of the tool is increased to the maximum. You'll probably note that other 
applications and GUI's running on the same platform will decrease
in responsiveness (e.g. Ethereal). Only one VoIP hard phone model has
been encountered by the authors thus far (out of 8) that requires a jitter
factor other than the default value. The timing is not as precise as
the table might indicate. A jitter factor too close to 0 usually
results in the tool failing, at some point in the playback, to output a
bogus packet before the next legitimate packet is received. The tool
detects that condition and halts with an appropriate error message.

Example:

./rtpinsertsound eth0 10.1.101.40 39120 10.1.101.60 64006 g711CaptureAlphabetRecitation -f 1 -j 10

In this example, the audio from the tcpdump file named
g711CaptureAlphabetRecitation within the rtpinsertsound folder is
inserted into the G.711 audio stream from the VoIP source at
10.1.101.40:39120 to the VoIP destination at 10.1.101.60:64006.
Each bogus audio packet is transmitted approximately 18 ms after
the prior legitimate audio packet is received by the tool. The
factor to apply to manipulate key RTP header and IP header
values in a bogus packet, relative to its legitimate trigger
packet is: 1

Alternatively, an appropriate wave file could be used:

./rtpinsertsound eth0 10.1.101.40 39120 10.1.101.60 64006 AlphabetRecitation.wav -f 1 -j 10

If the tool pauses for a noticeable interval when initially attempting
to sync to the audio stream, it very likely means one or more of the 
following conditions exist:

a) the stream is not present at the specified Ethernet interface
b) the audio stream does not exist (i.e. the call has ended or changed state)
c) the user has not entered the IPv4 addresses or UDP ports properly

Since the output of bogus audio is close-looped to the reception of the
target audio stream, the tool stalls if the target audio stream ends
or changes state during the playback.

A compilation directive determines whether the object code of the tool is
produced with Ethernet layer spoofing or whether IP layer spoofing is
sufficient. Testing to-date has demonstrated that Ethernet layer spoofing
is NOT required. The tool executes faster when it is not required to spoof
at the Ethernet layer. Ethernet layer spoofing is not recommended.

Mark O'Brien (10/11/2006)
