The G.711 codec conversion library is based upon open-source code from SUN
published in the early 1990's and updated by Borge Lindberg on 12/30/1994.
It was downloaded from the Net in an archive named: COSTG711.tar.gz

The source file was renamed to: g711conversions.c

The header file was created by the authors of this Readme file and reference
to it was edited into g711conversions.c. The header was created so the source
could be compiled into a distinct library for reference by other programs.

    Copyright (c)  2006  Mark D. Collier/Mark O'Brien
    Permission is granted to copy, distribute and/or modify this document
    under the terms of the GNU Free Documentation License, Version 1.2
    or any later version published by the Free Software Foundation;
    with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
    A copy of the license is included in the section entitled "GNU
    Free Documentation License".
 
Authors:  Mark D. Collier/Mark O'Brien   08/16/2006  v1.1
          www.securelogix.com - mark.collier@securelogix.com
          www.hackingexposedvoip.com
          
/*
 * This source code is a product of Sun Microsystems, Inc. and is provided
 * for unrestricted use.  Users may copy or modify this source code without
 * charge.
 */

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
