//-------------------------------------------------------------------------------
//
// g711conversions.h - header in support of
//                g711conversions.c
//
//                Please see the preamble for g711conversions.c
//                That code was downloaded from the Internet
//                in an archive named: COSTG711.tar.gz 
//
//                That archive included the source file g711.c
//                It also contained a driver which included
//                the g711.c file directly into the driver's source.
//                This header was created so that the 
//                source (renamed to g711conversions.c)
//                could be compiled into a distinct library. 
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
//   Author: Mark D. Collier/Mark O'Brien - 08/16/2006  v1.0
//         www.securelogix.com - mark.collier@securelogix.com
//         www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

/*
 * g711.h  - 
 *
 * u-law, A-law and linear PCM conversions.
 */
 
#ifndef __G711CONVERSIONS_H
#define __G711CONVERSIONS_H

//
//  linear2alaw() - Convert a 16-bit linear PCM value to 8-bit A-law
//
//  linear2alaw() accepts an 16-bit integer and encodes it as A-law data.
//
 
unsigned char linear2alaw ( short pcm_val );

//
//  alaw2linear() - Convert an A-law value to 16-bit linear PCM
//

short alaw2linear ( unsigned char a_val);

//
//  linear2ulaw() - Convert a linear PCM value to u-law
//
 
unsigned char linear2ulaw ( short pcm_val );

//
//  ulaw2linear() - Convert a u-law value to 16-bit linear PCM
//

short ulaw2linear( unsigned char u_val );

//
//  A-law to u-law conversion
//

unsigned char alaw2ulaw ( unsigned char	aval );

//
//  u-law to A-law conversion
//

unsigned char ulaw2alaw ( unsigned char	uval );

#endif  //  __G711CONVERSIONS_H
