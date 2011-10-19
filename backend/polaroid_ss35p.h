/* sane - Scanner Access Now Easy.
   Copyright (C) 2011 Andreas Sandberg
   This file is part of the SANE package.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA.

   As a special exception, the authors of SANE give permission for
   additional uses of the libraries contained in this release of SANE.

   The exception is that, if you link a SANE library with other files
   to produce an executable, this does not by itself cause the
   resulting executable to be covered by the GNU General Public
   License.  Your use of that executable is in no way restricted on
   account of linking the SANE library code into it.

   This exception does not, however, invalidate any other reasons why
   the executable file might be covered by the GNU General Public
   License.

   If you submit changes to SANE to the maintainers to be included in
   a subsequent release, you agree by submitting the changes that
   those changes may be distributed with this exception intact.

   If you write modifications of your own for SANE, it is your choice
   whether to permit this exception to apply to your modifications.
   If you do not wish that, delete this exception notice.  */

/* $Id$ */

#ifndef polaroid_ss35p_h
#define polaroid_ss35p_h

#include <sys/types.h>

typedef enum {
  OPT_NUM_OPTS = 0,

  /* ------------------------------------------- */
  OPT_MODE_GROUP,
  OPT_MODE,
  OPT_SOURCE,
  OPT_RESOLUTION,

  /* ------------------------------------------- */
  OPT_GEOMETRY_GROUP,
  OPT_TL_X,
  OPT_TL_Y,
  OPT_BR_X,
  OPT_BR_Y,

  /* ------------------------------------------- */
  NUM_OPTIONS
} Polaroid_SS35P_Option;


typedef enum {
    SS35P_MEDIA_LANDSCAPE = 0,
    SS35P_MEDIA_PORTRAIT = 1,
    SS35P_MEDIA_SUPER_SLIDE = 4
} Polaroid_SS35P_Media;

typedef enum {
    SS35P_COLOR_UNKNOWN = 0,
    SS35P_COLOR_GRAY = 2,
    SS35P_COLOR_COLOR = 5
} Polaroid_SS35P_Color;

typedef struct Polaroid_SS35P_Device {
  struct Polaroid_SS35P_Device *next;
  SANE_Device sane;

  /* Revision is only 4 bytes, but we zero-terminate for
     convenience */
  char revision[5];

} Polaroid_SS35P_Device;

typedef struct Polaroid_SS35P_Scanner {
  struct Polaroid_SS35P_Scanner *next;

  struct Polaroid_SS35P_Device *device;

  SANE_Option_Descriptor opt[NUM_OPTIONS];
  Option_Value val[NUM_OPTIONS];

  int fd;
  FILE *file_dmp;

  Polaroid_SS35P_Media media;
  Polaroid_SS35P_Color color_mode;
  u_int dpi;
  u_int bits_per_pixel;
  u_int bytes_per_pixel;
  u_int x0;
  u_int y0;
  u_int width;
  u_int height;

  u_int current_line;

} Polaroid_SS35P_Scanner;

#endif /* polaroid_ss35p_h */

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * c-file-style: "gnu"
 * End:
 */
