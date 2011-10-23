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
   If you do not wish that, delete this exception notice. */

#include "../include/sane/config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#define BUILD 0
#define BACKEND_NAME	polaroid_ss35p
#define POLAROID_SS35P_CONFIG_FILE "polaroid_ss35p.conf"

#include "../include/sane/sane.h"
#include "../include/sane/sanei.h"
#include "../include/sane/sanei_config.h"
#include "../include/sane/sanei_scsi.h"
#include "../include/sane/saneopts.h"

#include "../include/sane/sanei_backend.h"

#include "polaroid_ss35p.h"

#define DBG_ERROR0  0
#define DBG_ERROR   1
#define DBG_WARNING 2
#define DBG_INFO    3
#define DBG_SANE    4
#define DBG_SS35P   5
#define DBG_SCSI    6

#define MAX_SOURCE_SIZE 128
#define MAX_MODE_SIZE 128

#define SCSI_TEST_UNIT_READY 0x00
#define SCSI_REQUEST_SENSE 0x03
#define SCSI_INQUIRY 0x12
#define SCSI_MODE_SELECT 0x15
#define SCSI_START_STOP 0x1B
#define SCSI_READ_10 0x28
#define SCSI_WRITE_10 0x2A
#define SCSI_SET_WINDOW 0x24
#define SCSI_WRITE_BUFFER 0x3B


#define SCSI_INQ_REPLY_LEN 96
#define SCSI_INQ_VENDOR_OFFSET 8
#define SCSI_INQ_VENDOR_LEN 8
#define SCSI_INQ_PRODUCT_OFFSET 16
#define SCSI_INQ_PRODUCT_LEN 16
#define SCSI_INQ_REVISION_OFFSET 32
#define SCSI_INQ_REVISION_LEN 4

#define SCSI_SENSE_REPLY_LEN 19

#define SS35P_SENSE_LEN (SCSI_SENSE_REPLY_LEN + 11)

#define GET_BYTE(i, offset) (((i) >> offset) & 0xFF)
#define SET_BE_INT16(p, i)                      \
  do {                                          \
    (p)[0] = GET_BYTE((i), 8);                  \
    (p)[1] = GET_BYTE((i), 0);                  \
  } while(0)

#define SET_BE_INT24(p, i)                      \
  do {                                          \
    (p)[0] = GET_BYTE((i), 16);                 \
    (p)[1] = GET_BYTE((i), 8);                  \
    (p)[2] = GET_BYTE((i), 0);                  \
  } while(0)

#define SET_BE_INT32(p, i)                      \
  do {                                          \
    (p)[0] = GET_BYTE((i), 24);                 \
    (p)[1] = GET_BYTE((i), 16);                 \
    (p)[2] = GET_BYTE((i), 8);                  \
    (p)[3] = GET_BYTE((i), 0);                  \
  } while(0)

#define GET_BE_UINT16(p)                                 \
  (((u_int)(p)[0] << 8) |                                \
   ((u_int)(p)[1] << 0))

#define GET_BE_UINT32(p)                                 \
  (((u_int)(p)[0] << 24) |                               \
   ((u_int)(p)[1] << 16) |                               \
   ((u_int)(p)[2] << 8) |                                \
   ((u_int)(p)[3] << 0))

static SANE_String_Const scan_source_list[] = {
  "Landscape",
  "Portrait",
  "Super Slide",
};

static Polaroid_SS35P_Media scan_source_num[] = {
  SS35P_MEDIA_LANDSCAPE,
  SS35P_MEDIA_PORTRAIT,
  SS35P_MEDIA_SUPER_SLIDE,
};

static SANE_String_Const scan_mode_list[] = {
  SANE_VALUE_SCAN_MODE_COLOR,
  SANE_VALUE_SCAN_MODE_GRAY,
};

static Polaroid_SS35P_Color scan_mode_num[] = {
  SS35P_COLOR_COLOR,
  SS35P_COLOR_GRAY,
};

#define ABORT(m)                                                        \
  do {                                                                  \
    DBG(DBG_ERROR, "Assertion failure in '%s:%i': %s\n",                \
        __FILE__, __LINE__, m);                                         \
    abort();                                                            \
  } while(0)

static const SANE_Range dpi_range = { 127, 2700, 0 };

/* @2700 DPI
 * Landscape: 3916x2700
 * Portrait: 2700x3916
 * Super Slide: 3916x3916
 */

static const SANE_Range x_range = { 0, SANE_FIX(36), 0 };
static const SANE_Range y_range = { 0, SANE_FIX(36), 0 };

static SANE_Option_Descriptor default_opt[] = {
  {
    SANE_NAME_NUM_OPTIONS,
    SANE_TITLE_NUM_OPTIONS,
    SANE_DESC_NUM_OPTIONS,
    SANE_TYPE_INT,
    SANE_UNIT_NONE,
    sizeof(SANE_Word),
    SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_NONE,
    {NULL}
  },

  {
    "",
    SANE_I18N ("Scan Mode"),
    "",
    SANE_TYPE_GROUP,
    SANE_UNIT_NONE,
    0,
    0,
    SANE_CONSTRAINT_NONE,
    {NULL}
  }, {
    SANE_NAME_SCAN_MODE,
    SANE_TITLE_SCAN_MODE,
    SANE_DESC_SCAN_MODE,
    SANE_TYPE_STRING,
    SANE_UNIT_NONE,
    MAX_MODE_SIZE,
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_STRING_LIST,
    {(SANE_String_Const *)scan_mode_list}
  }, {
    SANE_NAME_SCAN_SOURCE,
    SANE_TITLE_SCAN_SOURCE,
    SANE_DESC_SCAN_SOURCE,
    SANE_TYPE_STRING,
    SANE_UNIT_NONE,
    MAX_SOURCE_SIZE,
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_STRING_LIST,
    {(SANE_String_Const *)scan_source_list}
  }, {
    SANE_NAME_SCAN_RESOLUTION,
    SANE_TITLE_SCAN_RESOLUTION,
    SANE_DESC_SCAN_RESOLUTION,
    SANE_TYPE_INT,
    SANE_UNIT_DPI,
    sizeof(SANE_Word),
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_RANGE,
    {(const SANE_String_Const *)&dpi_range}
  },

  {
    "",
    SANE_I18N ("Geometry"),
    "",
    SANE_TYPE_GROUP,
    SANE_UNIT_NONE,
    0,
    SANE_CAP_ADVANCED,
    SANE_CONSTRAINT_NONE,
    {NULL}
  }, {
    SANE_NAME_SCAN_TL_X,
    SANE_TITLE_SCAN_TL_X,
    SANE_DESC_SCAN_TL_X,
    SANE_TYPE_FIXED,
    SANE_UNIT_MM,
    sizeof (SANE_Word),
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_RANGE,
    {(const SANE_String_Const *)&x_range}
  }, {
    SANE_NAME_SCAN_TL_Y,
    SANE_TITLE_SCAN_TL_Y,
    SANE_DESC_SCAN_TL_Y,
    SANE_TYPE_FIXED,
    SANE_UNIT_MM,
    sizeof (SANE_Word),
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_RANGE,
    {(const SANE_String_Const *)&y_range}
  }, {
    SANE_NAME_SCAN_BR_X,
    SANE_TITLE_SCAN_BR_X,
    SANE_DESC_SCAN_BR_X,
    SANE_TYPE_FIXED,
    SANE_UNIT_MM,
    sizeof (SANE_Word),
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_RANGE,
    {(const SANE_String_Const *)&x_range}
  }, {
    SANE_NAME_SCAN_BR_Y,
    SANE_TITLE_SCAN_BR_Y,
    SANE_DESC_SCAN_BR_Y,
    SANE_TYPE_FIXED,
    SANE_UNIT_MM,
    sizeof (SANE_Word),
    SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT,
    SANE_CONSTRAINT_RANGE,
    {(const SANE_String_Const *)&y_range}
  },
};

static char *firmware_dir = NULL;

static SANE_Auth_Callback frontend_authorize_callback;

static Polaroid_SS35P_Device *ss35p_devices = NULL;
static int ss35p_num_devices = 0;

static void
dump_scsi_req(const void *req, size_t req_size,
              const void *data, size_t data_size)
{
  const u_char *c;

  if (DBG_SCSI <= DBG_LEVEL) {
    fprintf(stderr, "W: ");
    for (c = (const u_char *)req; c != (const u_char *)req + req_size; c++)
      fprintf(stderr, "%.2x", (u_int)*c);

    if (data) {
      for (c = (const u_char *)data; c != (const u_char *)data + data_size; c++)
        fprintf(stderr, "%.2x", (u_int)*c);
    }

    fprintf(stderr, "\n");
  }
}

#if 0
static SANE_Status
scsi_test_unit_ready(int fd)
{
  u_char req[] = {
    SCSI_TEST_UNIT_READY,
    0,               /* LUN */
    0, 0, 0,         /* Reserved */
    0                /* Control */
  };

  dump_scsi_req(req, sizeof(req), NULL, 0);
  return sanei_scsi_cmd(fd, req, sizeof(req), NULL, NULL);
}
#endif

static SANE_Status
scsi_inquiry(int fd, void *resp, size_t *resp_len)
{
  u_char req[] = {
    SCSI_INQUIRY,
    0,               /* LUN & EVPD */
    0,               /* Page */
    0, 0,            /* Response length */
    0                /* Control */
  };

  SET_BE_INT16(req + 3, *resp_len);

  dump_scsi_req(req, sizeof(req), NULL, 0);
  return sanei_scsi_cmd(fd, req, sizeof(req), resp, resp_len);
}

static SANE_Status
scsi_request_sense(int fd, void *buf, size_t *size)
{
  char req[] = {
    SCSI_REQUEST_SENSE,
    0,                   /* LUN & Reserved */
    0,                   /* Reserved */
    0,                   /* Reserved */
    0,                   /* Size */
    0                    /* Control */
  };

  req[4] = (u_char)*size;

  assert(*size <= 0xFF);

  dump_scsi_req(req, sizeof(req), NULL, 0);
  return sanei_scsi_cmd(fd, req, sizeof(req), buf, size);
}


static SANE_Status
scsi_read(int fd, u_int addr, u_int size, void *dst, size_t *dst_size)
{
  char req[] = {
    SCSI_READ_10,
    0,              /* LUN etc */
    0, 0, 0, 0,     /* Address */
    0,              /* Reserved */
    0, 0,           /* Size */
    0               /* Control */
  };

  SET_BE_INT32(req + 2, addr);
  SET_BE_INT16(req + 7, size);

  assert(addr <= 0xFFFFFFFF);
  assert(size <= 0xFFFF);
  
  dump_scsi_req(req, sizeof(req), NULL, 0);
  return sanei_scsi_cmd(fd, req, sizeof(req), dst, dst_size);
}

static SANE_Status
scsi_write(int fd, u_int addr, const void *data, size_t size)
{
  char req[] = {
    SCSI_WRITE_10,
    0,              /* Various control stuff */
    0, 0, 0, 0,     /* Address */
    0,              /* Group */
    0, 0,           /* Size */
    0               /* Control */
  };

  SET_BE_INT32(req + 2, addr);
  SET_BE_INT16(req + 7, size);

  assert(addr <= 0xFFFFFFFF);
  assert(size <= 0xFFFF);
  
  dump_scsi_req(req, sizeof(req), data, size);
  return sanei_scsi_cmd2(fd,
                         req, sizeof(req), data, size,
                         NULL, NULL);
}

static SANE_Status
scsi_write_buffer(int fd, u_char mode, u_char buffer_id, u_int offset,
                  void *data, size_t size)
{
  char req[] = {
    SCSI_WRITE_BUFFER,
    0,              /* Mode */
    0,              /* Buffer ID */
    0, 0, 0,        /* Offset */
    0, 0, 0,        /* Size */
    0               /* Control */
  };

  req[1] = mode;
  req[2] = buffer_id;
  SET_BE_INT24(req + 3, offset);
  SET_BE_INT24(req + 6, size);

  assert(offset <= 0xFFFFFF);
  assert(size <= 0xFFFFFF);

  dump_scsi_req(req, sizeof(req), data, size);
  return sanei_scsi_cmd2(fd,
                         req, sizeof(req), data, size,
                         NULL, NULL);
}

static SANE_Status
scsi_mode_select(int fd, void *data, size_t size)
{
  char req[] = {
    SCSI_MODE_SELECT,
    0x10,           /* LUN,flags, etc. Set PF. */
    0, 0,           /* Reserved */
    0,              /* Parameters list length */
    0               /* Control */
  };

  req[4] = (u_char)size;

  assert(size <= 0xFF);

  dump_scsi_req(req, sizeof(req), data, size);
  return sanei_scsi_cmd2(fd,
                         req, sizeof(req), data, size,
                         NULL, NULL);
}

static SANE_Status
scsi_set_window(int fd, void *data, size_t size)
{
  char req[] = {
    SCSI_SET_WINDOW,
    0,              /* Reserved */
    0,              /* Page/OP */
    0, 0, 0, 0,     /* Reserved */
    0, 0,  /* Data len */
    0               /* Control */
  };

  SET_BE_INT16(req + 7, size);
  assert(size <= 0xFFFF);

  dump_scsi_req(req, sizeof(req), data, size);
  return sanei_scsi_cmd2(fd, 
                         req, sizeof(req), data, size,
                         NULL, NULL);
}

static SANE_Status
scsi_start_stop(int fd, u_char cmd)
{
  char req[] = {
    SCSI_START_STOP,
    0,              /* Various control stuff */
    0, 0,           /* Reserved */
    0,              /* LoEj & Start/Stop */
    0,              /* Control */
    0,              /* ??? */
  };

  req[4] = cmd;

  dump_scsi_req(req, sizeof(req), NULL, 0);
  return sanei_scsi_cmd(fd, req, sizeof(req), NULL, NULL);
}

static SANE_Status
ss35p_on_sense(int fd, u_char *sense_buffer, void *arg)
{
  Polaroid_SS35P_Scanner *self = (Polaroid_SS35P_Scanner *)arg;

  u_int kcq = ((sense_buffer[2] & 0xF) << 16) |
    (sense_buffer[12] << 8) |
    sense_buffer[13];

  /* Silence warnings */
  fd = fd;
  self = self;

  DBG(DBG_INFO, "Sense (KCQ: 0x%.5x)\n", kcq);

  switch (kcq & 0x0FFFF) {
  case 0:
  case 0x2A01:
  case 0x4800:
    DBG(DBG_ERROR, "Sense: OK\n");
    return SANE_STATUS_GOOD;
  case 0x0005:
    DBG(DBG_ERROR, "Sense: Reading data past end of scan\n");
    return SANE_STATUS_IO_ERROR;
  case 0x0801:
    DBG(DBG_ERROR, "Sense: Timeout\n");
    return SANE_STATUS_IO_ERROR;
  case 0x0402:
  case 0x2200:
  case 0x2900:
    DBG(DBG_ERROR, "Sense: Reset code not cleared. Firmware not loaded?\n");
    return SANE_STATUS_IO_ERROR;
  case 0x1A00:
  case 0x2600:
  case 0x3B09:
  case 0x3B0A:
    DBG(DBG_ERROR, "Sense: Bad parameter\n");
    return SANE_STATUS_IO_ERROR;
  case 0x2000:
  case 0x2400:
  case 0x3900:
    DBG(DBG_ERROR, "Sense: Bad CDB\n");
    return SANE_STATUS_IO_ERROR;
  case 0x2500:
    DBG(DBG_ERROR, "Sense: Bad LUN\n");
    return SANE_STATUS_IO_ERROR;
  case 0x3D00:
    DBG(DBG_ERROR, "Sense: Invalid bits in identify message\n");
    return SANE_STATUS_IO_ERROR;
  case 0x4300:
    DBG(DBG_ERROR, "Sense: Bad command sequence\n");
    return SANE_STATUS_IO_ERROR;
  case 0x4700:
    DBG(DBG_ERROR, "Sense: Parity error\n");
    return SANE_STATUS_IO_ERROR;
  case 0x4900:
    DBG(DBG_ERROR, "Sense: Unknown message\n");
    return SANE_STATUS_IO_ERROR;
  case 0x1501:
    DBG(DBG_ERROR, "Sense: Mechanical error\n");
    return SANE_STATUS_IO_ERROR;
  case 0x4000:
    /* ? */
  default:
    DBG(DBG_ERROR, "Unhandled sense. KCQ: 0x%.5x\n", kcq);
    return SANE_STATUS_IO_ERROR;
  };

}

static SANE_Status
ss35p_load_fw(Polaroid_SS35P_Scanner *self)
{
  SANE_Status status;
  unsigned int i;
  char path[PATH_MAX];
  char rev[4];
  u_char header_data[POLAROID_SS35P_FW_HEADER_SIZE];
  u_char *fw_block = NULL;
  size_t max_block = 0;
  Polaroid_SS35P_Firmware fw;
  FILE *file = NULL;;

  if (!firmware_dir || !firmware_dir[0]) {
    DBG(DBG_ERROR, "Firmware dir not specified\n");
    status = SANE_STATUS_INVAL;
    goto err_out;
  }

  rev[0] = self->device->revision[0];
  rev[1] = self->device->revision[2];
  rev[2] = self->device->revision[1] != '.' ? self->device->revision[1] : '\0';
  rev[3] = '\0';

  snprintf(path, sizeof(path), "%s/ss35p.%s", firmware_dir, rev);
  file = fopen(path, "r");
  if (!file) {
    DBG(DBG_INFO, "Failed to open '%s'\n", path);
    snprintf(path, sizeof(path), "%s/SS35P.%s", firmware_dir, rev);
    file = fopen(path, "r");
    if (!file) {
      DBG(DBG_INFO, "Failed to open '%s'\n", path);
      DBG(DBG_ERROR, "No firmware found, can't upload firmware\n");
      status = SANE_STATUS_INVAL;
      goto err_out;
    }
  }

  if (fread(header_data, sizeof(header_data), 1, file) != 1) {
    DBG(DBG_ERROR, "Failed to read firmware header\n");
    status = SANE_STATUS_INVAL;
    goto err_out;
  }

  /* Load firmware structure from memory. We could just've fread into
     the structure, but since structure alignment is ABI specific,
     let's do it manually instead. */
  memcpy(fw.target_name, header_data + 0, 16);
  fw.ver_maj = GET_BE_UINT16(header_data + 16);
  fw.ver_min = GET_BE_UINT16(header_data + 18);
  fw.no_blocks = GET_BE_UINT16(header_data + 20);
  /*  2 unknown bytes, possibly padding */
  for (i = 0; i < 14; i++) {
    u_char *c = header_data + 24 + i * 20;
    fw.blocks[i].buffer_id = GET_BE_UINT32(c + 0);
    fw.blocks[i].dev_offset = GET_BE_UINT32(c + 4);
    fw.blocks[i].length = GET_BE_UINT32(c + 8);
    fw.blocks[i].file_offset = GET_BE_UINT32(c + 12);
    if (fw.blocks[i].length > max_block)
      max_block = fw.blocks[i].length;
    /* 4 Unknown bytes */
  }
  /* 8 unknown bytes */


  /* TODO: Should we check the firmware version here? The original
     driver doesn't seem to do that. */

  DBG(DBG_INFO, "Loaded firmware '%.16s', version %u.%u.\n",
      fw.target_name, fw.ver_maj, fw.ver_min);


  DBG(DBG_SS35P, "Uploading %u blocks to device\n", fw.no_blocks);
  fw_block = malloc(max_block);
  if (!fw_block) {
    status = SANE_STATUS_NO_MEM;
    goto err_out;
  }
  if (fw.no_blocks > 14) {
    DBG(DBG_ERROR, "Too many blocks in firmware file. File corrupted?\n");
    status = SANE_STATUS_INVAL;
    goto err_out;
  }
  for (i = 0; i < fw.no_blocks; i++) {
    Polaroid_SS35P_FirmwareBlock *b = fw.blocks + i;
    DBG(DBG_SS35P, "FW block %u (file offset: %u, buffer: %u, offset: %u, len: %u)\n",
        i, b->file_offset, b->buffer_id, b->dev_offset, b->length);
    if (fseek(file, b->file_offset, SEEK_SET) == -1) {
      DBG(DBG_ERROR, "Failed to set position (0x%x) in firmware file\n",
          b->file_offset);
      status = SANE_STATUS_INVAL;
      goto err_out;
    }

    if (fread(fw_block, b->length, 1, file) != 1) {
      DBG(DBG_ERROR, "Failed to read firmware block\n");
      status = SANE_STATUS_INVAL;
      goto err_out;
    }

    sleep(1);
    status = scsi_write_buffer(self->fd, 4, b->buffer_id, b->dev_offset,
                               fw_block, b->length);
    if (status != SANE_STATUS_GOOD)
      goto err_out;
  }

  free(fw_block);
  fclose(file);

  return SANE_STATUS_GOOD;

 err_out:
  if (fw_block)
    free(fw_block);

  if (file)
    fclose(file);

  return status;
}

static SANE_Status
ss35p_load_cv(Polaroid_SS35P_Scanner *self)
{
  SANE_Status status;
  char path[PATH_MAX];
  FILE *file = NULL;
  u_char buf[POLAROID_SS35P_REG_CV_LEN];
  u_int i;

  if (!firmware_dir || !firmware_dir[0]) {
    DBG(DBG_ERROR, "Firmware dir not specified\n");
    status = SANE_STATUS_INVAL;
    goto out;
  }

  /* There might apparently be 3 different CV files that are supposed
     to be mangled and written to different registers. I've only seen
     CV1 so far, so we won't try to look for the others at the
     moment. */ 
  snprintf(path, sizeof(path), "%s/ss35p.cv1", firmware_dir);
  file = fopen(path, "r");
  if (!file) {
    DBG(DBG_INFO, "Failed to open '%s'\n", path);
    snprintf(path, sizeof(path), "%s/SS35P.CV1", firmware_dir);
    file = fopen(path, "r");
    if (!file) {
      DBG(DBG_INFO, "Failed to open '%s'\n", path);
      DBG(DBG_ERROR, "No CV1 file found\n");
      status = SANE_STATUS_INVAL;
      goto out;
    }
  }

  if (fread(buf, sizeof(buf), 1, file) != 1) {
    DBG(DBG_ERROR, "Failde to read CV1 file.\n");
    status = SANE_STATUS_INVAL;
    goto out;
  }

  for (i = 0; i < sizeof(buf); i += 2) {
    unsigned int word;

    /* Why, why!? This is done by the original driver for some
       reason. */
    word = (buf[i + 1] << 14) |
      (buf[i + 0] << 6);
    buf[i + 0] = (word >> 8) & 0xFF;
    buf[i + 1] = word & 0xFF;
  }

  status = scsi_write(self->fd, POLAROID_SS35P_REG_CV_BASE | 0x1, buf, sizeof(buf));

 out:
  if (file)
    fclose(file);

  return status;
}

static SANE_Status
ss35p_request_sense(Polaroid_SS35P_Scanner *self)
{
  u_char sense_buf[POLAROID_SS35P_SENSE_LEN];
  Polaroid_SS35P_Sense *s = &self->sense;
  size_t size;
  SANE_Status status;

  memset(sense_buf, '\0', sizeof(sense_buf));
  size = sizeof(sense_buf);
  status = scsi_request_sense(self->fd, sense_buf, &size);
  if (status != SANE_STATUS_GOOD)
    return status;

  if (size != sizeof(sense_buf))
      DBG(DBG_WARNING, "Got '%u' bytes of SCSI sense, requested '%u' bytes.\n",
          (u_int)size, (u_int)sizeof(sense_buf));

  s->kcq = ((sense_buf[2] & 0xF) << 16) |
    (sense_buf[12] << 8) |
    sense_buf[13];

  s->unknown0 = GET_BE_UINT32(sense_buf + 18 + 0);
  s->no_scans = GET_BE_UINT32(sense_buf + 18 + 4);
  s->unknown1 = GET_BE_UINT32(sense_buf + 18 + 8);

  return SANE_STATUS_GOOD;
}

static SANE_Status
ss35p_start_scan(Polaroid_SS35P_Scanner *self)
{
  DBG(DBG_SS35P, "ss35p_start_scan\n");

  self->current_line = 0;

  /* Issue a start motor command */
  return scsi_start_stop(self->fd, 0x01);
}

static SANE_Status
ss35p_read_lines(Polaroid_SS35P_Scanner *self,
                 int lines, void *buf, size_t *size)
{
  SANE_Status status;
  DBG(DBG_SS35P, "ss35p_read_lines (lines = %i, current_line = %i, height = %i, width = %i)\n",
      lines, self->current_line, self->height, self->width);

  if (self->current_line >= self->height) {
    DBG(DBG_SS35P, "ss35p_read_lines: EOF\n");
    *size = 0;
    return SANE_STATUS_EOF;
  } else if (self->current_line + lines > self->height)
    lines = self->height - self->current_line;

  self->current_line += lines;
  *size = lines * self->bytes_per_pixel * self->width;

  status = scsi_read(self->fd, 0x01, lines, buf, size);
  if (status == SANE_STATUS_GOOD && self->file_dmp)
    fwrite(buf, *size, 1, self->file_dmp);

  return status;
}

static SANE_Status
ss35p_mode_select(Polaroid_SS35P_Scanner *self,
                  u_int bytes_per_line, u_int resolution)
{
  u_char data[] = {
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,     /* Bytes per line */
    0x03, 0x06, 0x00, 0x00,
    0x00, 0x00,     /* Resolution */
    0x00, 0x00      /* Unknown */
  };

  DBG(DBG_SS35P, "ss35p_mode_select\n");

  SET_BE_INT16(data + 10, bytes_per_line);
  SET_BE_INT16(data + 16, resolution);

  assert(bytes_per_line <= 0xFFFF);
  assert(resolution <= 0xFFFF);

  return scsi_mode_select(self->fd, data, sizeof(data));
}

static SANE_Status
ss35p_set_window(Polaroid_SS35P_Scanner *self,
                 u_int dpi,
		 u_int x0, u_int y0,
		 u_int width, u_int height,
		 Polaroid_SS35P_Color color_mode, u_char bits_per_pixel,
		 Polaroid_SS35P_Media media)
{
  char data[] = {
    0x00, 0x32,     /* Unknown, might be length of remaining data */
    0, 0, 0, 0, 0,
    0x2C,           /* Unknown, might be length of remaining data */
    0, 0,
    0, 0,               /* DPI */
    0, 0,               /* DPI */
    0, 0,
    0, 0,               /* x0 */
    0, 0,
    0, 0,               /* y0 */
    0, 0,
    0, 0,               /* Width */
    0, 0,
    0, 0,               /* Height */
    0, 0, 0,
    0,                  /* Color mode */
    0,                  /* Bits per pixel */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,                  /* Media */
    0x00, 0x40,         /* Seems to be related to debug flags */
    0
  };

  DBG(DBG_SS35P, "ss35p_set_window\n");

  SET_BE_INT16(data + 10, dpi);
  SET_BE_INT16(data + 12, dpi);
  SET_BE_INT16(data + 16, x0);
  SET_BE_INT16(data + 20, y0);
  SET_BE_INT16(data + 24, width);
  SET_BE_INT16(data + 28, height);
  data[33] = color_mode;
  data[34] = bits_per_pixel;
  data[48] = media;

  assert(dpi <= 0xFFFF);
  assert(x0 <= 0xFFFF);
  assert(y0 <= 0xFFFF);
  assert(width <= 0xFFFF);
  assert(height <= 0xFFFF);

  return scsi_set_window(self->fd, data, sizeof(data));
}

static SANE_Status
ss35p_open(Polaroid_SS35P_Scanner **handle, Polaroid_SS35P_Device *dev)
{
  SANE_Status status = SANE_STATUS_INVAL;
  Polaroid_SS35P_Scanner *self = NULL;
  int sense_len;

  DBG(DBG_SS35P, "ss35p_open: %s\n", dev->sane.name);

  self = malloc(sizeof(Polaroid_SS35P_Scanner));
  *handle = self;
  if (!self)
    return SANE_STATUS_NO_MEM;

  sense_len = POLAROID_SS35P_SENSE_LEN;
  status = sanei_scsi_open(dev->sane.name, &self->fd,
                           &ss35p_on_sense, self);
  if (status != SANE_STATUS_GOOD)
    goto err_out;
  if (sense_len < POLAROID_SS35P_SENSE_LEN) {
    DBG(DBG_ERROR, "Unable to reserve enough memory for a SCSI sense buffer\n");
    status = SANE_STATUS_NO_MEM;
    goto err_out;
  }

  /* TODO: Disable debug code */
#if 1
  self->file_dmp = fopen("/tmp/ss35p.dmp", "w");
#else
  self->file_dmp = NULL;
#endif

  self->device = dev;
  assert(sizeof(self->opt) == sizeof(default_opt));
  memcpy(self->opt, default_opt, sizeof(self->opt));
  self->val[OPT_NUM_OPTS].w = NUM_OPTIONS;
  self->val[OPT_MODE].s = strdup(scan_mode_list[0]);
  self->val[OPT_SOURCE].s = strdup(scan_source_list[0]);
  self->val[OPT_RESOLUTION].w = 2700;
  self->val[OPT_TL_X].w = 0;
  self->val[OPT_TL_Y].w = 0;
  self->val[OPT_BR_X].w = SANE_FIX(36);
  self->val[OPT_BR_Y].w = SANE_FIX(36);

  self->current_line = 0;

  /* Check if we need to load FW */
  status = ss35p_request_sense(self);
  switch (self->sense.kcq & 0x0FFFF) {
  case 0x0402:
  case 0x2200:
  case 0x2900:
    DBG(DBG_INFO, "Firmware not loaded, loading firmware...\n");
    status = ss35p_load_fw(self);
    if (status != SANE_STATUS_GOOD)
      goto err_out;
    status = ss35p_load_cv(self);
    if (status != SANE_STATUS_GOOD)
      goto err_out;
    break;
  default:
    break;
  }

  return SANE_STATUS_GOOD;

 err_out:
  if (self)
    free(self);

  return status;
}

static void
ss35p_close(Polaroid_SS35P_Scanner *self)
{
  DBG(DBG_SS35P, "ss35p_close\n");

  if (self->file_dmp)
    fclose(self->file_dmp);
  sanei_scsi_close(self->fd);
}

static SANE_Status
ss35p_attach(Polaroid_SS35P_Device **_dev, const char *devname)
{
  int fd = -1;
  Polaroid_SS35P_Device *dev = NULL;
  SANE_Status status = SANE_STATUS_INVAL;
  char inq[SCSI_INQ_REPLY_LEN];
  size_t inq_len = sizeof(inq);
  int sense_len;

  DBG(DBG_SS35P, "ss35p_attach: %s\n", devname);

  dev = malloc(sizeof(Polaroid_SS35P_Device));
  *_dev = dev;
  if (!dev)
    return SANE_STATUS_NO_MEM;

  sense_len = POLAROID_SS35P_SENSE_LEN;
  status = sanei_scsi_open(devname, &fd,
                                    &ss35p_on_sense, NULL);
  if (status != SANE_STATUS_GOOD)
    goto err_out;
  if (sense_len < POLAROID_SS35P_SENSE_LEN) {
    DBG(DBG_ERROR, "Unable to reserve enough memory for a SCSI sense buffer\n");
    status = SANE_STATUS_NO_MEM;
    goto err_out;
  }

  status = scsi_inquiry(fd, inq, &inq_len);
  if (status != SANE_STATUS_GOOD || inq_len < SCSI_INQ_REPLY_LEN) {
    DBG(DBG_ERROR, "Failed to request scanner inquiry information\n");
    goto err_out;
  }

  if (strncmp("POLAROID", inq + SCSI_INQ_VENDOR_OFFSET, SCSI_INQ_VENDOR_LEN) ||
      strncmp("35MM            ", inq + SCSI_INQ_PRODUCT_OFFSET, SCSI_INQ_PRODUCT_LEN)) {
    DBG(DBG_ERROR, "Device is not a Polaroid SprintScan 35P scanner\n");
    status = SANE_STATUS_INVAL;
    goto err_out;
  }

  memcpy(dev->revision, inq + SCSI_INQ_REVISION_OFFSET, SCSI_INQ_REVISION_LEN);
  dev->revision[SCSI_INQ_REVISION_LEN] = '\0';

  dev->next = NULL;
  dev->sane.name = strdup(devname);
  dev->sane.vendor = "Polaroid";
  dev->sane.model = "SprintScan 35+";
  dev->sane.type = "film scanner";

  if (!dev->sane.name) {
    status = SANE_STATUS_NO_MEM;
    goto err_out;
  }

  sanei_scsi_close(fd);

  DBG(DBG_INFO, "Found a Polaroid SprintScan 35+ revision %s.\n",
      dev->revision);

  return SANE_STATUS_GOOD;

 err_out:
  DBG(DBG_SANE, "ss35p_attach: failed (%d)\n", status);
  if (fd != -1)
    sanei_scsi_close(fd);
  if (dev)
    free(dev);

  return status;
}

/* ---------------------------------------------------------------------- */
/* SANE Glue                                                              */
/* ---------------------------------------------------------------------- */

static Polaroid_SS35P_Color
get_color_from_string(const char *name)
{
  int i;
  for (i = 0; i < NELEMS(scan_mode_num); i++) {
    if (!strcmp(name, scan_mode_list[i]))
      return scan_mode_num[i];
  }
  ABORT("Illegal color mode");
}

static Polaroid_SS35P_Media
get_media_from_string(const char *name)
{
  int i;
  for (i = 0; i < NELEMS(scan_source_num); i++) {
    if (!strcmp(name, scan_source_list[i]))
      return scan_source_num[i];
  }
  ABORT("Illegal media type");
}

static void
refresh_options(Polaroid_SS35P_Scanner *self)
{
  double x0, y0, x1, y1;
  double px_per_mm;

  self->media = get_media_from_string(self->val[OPT_SOURCE].s);
  self->color_mode = get_color_from_string(self->val[OPT_MODE].s);
  self->dpi = self->val[OPT_RESOLUTION].w;
  switch (self->color_mode) {
  case SS35P_COLOR_COLOR:
    self->bits_per_pixel = 24;
    self->bytes_per_pixel = 3;
    break;
  case SS35P_COLOR_GRAY:
    self->bits_per_pixel = 8;
    self->bytes_per_pixel = 1;
    break;
  default:
    ABORT("Illegal color mode");
  }
  px_per_mm = self->dpi / MM_PER_INCH;

  x0 = SANE_UNFIX(self->val[OPT_TL_X].w);
  y0 = SANE_UNFIX(self->val[OPT_TL_Y].w);
  x1 = SANE_UNFIX(self->val[OPT_BR_X].w);
  y1 = SANE_UNFIX(self->val[OPT_BR_Y].w);

  assert(x0 < x1);
  assert(y0 < y1);

  self->x0 = x0 * px_per_mm;
  self->y0 = y0 * px_per_mm;
  self->width = (x1 - x0) * px_per_mm;
  self->height = (y1 - y0) * px_per_mm;
}

static SANE_Status
attach_one(const char *name)
{
  Polaroid_SS35P_Device *dev;
  SANE_Status status;

  DBG(DBG_SANE, "attach_one: %s\n", name);

  /* Have we attached to this device already? */
  for (dev = ss35p_devices; dev; dev = dev->next) {
    if (!strcmp(dev->sane.name, name))
      return SANE_STATUS_GOOD;
  }

  status = ss35p_attach(&dev, name);
  if (status == SANE_STATUS_GOOD) {
    dev->next = ss35p_devices;
    ss35p_devices = dev;
    ss35p_num_devices++;
  }

  return SANE_STATUS_GOOD;
}

SANE_Status
sane_init(SANE_Int *version_code, SANE_Auth_Callback authorize)
{
  FILE *fp;
  char config_line[PATH_MAX];

  DBG_INIT();

  DBG(DBG_SANE, "sane_init\n");
  DBG(DBG_ERROR,"This is sane-polaroid_ss35p version %d.%d build %d\n",
      SANE_CURRENT_MAJOR, V_MINOR, BUILD);
  DBG(DBG_ERROR,"(C) 2011 by Andreas Sandberg <sandberg@update.uu.se>\n");

  frontend_authorize_callback = authorize;

  if (version_code)
    *version_code = SANE_VERSION_CODE(SANE_CURRENT_MAJOR, V_MINOR, BUILD);

  fp = sanei_config_open(POLAROID_SS35P_CONFIG_FILE);
  if (!fp) {
    attach_one("/dev/scanner");
    return SANE_STATUS_GOOD;
  }

  while(sanei_config_read(config_line, sizeof(config_line), fp)) {
    if (config_line[0] == '#' || !config_line[0])
      continue; /* ignore line comments */

    if (!strncmp("firmware ", config_line, 9)) {
      firmware_dir = strdup(&config_line[9]);
    } else if (!strncmp("option ", config_line, 7)) {
      DBG(DBG_WARNING, "Ingnoring unknown option '%s'\n", &config_line[7]);
    } else {
      sanei_config_attach_matching_devices(config_line, attach_one);
    }
  }
  fclose(fp);

  return SANE_STATUS_GOOD;
}

void
sane_exit(void)
{
  DBG(DBG_SANE, "sane_exit\n");

  return;
}

SANE_Status
sane_get_devices(const SANE_Device ***device_list, SANE_Bool local_only)
{
  static const SANE_Device **devlist = NULL;
  Polaroid_SS35P_Device *dev;
  int i = 0;

  DBG(DBG_SANE,"sane_get_devices(local_only = %d)\n", local_only);
  DBG(DBG_SANE,"No devices: %d\n", ss35p_num_devices);

  /* Silence warning */
  local_only = local_only;

  if (devlist)
    free(devlist);

  devlist = malloc((ss35p_num_devices + 1) * sizeof(devlist[0]));
  if (!devlist)
    return SANE_STATUS_NO_MEM;

  for (dev = ss35p_devices; dev; dev = dev->next) {
    devlist[i++] = &dev->sane;
  }
  devlist[i] = NULL;

  if (device_list)
    *device_list = devlist;

  return SANE_STATUS_GOOD;
}

SANE_Status
sane_open(SANE_String_Const devicename, SANE_Handle *handle)
{
  SANE_Status status = SANE_STATUS_INVAL;
  if (!devicename) {
    DBG(DBG_SANE, "sane_open: devicename = NULL\n");
    return SANE_STATUS_INVAL;
  }

  DBG(DBG_SANE, "sane_open: devicename = \"%s\"\n", devicename);

  if (!devicename[0]) {
    if (ss35p_devices)
      status = ss35p_open((Polaroid_SS35P_Scanner **)handle, ss35p_devices);
  } else {
    Polaroid_SS35P_Device *dev;
    for (dev = ss35p_devices; dev; dev = dev->next) {
      if (!strcmp(dev->sane.name, devicename)) {
        status = ss35p_open((Polaroid_SS35P_Scanner **)handle, dev);
        break;
      }
    }
  }

  if (status == SANE_STATUS_GOOD)
    refresh_options(*(Polaroid_SS35P_Scanner **)handle);

  return status;
}

void
sane_close(SANE_Handle handle)
{
  Polaroid_SS35P_Scanner *self = handle;

  DBG(DBG_SANE, "sane_close\n");
  ss35p_close(self);
}

const SANE_Option_Descriptor *
sane_get_option_descriptor(SANE_Handle handle, SANE_Int option)
{
  Polaroid_SS35P_Scanner *self = handle;

  DBG(DBG_SANE, "sane_get_option_descriptor: option = %d\n", option);

  if (option < 0 || option >= NELEMS(self->opt))
    return NULL;

  return &self->opt[option];
}

static SANE_Status
control_option_get_value(Polaroid_SS35P_Scanner *self,
                         Polaroid_SS35P_Option option,
                         void *value, SANE_Int *info)
{
  /* Silence warning */
  info = info;

  switch (option) {
  case OPT_MODE:
  case OPT_SOURCE:
    strcpy(value, self->val[option].s);
    return SANE_STATUS_GOOD;

  case OPT_NUM_OPTS:
  case OPT_RESOLUTION:
  case OPT_TL_X:
  case OPT_TL_Y:
  case OPT_BR_X:
  case OPT_BR_Y:
    DBG(DBG_ERROR, "Returning option %d: %d\n", option, self->val[option].w);
    *(SANE_Word *)value = self->val[option].w;
    return SANE_STATUS_GOOD;

  default:
    return SANE_STATUS_INVAL;
  }
}

static SANE_Status
control_option_set_value(Polaroid_SS35P_Scanner *self,
                         Polaroid_SS35P_Option option,
                         void *value, SANE_Int *info)
{
  SANE_Status status;

  if (!SANE_OPTION_IS_SETTABLE (self->opt[option].cap)) {
    DBG(DBG_ERROR, "control_option_set_value: option is not settable\n");
    return SANE_STATUS_INVAL;
  }
  status = sanei_constrain_value(self->opt + option, value, info);
  if (status != SANE_STATUS_GOOD)
    return status;

  switch (option) {
  case OPT_MODE:
  case OPT_SOURCE:
    strcpy(self->val[option].s, value);
    return SANE_STATUS_GOOD;

  case OPT_RESOLUTION:
  case OPT_TL_X:
  case OPT_TL_Y:
  case OPT_BR_X:
  case OPT_BR_Y:
    self->val[option].w = *(SANE_Word *)value;
    return SANE_STATUS_GOOD;

  default:
    return SANE_STATUS_INVAL;
  }
}

SANE_Status
sane_control_option(SANE_Handle handle, SANE_Int option,
                    SANE_Action action, void *value, SANE_Int *info)
{
  Polaroid_SS35P_Scanner *self = handle;
  SANE_Status status;

  DBG(DBG_SANE, "sane_control_option: opt=%d, act=%d\n", option, action);

  if (option < 0 || option >= NELEMS(self->opt)) {
    DBG(DBG_ERROR, "sane_control_option: option %d < 0 or >= number of options\n",
        option);
    return SANE_STATUS_INVAL;
  }

  if (!SANE_OPTION_IS_ACTIVE(self->opt[option].cap)) {
    DBG(DBG_ERROR, "sane_control_option: option is inactive\n");
    return SANE_STATUS_INVAL;
  }

  switch (action) {
  case SANE_ACTION_SET_AUTO:
    return SANE_STATUS_INVAL;
  case SANE_ACTION_SET_VALUE:
    status = control_option_set_value(self, (Polaroid_SS35P_Option)option,
                                      value, info);
    refresh_options(self);
    return status;
  case SANE_ACTION_GET_VALUE:
    return control_option_get_value(self, (Polaroid_SS35P_Option)option,
                                    value, info);
  default:
    return SANE_STATUS_INVAL;
  }
}

SANE_Status
sane_get_parameters(SANE_Handle handle, SANE_Parameters *params)
{
  Polaroid_SS35P_Scanner *self = handle;

  DBG(DBG_SANE, "sane_get_parameters\n");

  if (!params)
    return SANE_STATUS_INVAL;

  /* TODO: Calculate from scanner settings */
  switch (self->color_mode) {
  case SS35P_COLOR_COLOR:
    params->format = SANE_FRAME_RGB;
    break;
  case SS35P_COLOR_GRAY:
    params->format = SANE_FRAME_GRAY;
    break;
  default:
    ABORT("Illegal color mode");
  }

  params->last_frame = SANE_TRUE;
  params->bytes_per_line = self->width * self->bytes_per_pixel;
  params->pixels_per_line = self->width;
  params->lines = self->height;
  params->depth = 8;

  return SANE_STATUS_GOOD;
}

SANE_Status
sane_start(SANE_Handle handle)
{
  Polaroid_SS35P_Scanner *self = handle;
  SANE_Status status;

  DBG(DBG_SANE, "sane_start\n");

  status = ss35p_mode_select(self,
                             self->bytes_per_pixel * self->width,
                             self->dpi);
  if (status != SANE_STATUS_GOOD)
    return status;

  status = ss35p_set_window(self,
                            self->dpi,
                            self->x0, self->y0, self->width, self->height,
                            self->color_mode, self->bits_per_pixel,
                            self->media);
  if (status != SANE_STATUS_GOOD)
    return status;

  return ss35p_start_scan(self);
}

SANE_Status
sane_read(SANE_Handle handle, SANE_Byte *data,
          SANE_Int max_length, SANE_Int *length)
{
  Polaroid_SS35P_Scanner *self = handle;
  SANE_Status status;
  u_int no_lines;
  size_t size;

  DBG(DBG_SANE, "sane_read: max_length = %d\n", max_length);

  if (!length) {
    DBG (DBG_ERROR, "sane_read: length == NULL\n");
    return SANE_STATUS_INVAL;
  }

  if (!data) {
    DBG(DBG_ERROR, "sane_read: data == NULL\n");
    return SANE_STATUS_INVAL;
  }

  no_lines = max_length / self->bytes_per_pixel / self->width;
  assert(no_lines > 0);

  size = max_length;
  status = ss35p_read_lines(self, no_lines, data, &size);
  *length = size;
  return status;
}

void
sane_cancel(SANE_Handle handle)
{
  DBG(DBG_SANE, "sane_cancel: handle = %p\n", handle);

  /* TODO: Implement this if possible */

  return;
}

SANE_Status
sane_set_io_mode(SANE_Handle handle, SANE_Bool non_blocking)
{
  /* Polaroid_SS35P_Scanner *self = handle; */

  DBG(DBG_SANE, "sane_set_io_mode: handle = %p, non_blocking = %d\n", 
      handle, non_blocking);

  if (non_blocking)
    return SANE_STATUS_UNSUPPORTED;

  return SANE_STATUS_GOOD;
}

SANE_Status
sane_get_select_fd(SANE_Handle handle, SANE_Int *fd)
{
  /* Polaroid_SS35P_Scanner *self = handle; */

  DBG(DBG_SANE, "sane_get_select_fd: handle = %p, fd %s 0\n",
      handle, fd ? "!=" : "=");

  return SANE_STATUS_UNSUPPORTED;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * c-file-style: "gnu"
 * End:
 */
