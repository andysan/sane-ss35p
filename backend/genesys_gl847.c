/* sane - Scanner Access Now Easy.

   Copyright (C) 2010-2011 St�phane Voltz <stef.dev@free.fr>
   
    
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
   If you do not wish that, delete this exception notice. 
*/

#include "genesys_gl847.h"

/****************************************************************************
 Low level function
 ****************************************************************************/

/**
 * decodes and prints content of status (0x41) register
 * @param val value read from reg41
 */
static void
print_status (uint8_t val)
{
  char msg[80];

  sprintf (msg, "%s%s%s%s%s%s%s%s",
	   val & REG41_PWRBIT ? "PWRBIT " : "",
	   val & REG41_BUFEMPTY ? "BUFEMPTY " : "",
	   val & REG41_FEEDFSH ? "FEEDFSH " : "",
	   val & REG41_SCANFSH ? "SCANFSH " : "",
	   val & REG41_HOMESNR ? "HOMESNR " : "",
	   val & REG41_LAMPSTS ? "LAMPSTS " : "",
	   val & REG41_FEBUSY ? "FEBUSY " : "",
	   val & REG41_MOTORENB ? "MOTORENB" : "");
  DBG (DBG_info, "status=%s\n", msg);
}

/* ------------------------------------------------------------------------ */
/*                  Read and write RAM, registers and AFE                   */
/* ------------------------------------------------------------------------ */

/**
 * Write to many GL847 registers at once
 * Note: sequential call to write register, no effective
 * bulk write implemented.
 * @param dev device to write to
 * @param reg pointer to an array of registers
 * @param elems size of the array
 */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl847_bulk_write_register (Genesys_Device * dev,
			   Genesys_Register_Set * reg, size_t elems)
{
  SANE_Status status = SANE_STATUS_GOOD;
  size_t i;

  for (i = 0; i < elems && status == SANE_STATUS_GOOD; i++)
    {
      if (reg[i].address != 0)
	{
	  status =
	    sanei_genesys_write_register (dev, reg[i].address, reg[i].value);
	}
    }

  DBG (DBG_io, "gl847_bulk_write_register: wrote %lu registers\n",
       (u_long) elems);
  return status;
}

/** @brief read scanned data
 * Read in 0xeff0 maximum sized blocks. This read is done in 2
 * parts if not multple of 512. First read is rounded to a multiple of 512 bytes, last read fetches the 
 * remainder. Read addr is always 0x10000000 with the memory layout setup.
 * @param dev device to read data from
 * @param addr address within ASIC memory space, unused but kept for API
 * @param data pointer where to store the read data
 * @param len size to read
 */
static SANE_Status
gl847_bulk_read_data (Genesys_Device * dev, uint8_t addr,
		      uint8_t * data, size_t len)
{
  SANE_Status status;
  size_t size, target, read, done;
  uint8_t outdata[8];
  uint8_t *buffer;

  DBG (DBG_io, "gl847_bulk_read_data: requesting %lu bytes at addr=0x%02x\n", (u_long) len, addr);

  if (len == 0)
    return SANE_STATUS_GOOD;

  target = len;
  buffer = data;

  /* loop until computed data size is read */
  while (target)
    {
      if (target > 0xeff0)
	{
	  size = 0xeff0;
	}
      else
	{
	  size = target;
	}

      /* hard coded 0x10000000 addr */
      outdata[0] = 0;
      outdata[1] = 0;
      outdata[2] = 0;
      outdata[3] = 0x10;

      /* data size to transfer */
      outdata[4] = (size & 0xff);
      outdata[5] = ((size >> 8) & 0xff);
      outdata[6] = ((size >> 16) & 0xff);
      outdata[7] = ((size >> 24) & 0xff);

      status =
	sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_BUFFER,
			       VALUE_BUFFER, 0x00, sizeof (outdata),
			       outdata);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error, "%s failed while writing command: %s\n",
	       __FUNCTION__, sane_strstatus (status));
	  return status;
	}

      /* blocks must be multiple of 512 but not last block */
      read = size;
      if (read >= 512)
	{
	  read /= 512;
	  read *= 512;
	}
     
      DBG (DBG_io2,
	   "gl847_bulk_read_data: trying to read %lu bytes of data\n",
	   (u_long) read);
      status = sanei_usb_read_bulk (dev->dn, buffer, &read);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_bulk_read_data failed while reading bulk data: %s\n",
	       sane_strstatus (status));
	  return status;
	}
      done=read;
      DBG (DBG_io2, "gl847_bulk_read_data: %lu bytes of data read\n", (u_long) done);

      /* read less than 512 bytes remainder */
      if (read < size)
	{
	  read = size - read;
	  DBG (DBG_io2,
	       "gl847_bulk_read_data: trying to read %lu bytes of data\n",
	       (u_long) read);
	  status = sanei_usb_read_bulk (dev->dn, buffer+done, &read);
	  if (status != SANE_STATUS_GOOD)
	    {
	      DBG (DBG_error,
		   "gl847_bulk_read_data failed while reading bulk data: %s\n",
		   sane_strstatus (status));
	      return status;
	    }
          done=read;
          DBG (DBG_io2, "gl847_bulk_read_data: %lu bytes of data read\n", (u_long) done);
	}

      DBG (DBG_io2, "%s: read %lu bytes, %lu remaining\n", __FUNCTION__,
	   (u_long) size, (u_long) (target - size));

      target -= size;
      buffer += size;
    }

  if (DBG_LEVEL >= DBG_data && dev->binary!=NULL)
    {
      fwrite(data, len, 1, dev->binary);
    }

  DBGCOMPLETED;

  return SANE_STATUS_GOOD;
}

/****************************************************************************
 Mid level functions 
 ****************************************************************************/

static SANE_Bool
gl847_get_fast_feed_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG02);
  if (r && (r->value & REG02_FASTFED))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_get_filter_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_FILTER))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_get_lineart_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_LINEART))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_get_bitset_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_BITSET))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_get_gain4_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, 0x06);
  if (r && (r->value & REG06_GAIN4))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_test_buffer_empty_bit (SANE_Byte val)
{
  if (val & REG41_BUFEMPTY)
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl847_test_motor_flag_bit (SANE_Byte val)
{
  if (val & REG41_MOTORENB)
    return SANE_TRUE;
  return SANE_FALSE;
}

/**
 * compute the step multiplier used
 */
static int
gl847_get_step_multiplier (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;
  int value = 1;

  r = sanei_genesys_get_address (regs, 0x9d);
  if (r != NULL)
    {
      value = (r->value & 0x0f)>>1;
      value = 1 << value;
    }
  DBG (DBG_io, "%s: step multiplier is %d\n", __FUNCTION__, value);
  return value;
}

/** @get sensor profile
 * search for the database of motor profiles and get the best one. Each
 * profile is at a specific dpihw. Use LiDE 110 table by default.
 * @param sensor_type sensor id
 * @param dpi hardware dpi for the scan
 * @return a pointer to a Sensor_Profile struct
 */
static Sensor_Profile *get_sensor_profile(int sensor_type, int dpi)
{
  unsigned int i;
  int idx;

  i=0;
  idx=-1;
  while(i<sizeof(sensors)/sizeof(Sensor_Profile))
    {
      /* exact match */
      if(sensors[i].sensor_type==sensor_type && sensors[i].dpi==dpi)
        {
          return &(sensors[i]);
        }

      /* closest match */
      if(sensors[i].sensor_type==sensor_type)
        {
          if(idx<0)
            {
              idx=i;
            }
          else
            {
              if(sensors[i].dpi>=dpi 
              && sensors[i].dpi<sensors[idx].dpi)
                {
                  idx=i;
                }
            }
        }
      i++;
    }

  /* default fallback */
  if(idx<0)
    {
      DBG (DBG_warn,"%s: using default sensor profile\n",__FUNCTION__);
      idx=0;
    }

  return &(sensors[idx]);
}

/**@brief compute exposure to use
 * compute the sensor exposure based on target resolution
 */
static int gl847_compute_exposure(Genesys_Device *dev, int xres)
{
  Sensor_Profile *sensor;

  sensor=get_sensor_profile(dev->model->ccd_type, xres);
  return sensor->exposure;
}


/** @brief sensor specific settings
*/
static void
gl847_setup_sensor (Genesys_Device * dev, Genesys_Register_Set * regs, int dpi)
{
  Genesys_Register_Set *r;
  Sensor_Profile *sensor;
  int dpihw, i;
  uint16_t exp;

  DBGSTART;
  dpihw=sanei_genesys_compute_dpihw(dev,dpi);

  for (i = 0x06; i < 0x0e; i++)
    {
      r = sanei_genesys_get_address (regs, 0x10 + i);
      if (r)
	r->value = dev->sensor.regs_0x10_0x1d[i];
    }

  for (i = 0; i < 9; i++)
    {
      r = sanei_genesys_get_address (regs, 0x52 + i);
      if (r)
	r->value = dev->sensor.regs_0x52_0x5e[i];
    }

  /* set EXPDUMMY and CKxMAP */
  dpihw=sanei_genesys_compute_dpihw(dev,dpi);
  sensor=get_sensor_profile(dev->model->ccd_type, dpihw);

  sanei_genesys_set_reg_from_set(regs,REG_EXPDMY,(uint8_t)((sensor->expdummy) & 0xff));

  /* if no calibration has been done, set default values for exposures */
  exp=dev->sensor.regs_0x10_0x1d[0]*256+dev->sensor.regs_0x10_0x1d[1];
  if(exp==0)
    {
      exp=sensor->expr;
    }
  sanei_genesys_set_double(regs,REG_EXPR,exp);

  exp=dev->sensor.regs_0x10_0x1d[2]*256+dev->sensor.regs_0x10_0x1d[3];
  if(exp==0)
    {
      exp=sensor->expg;
    }
  sanei_genesys_set_double(regs,REG_EXPG,exp);

  exp=dev->sensor.regs_0x10_0x1d[4]*256+dev->sensor.regs_0x10_0x1d[5];
  if(exp==0)
    {
      exp=sensor->expb;
    }
  sanei_genesys_set_double(regs,REG_EXPB,exp);

  sanei_genesys_set_triple(regs,REG_CK1MAP,sensor->ck1map);
  sanei_genesys_set_triple(regs,REG_CK3MAP,sensor->ck3map);
  sanei_genesys_set_triple(regs,REG_CK4MAP,sensor->ck4map);

  r = sanei_genesys_get_address (regs, 0x17);
  r->value = sensor->r17;

  DBGCOMPLETED;
}


/* returns the max register bulk size */
static int
gl847_bulk_full_size (void)
{
  return GENESYS_GL847_MAX_REGS;
}

/** @brief set all registers to default values .
 * This function is called only once at the beginning and
 * fills register startup values for registers reused across scans.
 * Those that are rarely modified or not modified are written
 * individually.
 * @param dev device structure holding register set to initialize
 */
static void
gl847_init_registers (Genesys_Device * dev)
{
  DBGSTART;

  memset (dev->reg, 0,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  SETREG (0x01, 0x82);
  SETREG (0x02, 0x18);
  SETREG (0x03, 0x50);
  SETREG (0x04, 0x12);
  SETREG (0x05, 0x80);
  SETREG (0x06, 0x50);		/* FASTMODE + POWERBIT */
  SETREG (0x08, 0x10);
  SETREG (0x09, 0x01);
  SETREG (0x0a, 0x00);
  SETREG (0x0b, 0x01);
  SETREG (0x0c, 0x02);

  /* LED exposures */
  SETREG (0x10, 0x00);
  SETREG (0x11, 0x00);
  SETREG (0x12, 0x00);
  SETREG (0x13, 0x00);
  SETREG (0x14, 0x00);
  SETREG (0x15, 0x00);

  SETREG (0x16, 0x10);
  SETREG (0x17, 0x08);
  SETREG (0x18, 0x00);

  /* EXPDMY */
  SETREG (0x19, 0x50);

  SETREG (0x1a, 0x34);
  SETREG (0x1b, 0x00);
  SETREG (0x1c, 0x02);
  SETREG (0x1d, 0x04);
  SETREG (0x1e, 0x10);
  SETREG (0x1f, 0x04);
  SETREG (0x20, 0x02);
  SETREG (0x21, 0x10);
  SETREG (0x22, 0x7f);
  SETREG (0x23, 0x7f);
  SETREG (0x24, 0x10);
  SETREG (0x25, 0x00);
  SETREG (0x26, 0x00);
  SETREG (0x27, 0x00);
  SETREG (0x2c, 0x09);
  SETREG (0x2d, 0x60);
  SETREG (0x2e, 0x80);
  SETREG (0x2f, 0x80);
  SETREG (0x30, 0x00);
  SETREG (0x31, 0x10);
  SETREG (0x32, 0x15);
  SETREG (0x33, 0x0e);
  SETREG (0x34, 0x40);
  SETREG (0x35, 0x00);
  SETREG (0x36, 0x2a);
  SETREG (0x37, 0x30);
  SETREG (0x38, 0x2a);
  SETREG (0x39, 0xf8);
  SETREG (0x3d, 0x00);
  SETREG (0x3e, 0x00);
  SETREG (0x3f, 0x00);
  SETREG (0x52, 0x03);
  SETREG (0x53, 0x07);
  SETREG (0x54, 0x00);
  SETREG (0x55, 0x00);
  SETREG (0x56, 0x00);
  SETREG (0x57, 0x00);
  SETREG (0x58, 0x2a);
  SETREG (0x59, 0xe1);
  SETREG (0x5a, 0x55);
  SETREG (0x5e, 0x41);
  SETREG (0x5f, 0x40);
  SETREG (0x60, 0x00);
  SETREG (0x61, 0x21);
  SETREG (0x62, 0x40);
  SETREG (0x63, 0x00);
  SETREG (0x64, 0x21);
  SETREG (0x65, 0x40);
  SETREG (0x67, 0x80);
  SETREG (0x68, 0x80);
  SETREG (0x69, 0x20);
  SETREG (0x6a, 0x20);

  /* CK1MAP */
  SETREG (0x74, 0x00);
  SETREG (0x75, 0x00);
  SETREG (0x76, 0x3c);

  /* CK3MAP */
  SETREG (0x77, 0x00);
  SETREG (0x78, 0x00);
  SETREG (0x79, 0x9f);

  /* CK4MAP */
  SETREG (0x7a, 0x00);
  SETREG (0x7b, 0x00);
  SETREG (0x7c, 0x55);

  SETREG (0x7d, 0x00);
  /* NOTE: autoconf is a non working option */
  SETREG (0x87, 0x02);
  SETREG (0x9d, 0x00); /* 1x multiplier instead of 8x */
  SETREG (0x9d, 0x06);
  SETREG (0xa2, 0x0f);
  SETREG (0xa6, 0x04);
  SETREG (0xbd, 0x18);
  SETREG (0xfe, 0x08);

  /* gamma[0] and gamma[256] values */
  SETREG (0xbe, 0x00);
  SETREG (0xc5, 0x00);
  SETREG (0xc6, 0x00);
  SETREG (0xc7, 0x00);
  SETREG (0xc8, 0x00);
  SETREG (0xc9, 0x00);
  SETREG (0xca, 0x00);

  /* fine tune upon device description */
  dev->reg[reg_0x05].value &= ~REG05_DPIHW;
  switch (dev->sensor.optical_res)
    {
    case 600:
      dev->reg[reg_0x05].value |= REG05_DPIHW_600;
      break;
    case 1200:
      dev->reg[reg_0x05].value |= REG05_DPIHW_1200;
      break;
    case 2400:
      dev->reg[reg_0x05].value |= REG05_DPIHW_2400;
      break;
    case 4800:
      dev->reg[reg_0x05].value |= REG05_DPIHW_4800;
      break;
    }

  /* initalize calibration reg */
  memcpy (dev->calib_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  DBGCOMPLETED;
}

/**@brief send slope table for motor movement 
 * Send slope_table in machine byte order
 * @param dev device to send slope table
 * @param table_nr index of the slope table in ASIC memory
 * Must be in the [0-4] range.
 * @param slope_table pointer to 16 bit values array of the slope table
 * @param steps number of elemnts in the slope table
 */
static SANE_Status
gl847_send_slope_table (Genesys_Device * dev, int table_nr,
			uint16_t * slope_table, int steps)
{
  SANE_Status status;
  uint8_t *table;
  int i;
  char msg[2048];

  DBG (DBG_proc, "%s (table_nr = %d, steps = %d)\n", __FUNCTION__,
       table_nr, steps);

  /* sanity check */
  if(table_nr<0 || table_nr>4)
    {
      DBG (DBG_error, "%s: invalid table number %d!\n", __FUNCTION__, table_nr);
      return SANE_STATUS_INVAL;
    }

  table = (uint8_t *) malloc (steps * 2);
  for (i = 0; i < steps; i++)
    {
      table[i * 2] = slope_table[i] & 0xff;
      table[i * 2 + 1] = slope_table[i] >> 8;
    }

  if (DBG_LEVEL >= DBG_io)
    {
      sprintf (msg, "write slope %d (%d)=", table_nr, steps);
      for (i = 0; i < steps; i++)
	{
	  sprintf (msg, "%s,%d", msg, slope_table[i]);
	}
      DBG (DBG_io, "%s: %s\n", __FUNCTION__, msg);
    }

  /* slope table addresses are fixed */
  status =
    sanei_genesys_write_ahb (dev->dn, 0x10000000 + 0x4000 * table_nr, steps * 2, table);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "%s: write to AHB failed writing slope table %d (%s)\n",
	   __FUNCTION__, table_nr, sane_strstatus (status));
    }

  free (table);
  DBGCOMPLETED;
  return status;
}

/**
 * Set register values of Analog Device type frontend
 * */
static SANE_Status
gl847_set_ad_fe (Genesys_Device * dev, uint8_t set)
{
  SANE_Status status = SANE_STATUS_GOOD;
  int i;
  uint16_t val;

  DBG (DBG_proc, "gl847_set_ad_fe(): start\n");
  if (set == AFE_INIT)
    {
      DBG (DBG_proc, "gl847_set_ad_fe(): setting DAC %u\n",
	   dev->model->dac_type);

      /* sets to default values */
      sanei_genesys_init_fe (dev);
    }

  /* reset DAC */
  status = sanei_genesys_fe_write_data (dev, 0x00, 0x80);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "gl847_set_ad_fe: failed to write reg0: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* write them to analog frontend */
  val = dev->frontend.reg[0];
  status = sanei_genesys_fe_write_data (dev, 0x00, val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "gl847_set_ad_fe: failed to write reg0: %s\n",
	   sane_strstatus (status));
      return status;
    }
  val = dev->frontend.reg[1];
  status = sanei_genesys_fe_write_data (dev, 0x01, val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "gl847_set_ad_fe: failed to write reg1: %s\n",
	   sane_strstatus (status));
      return status;
    }

  for (i = 0; i < 3; i++)
    {
      val = dev->frontend.gain[i];
      status = sanei_genesys_fe_write_data (dev, 0x02 + i, val);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_set_ad_fe: failed to write gain %d: %s\n", i,
	       sane_strstatus (status));
	  return status;
	}
    }
  for (i = 0; i < 3; i++)
    {
      val = dev->frontend.offset[i];
      status = sanei_genesys_fe_write_data (dev, 0x05 + i, val);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_set_ad_fe: failed to write offset %d: %s\n", i,
	       sane_strstatus (status));
	  return status;
	}
    }

  DBG (DBG_proc, "gl847_set_ad_fe(): end\n");

  return status;
}

/* Set values of analog frontend */
static SANE_Status
gl847_set_fe (Genesys_Device * dev, uint8_t set)
{
  SANE_Status status;
  uint8_t val;

  DBG (DBG_proc, "gl847_set_fe (%s)\n",
       set == AFE_INIT ? "init" : set == AFE_SET ? "set" : set ==
       AFE_POWER_SAVE ? "powersave" : "huh?");
  
  RIE (sanei_genesys_read_register (dev, REG04, &val));

  /* route to AD devices */
  if ((val & REG04_FESET) == 0x02)
    {
      return gl847_set_ad_fe (dev, set);
    }

  /* for now ther is no support for wolfson fe */
  DBG (DBG_proc, "gl847_set_fe(): unsupported frontend type %d\n",
       dev->reg[reg_0x04].value & REG04_FESET);

  DBGCOMPLETED;
  return SANE_STATUS_UNSUPPORTED;
}

#define MOTOR_FLAG_AUTO_GO_HOME             1
#define MOTOR_FLAG_DISABLE_BUFFER_FULL_MOVE 2

/** @brief setup motor for off mode
 * 
 */
static SANE_Status
gl847_init_motor_regs_off (Genesys_Device * dev,
			   Genesys_Register_Set * reg,
			   unsigned int scan_lines)
{
  unsigned int feedl;
  Genesys_Register_Set *r;

  DBG (DBG_proc, "gl847_init_motor_regs_off : scan_lines=%d\n", scan_lines);

  feedl = 2;

  r = sanei_genesys_get_address (reg, 0x3d);
  r->value = (feedl >> 16) & 0xf;
  r = sanei_genesys_get_address (reg, 0x3e);
  r->value = (feedl >> 8) & 0xff;
  r = sanei_genesys_get_address (reg, 0x3f);
  r->value = feedl & 0xff;
  DBG (DBG_io ,"%s: feedl=%d\n",__FUNCTION__,feedl);

  r = sanei_genesys_get_address (reg, 0x25);
  r->value = (scan_lines >> 16) & 0xf;
  r = sanei_genesys_get_address (reg, 0x26);
  r->value = (scan_lines >> 8) & 0xff;
  r = sanei_genesys_get_address (reg, 0x27);
  r->value = scan_lines & 0xff;

  r = sanei_genesys_get_address (reg, REG02);
  r->value &= ~0x01;		/*LONGCURV OFF */
  r->value &= ~0x80;		/*NOT_HOME OFF */

  r->value &= ~0x10;

  r->value &= ~0x06;

  r->value &= ~0x08;

  r->value &= ~0x20;

  r->value &= ~0x40;

  r = sanei_genesys_get_address (reg, REG67);
  r->value = REG67_MTRPWM;

  r = sanei_genesys_get_address (reg, REG68);
  r->value = REG68_FASTPWM;

  r = sanei_genesys_get_address (reg, 0x21);
  r->value = 1;

  r = sanei_genesys_get_address (reg, 0x24);
  r->value = 1;

  r = sanei_genesys_get_address (reg, 0x69);
  r->value = 1;

  r = sanei_genesys_get_address (reg, 0x6a);
  r->value = 1;

  r = sanei_genesys_get_address (reg, 0x5f);
  r->value = 1;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** @brief set up motor related register for scan
 */
static SANE_Status
gl847_init_motor_regs_scan (Genesys_Device * dev,
                            Genesys_Register_Set * reg,
                            unsigned int scan_exposure_time,
			    float scan_yres,
			    int scan_step_type,
			    unsigned int scan_lines,
			    unsigned int scan_dummy,
			    unsigned int feed_steps,
			    int scan_power_mode,
                            unsigned int flags)
{
  SANE_Status status;
  int use_fast_fed;
  unsigned int fast_time;
  unsigned int slow_time;
  unsigned int fast_dpi;
  uint16_t scan_table[SLOPE_TABLE_SIZE];
  uint16_t fast_table[SLOPE_TABLE_SIZE];
  int scan_steps, fast_steps, factor;
  unsigned int feedl, dist;
  Genesys_Register_Set *r;
  uint32_t z1, z2;
  unsigned int min_restep = 0x20;
  uint8_t val, effective;
  int fast_step_type;
  int acdcdis;
  unsigned int ccdlmt,tgtime;

  DBGSTART;
  DBG (DBG_proc, "gl847_init_motor_regs_scan : scan_exposure_time=%d, "
       "scan_yres=%g, scan_step_type=%d, scan_lines=%d, scan_dummy=%d, "
       "feed_steps=%d, scan_power_mode=%d, flags=%x\n",
       scan_exposure_time,
       scan_yres,
       scan_step_type,
       scan_lines, scan_dummy, feed_steps, scan_power_mode, flags);

  /* get step multiplier */
  factor = gl847_get_step_multiplier (reg);

  use_fast_fed=0;
  if(dev->settings.yres>=1200 && feed_steps>100)
    {
      use_fast_fed=1;
    }

  sanei_genesys_set_triple(reg, REG_LINCNT, scan_lines);
  DBG (DBG_io, "%s: lincnt=%d\n", __FUNCTION__, scan_lines);

  /* compute register 02 value */
  r = sanei_genesys_get_address (reg, REG02);
  r->value = 0x00;
  r->value |= REG02_NOTHOME | REG02_MTRPWR;

  if (use_fast_fed)
    r->value |= REG02_FASTFED;
  else
    r->value &= ~REG02_FASTFED;

  if (flags & MOTOR_FLAG_AUTO_GO_HOME)
    r->value |= REG02_AGOHOME;

  acdcdis=0;
  if (flags & MOTOR_FLAG_DISABLE_BUFFER_FULL_MOVE)
    {
      r->value |= REG02_ACDCDIS;
      acdcdis=1;
    }

  /* scan and backtracking slope table */
  slow_time=sanei_genesys_slope_table(scan_table,
                                      &scan_steps,
                                      scan_yres,
                                      scan_exposure_time,
                                      dev->motor.base_ydpi,
                                      scan_step_type,
                                      factor,
                                      dev->model->motor_type,
                                      gl847_motors);
  RIE(gl847_send_slope_table (dev, SCAN_TABLE, scan_table, scan_steps*factor));
  RIE(gl847_send_slope_table (dev, BACKTRACK_TABLE, scan_table, scan_steps*factor));

  /* fast table */
  fast_dpi=sanei_genesys_get_lowest_ydpi(dev);
  fast_step_type=scan_step_type;
  if(scan_step_type>=2)
    {
      fast_step_type=2;
    }
  fast_time=sanei_genesys_slope_table(fast_table,
                                      &fast_steps,
                                      fast_dpi,
                                      scan_exposure_time,
                                      dev->motor.base_ydpi,
                                      fast_step_type,
                                      factor,
                                      dev->model->motor_type,
                                      gl847_motors);
  /* manual override of high start value */
  fast_table[0]=fast_table[1];
  RIE(gl847_send_slope_table (dev, STOP_TABLE, fast_table, fast_steps*factor));
  RIE(gl847_send_slope_table (dev, FAST_TABLE, fast_table, fast_steps*factor));
  RIE(gl847_send_slope_table (dev, HOME_TABLE, fast_table, fast_steps*factor));

  /* substract acceleration distance from feedl XXX STEF XXX : 2 different step type */
  feedl=feed_steps;

  dist = scan_steps;
  if (use_fast_fed) 
    {
        feedl<<=fast_step_type;
        dist += fast_steps*2;
    }
  else
    {
      feedl<<=scan_step_type;
    }
  dist *=factor;
  DBG (DBG_io2, "%s: acceleration distance=%d\n", __FUNCTION__, dist);

  /* get sure we don't use insane value */
  if(dist<feedl)
    feedl -= dist;
  else
    feedl = 1;

  sanei_genesys_set_triple(reg,REG_FEEDL,feedl);
  DBG (DBG_io ,"%s: feedl=%d\n",__FUNCTION__,feedl);

  r = sanei_genesys_get_address (reg, REG0C);
  ccdlmt=(r->value & REG0C_CCDLMT)+1;

  r = sanei_genesys_get_address (reg, REG1C);
  tgtime=1<<(r->value & REG1C_TGTIME);

  /* hi res motor speed GPIO */
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));

  /* if quarter step, bipolar Vref2 */
  if (scan_step_type > 1)
    {
      if (scan_step_type < 3)
        {
          val = effective & ~REG6C_GPIO13;
        }
      else
        {
          val = effective | REG6C_GPIO13;
        }
    }
  else
    {
      val = effective;
    }
  RIE (sanei_genesys_write_register (dev, REG6C, val));

  /* effective scan */
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  val = effective | REG6C_GPIO10;
  RIE (sanei_genesys_write_register (dev, REG6C, val));

  min_restep=scan_steps/2-1;
  if (min_restep < 1)
    min_restep = 1;
  r = sanei_genesys_get_address (reg, REG_FWDSTEP);
  r->value = min_restep;
  r = sanei_genesys_get_address (reg, REG_BWDSTEP);
  r->value = min_restep;

  sanei_genesys_calculate_zmode2(use_fast_fed,
			         scan_exposure_time*ccdlmt*tgtime,
				 scan_table,
				 scan_steps*factor,
				 feedl,
                                 min_restep*factor,
                                 &z1,
                                 &z2);

  DBG (DBG_info, "gl847_init_motor_regs_scan: z1 = %d\n", z1);
  r = sanei_genesys_get_address (reg, REG60);
  r->value = ((z1 >> 16) & REG60_Z1MOD) | (scan_step_type << REG60S_STEPSEL);
  r = sanei_genesys_get_address (reg, REG61);
  r->value = ((z1 >> 8) & REG61_Z1MOD);
  r = sanei_genesys_get_address (reg, REG62);
  r->value = (z1 & REG62_Z1MOD);

  DBG (DBG_info, "gl847_init_motor_regs_scan: z2 = %d\n", z2);
  r = sanei_genesys_get_address (reg, REG63);
  r->value = ((z2 >> 16) & REG63_Z2MOD) | (fast_step_type << REG63S_FSTPSEL);
  r = sanei_genesys_get_address (reg, REG64);
  r->value = ((z2 >> 8) & REG64_Z2MOD);
  r = sanei_genesys_get_address (reg, REG65);
  r->value = (z2 & REG65_Z2MOD);

  r = sanei_genesys_get_address (reg, 0x1e);
  r->value &= 0xf0;		/* 0 dummy lines */
  r->value |= scan_dummy;	/* dummy lines */

  r = sanei_genesys_get_address (reg, REG67);
  r->value = REG67_MTRPWM;

  r = sanei_genesys_get_address (reg, REG68);
  r->value = REG68_FASTPWM;

  r = sanei_genesys_get_address (reg, REG_STEPNO);
  r->value = scan_steps;

  r = sanei_genesys_get_address (reg, REG_FASTNO);
  r->value = scan_steps;

  r = sanei_genesys_get_address (reg, REG_FSHDEC);
  r->value = scan_steps;

  r = sanei_genesys_get_address (reg, REG_FMOVNO);
  r->value = fast_steps;

  r = sanei_genesys_get_address (reg, REG_FMOVDEC);
  r->value = fast_steps;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl847_init_optical_regs_off (Genesys_Device * dev, Genesys_Register_Set * reg)
{
  Genesys_Register_Set *r;

  DBG (DBG_proc, "gl847_init_optical_regs_off : start\n");

  r = sanei_genesys_get_address (reg, REG01);
  r->value &= ~REG01_SCAN;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** @brief set up registers related to sensor
 * Set up the following registers
   0x01
   0x03
   0x10-0x015     R/G/B exposures
   0x19           EXPDMY
   0x2e           BWHI
   0x2f           BWLO
   0x04
   0x87
   0x05
   0x2c,0x2d      DPISET
   0x30,0x31      STRPIXEL
   0x32,0x33      ENDPIXEL
   0x35,0x36,0x37 MAXWD [25:2] (>>2)
   0x38,0x39      LPERIOD
   0x34           DUMMY
 */
static SANE_Status
gl847_init_optical_regs_scan (Genesys_Device * dev,
			      Genesys_Register_Set * reg,
			      unsigned int exposure_time,
			      int used_res,
			      unsigned int start,
			      unsigned int pixels,
			      int channels,
			      int depth,
			      SANE_Bool half_ccd, int color_filter, int flags)
{
  unsigned int words_per_line;
  unsigned int startx, endx, used_pixels;
  unsigned int dpiset, dpihw,segnb,cksel,factor;
  unsigned int bytes;
  Genesys_Register_Set *r;
  SANE_Status status;
  Sensor_Profile *sensor;

  DBG (DBG_proc, "gl847_init_optical_regs_scan :  exposure_time=%d, "
       "used_res=%d, start=%d, pixels=%d, channels=%d, depth=%d, "
       "half_ccd=%d, flags=%x\n", exposure_time,
       used_res, start, pixels, channels, depth, half_ccd, flags);

  /* resolution is divided according to CKSEL */ 
  r = sanei_genesys_get_address (reg, REG18);
  cksel= (r->value & REG18_CKSEL)+1;
  DBG (DBG_io2, "%s: cksel=%d\n", __FUNCTION__, cksel);
  
  /* to manage high resolution device while keeping good
   * low resolution scanning speed, we make hardware dpi vary */
  dpihw=sanei_genesys_compute_dpihw(dev, used_res * cksel);
  factor=dev->sensor.optical_res/dpihw;
  DBG (DBG_io2, "%s: dpihw=%d (factor=%d)\n", __FUNCTION__, dpihw, factor);

  /* sensor parameters */
  sensor=get_sensor_profile(dev->model->ccd_type, dpihw);
  gl847_setup_sensor (dev, reg, dpihw);
  dpiset = used_res * cksel;

  /* start and end coordinate in optical dpi coordinates */
  startx = start/cksel+dev->sensor.CCD_start_xoffset;
  used_pixels=pixels/cksel;
 
  /* end of sensor window */
  endx = startx + used_pixels;

  /* sensors are built from 600 dpi segments */
  segnb=dpihw/600;

  /* compute pixel coordinate in the given dpihw space,
   * taking segments into account */
  startx/=factor*segnb;
  endx/=factor*segnb;
  dev->len=endx-startx;
  dev->dist=0;
  dev->skip=0;

  /* in case of 4800 dpi, we must match full sensor width */
  if(dpihw==4800)
    {
      dev->skip=startx-dev->sensor.CCD_start_xoffset/segnb;
      if(depth==16)
        dev->skip*=2;
      startx = dev->sensor.CCD_start_xoffset/segnb;
      used_pixels = sensor->segcnt;
      endx = startx + used_pixels;
    }

  /* in cas of multi-segments sensor, we have to add the witdh
   * of the sensor crossed by the scan area */
  if (dev->model->flags & GENESYS_FLAG_SIS_SENSOR && segnb>1)
    {
      dev->dist = sensor->segcnt;
    }
  endx += dev->dist*(segnb-1);
  used_pixels=endx-startx;

  status = gl847_set_fe (dev, AFE_SET);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_init_optical_regs_scan: failed to set frontend: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* enable shading */
  r = sanei_genesys_get_address (reg, REG01);
  r->value &= ~REG01_SCAN;
  r->value |= REG01_SHDAREA;
  if ((flags & OPTICAL_FLAG_DISABLE_SHADING) ||
      (dev->model->flags & GENESYS_FLAG_NO_CALIBRATION))
    {
      r->value &= ~REG01_DVDSET;
    }
  else
    {
      r->value |= REG01_DVDSET;
    }

  r = sanei_genesys_get_address (reg, REG03);
  r->value &= ~REG03_AVEENB;

  if (flags & OPTICAL_FLAG_DISABLE_LAMP)
    r->value &= ~REG03_LAMPPWR;
  else
    r->value |= REG03_LAMPPWR;

  /* BW threshold */
  r = sanei_genesys_get_address (reg, 0x2e);
  r->value = dev->settings.threshold;
  r = sanei_genesys_get_address (reg, 0x2f);
  r->value = dev->settings.threshold;

  /* monochrome / color scan */
  r = sanei_genesys_get_address (reg, REG04);
  switch (depth)
    {
    case 1:
      r->value &= ~REG04_BITSET;
      r->value |= REG04_LINEART;
      break;
    case 8:
      r->value &= ~(REG04_LINEART | REG04_BITSET);
      break;
    case 16:
      r->value &= ~REG04_LINEART;
      r->value |= REG04_BITSET;
      break;
    }

  r->value &= ~(REG04_FILTER | REG04_AFEMOD);
  if (channels == 1)
    {
      switch (color_filter)
	{
	case 0:
	  r->value |= 0x14;	/* red filter */
	  break;
	case 2:
	  r->value |= 0x1c;	/* blue filter */
	  break;
	default:
	  r->value |= 0x18;	/* green filter */
	  break;
	}
    }
  else
    r->value |= 0x10;		/* mono */

  /* register 05 */
  r = sanei_genesys_get_address (reg, REG05);

  /* set up dpihw */
  r->value &= ~REG05_DPIHW;
  switch(dpihw)
    {
      case 600:
        r->value |= REG05_DPIHW_600;
        break;
      case 1200:
        r->value |= REG05_DPIHW_1200;
        break;
      case 2400:
        r->value |= REG05_DPIHW_2400;
        break;
      case 4800:
        r->value |= REG05_DPIHW_4800;
        break;
    }

  /* enable gamma tables */
  if (flags & OPTICAL_FLAG_DISABLE_GAMMA)
    r->value &= ~REG05_GMMENB;
  else
    r->value |= REG05_GMMENB;

  /* CIS scanners can do true gray by setting LEDADD */
  /* we set up LEDADD only when asked */
  if (dev->model->is_cis == SANE_TRUE)
    {
      r = sanei_genesys_get_address (reg, 0x87);
      r->value &= ~REG87_LEDADD;
      if (channels == 1 && (flags & OPTICAL_FLAG_ENABLE_LEDADD))
	{
	  r->value |= REG87_LEDADD;
	}
      /* RGB weighting 
      r = sanei_genesys_get_address (reg, 0x01);
      r->value &= ~REG01_TRUEGRAY;
      if (channels == 1 && (flags & OPTICAL_FLAG_ENABLE_LEDADD))
	{
	  r->value |= REG01_TRUEGRAY;
	}*/
    }

  sanei_genesys_set_double(reg,REG_DPISET,dpiset);
  DBG (DBG_io2, "%s: dpiset used=%d\n", __FUNCTION__, dpiset);

  sanei_genesys_set_double(reg,REG_STRPIXEL,startx);
  sanei_genesys_set_double(reg,REG_ENDPIXEL,endx);

  /* words(16bit) before gamma, conversion to 8 bit or lineart*/
  words_per_line = (used_pixels * dpiset) / dpihw;
  bytes=depth/8;
  if (depth == 1)
    {
      words_per_line = (words_per_line >> 3) + ((words_per_line & 7) ? 1 : 0);
      dev->len = (dev->len >> 3) + ((dev->len & 7) ? 1 : 0);
      dev->dist = (dev->dist >> 3) + ((dev->dist & 7) ? 1 : 0);
    }
  else
    {
      words_per_line *= bytes;
      dev->dist *= bytes;
      dev->len *= bytes;
    }

  dev->bpl = words_per_line;
  dev->cur=0;
  dev->segnb=segnb;
  dev->line_interp = 0;

  DBG (DBG_io2, "%s: used_pixels=%d\n", __FUNCTION__, used_pixels);
  DBG (DBG_io2, "%s: pixels     =%d\n", __FUNCTION__, pixels);
  DBG (DBG_io2, "%s: depth      =%d\n", __FUNCTION__, depth);
  DBG (DBG_io2, "%s: dev->bpl   =%lu\n", __FUNCTION__, (unsigned long)dev->bpl);
  DBG (DBG_io2, "%s: dev->len   =%lu\n", __FUNCTION__, (unsigned long)dev->len);
  DBG (DBG_io2, "%s: dev->dist  =%lu\n", __FUNCTION__, (unsigned long)dev->dist);
  DBG (DBG_io2, "%s: dev->segnb =%lu\n", __FUNCTION__, (unsigned long)dev->segnb);
  
  words_per_line *= channels;
  dev->wpl = words_per_line;

  if(dev->oe_buffer.buffer!=NULL)
    {
      sanei_genesys_buffer_free (&(dev->oe_buffer));
    }
  RIE (sanei_genesys_buffer_alloc (&(dev->oe_buffer), dev->wpl));

  /* MAXWD is expressed in 4 words unit */
  sanei_genesys_set_triple(reg, REG_MAXWD, (words_per_line >> 2));
  DBG (DBG_io2, "%s: words_per_line used=%d\n", __FUNCTION__, words_per_line);

  sanei_genesys_set_double(reg, REG_LPERIOD, exposure_time);
  DBG (DBG_io2, "%s: exposure_time used=%d\n", __FUNCTION__, exposure_time);

  r = sanei_genesys_get_address (reg, 0x34);
  r->value = dev->sensor.dummy_pixel;
  
  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/* set up registers for an actual scan
 *
 * this function sets up the scanner to scan in normal or single line mode
 */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl847_init_scan_regs (Genesys_Device * dev,
                      Genesys_Register_Set * reg,
                      float xres,	/*dpi */
		      float yres,	/*dpi */
		      float startx,	/*optical_res, from dummy_pixel+1 */
		      float starty,	/*base_ydpi, from home! */
		      float pixels,
		      float lines,
		      unsigned int depth,
		      unsigned int channels,
		      int color_filter,
                      unsigned int flags)
{
  int used_res;
  int start, used_pixels;
  int bytes_per_line;
  int move;
  unsigned int lincnt, dpihw;
  unsigned int oflags; /**> optical flags */
  int exposure_time;
  int i;
  int stagger;

  int slope_dpi = 0;
  int dummy = 0;
  int scan_step_type = 1;
  int scan_power_mode = 0;
  int max_shift;
  size_t requested_buffer_size, read_buffer_size;

  SANE_Bool half_ccd;		/* false: full CCD res is used, true, half max CCD res is used */
  int optical_res;
  SANE_Status status;

  DBG (DBG_info,
       "gl847_init_scan_regs settings:\n"
       "Resolution    : %gDPI/%gDPI\n"
       "Lines         : %g\n"
       "PPL           : %g\n"
       "Startpos      : %g/%g\n"
       "Depth/Channels: %u/%u\n"
       "Flags         : %x\n\n",
       xres, yres, lines, pixels, startx, starty, depth, channels, flags);

  /* we may have 2 domains for ccd: xres below or above half ccd max dpi */
  if (dev->sensor.optical_res < 2 * xres ||
      !(dev->model->flags & GENESYS_FLAG_HALF_CCD_MODE))
    {
      half_ccd = SANE_FALSE;
    }
  else
    {
      half_ccd = SANE_TRUE;
    }

  /* optical_res */
  optical_res = dev->sensor.optical_res;
  if (half_ccd)
    optical_res /= 2;

  /* stagger */
  if ((!half_ccd) && (dev->model->flags & GENESYS_FLAG_STAGGERED_LINE))
    stagger = (4 * yres) / dev->motor.base_ydpi;
  else
    stagger = 0;
  DBG (DBG_info, "gl847_init_scan_regs : stagger=%d lines\n", stagger);

  /* used_res */
  i = optical_res / xres;
  if (flags & SCAN_FLAG_USE_OPTICAL_RES)
    {
      used_res = optical_res;
    }
  else
    {
      /* resolution is choosen from a list */
      used_res = xres;
    }

  /* compute scan parameters values */
  /* pixels are allways given at full optical resolution */
  /* use detected left margin and fixed value */
  /* start */
  /* add x coordinates */
  start = startx;

  if (stagger > 0)
    start |= 1;

  /* compute correct pixels number */
  /* pixels */
  used_pixels = (pixels * optical_res) / xres;

  /* round up pixels number if needed */
  if (used_pixels * xres < pixels * optical_res)
    used_pixels++;

  dummy = 3-channels;

/* slope_dpi */
/* cis color scan is effectively a gray scan with 3 gray lines per color
   line and a FILTER of 0 */
  if (dev->model->is_cis)
    slope_dpi = yres * channels;
  else
    slope_dpi = yres;

  slope_dpi = slope_dpi * (1 + dummy);

  dpihw=sanei_genesys_compute_dpihw(dev,xres);
  exposure_time = gl847_compute_exposure (dev, used_res);
  scan_step_type = sanei_genesys_compute_step_type(gl847_motors, dev->model->motor_type, exposure_time);

  DBG (DBG_info, "gl847_init_scan_regs : exposure_time=%d pixels\n",
       exposure_time);
  DBG (DBG_info, "gl847_init_scan_regs : scan_step_type=%d\n",
       scan_step_type);

/*** optical parameters ***/
  /* in case of dynamic lineart, we use an internal 8 bit gray scan
   * to generate 1 lineart data */
  if ((flags & SCAN_FLAG_DYNAMIC_LINEART) && (dev->settings.scan_mode == SCAN_MODE_LINEART))
    {
      depth = 8;
    }

  /* we enable true gray for cis scanners only, and just when doing 
   * scan since color calibration is OK for this mode
   */
  oflags = 0;
  if(flags & SCAN_FLAG_DISABLE_SHADING)
    oflags |= OPTICAL_FLAG_DISABLE_SHADING;
  if(flags & SCAN_FLAG_DISABLE_GAMMA)
    oflags |= OPTICAL_FLAG_DISABLE_GAMMA;
  if(flags & SCAN_FLAG_DISABLE_LAMP)
    oflags |= OPTICAL_FLAG_DISABLE_LAMP;
  
  if (dev->model->is_cis && dev->settings.true_gray)
    {
      oflags |= OPTICAL_FLAG_ENABLE_LEDADD;
    }

  status = gl847_init_optical_regs_scan (dev,
					 reg,
					 exposure_time,
					 used_res,
					 start,
					 used_pixels,
					 channels,
					 depth,
					 half_ccd,
					 color_filter,
                                         oflags);

  if (status != SANE_STATUS_GOOD)
    return status;

/*** motor parameters ***/

/* max_shift */
  /* scanned area must be enlarged by max color shift needed */
  /* all values are assumed >= 0 */
  if (channels > 1 && !(flags & SCAN_FLAG_IGNORE_LINE_DISTANCE))
    {
      max_shift = dev->model->ld_shift_r;
      if (dev->model->ld_shift_b > max_shift)
	max_shift = dev->model->ld_shift_b;
      if (dev->model->ld_shift_g > max_shift)
	max_shift = dev->model->ld_shift_g;
      max_shift = (max_shift * yres) / dev->motor.base_ydpi;
    }
  else
    {
      max_shift = 0;
    }

/* lincnt */
  lincnt = lines + max_shift + stagger;

  /* add tl_y to base movement */
  move = starty;
  DBG (DBG_info, "gl847_init_scan_regs: move=%d steps\n", move);

    status = gl847_init_motor_regs_scan (dev,
					 reg,
					 exposure_time,
					 slope_dpi,
					 scan_step_type,
					 dev->model->is_cis ? lincnt *
					 channels : lincnt, dummy, move,
					 scan_power_mode,
					 (flags &
					  SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE)
					 ?
					 MOTOR_FLAG_DISABLE_BUFFER_FULL_MOVE
					 : 0);

  if (status != SANE_STATUS_GOOD)
    return status;


  /*** prepares data reordering ***/

/* words_per_line */
  bytes_per_line = (used_pixels * used_res) / optical_res;
  bytes_per_line = (bytes_per_line * channels * depth) / 8;

  requested_buffer_size = 8 * bytes_per_line;
  /* we must use a round number of bytes_per_line */
  /* XXX STEF XXX
  if (requested_buffer_size > BULKIN_MAXSIZE)
    requested_buffer_size =
      (BULKIN_MAXSIZE / bytes_per_line) * bytes_per_line;
  */

  read_buffer_size =
    2 * requested_buffer_size +
    ((max_shift + stagger) * used_pixels * channels * depth) / 8;

  RIE (sanei_genesys_buffer_free (&(dev->read_buffer)));
  RIE (sanei_genesys_buffer_alloc (&(dev->read_buffer), read_buffer_size));

  RIE (sanei_genesys_buffer_free (&(dev->lines_buffer)));
  RIE (sanei_genesys_buffer_alloc (&(dev->lines_buffer), read_buffer_size));

  RIE (sanei_genesys_buffer_free (&(dev->shrink_buffer)));
  RIE (sanei_genesys_buffer_alloc (&(dev->shrink_buffer),
				   requested_buffer_size));

  RIE (sanei_genesys_buffer_free (&(dev->out_buffer)));
  RIE (sanei_genesys_buffer_alloc (&(dev->out_buffer),
				   (8 * dev->settings.pixels * channels *
				    depth) / 8));


  dev->read_bytes_left = bytes_per_line * lincnt;

  DBG (DBG_info,
       "gl847_init_scan_regs: physical bytes to read = %lu\n",
       (u_long) dev->read_bytes_left);
  dev->read_active = SANE_TRUE;


  dev->current_setup.pixels = (used_pixels * used_res) / optical_res;
  dev->current_setup.lines = lincnt;
  dev->current_setup.depth = depth;
  dev->current_setup.channels = channels;
  dev->current_setup.exposure_time = exposure_time;
  dev->current_setup.xres = used_res;
  dev->current_setup.yres = yres;
  dev->current_setup.half_ccd = half_ccd;
  dev->current_setup.stagger = stagger;
  dev->current_setup.max_shift = max_shift + stagger;

/* TODO: should this be done elsewhere? */
  /* scan bytes to send to the frontend */
  /* theory :
     target_size =
     (dev->settings.pixels * dev->settings.lines * channels * depth) / 8;
     but it suffers from integer overflow so we do the following: 

     1 bit color images store color data byte-wise, eg byte 0 contains 
     8 bits of red data, byte 1 contains 8 bits of green, byte 2 contains 
     8 bits of blue.
     This does not fix the overflow, though. 
     644mp*16 = 10gp, leading to an overflow
     -- pierre
   */

  dev->total_bytes_read = 0;
  if (depth == 1 || dev->settings.scan_mode == SCAN_MODE_LINEART)
    dev->total_bytes_to_read =
      ((dev->settings.pixels * dev->settings.lines) / 8 +
       (((dev->settings.pixels * dev->settings.lines) % 8) ? 1 : 0)) *
      channels;
  else
    dev->total_bytes_to_read =
      dev->settings.pixels * dev->settings.lines * channels * (depth / 8);

  DBG (DBG_info, "gl847_init_scan_regs: total bytes to send = %lu\n",
       (u_long) dev->total_bytes_to_read);
/* END TODO */

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl847_calculate_current_setup (Genesys_Device * dev)
{
  int channels;
  int depth;
  int start;

  float xres;			/*dpi */
  float yres;			/*dpi */
  float startx;			/*optical_res, from dummy_pixel+1 */
  float pixels;
  float lines;
  int color_filter;

  int used_res;
  int used_pixels;
  unsigned int lincnt, dpihw;
  int exposure_time;
  int stagger;

  int slope_dpi = 0;
  int dummy = 0;
  int scan_step_type = 1;
  int max_shift;

  SANE_Bool half_ccd;		/* false: full CCD res is used, true, half max CCD res is used */
  int optical_res;

  DBG (DBG_info,
       "gl847_calculate_current_setup settings:\n"
       "Resolution: %uDPI\n"
       "Lines     : %u\n"
       "PPL       : %u\n"
       "Startpos  : %.3f/%.3f\n"
       "Scan mode : %d\n\n",
       dev->settings.yres, dev->settings.lines, dev->settings.pixels,
       dev->settings.tl_x, dev->settings.tl_y, dev->settings.scan_mode);

  /* channels */
  if (dev->settings.scan_mode == 4)	/* single pass color */
    channels = 3;
  else
    channels = 1;

  /* depth */
  depth = dev->settings.depth;
  if (dev->settings.scan_mode == 0)
    depth = 1;

  /* start */
  start = SANE_UNFIX (dev->model->x_offset);
  start += dev->settings.tl_x;
  start = (start * dev->sensor.optical_res) / MM_PER_INCH;


  xres = dev->settings.xres;	/*dpi */
  yres = dev->settings.yres;	/*dpi */
  startx = start;		/*optical_res, from dummy_pixel+1 */
  pixels = dev->settings.pixels;
  lines = dev->settings.lines;
  color_filter = dev->settings.color_filter;


  DBG (DBG_info,
       "gl847_calculate_current_setup settings:\n"
       "Resolution    : %gDPI/%gDPI\n"
       "Lines         : %g\n"
       "PPL           : %g\n"
       "Startpos      : %g\n"
       "Depth/Channels: %u/%u\n\n",
       xres, yres, lines, pixels, startx, depth, channels);

/* half_ccd */
  /* we have 2 domains for ccd: xres below or above half ccd max dpi */
  if ((dev->sensor.optical_res < 2 * xres) ||
      !(dev->model->flags & GENESYS_FLAG_HALF_CCD_MODE))
    {
      half_ccd = SANE_FALSE;
    }
  else
    {
      half_ccd = SANE_TRUE;
    }

  /* optical_res */
  optical_res = dev->sensor.optical_res;

  /* stagger */
  if (dev->model->flags & GENESYS_FLAG_STAGGERED_LINE)
    stagger = (4 * yres) / dev->motor.base_ydpi;
  else
    stagger = 0;
  DBG (DBG_info, "gl847_calculate_current_setup: stagger=%d lines\n",
       stagger);

  /* resolution is choosen from a fixed list */
  used_res = xres;

  /* compute scan parameters values */
  /* pixels are allways given at half or full CCD optical resolution */
  /* use detected left margin  and fixed value */

  /* compute correct pixels number */
  used_pixels = (pixels * optical_res) / used_res;
  dummy = 3-channels;

  /* slope_dpi */
  /* cis color scan is effectively a gray scan with 3 gray lines per color
   line and a FILTER of 0 */
  if (dev->model->is_cis)
    slope_dpi = yres * channels;
  else
    slope_dpi = yres;

  slope_dpi = slope_dpi * (1 + dummy);

  dpihw=sanei_genesys_compute_dpihw(dev,xres);
  exposure_time = gl847_compute_exposure (dev, used_res);
  scan_step_type = sanei_genesys_compute_step_type(gl847_motors, dev->model->motor_type, exposure_time);

  DBG (DBG_info,
       "gl847_calculate_current_setup : exposure_time=%d pixels\n",
       exposure_time);

/* max_shift */
  /* scanned area must be enlarged by max color shift needed */
  /* all values are assumed >= 0 */
  if (channels > 1)
    {
      max_shift = dev->model->ld_shift_r;
      if (dev->model->ld_shift_b > max_shift)
	max_shift = dev->model->ld_shift_b;
      if (dev->model->ld_shift_g > max_shift)
	max_shift = dev->model->ld_shift_g;
      max_shift = (max_shift * yres) / dev->motor.base_ydpi;
    }
  else
    {
      max_shift = 0;
    }

/* lincnt */
  lincnt = lines + max_shift + stagger;

  dev->current_setup.pixels = (used_pixels * used_res) / optical_res;
  dev->current_setup.lines = lincnt;
  dev->current_setup.depth = depth;
  dev->current_setup.channels = channels;
  dev->current_setup.exposure_time = exposure_time;
  dev->current_setup.xres = used_res;
  dev->current_setup.yres = yres;
  dev->current_setup.half_ccd = half_ccd;
  dev->current_setup.stagger = stagger;
  dev->current_setup.max_shift = max_shift + stagger;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static void
gl847_set_motor_power (Genesys_Register_Set * regs, SANE_Bool set)
{

  DBG (DBG_proc, "gl847_set_motor_power\n");

  if (set)
    {
      sanei_genesys_set_reg_from_set (regs, REG02,
				      sanei_genesys_read_reg_from_set (regs,
								       REG02)
				      | REG02_MTRPWR);
    }
  else
    {
      sanei_genesys_set_reg_from_set (regs, REG02,
				      sanei_genesys_read_reg_from_set (regs,
								       REG02)
				      & ~REG02_MTRPWR);
    }
}

static void
gl847_set_lamp_power (Genesys_Device * dev,
		      Genesys_Register_Set * regs, SANE_Bool set)
{
  if (set)
    {
      sanei_genesys_set_reg_from_set (regs, REG03,
				      sanei_genesys_read_reg_from_set (regs, REG03)
				      | REG03_LAMPPWR);
    }
  else
    {
      sanei_genesys_set_reg_from_set (regs, REG03,
				      sanei_genesys_read_reg_from_set (regs, REG03)
				      & ~REG03_LAMPPWR);
    }
}

/*for fast power saving methods only, like disabling certain amplifiers*/
static SANE_Status
gl847_save_power (Genesys_Device * dev, SANE_Bool enable)
{
  DBG (DBG_proc, "gl847_save_power: enable = %d\n", enable);
  if (dev == NULL)
    return SANE_STATUS_INVAL;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl847_set_powersaving (Genesys_Device * dev, int delay /* in minutes */ )
{
  DBG (DBG_proc, "gl847_set_powersaving (delay = %d)\n", delay);
  if (dev == NULL)
    return SANE_STATUS_INVAL;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl847_start_action (Genesys_Device * dev)
{
  return sanei_genesys_write_register (dev, 0x0f, 0x01);
}

static SANE_Status
gl847_stop_action (Genesys_Device * dev)
{
  Genesys_Register_Set local_reg[GENESYS_GL847_MAX_REGS];
  SANE_Status status;
  uint8_t val40, val;
  unsigned int loop;

  DBG (DBG_proc, "%s\n", __FUNCTION__);

  status = sanei_genesys_get_status (dev, &val);
  if (DBG_LEVEL >= DBG_io)
    {
      print_status (val);
    }

  val40 = 0;
  status = sanei_genesys_read_register (dev, REG40, &val40);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "%s: failed to read home sensor: %s\n", __FUNCTION__,
	   sane_strstatus (status));
      DBGCOMPLETED;
      return status;
    }

  /* only stop action if needed */
  if (!(val40 & REG40_DATAENB) && !(val40 & REG40_MOTMFLG))
    {
      DBG (DBG_info, "%s: already stopped\n", __FUNCTION__);
      DBGCOMPLETED;
      return SANE_STATUS_GOOD;
    }

  memset (local_reg, 0, sizeof (local_reg));

  memcpy (local_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  gl847_init_optical_regs_off (dev, local_reg);

  gl847_init_motor_regs_off (dev, local_reg, 0);
  status = gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "%s: failed to bulk write registers: %s\n",
	   __FUNCTION__, sane_strstatus (status));
      return status;
    }

  /* looks like writing the right registers to zero is enough to get the chip 
     out of scan mode into command mode, actually triggering(writing to 
     register 0x0f) seems to be unnecessary */

  loop = 10;
  while (loop > 0)
    {
      status = sanei_genesys_get_status (dev, &val);
      if (DBG_LEVEL >= DBG_io)
	{
	  print_status (val);
	}
      val40 = 0;
      status = sanei_genesys_read_register (dev, 0x40, &val40);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "%s: failed to read home sensor: %s\n", __FUNCTION__,
	       sane_strstatus (status));
          DBGCOMPLETED;
	  return status;
	}

      /* if scanner is in command mode, we are done */
      if (!(val40 & REG40_DATAENB) && !(val40 & REG40_MOTMFLG)
	  && !(val & REG41_MOTORENB))
	{
          DBGCOMPLETED;
	  return SANE_STATUS_GOOD;
	}

      usleep (100 * 1000);
      loop--;
    }

  DBGCOMPLETED;
  return SANE_STATUS_IO_ERROR;
}

/* Send the low-level scan command */
/* todo : is this that useful ? */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl847_begin_scan (Genesys_Device * dev, Genesys_Register_Set * reg,
		  SANE_Bool start_motor)
{
  SANE_Status status;
  uint8_t val;
  Genesys_Register_Set *r;

  DBGSTART;

  /* clear GPIO 10 */
  RIE (sanei_genesys_read_register (dev, REG6C, &val));
  val &= ~REG6C_GPIO10;
  RIE (sanei_genesys_write_register (dev, REG6C, val));

  val = REG0D_CLRLNCNT;
  RIE (sanei_genesys_write_register (dev, REG0D, val));
  val = REG0D_CLRMCNT;
  RIE (sanei_genesys_write_register (dev, REG0D, val));

  RIE (sanei_genesys_read_register (dev, REG01, &val));
  val |= REG01_SCAN;
  RIE (sanei_genesys_write_register (dev, REG01, val));
  r = sanei_genesys_get_address (reg, REG01);
  r->value = val;

  if (start_motor)
    {
      RIE (sanei_genesys_write_register (dev, REG0F, 1));
    }
  else
    {
      RIE (sanei_genesys_write_register (dev, REG0F, 0));
    }

  DBGCOMPLETED;

  return status;
}


/* Send the stop scan command */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl847_end_scan (Genesys_Device * dev, Genesys_Register_Set * reg,
		SANE_Bool check_stop)
{
  SANE_Status status;

  DBG (DBG_proc, "gl847_end_scan (check_stop = %d)\n", check_stop);
  if (reg == NULL)
    return SANE_STATUS_INVAL;

  if (dev->model->is_sheetfed == SANE_TRUE)
    {
      status = SANE_STATUS_GOOD;
    }
  else				/* flat bed scanners */
    {
      status = gl847_stop_action (dev);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_end_scan: Failed to stop: %s\n",
	       sane_strstatus (status));
	  return status;
	}
    }

  DBGCOMPLETED;
  return status;
}

/* Moves the slider to the home (top) postion slowly */
static SANE_Status
gl847_slow_back_home (Genesys_Device * dev, SANE_Bool wait_until_home)
{
  Genesys_Register_Set local_reg[GENESYS_GL847_MAX_REGS];
  SANE_Status status;
  Genesys_Register_Set *r;
  float resolution;
  uint8_t val;
  int loop = 0;


  DBG (DBG_proc, "gl847_slow_back_home (wait_until_home = %d)\n",
       wait_until_home);

  memset (local_reg, 0, sizeof (local_reg));

  /* reset gpio pin */
  RIE (sanei_genesys_read_register (dev, REG6C, &val));
  val = dev->gpo.value[0];
  RIE (sanei_genesys_write_register (dev, REG6C, val));

  /* first read gives HOME_SENSOR true */
  status = sanei_genesys_get_status (dev, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_slow_back_home: failed to read home sensor: %s\n",
	   sane_strstatus (status));
      return status;
    }
  if (DBG_LEVEL >= DBG_io)
    {
      print_status (val);
    }
  usleep (100000);		/* sleep 100 ms */

  /* second is reliable */
  status = sanei_genesys_get_status (dev, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_slow_back_home: failed to read home sensor: %s\n",
	   sane_strstatus (status));
      return status;
    }
  if (DBG_LEVEL >= DBG_io)
    {
      print_status (val);
    }

  dev->scanhead_position_in_steps = 0;

  if (val & REG41_HOMESNR)	/* is sensor at home? */
    {
      DBG (DBG_info, "gl847_slow_back_home: already at home, completed\n");
      dev->scanhead_position_in_steps = 0;
      DBGCOMPLETED;
      return SANE_STATUS_GOOD;
    }

  /* if motor is on, stop current action */
  if (val & REG41_MOTORENB)
    {
      status = gl847_stop_action (dev);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_slow_back_home: failed to stop motor: %s\n",
	       sane_strstatus (status));
	  return SANE_STATUS_IO_ERROR;
	}
    }

  memcpy (local_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));
  
  resolution=sanei_genesys_get_lowest_ydpi(dev);
  gl847_init_scan_regs (dev,
			local_reg,
			resolution,
			resolution,
			0,
			30000,
			100,
			3,
			8,
			1,
			dev->settings.color_filter,
			SCAN_FLAG_DISABLE_SHADING |
			SCAN_FLAG_DISABLE_GAMMA |
			SCAN_FLAG_IGNORE_LINE_DISTANCE);

  /* clear scan and feed count */
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRLNCNT));
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRMCNT));
  
  /* set up for reverse and no scan */
  r = sanei_genesys_get_address (local_reg, REG02);
  r->value |= REG02_MTRREV;
  r = sanei_genesys_get_address (local_reg, REG01);
  r->value &= ~REG01_SCAN;

  RIE (gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS));

  status = gl847_start_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_slow_back_home: failed to start motor: %s\n",
	   sane_strstatus (status));
      gl847_stop_action (dev);
      /* send original registers */
      gl847_bulk_write_register (dev, dev->reg, GENESYS_GL847_MAX_REGS);
      return status;
    }

  if (wait_until_home)
    {
      while (loop < 300)	/* do not wait longer then 30 seconds */
	{
	  status = sanei_genesys_get_status (dev, &val);
	  if (status != SANE_STATUS_GOOD)
	    {
	      DBG (DBG_error,
		   "gl847_slow_back_home: failed to read home sensor: %s\n",
		   sane_strstatus (status));
	      return status;
	    }

	  if (val & REG41_HOMESNR)	/* home sensor */
	    {
	      DBG (DBG_info, "gl847_slow_back_home: reached home position\n");
	      DBG (DBG_proc, "gl847_slow_back_home: finished\n");
	      return SANE_STATUS_GOOD;
	    }
	  usleep (100000);	/* sleep 100 ms */
	  ++loop;
	}

      /* when we come here then the scanner needed too much time for this, so we better stop the motor */
      gl847_stop_action (dev);
      DBG (DBG_error,
	   "gl847_slow_back_home: timeout while waiting for scanhead to go home\n");
      return SANE_STATUS_IO_ERROR;
    }

  DBG (DBG_info, "gl847_slow_back_home: scanhead is still moving\n");
  DBG (DBG_proc, "gl847_slow_back_home: finished\n");
  return SANE_STATUS_GOOD;
}

/* Automatically set top-left edge of the scan area by scanning a 200x200 pixels
   area at 600 dpi from very top of scanner */
static SANE_Status
gl847_search_start_position (Genesys_Device * dev)
{
  int size;
  SANE_Status status;
  uint8_t *data;
  Genesys_Register_Set local_reg[GENESYS_GL847_MAX_REGS];
  int steps;

  int pixels = 600;
  int dpi = 300;

  DBG (DBG_proc, "gl847_search_start_position\n");

  memset (local_reg, 0, sizeof (local_reg));
  memcpy (local_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  /* sets for a 200 lines * 600 pixels */
  /* normal scan with no shading */

  status = gl847_init_scan_regs (dev, local_reg, dpi, dpi, 0, 0,	/*we should give a small offset here~60 steps */
				 600, dev->model->search_lines, 8, 1, 1,	/*green */
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);

  /* send to scanner */
  status = gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_search_start_position: failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  size = pixels * dev->model->search_lines;

  data = malloc (size);
  if (!data)
    {
      DBG (DBG_error,
	   "gl847_search_start_position: failed to allocate memory\n");
      return SANE_STATUS_NO_MEM;
    }

  status = gl847_begin_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_start_position: failed to begin scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* waits for valid data */
  do
    sanei_genesys_test_buffer_empty (dev, &steps);
  while (steps);

  /* now we're on target, we can read data */
  status = sanei_genesys_read_data_from_scanner (dev, data, size);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_start_position: failed to read data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  if (DBG_LEVEL >= DBG_data)
    sanei_genesys_write_pnm_file ("search_position.pnm", data, 8, 1, pixels,
				  dev->model->search_lines);

  status = gl847_end_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_start_position: failed to end scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* update regs to copy ASIC internal state */
  memcpy (dev->reg, local_reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

/*TODO: find out where sanei_genesys_search_reference_point 
  stores information, and use that correctly*/
  status =
    sanei_genesys_search_reference_point (dev, data, 0, dpi, pixels,
					  dev->model->search_lines);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_start_position: failed to set search reference point: %s\n",
	   sane_strstatus (status));
      return status;
    }

  free (data);
  return SANE_STATUS_GOOD;
}

/* 
 * sets up register for coarse gain calibration
 * todo: check it for scanners using it */
static SANE_Status
gl847_init_regs_for_coarse_calibration (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t channels;
  uint8_t cksel;

  DBG (DBG_proc, "gl847_init_regs_for_coarse_calibration\n");


  cksel = (dev->calib_reg[reg_0x18].value & REG18_CKSEL) + 1;	/* clock speed = 1..4 clocks */

  /* set line size */
  if (dev->settings.scan_mode == SCAN_MODE_COLOR)	/* single pass color */
    channels = 3;
  else
    channels = 1;

  status = gl847_init_scan_regs (dev,
				 dev->calib_reg,
				 dev->settings.xres,
				 dev->settings.yres,
				 0,
				 0,
				 dev->sensor.optical_res / cksel,
				 20,
				 16,
				 channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_SINGLE_LINE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_init_register_for_coarse_calibration: Failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  DBG (DBG_info,
       "gl847_init_register_for_coarse_calibration: optical sensor res: %d dpi, actual res: %d\n",
       dev->sensor.optical_res / cksel, dev->settings.xres);

  status =
    gl847_bulk_write_register (dev, dev->calib_reg, GENESYS_GL847_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_init_register_for_coarse_calibration: Failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** @brief moves the slider to steps at motor base dpi
 * @param dev device to work on
 * @param steps number of steps to move
 * */
#ifndef UNIT_TESTING
static
#endif
SANE_Status
gl847_feed (Genesys_Device * dev, unsigned int steps)
{
  Genesys_Register_Set local_reg[GENESYS_GL847_MAX_REGS];
  SANE_Status status;
  Genesys_Register_Set *r;
  float resolution;
  uint8_t val;

  DBGSTART;

  /* prepare local registers */
  memset (local_reg, 0, sizeof (local_reg));
  memcpy (local_reg, dev->reg, GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  resolution=200;
  gl847_init_scan_regs (dev,
			local_reg,
			resolution,
			resolution,
			0,
			steps,
			100,
			3,
			8,
			3,
			dev->settings.color_filter,
			SCAN_FLAG_DISABLE_SHADING |
			SCAN_FLAG_DISABLE_GAMMA |
                        SCAN_FLAG_FEEDING |
			SCAN_FLAG_IGNORE_LINE_DISTANCE);
  sanei_genesys_set_triple(local_reg,REG_EXPR,0);
  sanei_genesys_set_triple(local_reg,REG_EXPG,0);
  sanei_genesys_set_triple(local_reg,REG_EXPB,0);

  /* clear scan and feed count */
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRLNCNT));
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRMCNT));
  
  /* set up for no scan */
  r = sanei_genesys_get_address (local_reg, REG01);
  r->value &= ~REG01_SCAN;
  
  /* send registers */
  RIE (gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS));

  status = gl847_start_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "%s: failed to start motor: %s\n", __FUNCTION__, sane_strstatus (status));
      gl847_stop_action (dev);

      /* restore original registers */
      gl847_bulk_write_register (dev, dev->reg, GENESYS_GL847_MAX_REGS);
      return status;
    }

  /* wait until feed count reaches the required value, but do not
   * exceed 30s */
  do
    {
          status = sanei_genesys_get_status (dev, &val);
    }
  while (status == SANE_STATUS_GOOD && !(val & FEEDFSH));
  
  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}


/* init registers for shading calibration */
static SANE_Status
gl847_init_regs_for_shading (Genesys_Device * dev)
{
  SANE_Status status;

  DBG (DBG_proc, "gl847_init_regs_for_shading: lines = %d\n", dev->calib_lines);

  dev->calib_channels = 3;

  /* initial calibration reg values */
  memcpy (dev->calib_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  dev->calib_resolution = sanei_genesys_compute_dpihw(dev,dev->settings.xres);
  dev->calib_lines = dev->model->shading_lines;
  if(dev->calib_resolution==4800)
    dev->calib_lines *= 2;
  dev->calib_pixels = (dev->sensor.sensor_pixels*dev->calib_resolution)/dev->sensor.optical_res;

  status = gl847_init_scan_regs (dev,
				 dev->calib_reg,
                                 dev->calib_resolution,
				 dev->calib_resolution,
				 0,
				 0,
				 dev->calib_pixels,
				 dev->calib_lines,
                                 16,
				 dev->calib_channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
  				 SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);

  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "%s: failed to setup scan: %s\n", __FUNCTION__, sane_strstatus (status));
      return status;
    }
 
  status = gl847_bulk_write_register (dev, dev->calib_reg, GENESYS_GL847_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "%s: failed to bulk write registers: %s\n", __FUNCTION__, sane_strstatus (status));
      return status;
    }

  /* TODO this is a good approximation, replace by exact value */
  dev->scanhead_position_in_steps = (5*dev->calib_lines*600)/dev->calib_resolution;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** @brief set up registers for the actual scan
 */
static SANE_Status
gl847_init_regs_for_scan (Genesys_Device * dev)
{
  int channels;
  int flags;
  int depth;
  float move;
  int move_dpi;
  float start;
  uint8_t val;

  SANE_Status status;

  DBG (DBG_info,
       "gl847_init_regs_for_scan settings:\nResolution: %uDPI\n"
       "Lines     : %u\nPPL       : %u\nStartpos  : %.3f/%.3f\nScan mode : %d\n\n",
       dev->settings.yres, dev->settings.lines, dev->settings.pixels,
       dev->settings.tl_x, dev->settings.tl_y, dev->settings.scan_mode);

 /* channels */
  if (dev->settings.scan_mode == SCAN_MODE_COLOR)	/* single pass color */
    channels = 3;
  else
    channels = 1;

  /* depth */
  depth = dev->settings.depth;
  if (dev->settings.scan_mode == SCAN_MODE_LINEART)
    depth = 1;


  /* steps to move to reach scanning area:
     - first we move to physical start of scanning
     either by a fixed steps amount from the black strip
     or by a fixed amount from parking position,
     minus the steps done during shading calibration
     - then we move by the needed offset whitin physical
     scanning area

     assumption: steps are expressed at maximum motor resolution

     we need:   
     SANE_Fixed y_offset;                       
     SANE_Fixed y_size;                 
     SANE_Fixed y_offset_calib;
     mm_to_steps()=motor dpi / 2.54 / 10=motor dpi / MM_PER_INCH */

  /* if scanner uses GENESYS_FLAG_SEARCH_START y_offset is
     relative from origin, else, it is from parking position */

  move_dpi = dev->motor.base_ydpi;

  move = SANE_UNFIX (dev->model->y_offset);
  move += dev->settings.tl_y;
  move = (move * move_dpi) / MM_PER_INCH;
  move -= dev->scanhead_position_in_steps;
  DBG (DBG_info, "%s: move=%f steps\n",__FUNCTION__, move);

  /* unused for now */
  if(dev->settings.yres>31200)
    {
      status = gl847_feed (dev, move);
      if (status != SANE_STATUS_GOOD)
        {
          DBG (DBG_error, "%s: failed to move to scan area\n",__FUNCTION__);
          return status;
        }
      move=0;
    }
  DBG (DBG_info, "%s: move=%f steps\n", __FUNCTION__, move);

  /* clear scancnt and fedcnt */
  val = REG0D_CLRLNCNT;
  RIE (sanei_genesys_write_register (dev, REG0D, val));
  val = REG0D_CLRMCNT;
  RIE (sanei_genesys_write_register (dev, REG0D, val));

  /* start */
  start = SANE_UNFIX (dev->model->x_offset);
  start += dev->settings.tl_x;
  start = (start * dev->sensor.optical_res) / MM_PER_INCH;

  flags = 0;

  /* emulated lineart from gray data is required for now */
  if(dev->settings.scan_mode == SCAN_MODE_LINEART 
     && dev->settings.dynamic_lineart)
    {
      flags |= SCAN_FLAG_DYNAMIC_LINEART;
    }

  /* backtracking isn't handled well, so don't enable it */
  flags |= SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE;

  status = gl847_init_scan_regs (dev,
				 dev->reg,
				 dev->settings.xres,
				 dev->settings.yres,
				 start,
				 move,
				 dev->settings.pixels,
				 dev->settings.lines,
				 depth,
				 channels,
                                 dev->settings.color_filter,
                                 flags);

  if (status != SANE_STATUS_GOOD)
    return status;
  
  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}


/** @brief send gmma table to scanner
 * This function sends generic gamma table (ie ones built with
 * provided gamma) or the user defined one if provided by 
 * fontend.
 * @param dev device to write to
 * @param generic flag for using generic gamma tables
 */
static SANE_Status
gl847_send_gamma_table (Genesys_Device * dev, SANE_Bool generic)
{
  int size;
  int status;
  uint8_t *gamma, val;
  int i, gmmval;

  DBG (DBG_proc, "gl847_send_gamma_table\n");

  /* don't send anything if no specific gamma table defined */
  if (!generic
      && (dev->sensor.red_gamma_table == NULL
	  || dev->sensor.green_gamma_table == NULL
	  || dev->sensor.blue_gamma_table == NULL))
    {
      DBG (DBG_proc, "gl847_send_gamma_table: nothing to send, skipping\n");
      return SANE_STATUS_GOOD;
    }

  size = 256;

  /* allocate temporary gamma tables: 16 bits words, 3 channels */
  gamma = (uint8_t *) malloc (size * 2 * 3);
  if (!gamma)
    return SANE_STATUS_NO_MEM;

  /* take care off generic/specific data */
  if (generic)
    {
      /* fill with default values */
      for (i = 0; i < size; i++)
	{
	  gmmval = i * 256;
	  gamma[i * 2 + size * 0 + 0] = gmmval & 0xff;
	  gamma[i * 2 + size * 0 + 1] = (gmmval >> 8) & 0xff;
	  gamma[i * 2 + size * 2 + 0] = gmmval & 0xff;
	  gamma[i * 2 + size * 2 + 1] = (gmmval >> 8) & 0xff;
	  gamma[i * 2 + size * 4 + 0] = gmmval & 0xff;
	  gamma[i * 2 + size * 4 + 1] = (gmmval >> 8) & 0xff;
	}
    }
  else
    {
      /* copy sensor specific's gamma tables */
      for (i = 0; i < size; i++)
	{
	  gamma[i * 2 + size * 0 + 0] = dev->sensor.red_gamma_table[i] & 0xff;
	  gamma[i * 2 + size * 0 + 1] =
	    (dev->sensor.red_gamma_table[i] >> 8) & 0xff;
	  gamma[i * 2 + size * 2 + 0] =
	    dev->sensor.green_gamma_table[i] & 0xff;
	  gamma[i * 2 + size * 2 + 1] =
	    (dev->sensor.green_gamma_table[i] >> 8) & 0xff;
	  gamma[i * 2 + size * 4 + 0] =
	    dev->sensor.blue_gamma_table[i] & 0xff;
	  gamma[i * 2 + size * 4 + 1] =
	    (dev->sensor.blue_gamma_table[i] >> 8) & 0xff;
	}
    }

  /* loop sending gamma tables NOTE: 0x01000000 not 0x10000000 */
  for (i = 0; i < 3; i++)
    {
      /* clear corresponding GMM_N bit */
      RIE (sanei_genesys_read_register (dev, 0xbd, &val));
      val &= ~(0x01 << i);
      RIE (sanei_genesys_write_register (dev, 0xbd, val));

      /* clear corresponding GMM_F bit */
      RIE (sanei_genesys_read_register (dev, 0xbe, &val));
      val &= ~(0x01 << i);
      RIE (sanei_genesys_write_register (dev, 0xbe, val));

      /* set GMM_Z */
      RIE (sanei_genesys_write_register (dev, 0xc5+2*i, 0x00));
      RIE (sanei_genesys_write_register (dev, 0xc6+2*i, 0x00));

      status =
	sanei_genesys_write_ahb (dev->dn, 0x01000000 + 0x200 * i, size * 2,
		   gamma + i * size * 2);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_send_gamma_table: write to AHB failed writing table %d (%s)\n",
	       i, sane_strstatus (status));
	}
    }

  free (gamma);
  DBGCOMPLETED;
  return status;
}

/**
 * Send shading calibration data. The buffer is considered to always hold values
 * for all the channels.
 */
static SANE_Status
gl847_send_shading_data (Genesys_Device * dev, uint8_t * data, int size)
{
  SANE_Status status = SANE_STATUS_GOOD;
  uint32_t addr, length, i, x, factor, pixels;
  uint32_t dpiset, dpihw, strpixel, endpixel;
  uint16_t tempo;
  uint32_t lines, channels;
  uint8_t val,*buffer,*ptr,*src;

  DBGSTART;
  DBG( DBG_io2, "%s: writing %d bytes of shading data\n",__FUNCTION__,size);

  /* shading data is plit in 3 (up to 5 with IR) areas 
     write(0x10014000,0x00000dd8)
     URB 23429  bulk_out len  3544  wrote 0x33 0x10 0x....
     write(0x1003e000,0x00000dd8)
     write(0x10068000,0x00000dd8)
   */
  length = (uint32_t) (size / 3);
  sanei_genesys_get_double(dev->reg,REG_STRPIXEL,&tempo);
  strpixel=tempo;
  sanei_genesys_get_double(dev->reg,REG_ENDPIXEL,&tempo);
  endpixel=tempo;
  DBG( DBG_io2, "%s: STRPIXEL=%d, ENDPIXEL=%d, PIXELS=%d\n",__FUNCTION__,strpixel,endpixel,endpixel-strpixel);

  /* compute deletion factor */
  sanei_genesys_get_double(dev->reg,REG_DPISET,&tempo);
  dpiset=tempo;
  dpihw=sanei_genesys_compute_dpihw(dev,dpiset);
  factor=dpihw/dpiset;
  DBG( DBG_io2, "%s: factor=%d\n",__FUNCTION__,factor);

  if(DBG_LEVEL>=DBG_data)
    {
      dev->binary=fopen("binary.pnm","wb");
      sanei_genesys_get_triple(dev->reg, REG_LINCNT, &lines);
      channels=3;
      if(dev->binary!=NULL)
        {
          fprintf(dev->binary,"P5\n%d %d\n%d\n",(endpixel-strpixel)/factor*channels,lines/channels,255);
        }
    }
  
  pixels=endpixel-strpixel;

  /* since we're using SHDAREA, substract startx coordinate from shading,
   * but not a 4800 dpi where hardware coordinates are fixed */
  if(dpihw!=4800)
    {
      strpixel-=((dev->sensor.CCD_start_xoffset*600)/dev->sensor.optical_res);
    }
  else
    {
      strpixel=0;
    }
  
  /* turn pixel value into bytes 2x16 bits words */
  strpixel*=2*2; 
  endpixel*=2*2;
  pixels*=2*2;

  /* allocate temporary buffer */
  buffer=(uint8_t *)malloc(pixels);
  memset(buffer,0,pixels);
  DBG( DBG_io2, "%s: using chunks of %d (0x%04x) bytes\n",__FUNCTION__,pixels,pixels);

  /* base addr of data has been written in reg D0-D4 in 4K word, so AHB address
   * is 8192*reg value */

  /* write actual color channel data */
  for(i=0;i<3;i++)
    {
      /* build up actual shading data by copying the part from the full width one
       * to the one corresponding to SHDAREA */
      ptr=buffer;

      /* iterate on both sensor segment */
      for(x=0;x<pixels;x+=4*factor)
        {
          /* coefficient source */
          src=(data+strpixel+i*length)+x;

          /* coefficient copy */
          ptr[0]=src[0];
          ptr[1]=src[1];
          ptr[2]=src[2];
          ptr[3]=src[3];
          
          /* next shading coefficient */
          ptr+=4;
        }

      RIE (sanei_genesys_read_register (dev, 0xd0+i, &val));
      addr = val * 8192 + 0x10000000;
      status = sanei_genesys_write_ahb (dev->dn, addr, pixels, buffer);
      if (status != SANE_STATUS_GOOD)
        {
          DBG (DBG_error, "gl847_send_shading_data; write to AHB failed (%s)\n",
	      sane_strstatus (status));
          return status;
        }
    }

  free(buffer);
  DBGCOMPLETED;

  return status;
}

/* this function does the led calibration by scanning one line of the calibration
   area below scanner's top on white strip.

-needs working coarse/gain
*/
static SANE_Status
gl847_led_calibration (Genesys_Device * dev)
{
  int num_pixels;
  int total_size;
  int used_res;
  uint8_t *line;
  int i, j;
  SANE_Status status = SANE_STATUS_GOOD;
  int val;
  int channels, depth;
  int avg[3], avga, avge;
  int turn;
  char fn[20];
  uint16_t expr, expg, expb;
  Sensor_Profile *sensor;
  Genesys_Register_Set *r;

  SANE_Bool acceptable = SANE_FALSE;

  DBGSTART;

  /* offset calibration is always done in color mode */
  channels = 3;
  depth=16;
  used_res=sanei_genesys_compute_dpihw(dev,dev->settings.xres);
  sensor=get_sensor_profile(dev->model->ccd_type, used_res);
  num_pixels = (dev->sensor.sensor_pixels*used_res)/dev->sensor.optical_res;
  
  /* initial calibration reg values */
  memcpy (dev->calib_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  status = gl847_init_scan_regs (dev,
				 dev->calib_reg,
				 used_res,
				 used_res,
				 0,
				 0,
				 num_pixels,
                                 1,
                                 depth,
                                 channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_SINGLE_LINE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);

  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_led_calibration: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  RIE (gl847_bulk_write_register
       (dev, dev->calib_reg, GENESYS_GL847_MAX_REGS));


  total_size = num_pixels * channels * (depth/8) * 1;	/* colors * bytes_per_color * scan lines */

  line = malloc (total_size);
  if (!line)
    return SANE_STATUS_NO_MEM;

/* 
   we try to get equal bright leds here:

   loop:
     average per color
     adjust exposure times
 */

  expr=sensor->expr;
  expg=sensor->expg;
  expb=sensor->expb;

  turn = 0;

  /* no move during led calibration */
  r = sanei_genesys_get_address (dev->calib_reg, REG02);
  r->value &= ~REG02_MTRPWR;
  do
    {
      sanei_genesys_set_double(dev->calib_reg,REG_EXPR,expr);
      sanei_genesys_set_double(dev->calib_reg,REG_EXPG,expg);
      sanei_genesys_set_double(dev->calib_reg,REG_EXPB,expb);

      RIE (gl847_bulk_write_register
	   (dev, dev->calib_reg, GENESYS_GL847_MAX_REGS));

      DBG (DBG_info, "gl847_led_calibration: starting first line reading\n");
      RIE (gl847_begin_scan (dev, dev->calib_reg, SANE_TRUE));
      RIE (sanei_genesys_read_data_from_scanner (dev, line, total_size));

      if (DBG_LEVEL >= DBG_data)
	{
	  snprintf (fn, 20, "led_%02d.pnm", turn);
	  sanei_genesys_write_pnm_file (fn,
					line, depth, channels, num_pixels, 1);
	}

      acceptable = SANE_TRUE;

      for (j = 0; j < channels; j++)
	{
	  avg[j] = 0;
	  for (i = 0; i < num_pixels; i++)
	    {
	      if (dev->model->is_cis)
		val =
		  line[i * 2 + j * 2 * num_pixels + 1] * 256 +
		  line[i * 2 + j * 2 * num_pixels];
	      else
		val =
		  line[i * 2 * channels + 2 * j + 1] * 256 +
		  line[i * 2 * channels + 2 * j];
	      avg[j] += val;
	    }

	  avg[j] /= num_pixels;
	}
      avga = (avg[0] + avg[1] + avg[2]) / 3;

      DBG (DBG_info, "gl847_led_calibration: average: "
	   "%d,%d,%d\n", avg[0], avg[1], avg[2]);

      acceptable = SANE_TRUE;

      if (avg[0] < avg[1] * 0.95 || avg[1] < avg[0] * 0.95 ||
	  avg[0] < avg[2] * 0.95 || avg[2] < avg[0] * 0.95 ||
	  avg[1] < avg[2] * 0.95 || avg[2] < avg[1] * 0.95)
	acceptable = SANE_FALSE;

      if (!acceptable)
	{
	  expr = (expr * avga) / avg[0];
	  expg = (expg * avga) / avg[1];
	  expb = (expb * avga) / avg[2];
/*
  keep the resulting exposures below this value.
  too long exposure drives the ccd into saturation.
  we may fix this by relying on the fact that 
  we get a striped scan without shading, by means of
  statistical calculation 
*/
	  avge = (expr + expg + expb) / 3;

          /* don't overflow max exposure */
	  if (avge > 3000)
	    {
	      expr = (expr * 2000) / avge;
	      expg = (expg * 2000) / avge;
	      expb = (expb * 2000) / avge;
	    }
	  if (avge < 50)
	    {
	      expr = (expr * 50) / avge;
	      expg = (expg * 50) / avge;
	      expb = (expb * 50) / avge;
	    }

	}

      RIE (gl847_stop_action (dev));

      turn++;

    }
  while (!acceptable && turn < 100);

  DBG (DBG_info, "gl847_led_calibration: acceptable exposure: %d,%d,%d\n",
       expr, expg, expb);

  /* set these values as final ones for scan */
  sanei_genesys_set_double(dev->reg,REG_EXPR,expr);
  sanei_genesys_set_double(dev->reg,REG_EXPG,expg);
  sanei_genesys_set_double(dev->reg,REG_EXPB,expb);

  /* store in this struct since it is the one used by cache calibration */
  dev->sensor.regs_0x10_0x1d[0] = (expr >> 8) & 0xff;
  dev->sensor.regs_0x10_0x1d[1] = expr & 0xff;
  dev->sensor.regs_0x10_0x1d[2] = (expg >> 8) & 0xff;
  dev->sensor.regs_0x10_0x1d[3] = expg & 0xff;
  dev->sensor.regs_0x10_0x1d[4] = (expb >> 8) & 0xff;
  dev->sensor.regs_0x10_0x1d[5] = expb & 0xff;

  /* cleanup before return */
  free (line);
 
  DBGCOMPLETED;
  return status;
}

/* this function does the offset calibration by scanning one line of the calibration
   area below scanner's top. There is a black margin and the remaining is white.
   sanei_genesys_search_start() must have been called so that the offsets and margins
   are allready known.

this function expects the slider to be where?
*/
static SANE_Status
gl847_offset_calibration (Genesys_Device * dev)
{
  DBG (DBG_proc, "%s: not implemented \n", __FUNCTION__);
  return SANE_STATUS_GOOD;
}


/* alternative coarse gain calibration 
   this on uses the settings from offset_calibration and
   uses only one scanline
 */
/*
  with offset and coarse calibration we only want to get our input range into
  a reasonable shape. the fine calibration of the upper and lower bounds will 
  be done with shading.
 */
static SANE_Status
gl847_coarse_gain_calibration (Genesys_Device * dev, int dpi)
{
  DBG (DBG_proc, "%s: not implemented \n", __FUNCTION__);
  return SANE_STATUS_GOOD;
}

/*
 * wait for lamp warmup by scanning the same line until difference
 * between 2 scans is below a threshold
 */
static SANE_Status
gl847_init_regs_for_warmup (Genesys_Device * dev,
			    Genesys_Register_Set * local_reg,
			    int *channels, int *total_size)
{
  DBG (DBG_proc, "%s: not implemented \n", __FUNCTION__);
  return SANE_STATUS_INVAL;
}

/** 
 * set up GPIO/GPOE for idle state
 */
static SANE_Status
gl847_init_gpio (Genesys_Device * dev)
{
  SANE_Status status = SANE_STATUS_GOOD;
  uint8_t val, effective;

  DBG (DBG_proc, "gl847_init_gpio: start\n");

  RIE (sanei_genesys_write_register (dev, 0x6e, dev->gpo.enable[0]));
  RIE (sanei_genesys_write_register (dev, 0x6f, dev->gpo.enable[1]));
  RIE (sanei_genesys_write_register (dev, 0xa7, 0x04));
  RIE (sanei_genesys_write_register (dev, 0xa8, 0x00));
  RIE (sanei_genesys_write_register (dev, 0xa9, 0x00));

  /* toggle needed bits one after all */
  /* TODO define a function for bit toggling */
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  val = effective | 0x80;
  RIE (sanei_genesys_write_register (dev, REG6C, val));
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  if (effective != val)
    {
      DBG (DBG_warn,
	   "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
	   effective, val);
    }

  val = effective | 0x40;
  RIE (sanei_genesys_write_register (dev, REG6C, val));
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  if (effective != val)
    {
      DBG (DBG_warn,
	   "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
	   effective, val);
    }

  val = effective | 0x20;
  RIE (sanei_genesys_write_register (dev, REG6C, val));

  /* seems useless : memory or clock related ? */
  RIE (sanei_genesys_read_register (dev, REG0B, &effective));
  RIE (sanei_genesys_write_register (dev, REG0B, effective));

  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  if (effective != val)
    {
      DBG (DBG_warn,
	   "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
	   effective, val);
    }

  /* not done yet for LiDE 100
     val = effective | 0x08;
     RIE (sanei_genesys_write_register (dev, REG6C, val));
     RIE (sanei_genesys_read_register (dev, REG6C, &effective));
     if (effective != val)
     {
     DBG (DBG_warn, "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
     effective, val);
     } */

  val = effective | 0x02;
  RIE (sanei_genesys_write_register (dev, REG6C, val));
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  if (effective != val)
    {
      DBG (DBG_warn,
	   "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
	   effective, val);
    }

  val = effective | 0x01;
  RIE (sanei_genesys_write_register (dev, REG6C, val));
  RIE (sanei_genesys_read_register (dev, REG6C, &effective));
  if (effective != val)
    {
      DBG (DBG_warn,
	   "gl847_init_gpio: effective!=needed (0x%02x!=0x%02x) \n",
	   effective, val);
    }

  DBGCOMPLETED;
  return status;
}

/** 
 * set memory layout by filling values in dedicated registers
 */
static SANE_Status
gl847_init_memory_layout (Genesys_Device * dev)
{
  SANE_Status status = SANE_STATUS_GOOD;
  int idx = 0;

  DBG (DBG_proc, "gl847_init_memory_layout\n");

  /* point to per model memory layout */
  idx = 0;
  if (strcmp (dev->model->name, "canon-lide-100") == 0)
    {
      idx = 0;
    }
  if (strcmp (dev->model->name, "canon-lide-200") == 0)
    {
      idx = 1;
    }
  if (strcmp (dev->model->name, "canon-5600f") == 0)
    {
      idx = 2;
    }
  if (strcmp (dev->model->name, "canon-lide-700f") == 0)
    {
      idx = 3;
    }

  /* setup base address for shading data. */
  /* values must be multiplied by 8192=0x4000 to give address on AHB */
  /* R-Channel shading bank0 address setting for CIS */
  sanei_genesys_write_register (dev, 0xd0, layouts[idx].rd0);
  /* G-Channel shading bank0 address setting for CIS */
  sanei_genesys_write_register (dev, 0xd1, layouts[idx].rd1);
  /* B-Channel shading bank0 address setting for CIS */
  sanei_genesys_write_register (dev, 0xd2, layouts[idx].rd2);

  /* setup base address for scanned data. */
  /* values must be multiplied by 1024*2=0x0800 to give address on AHB */
  /* R-Channel ODD image buffer 0x0124->0x92000 */
  /* size for each buffer is 0x16d*1k word */
  sanei_genesys_write_register (dev, 0xe0, layouts[idx].re0);
  sanei_genesys_write_register (dev, 0xe1, layouts[idx].re1);
/* R-Channel ODD image buffer end-address 0x0291->0x148800 => size=0xB6800*/
  sanei_genesys_write_register (dev, 0xe2, layouts[idx].re2);
  sanei_genesys_write_register (dev, 0xe3, layouts[idx].re3);

  /* R-Channel EVEN image buffer 0x0292 */
  sanei_genesys_write_register (dev, 0xe4, layouts[idx].re4);
  sanei_genesys_write_register (dev, 0xe5, layouts[idx].re5);
/* R-Channel EVEN image buffer end-address 0x03ff*/
  sanei_genesys_write_register (dev, 0xe6, layouts[idx].re6);
  sanei_genesys_write_register (dev, 0xe7, layouts[idx].re7);

/* same for green, since CIS, same addresses */
  sanei_genesys_write_register (dev, 0xe8, layouts[idx].re0);
  sanei_genesys_write_register (dev, 0xe9, layouts[idx].re1);
  sanei_genesys_write_register (dev, 0xea, layouts[idx].re2);
  sanei_genesys_write_register (dev, 0xeb, layouts[idx].re3);
  sanei_genesys_write_register (dev, 0xec, layouts[idx].re4);
  sanei_genesys_write_register (dev, 0xed, layouts[idx].re5);
  sanei_genesys_write_register (dev, 0xee, layouts[idx].re6);
  sanei_genesys_write_register (dev, 0xef, layouts[idx].re7);

/* same for blue, since CIS, same addresses */
  sanei_genesys_write_register (dev, 0xf0, layouts[idx].re0);
  sanei_genesys_write_register (dev, 0xf1, layouts[idx].re1);
  sanei_genesys_write_register (dev, 0xf2, layouts[idx].re2);
  sanei_genesys_write_register (dev, 0xf3, layouts[idx].re3);
  sanei_genesys_write_register (dev, 0xf4, layouts[idx].re4);
  sanei_genesys_write_register (dev, 0xf5, layouts[idx].re5);
  sanei_genesys_write_register (dev, 0xf6, layouts[idx].re6);
  sanei_genesys_write_register (dev, 0xf7, layouts[idx].re7);

  DBGCOMPLETED;
  return status;
}

/* *
 * initialize ASIC from power on condition
 */
static SANE_Status
gl847_cold_boot (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t val;

  DBGSTART;

  RIE (sanei_genesys_write_register (dev, 0x0e, 0x01));
  RIE (sanei_genesys_write_register (dev, 0x0e, 0x00));

  /* test CHKVER */
  RIE (sanei_genesys_read_register (dev, REG40, &val));
  if (val & REG40_CHKVER)
    {
      RIE (sanei_genesys_read_register (dev, 0x00, &val));
      DBG (DBG_info, "gl847_cold_boot: reported version for genesys chip is 0x%02x\n", val);
    }

  /* setup GPIO */
  sanei_genesys_read_register (dev, REGA6, &val);
  sanei_genesys_write_register (dev, REGA6, val | 0x04);
  sanei_genesys_write_register (dev, REGA7, 0x0f);
  sanei_genesys_write_register (dev, REGA9, 0x00);

  /* Set default values for registers */
  gl847_init_registers (dev);

  RIE (sanei_genesys_write_register (dev, REG6B, 0x02));
  RIE (sanei_genesys_write_register (dev, REG6C, 0x00));
  RIE (sanei_genesys_write_register (dev, REG6D, 0x20));
  RIE (sanei_genesys_write_register (dev, REG6E, 0x7e));
  RIE (sanei_genesys_write_register (dev, REG6F, 0x21));

  /* Write initial registers */
  RIE (gl847_bulk_write_register (dev, dev->reg, GENESYS_GL847_MAX_REGS));

  /* Enable DRAM by setting a rising edge on bit 3 of reg 0x0b */
  val = dev->reg[reg_0x0b].value & REG0B_DRAMSEL;
  val = (val | REG0B_ENBDRAM);
  RIE (sanei_genesys_write_register (dev, REG0B, val));
  dev->reg[reg_0x0b].value = val;

  /* read back GPIO TODO usefull ? */
  sanei_genesys_read_register (dev, REGA6, &val);
  if (val != 0x04)
    {
      DBG (DBG_warn, "gl847_cold_boot: GPIO is 0x%02d instead of 0x04\n", val);
    }

  /* set up clock once for all */
  RIE (sanei_genesys_write_register (dev, 0x77, 0x00));
  RIE (sanei_genesys_write_register (dev, 0x78, 0x00));
  RIE (sanei_genesys_write_register (dev, 0x79, 0x9f));

  /* CLKSET */
  val = (dev->reg[reg_0x0b].value & ~REG0B_CLKSET) | REG0B_30MHZ;
  RIE (sanei_genesys_write_register (dev, REG0B, val));
  dev->reg[reg_0x0b].value = val;

  /* prevent further writings by bulk write register */
  dev->reg[reg_0x0b].address = 0x00;

  /* CIS_LINE */
  SETREG (0x08, REG08_CIS_LINE);
  RIE (sanei_genesys_write_register (dev, 0x08, dev->reg[reg_0x08].value));

  /* set up end access */
  RIE (sanei_genesys_write_0x8c (dev, 0x10, 0x0b));
  RIE (sanei_genesys_write_0x8c (dev, 0x13, 0x0e));

  sanei_genesys_write_register (dev, REGA7, 0x04);
  sanei_genesys_write_register (dev, REGA9, 0x00);

  /* setup gpio */
  RIE (gl847_init_gpio (dev));

  /* setup internal memory layout */
  RIE (gl847_init_memory_layout (dev));

  SETREG (0xf8, 0x01);
  RIE (sanei_genesys_write_register (dev, 0xf8, dev->reg[reg_0xf8].value));

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/* *
 * initialize backend and ASIC : registers, motor tables, and gamma tables
 * then ensure scanner's head is at home
 */
static SANE_Status
gl847_init (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t val;
  SANE_Bool cold = SANE_TRUE;
  int size;

  DBG_INIT ();
  DBGSTART;
  
  status = sanei_usb_control_msg (dev->dn, REQUEST_TYPE_IN, REQUEST_REGISTER, VALUE_GET_REGISTER, 0, 1, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_init: request register failed %s\n", sane_strstatus (status));
      return status;
    }
  DBG( DBG_io2, "gl847_init: value=0x%02x\n",val);

  /* check if the device has already been initialized and powered up 
   * we read register 6 and check PWRBIT, if reset scanner has been
   * freshly powered up. This bit will be set to later so that following
   * reads can detect power down/up cycle*/
  RIE (sanei_genesys_read_register (dev, 0x06, &val));
  if (val & REG06_PWRBIT)
    {
      cold = SANE_FALSE;
    }
  DBG (DBG_info, "%s: device is %s\n", __FUNCTION__, cold ? "cold" : "warm");

  /* don't do anything is backend is initialized and hardware hasn't been
   * replug */
  if (dev->already_initialized && !cold)
    {
      DBG (DBG_info, "gl847_init: already initialized, nothing to do\n");
      return SANE_STATUS_GOOD;
    }

  /* set up hardware and registers */
  RIE (gl847_cold_boot (dev));

  /* move head away from park position */
  gl847_feed (dev, 300);

  /* now hardware part is OK, set up device struct */
  FREE_IFNOT_NULL (dev->white_average_data);
  FREE_IFNOT_NULL (dev->dark_average_data);
  FREE_IFNOT_NULL (dev->sensor.red_gamma_table);
  FREE_IFNOT_NULL (dev->sensor.green_gamma_table);
  FREE_IFNOT_NULL (dev->sensor.blue_gamma_table);

  dev->settings.color_filter = 0;

  memcpy (dev->calib_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  /* Set analog frontend */
  RIE (gl847_set_fe (dev, AFE_INIT));

  /* init gamma tables */
  size = 256;
  if (dev->sensor.red_gamma_table == NULL)
    {
      dev->sensor.red_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl847_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.red_gamma_table, size,
					65535, 65535, dev->sensor.red_gamma);
    }
  if (dev->sensor.green_gamma_table == NULL)
    {
      dev->sensor.green_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl847_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.green_gamma_table, size,
					65535, 65535,
					dev->sensor.green_gamma);
    }
  if (dev->sensor.blue_gamma_table == NULL)
    {
      dev->sensor.blue_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl847_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.blue_gamma_table, size,
					65535, 65535, dev->sensor.blue_gamma);
    }
  
  dev->oe_buffer.buffer=NULL;
  dev->already_initialized = SANE_TRUE;

  /* Move home if needed */
  RIE (gl847_slow_back_home (dev, SANE_TRUE));

  /* Set powersaving (default = 15 minutes) */
  RIE (gl847_set_powersaving (dev, 15));

  DBGCOMPLETED;
  return status;
}

static SANE_Status
gl847_update_hardware_sensors (Genesys_Scanner * s)
{
  /* do what is needed to get a new set of events, but try to not lose
     any of them.
   */
  SANE_Status status = SANE_STATUS_GOOD;
  uint8_t val;

  RIE (sanei_genesys_read_register (s->dev, REG6D, &val));

  if (s->val[OPT_SCAN_SW].b == s->last_val[OPT_SCAN_SW].b)
    s->val[OPT_SCAN_SW].b = (val & 0x01) == 0;
  if (s->val[OPT_FILE_SW].b == s->last_val[OPT_FILE_SW].b)
    s->val[OPT_FILE_SW].b = (val & 0x02) == 0;
  if (s->val[OPT_EMAIL_SW].b == s->last_val[OPT_EMAIL_SW].b)
    s->val[OPT_EMAIL_SW].b = (val & 0x04) == 0;
  if (s->val[OPT_COPY_SW].b == s->last_val[OPT_COPY_SW].b)
    s->val[OPT_COPY_SW].b = (val & 0x08) == 0;

  return status;
}

/** @brief search for a full width black or white strip.
 * This function searches for a black or white stripe across the scanning area.
 * When searching backward, the searched area must completely be of the desired 
 * color since this area will be used for calibration which scans forward.
 * @param dev scanner device
 * @param forward SANE_TRUE if searching forward, SANE_FALSE if searching backward
 * @param black SANE_TRUE if searching for a black strip, SANE_FALSE for a white strip
 * @return SANE_STATUS_GOOD if a matching strip is found, SANE_STATUS_UNSUPPORTED if not
 */
static SANE_Status
gl847_search_strip (Genesys_Device * dev, SANE_Bool forward, SANE_Bool black)
{
  unsigned int pixels, lines, channels;
  SANE_Status status;
  Genesys_Register_Set local_reg[GENESYS_GL847_MAX_REGS];
  size_t size;
  uint8_t *data;
  int steps, depth, dpi;
  unsigned int pass, count, found, x, y;
  char title[80];
  Genesys_Register_Set *r;

  DBG (DBG_proc, "gl847_search_strip %s %s\n", black ? "black" : "white",
       forward ? "forward" : "reverse");

  gl847_set_fe (dev, AFE_SET);
  status = gl847_stop_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_search_strip: failed to stop: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* set up for a gray scan at lowest dpi */
  dpi = 9600;
  for (x = 0; x < MAX_RESOLUTIONS; x++)
    {
      if (dev->model->xdpi_values[x] > 0 && dev->model->xdpi_values[x] < dpi)
	dpi = dev->model->xdpi_values[x];
    }
  channels = 1;
  /* 10 MM */
  lines = (10 * dpi) / MM_PER_INCH;
  /* shading calibation is done with dev->motor.base_ydpi */
  lines = (dev->model->shading_lines * dpi) / dev->motor.base_ydpi;
  depth = 8;
  pixels = (dev->sensor.sensor_pixels * dpi) / dev->sensor.optical_res;
  size = pixels * channels * lines * (depth / 8);
  data = malloc (size);
  if (!data)
    {
      DBG (DBG_error, "gl847_search_strip: failed to allocate memory\n");
      return SANE_STATUS_NO_MEM;
    }
  dev->scanhead_position_in_steps = 0;

  memcpy (local_reg, dev->reg,
	  GENESYS_GL847_MAX_REGS * sizeof (Genesys_Register_Set));

  status = gl847_init_scan_regs (dev,
				 local_reg,
				 dpi,
				 dpi,
				 0,
				 0,
				 pixels,
				 lines,
				 depth,
				 channels,
				 0,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_search_strip: failed to setup for scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* set up for reverse or forward */
  r = sanei_genesys_get_address (local_reg, REG02);
  if (forward)
    r->value &= ~REG02_MTRREV;
  else
    r->value |= REG02_MTRREV;


  status = gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl847_search_strip: Failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  status = gl847_begin_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_strip: failed to begin scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* waits for valid data */
  do
    sanei_genesys_test_buffer_empty (dev, &steps);
  while (steps);

  /* now we're on target, we can read data */
  status = sanei_genesys_read_data_from_scanner (dev, data, size);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl847_search_start_position: failed to read data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  status = gl847_stop_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error, "gl847_search_strip: gl847_stop_action failed\n");
      return status;
    }

  pass = 0;
  if (DBG_LEVEL >= DBG_data)
    {
      sprintf (title, "search_strip_%s_%s%02d.pnm",
	       black ? "black" : "white", forward ? "fwd" : "bwd", pass);
      sanei_genesys_write_pnm_file (title, data, depth, channels, pixels,
				    lines);
    }

  /* loop until strip is found or maximum pass number done */
  found = 0;
  while (pass < 20 && !found)
    {
      status =
	gl847_bulk_write_register (dev, local_reg, GENESYS_GL847_MAX_REGS);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl847_search_strip: Failed to bulk write registers: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      /* now start scan */
      status = gl847_begin_scan (dev, local_reg, SANE_TRUE);
      if (status != SANE_STATUS_GOOD)
	{
	  free (data);
	  DBG (DBG_error,
	       "gl847_search_strip: failed to begin scan: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      /* waits for valid data */
      do
	sanei_genesys_test_buffer_empty (dev, &steps);
      while (steps);

      /* now we're on target, we can read data */
      status = sanei_genesys_read_data_from_scanner (dev, data, size);
      if (status != SANE_STATUS_GOOD)
	{
	  free (data);
	  DBG (DBG_error,
	       "gl847_search_start_position: failed to read data: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      status = gl847_stop_action (dev);
      if (status != SANE_STATUS_GOOD)
	{
	  free (data);
	  DBG (DBG_error, "gl847_search_strip: gl847_stop_action failed\n");
	  return status;
	}

      if (DBG_LEVEL >= DBG_data)
	{
	  sprintf (title, "search_strip_%s_%s%02d.pnm",
		   black ? "black" : "white", forward ? "fwd" : "bwd", pass);
	  sanei_genesys_write_pnm_file (title, data, depth, channels,
					pixels, lines);
	}

      /* search data to find black strip */
      /* when searching forward, we only need one line of the searched color since we
       * will scan forward. But when doing backward search, we need all the area of the
       * same color */
      if (forward)
	{
	  for (y = 0; y < lines && !found; y++)
	    {
	      count = 0;
	      /* count of white/black pixels depending on the color searched */
	      for (x = 0; x < pixels; x++)
		{
		  /* when searching for black, detect white pixels */
		  if (black && data[y * pixels + x] > 90)
		    {
		      count++;
		    }
		  /* when searching for white, detect black pixels */
		  if (!black && data[y * pixels + x] < 60)
		    {
		      count++;
		    }
		}

	      /* at end of line, if count >= 3%, line is not fully of the desired color
	       * so we must go to next line of the buffer */
	      /* count*100/pixels < 3 */
	      if ((count * 100) / pixels < 3)
		{
		  found = 1;
		  DBG (DBG_data,
		       "gl847_search_strip: strip found forward during pass %d at line %d\n",
		       pass, y);
		}
	      else
		{
		  DBG (DBG_data,
		       "gl847_search_strip: pixels=%d, count=%d (%d%%)\n",
		       pixels, count, (100 * count) / pixels);
		}
	    }
	}
      else			/* since calibration scans are done forward, we need the whole area
				   to be of the required color when searching backward */
	{
	  count = 0;
	  for (y = 0; y < lines; y++)
	    {
	      /* count of white/black pixels depending on the color searched */
	      for (x = 0; x < pixels; x++)
		{
		  /* when searching for black, detect white pixels */
		  if (black && data[y * pixels + x] > 90)
		    {
		      count++;
		    }
		  /* when searching for white, detect black pixels */
		  if (!black && data[y * pixels + x] < 60)
		    {
		      count++;
		    }
		}
	    }

	  /* at end of area, if count >= 3%, area is not fully of the desired color
	   * so we must go to next buffer */
	  if ((count * 100) / (pixels * lines) < 3)
	    {
	      found = 1;
	      DBG (DBG_data,
		   "gl847_search_strip: strip found backward during pass %d \n",
		   pass);
	    }
	  else
	    {
	      DBG (DBG_data,
		   "gl847_search_strip: pixels=%d, count=%d (%d%%)\n",
		   pixels, count, (100 * count) / pixels);
	    }
	}
      pass++;
    }
  free (data);
  if (found)
    {
      status = SANE_STATUS_GOOD;
      DBG (DBG_info, "gl847_search_strip: %s strip found\n",
	   black ? "black" : "white");
    }
  else
    {
      status = SANE_STATUS_UNSUPPORTED;
      DBG (DBG_info, "gl847_search_strip: %s strip not found\n",
	   black ? "black" : "white");
    }

  DBGCOMPLETED;
  return status;
}

/** the gl847 command set */
static Genesys_Command_Set gl847_cmd_set = {
  "gl847-generic",		/* the name of this set */

  gl847_init,
  gl847_init_regs_for_warmup,
  gl847_init_regs_for_coarse_calibration,
  gl847_init_regs_for_shading,
  gl847_init_regs_for_scan,

  gl847_get_filter_bit,
  gl847_get_lineart_bit,
  gl847_get_bitset_bit,
  gl847_get_gain4_bit,
  gl847_get_fast_feed_bit,
  gl847_test_buffer_empty_bit,
  gl847_test_motor_flag_bit,

  gl847_bulk_full_size,

  gl847_set_fe,
  gl847_set_powersaving,
  gl847_save_power,

  gl847_set_motor_power,
  gl847_set_lamp_power,

  gl847_begin_scan,
  gl847_end_scan,

  gl847_send_gamma_table,

  gl847_search_start_position,

  gl847_offset_calibration,
  gl847_coarse_gain_calibration,
  gl847_led_calibration,

  gl847_slow_back_home,

  gl847_bulk_write_register,
  NULL,
  gl847_bulk_read_data,

  gl847_update_hardware_sensors,

  NULL, /* no known gl847 sheetfed scanner */
  NULL, /* no known gl847 sheetfed scanner */
  NULL, /* no known gl847 sheetfed scanner */
  gl847_search_strip,

  sanei_genesys_is_compatible_calibration,
  NULL,
  gl847_send_shading_data,
  gl847_calculate_current_setup
};

SANE_Status
sanei_gl847_init_cmd_set (Genesys_Device * dev)
{
  dev->model->cmd_set = &gl847_cmd_set;
  return SANE_STATUS_GOOD;
}

/* vim: set sw=2 cino=>2se-1sn-1s{s^-1st0(0u0 smarttab expandtab: */
