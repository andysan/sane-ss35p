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

#include "genesys_gl843.h"

/****************************************************************************
 Low level function
 ****************************************************************************/

/* ------------------------------------------------------------------------ */
/*                  Read and write RAM, registers and AFE                   */
/* ------------------------------------------------------------------------ */

/**
 *
 */
static SANE_Status
write_end_access (Genesys_Device * dev, uint8_t index, uint8_t val)
{
  SANE_Status status;

  DBG (DBG_io, "write_end_access: 0x%02x,0x%02x\n", index, val);

  status =
    sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_REGISTER,
			   VALUE_BUF_ENDACCESS, index, 1, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "write_end_access: failed %s\n", sane_strstatus (status));
    }
  return status;
}

/* Write bulk data (e.g. gamma) */
static SANE_Status
gl843_bulk_write_data (Genesys_Device * dev, uint8_t addr,
		       uint8_t * data, size_t len)
{
  SANE_Status status;
  size_t size;
  uint8_t outdata[8];

  DBGSTART;
  DBG (DBG_io, "gl843_bulk_write_data writing %lu bytes\n", (u_long) len);

  status =
    sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_REGISTER,
			   VALUE_SET_REGISTER, INDEX, 1, &addr);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_bulk_write_data failed while setting register: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* TODO check with G4050 that we shouldn't loop at all */
  while (len)
    {
      size = len;

      outdata[0] = BULK_OUT;
      outdata[1] = BULK_RAM;
      outdata[2] = 0x00;
      outdata[3] = 0x00;
      outdata[4] = (size & 0xff);
      outdata[5] = ((size >> 8) & 0xff);
      outdata[6] = ((size >> 16) & 0xff);
      outdata[7] = ((size >> 24) & 0xff);

      status =
	sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_BUFFER,
			       VALUE_BUFFER, INDEX, sizeof (outdata),
			       outdata);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_bulk_write_data failed while writing command: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      status = sanei_usb_write_bulk (dev->dn, data, &size);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_bulk_write_data failed while writing bulk data: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      DBG (DBG_io2,
	   "gl843_bulk_write_data: gamma wrote %lu bytes, %lu remaining\n",
	   (u_long) size, (u_long) (len - size));

      len -= size;
      data += size;
    }

  DBGCOMPLETED;
  return status;
}

/* Set address for writing data */
static SANE_Status
gl843_set_buffer_address (Genesys_Device * dev, uint32_t addr)
{
  SANE_Status status;

  DBG (DBG_io, "gl843_set_buffer_address: setting address to 0x%05x\n",
       addr & 0xffff);

  status = sanei_genesys_write_register (dev, 0x5b, ((addr >> 8) & 0xff));
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_set_buffer_address: failed while writing high byte: %s\n",
	   sane_strstatus (status));
      return status;
    }

  status = sanei_genesys_write_register (dev, 0x5c, (addr & 0xff));
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_set_buffer_address: failed while writing low byte: %s\n",
	   sane_strstatus (status));
      return status;
    }

  DBG (DBG_io, "gl843_set_buffer_address: completed\n");

  return status;
}

/**
 * writes a block of data to RAM
 * @param dev USB device
 * @param addr RAM address to write to
 * @param size size of the chunk of data
 * @param data pointer to the data to write
 */
static SANE_Status
write_data (Genesys_Device * dev, uint32_t addr, uint32_t size,
	    uint8_t * data)
{
  SANE_Status status = SANE_STATUS_GOOD;

  DBGSTART;

  status = gl843_set_buffer_address (dev, addr);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "write_data: failed while setting address for bulk write data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* write actual data */
  status = gl843_bulk_write_data (dev, 0x28, data, size);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "write_data: failed while writing bulk write data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* set back address to 0 */
  status = gl843_set_buffer_address (dev, 0);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "write_data: failed setting to default RAM address: %s\n",
	   sane_strstatus (status));
      return status;
    }
  DBGCOMPLETED;
  return status;
}

/**
 * Write to many GL843 registers at once
 */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_bulk_write_register (Genesys_Device * dev, Genesys_Register_Set * reg,
			   size_t elems)
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

  DBG (DBG_io, "gl843_bulk_write_register: wrote %lu registers\n",
       (u_long) elems);
  return status;
}

static SANE_Status
gl843_bulk_read_data (Genesys_Device * dev, uint8_t addr,
		      uint8_t * data, size_t len)
{
  SANE_Status status;
  size_t size;
  uint8_t outdata[8];

  DBGSTART;
  DBG (DBG_io,
       "gl843_bulk_read_data: requesting %lu bytes from 0x%02x addr\n",
       (u_long) len, addr);

  status =
    sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_REGISTER,
			   VALUE_SET_REGISTER, 0, 1, &addr);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "write_data: failed to set register address %s\n",
	   sane_strstatus (status));
      return status;
    }

  if (len == 0)
    return SANE_STATUS_GOOD;

  outdata[0] = BULK_IN;
  outdata[1] = BULK_RAM;
  outdata[2] = VALUE_BUFFER;
  outdata[3] = 0;
  outdata[4] = (len & 0xff);
  outdata[5] = ((len >> 8) & 0xff);
  outdata[6] = ((len >> 16) & 0xff);
  outdata[7] = ((len >> 24) & 0xff);

  status =
    sanei_usb_control_msg (dev->dn, REQUEST_TYPE_OUT, REQUEST_BUFFER,
			   VALUE_BUFFER, INDEX, sizeof (outdata), outdata);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_bulk_read_data failed while writing command: %s\n",
	   sane_strstatus (status));
      return status;
    }

  while (len)
    {
      if (len > 0xF000)
	size = 0xF000;
      else
	size = len;
      if (size >= 512)
	{
	  size /= 512;
	  size *= 512;
	}

      DBG (DBG_io2,
	   "gl843_bulk_read_data: trying to read %lu bytes of data\n",
	   (u_long) size);

      status = sanei_usb_read_bulk (dev->dn, data, &size);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_bulk_read_data failed while reading bulk data: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      DBG (DBG_io2,
	   "gl843_bulk_read_data read %lu bytes, %lu remaining\n",
	   (u_long) size, (u_long) (len - size));

      len -= size;
      data += size;
    }

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/****************************************************************************
 Mid level functions 
 ****************************************************************************/

static SANE_Bool
gl843_get_fast_feed_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG02);
  if (r && (r->value & REG02_FASTFED))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl843_get_filter_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_FILTER))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl843_get_lineart_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_LINEART))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl843_get_bitset_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG04);
  if (r && (r->value & REG04_BITSET))
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl843_get_gain4_bit (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;

  r = sanei_genesys_get_address (regs, REG06);
  if (r && (r->value & REG06_GAIN4))
    return SANE_TRUE;
  return SANE_FALSE;
}

/**
 * compute the step multiplier used
 */
static int
gl843_get_step_multiplier (Genesys_Register_Set * regs)
{
  Genesys_Register_Set *r = NULL;
  int value = 1;

  r = sanei_genesys_get_address (regs, 0x9d);
  if (r != NULL)
    {
      switch (r->value & 0x0c)
	{
	case 0x04:
	  value = 2;
	  break;
	case 0x08:
	  value = 4;
	  break;
	default:
	  value = 1;
	}
    }
  DBG (DBG_io, "%s: step multiplier is %d\n", __FUNCTION__, value);
  return value;
}

static SANE_Bool
gl843_test_buffer_empty_bit (SANE_Byte val)
{
  if (val & REG41_BUFEMPTY)
    return SANE_TRUE;
  return SANE_FALSE;
}

static SANE_Bool
gl843_test_motor_flag_bit (SANE_Byte val)
{
  if (val & REG41_MOTORENB)
    return SANE_TRUE;
  return SANE_FALSE;
}

/** @get sensor profile
 * search for the database of motor profiles and get the best one. Each
 * profile is at a specific dpihw. Use first entry of table by default.
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

/** @get motor profile
 * search for the database of motor profiles and get the best one. Each
 * profile is at full step and at a reference exposure. Use KV-SS080 table
 * by default.
 * @param motor_type motor id
 * @param exposure exposure time
 * @return a pointer to a Motor_Profile struct
 */
static Motor_Profile *get_motor_profile(int motor_type, int exposure)
{
  unsigned int i;
  int idx;

  i=0;
  idx=-1;
  while(i<sizeof(motors)/sizeof(Motor_Profile))
    {
      /* exact match */
      if(motors[i].motor_type==motor_type && motors[i].exposure==exposure)
        {
          return &(motors[i]);
        }

      /* closest match */
      if(motors[i].motor_type==motor_type)
        {
          if(idx<0)
            {
              idx=i;
            }
          else
            {
              if(motors[i].exposure>=exposure 
              && motors[i].exposure<motors[idx].exposure)
                {
                  idx=i;
                }
            }
        }
      i++;
    }

  /* default fallback */
  if(idx<0)
    idx=0;

  return &(motors[idx]);
}

static int gl843_slope_table(uint16_t *slope,
		             int       *steps,
			     int       dpi,
			     int       exposure,
			     int       base_dpi,
			     int       step_type,
			     int       factor,
                             int       motor_type)
{
int sum, i;
uint16_t target,current;
Motor_Profile *profile;

	/* required speed */
	target=((exposure * dpi) / base_dpi)>>step_type;
	
	/* fill result with target speed */
        for(i=0;i<256*factor;i++)
          slope[i]=target;

        profile=get_motor_profile(motor_type,exposure);

	/* use profile to build table */
	sum=0;
        i=0;
        current=profile->table[0]>>step_type;
        while(i<(256*factor) && current>target)
          {
            slope[i]=current;
            sum+=slope[i];
            i++;
            current=profile->table[i]>>step_type;
          }

        /* flat table case */
        if(i==0)
          {
            for(i=0;i<1024;i++)
              {
                slope[i]=profile->table[i]>>step_type;
                sum+=slope[i];
              }
          }

        /* align size on step time factor */
        while(i%factor!=0)
          {
            sum+=slope[i];
            i++;
          }

        /* return used steps and acceleration sum */
        *steps=i;
	return sum;
}




/** copy sensor specific settings */
static void
gl843_setup_sensor (Genesys_Device * dev, Genesys_Register_Set * regs, int dpi)
{
  Genesys_Register_Set *r;
  Sensor_Profile *sensor;
  int i,dpihw;

  DBGSTART;

  /* common settings */
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
  
  /* specific registers */
  r = sanei_genesys_get_address (regs, 0x18);
  if (r)
    {
      r->value = sensor->reg18;
    }
  r = sanei_genesys_get_address (regs, 0x5a);
  if (r)
    {
      r->value = sensor->reg5a;
    }
  r = sanei_genesys_get_address (regs, 0x7d);
  if (r)
    {
      r->value = sensor->reg7d;
    }
  r = sanei_genesys_get_address (regs, 0x80);
  if (r)
    {
      r->value = sensor->reg80;
    }
  r = sanei_genesys_get_address (regs, 0x9e);
  if (r)
    {
      r->value = sensor->reg9e;
    }

  /* CKxMAP */
  sanei_genesys_set_triple(regs,REG_CK1MAP,sensor->ck1map);
  sanei_genesys_set_triple(regs,REG_CK3MAP,sensor->ck3map);
  sanei_genesys_set_triple(regs,REG_CK4MAP,sensor->ck4map);

  DBG (DBG_proc, "gl843_setup_sensor: completed \n");
}


/* returns the max register bulk size */
static int
gl843_bulk_full_size (void)
{
  return GENESYS_GL843_MAX_REGS;
}

/** @brief set all registers to default values .
 * This function is called only once at the beginning and
 * fills register startup values for registers reused across scans.
 * Those that are rarely modified or not modified are written
 * individually.
 * @param dev device structure holding register set to initialize
 */
static void
gl843_init_registers (Genesys_Device * dev)
{
  DBGSTART;

  memset (dev->reg, 0,
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  /* default to KV-SS080 */
  SETREG (0xa2, 0x0f);
  SETREG (0x01, 0x00);
  SETREG (0x02, 0x78);
  SETREG (0x03, 0x1f);
  SETREG (0x04, 0x10);
  SETREG (0x05, 0x80);
  SETREG (0x06, 0xd8); /* SCANMOD=110, PWRBIT and GAIN4 */
  SETREG (0x08, 0x00);
  SETREG (0x09, 0x00);
  SETREG (0x0a, 0x00);
  SETREG (0x0b, 0x6a);
  SETREG (0x0c, 0x00);
  SETREG (0x10, 0x00);
  SETREG (0x11, 0x00);
  SETREG (0x12, 0x00);
  SETREG (0x13, 0x00);
  SETREG (0x14, 0x00);
  SETREG (0x15, 0x00);
  SETREG (0x16, 0x33);
  SETREG (0x17, 0x1c);
  SETREG (0x18, 0x10);
  SETREG (0x19, 0x2a);
  SETREG (0x1a, 0x04);
  SETREG (0x1b, 0x00);
  SETREG (0x1c, 0x20);
  SETREG (0x1d, 0x04);
  SETREG (0x1e, 0x10);
  SETREG (0x1f, 0x01);
  SETREG (0x20, 0x10);
  SETREG (0x21, 0x04);
  SETREG (0x22, 0x01);
  SETREG (0x23, 0x01);
  SETREG (0x24, 0x04);
  SETREG (0x25, 0x00);
  SETREG (0x26, 0x00);
  SETREG (0x27, 0x00);
  SETREG (0x2c, 0x02);
  SETREG (0x2d, 0x58);
  SETREG (0x2e, 0x80);
  SETREG (0x2f, 0x80);
  SETREG (0x30, 0x00);
  SETREG (0x31, 0x14);
  SETREG (0x32, 0x27);
  SETREG (0x33, 0xec);
  SETREG (0x34, 0x24);
  SETREG (0x35, 0x00);
  SETREG (0x36, 0xff);
  SETREG (0x37, 0xff);
  SETREG (0x38, 0x55);
  SETREG (0x39, 0xf0);
  SETREG (0x3d, 0x00);
  SETREG (0x3e, 0x00);
  SETREG (0x3f, 0x01);
  SETREG (0x52, 0x01);
  SETREG (0x53, 0x04);
  SETREG (0x54, 0x07);
  SETREG (0x55, 0x0a);
  SETREG (0x56, 0x0d);
  SETREG (0x57, 0x10);
  SETREG (0x58, 0x1b);
  SETREG (0x59, 0x00);
  SETREG (0x5a, 0x40);
  SETREG (0x5e, 0x23);
  SETREG (0x5f, 0x01);
  SETREG (0x60, 0x00);
  SETREG (0x61, 0x00);
  SETREG (0x62, 0x00);
  SETREG (0x63, 0x00);
  SETREG (0x64, 0x00);
  SETREG (0x65, 0x00);
  SETREG (0x67, 0x7f);
  SETREG (0x68, 0x7f);
  SETREG (0x69, 0x01);
  SETREG (0x6a, 0x04);
  SETREG (0x6b, 0x30);
  SETREG (0x70, 0x01);
  SETREG (0x71, 0x03);
  SETREG (0x72, 0x04);
  SETREG (0x73, 0x05);

  /* CKxMAP */
  SETREG (0x74, 0x00);
  SETREG (0x75, 0x00);
  SETREG (0x76, 0x3c);
  SETREG (0x77, 0x00);
  SETREG (0x78, 0x00);
  SETREG (0x79, 0x9f);
  SETREG (0x7a, 0x00);
  SETREG (0x7b, 0x00);
  SETREG (0x7c, 0x55);

  SETREG (0x7d, 0x00);
  SETREG (0x7f, 0x00);
  SETREG (0x80, 0x00);
  SETREG (0x81, 0x00);
  SETREG (0x82, 0x00);
  SETREG (0x83, 0x00);
  SETREG (0x84, 0x00);
  SETREG (0x85, 0x00);
  SETREG (0x86, 0x00);
  SETREG (0x87, 0x00);
  SETREG (0x9d, 0x04);
  SETREG (0x94, 0xff);
  SETREG (0x9e, 0x00);
  SETREG (0xab, 0x50);

  /* G4050 values */
  if ((strcmp (dev->model->name, "hewlett-packard-scanjet-g4050") == 0)
   || (strcmp (dev->model->name, "hewlett-packard-scanjet-g4010") == 0))
    {
      SETREG (0x03, 0x1d);
      SETREG (0x05, 0x08);
      SETREG (0x06, 0xd0); /* SCANMOD=110, PWRBIT and no GAIN4 */
      SETREG (0x0a, 0x18);
      SETREG (0x0b, 0x69);
      SETREG (0x5e, 0x6f);
      SETREG (0x6b, 0xf4);

      SETREG (0x70, 0x00);
      SETREG (0x71, 0x02);
      SETREG (0x72, 0x00);
      SETREG (0x73, 0x00);
      SETREG (0x7d, 0x90);
      
      SETREG (0x80, 0x50);
      SETREG (0x9d, 0x08);
      SETREG (0xab, 0x40);

      /* XXX STEF XXX TODO move to set for scan */
      SETREG (0x98, 0x03);
      SETREG (0x99, 0x30);
      SETREG (0x9a, 0x01);
      SETREG (0x9b, 0x80);
      
      SETREG (0xac, 0x00);
    }

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
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  DBGCOMPLETED;
}

/* Send slope table for motor movement 
   slope_table in machine byte order
 */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_send_slope_table (Genesys_Device * dev, int table_nr,
			uint16_t * slope_table, int steps)
{
  SANE_Status status;
  uint8_t *table;
  int i;
  char msg[2048 * 4];

  DBG (DBG_proc, "%s (table_nr = %d, steps = %d)\n", __FUNCTION__,
       table_nr, steps);

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

  /* slope table addresses are fixed : 0x4000,  0x4800,  0x5000,  0x5800,  0x6000 */
  /* XXX STEF XXX USB 1.1 ? write_end_access (dev, 0x0f, 0x14); */
  status = write_data (dev, 0x4000 + 0x800 * table_nr, steps * 2, table);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "%s: write data failed writing slope table %d (%s)\n",
	   __FUNCTION__, table_nr, sane_strstatus (status));
    }

  free (table);
  DBG (DBG_proc, "%s: completed\n", __FUNCTION__);
  return status;
}


/* Set values of analog frontend */
static SANE_Status
gl843_set_fe (Genesys_Device * dev, uint8_t set)
{
  SANE_Status status;
  uint8_t val;
  int i;

  DBG (DBG_proc, "gl843_set_fe (%s)\n",
       set == AFE_INIT ? "init" : set == AFE_SET ? "set" : set ==
       AFE_POWER_SAVE ? "powersave" : "huh?");

  if (set == AFE_INIT)
    {
      DBG (DBG_proc, "gl843_set_fe(): setting DAC %u\n",
	   dev->model->dac_type);
      sanei_genesys_init_fe (dev);
    }

  /* check analog frontend type */
  RIE (sanei_genesys_read_register (dev, REG04, &val));
  if ((val & REG04_FESET) != 0x00)
    {
      /* for now there is no support for AD fe */
      DBG (DBG_proc, "gl843_set_fe(): unsupported frontend type %d\n",
	   dev->reg[reg_0x04].value & REG04_FESET);
      return SANE_STATUS_UNSUPPORTED;
    }

  DBG (DBG_proc, "gl843_set_fe(): frontend reset complete\n");

  for (i = 1; i <= 3; i++)
    {
      status = sanei_genesys_fe_write_data (dev, i, dev->frontend.reg[i]);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_set_fe: writing reg[%d] failed: %s\n", i,
	       sane_strstatus (status));
	  return status;
	}
    }

  for (i = 0; i < 3; i++)
    {
      status =
	sanei_genesys_fe_write_data (dev, 0x20 + i, dev->frontend.offset[i]);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_set_fe: writing offset[%d] failed: %s\n", i,
	       sane_strstatus (status));
	  return status;
	}
    }

  if (dev->model->ccd_type == CCD_KVSS080)
    {
      for (i = 0; i < 3; i++)
	{
	  status =
	    sanei_genesys_fe_write_data (dev, 0x24 + i,
					 dev->frontend.sign[i]);
	  if (status != SANE_STATUS_GOOD)
	    {
	      DBG (DBG_error,
		   "gl843_set_fe: writing sign[%d] failed: %s\n", i,
		   sane_strstatus (status));
	      return status;
	    }
	}
    }

  for (i = 0; i < 3; i++)
    {
      status =
	sanei_genesys_fe_write_data (dev, 0x28 + i, dev->frontend.gain[i]);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_set_fe: writing gain[%d] failed: %s\n", i,
	       sane_strstatus (status));
	  return status;
	}
    }

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}


static SANE_Status
gl843_init_motor_regs_scan (Genesys_Device * dev,
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
  unsigned int lincnt;
  uint16_t scan_table[1024];
  uint16_t fast_table[1024];
  int scan_steps,fast_steps;
  unsigned int feedl,factor,dist;
  Genesys_Register_Set *r;
  uint32_t z1, z2;

  DBGSTART;
  DBG (DBG_info, "gl843_init_motor_regs_scan : scan_exposure_time=%d, "
       "scan_yres=%g, scan_step_type=%d, scan_lines=%d, scan_dummy=%d, "
       "feed_steps=%d, scan_power_mode=%d, flags=%x\n",
       scan_exposure_time,
       scan_yres,
       scan_step_type,
       scan_lines, scan_dummy, feed_steps, scan_power_mode, flags);

  /* get step multiplier */
  factor = gl843_get_step_multiplier (reg);

  use_fast_fed = 0;

  if((scan_yres>=300 && feed_steps>900) || (flags & MOTOR_FLAG_FEED))
    use_fast_fed=1;
  lincnt=scan_lines;

  r = sanei_genesys_get_address (reg, 0x25);
  r->value = (lincnt >> 16) & 0xf;
  r = sanei_genesys_get_address (reg, 0x26);
  r->value = (lincnt >> 8) & 0xff;
  r = sanei_genesys_get_address (reg, 0x27);
  r->value = lincnt & 0xff;
  DBG (DBG_io, "%s: lincnt=%d\n", __FUNCTION__, lincnt);

  /* compute register 02 value */
  r = sanei_genesys_get_address (reg, REG02);
  r->value = 0x00;
  r->value |= REG02_MTRPWR;

  if (use_fast_fed)
    r->value |= REG02_FASTFED;
  else
    r->value &= ~REG02_FASTFED;

  if (flags & MOTOR_FLAG_AUTO_GO_HOME)
    r->value |= REG02_AGOHOME;

  if (flags & MOTOR_FLAG_DISABLE_BUFFER_FULL_MOVE)
    r->value |= REG02_ACDCDIS;

  /* scan and backtracking slope table */
  slow_time=gl843_slope_table(scan_table,
                              &scan_steps,
                              scan_yres,
                              scan_exposure_time,
                              dev->motor.base_ydpi,
                              scan_step_type,
                              factor,
                              dev->model->motor_type);
  RIE(gl843_send_slope_table (dev, SCAN_TABLE, scan_table, scan_steps));
  RIE(gl843_send_slope_table (dev, BACKTRACK_TABLE, scan_table, scan_steps));

  r = sanei_genesys_get_address (reg, 0x21);
  r->value = scan_steps/factor;

  r = sanei_genesys_get_address (reg, 0x24);
  r->value = scan_steps/factor;

  /* fast table */
  fast_time=gl843_slope_table(fast_table,
                              &fast_steps,
                              sanei_genesys_get_lowest_ydpi(dev),
                              scan_exposure_time,
                              dev->motor.base_ydpi,
                              scan_step_type,
                              factor,
                              dev->model->motor_type);
  RIE(gl843_send_slope_table (dev, STOP_TABLE, fast_table, fast_steps));
  RIE(gl843_send_slope_table (dev, FAST_TABLE, fast_table, fast_steps));

  r = sanei_genesys_get_address (reg, 0x69);
  r->value = fast_steps / factor;
  /* better stop time */
  r->value = 1;

  r = sanei_genesys_get_address (reg, REG6A);
  r->value = fast_steps / factor;

  /* substract acceleration distance from feedl */
  feedl=feed_steps;
  feedl<<=scan_step_type;

  dist = scan_steps;
  if (use_fast_fed) 
    {
        dist += fast_steps*2;
    }
  DBG (DBG_io2, "%s: acceleration distance=%d\n", __FUNCTION__, dist);

  /* get sure when don't insane value */
  if(dist<feedl)
    feedl -= dist;
  else
    feedl = 1;

  r = sanei_genesys_get_address (reg, 0x3d);
  r->value = (feedl >> 16) & 0xf;
  r = sanei_genesys_get_address (reg, 0x3e);
  r->value = (feedl >> 8) & 0xff;
  r = sanei_genesys_get_address (reg, 0x3f);
  r->value = feedl & 0xff;
  DBG (DBG_io, "%s: feedl=%d\n", __FUNCTION__, feedl);

  /* doesn't seem to matter that much */
  sanei_genesys_calculate_zmode2 (use_fast_fed,
				  scan_exposure_time,
				  scan_table,
				  scan_steps,
				  feedl,
                                  scan_steps,
                                  &z1,
                                  &z2);

  DBG (DBG_info, "gl843_init_motor_regs_scan: z1 = %d\n", z1);
  r = sanei_genesys_get_address (reg, REG60);
  r->value = ((z1 >> 16) & REG60_Z1MOD);
  r = sanei_genesys_get_address (reg, REG61);
  r->value = ((z1 >> 8) & REG61_Z1MOD);
  r = sanei_genesys_get_address (reg, REG62);
  r->value = (z1 & REG62_Z1MOD);

  DBG (DBG_info, "gl843_init_motor_regs_scan: z2 = %d\n", z2);
  r = sanei_genesys_get_address (reg, REG63);
  r->value = ((z2 >> 16) & REG63_Z2MOD);
  r = sanei_genesys_get_address (reg, REG64);
  r->value = ((z2 >> 8) & REG64_Z2MOD);
  r = sanei_genesys_get_address (reg, REG65);
  r->value = (z2 & REG65_Z2MOD);

  r = sanei_genesys_get_address (reg, REG1E);
  r->value &= 0xf0;		/* 0 dummy lines */
  r->value |= scan_dummy;	/* dummy lines */

  r = sanei_genesys_get_address (reg, REG67);
  r->value = 0x3f | (scan_step_type << REG67S_STEPSEL);

  r = sanei_genesys_get_address (reg, REG68);
  r->value = 0x3f | (scan_step_type << REG68S_FSTPSEL);

  /* steps for STOP table */
  r = sanei_genesys_get_address (reg, 0x5f);
  r->value = 1;

  /* Vref */
  r = sanei_genesys_get_address (reg, 0x80);
  r->value = 0x05;		/* kv 75,150,300 dpi */

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

#if 0
static int
gl843_get_dpihw (Genesys_Device * dev)
{
  Genesys_Register_Set *r;
  r = sanei_genesys_get_address (dev->reg, REG05);
  if ((r->value & REG05_DPIHW) == REG05_DPIHW_600)
    return 600;
  if ((r->value & REG05_DPIHW) == REG05_DPIHW_1200)
    return 1200;
  if ((r->value & REG05_DPIHW) == REG05_DPIHW_2400)
    return 2400;
  if ((r->value & REG05_DPIHW) == REG05_DPIHW_4800)
    return 4800;
  return 0;
}
#endif


/**@brief compute exposure to use
 * compute the sensor exposure based on target resolution
 */
static int gl843_compute_exposure(Genesys_Device *dev, int xres)
{
  Sensor_Profile *sensor;

  sensor=get_sensor_profile(dev->model->ccd_type, xres);
  return sensor->exposure;
}

/**@brief compute motor step type to use
 * compute the step type (full, half, quarter, ...) to use based
 * on target resolution
 * @param dev device description
 * @param exposure sensor exposure
 * @return 0 for full step
 *         1 for half step
 *         2 for quarter step
 *         3 for eighth step
 */
static int gl843_compute_step_type(Genesys_Device *dev, int exposure)
{
Motor_Profile *profile;

    profile=get_motor_profile(dev->model->motor_type,exposure);
    return profile->step_type;
}

/** @brief setup optical related registers
 * start and pixels are expressed in optical sensor resolution coordinate
 * space. 
 * @param exposure_time exposure time to use
 * @param used_res scanning resolution used, may differ from
 *        scan's one
 * @param start logical start pixel coordinate
 * @param pixels logical number of pixels to use
 * @return SANE_STATUS_GOOD if OK
 */
static SANE_Status
gl843_init_optical_regs_scan (Genesys_Device * dev,
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
  unsigned int dpiset, cksel, dpihw, factor;
  unsigned int bytes;
  Genesys_Register_Set *r;
  SANE_Status status;

  DBG (DBG_proc, "gl843_init_optical_regs_scan :  exposure_time=%d, "
       "used_res=%d, start=%d, pixels=%d, channels=%d, depth=%d, "
       "half_ccd=%d, flags=%x\n",
       exposure_time,
       used_res, start, pixels, channels, depth, half_ccd, flags);

  /* resolution is divided according to CKSEL */ 
  r = sanei_genesys_get_address (reg, REG18);
  cksel= (r->value & REG18_CKSEL)+1;
  DBG (DBG_io2, "%s: cksel=%d\n", __FUNCTION__, cksel);

  /* to manage high resolution device while keeping good
   * low resolution scanning speed, we make hardware dpi vary */
  dpihw=sanei_genesys_compute_dpihw(dev, used_res);
  factor=dev->sensor.optical_res/dpihw;
  DBG (DBG_io2, "%s: dpihw=%d (factor=%d)\n", __FUNCTION__, dpihw, factor);

  /* sensor parameters */
  gl843_setup_sensor (dev, reg, dpihw);
  dpiset = used_res * cksel;

  /* start and end coordinate in optical dpi coordinates */
  startx = (start + dev->sensor.dummy_pixel)/cksel;
  used_pixels=pixels/cksel;
  endx = startx + used_pixels;

  /* pixel coordinate factor correction when used dpihw is not maximal one */
  startx/=factor;
  endx/=factor;
  used_pixels=endx-startx;

  status = gl843_set_fe (dev, AFE_SET);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_init_optical_regs_scan: failed to set frontend: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* enable shading */
  r = sanei_genesys_get_address (reg, REG01);
  r->value &= ~REG01_SCAN;
  if ((flags & OPTICAL_FLAG_DISABLE_SHADING) || (dev->model->flags & GENESYS_FLAG_NO_CALIBRATION))
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
  r = sanei_genesys_get_address (reg, REG2E);
  r->value = dev->settings.threshold;
  r = sanei_genesys_get_address (reg, REG2F);
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

  sanei_genesys_set_double(reg,REG_DPISET,dpiset);
  DBG (DBG_io2, "%s: dpiset used=%d\n", __FUNCTION__, dpiset);

  sanei_genesys_set_double(reg,REG_STRPIXEL,startx);
  sanei_genesys_set_double(reg,REG_ENDPIXEL,endx);

  /* words(16bit) before gamma, conversion to 8 bit or lineart */
  words_per_line = (used_pixels * dpiset) / dpihw;
  bytes = depth / 8;
  if (depth == 1)
    {
      words_per_line = (words_per_line >> 3) + ((words_per_line & 7) ? 1 : 0);
    }
  else
    {
      words_per_line *= bytes;
    }

  dev->bpl = words_per_line;

  DBG (DBG_io2, "%s: used_pixels=%d\n", __FUNCTION__, used_pixels);
  DBG (DBG_io2, "%s: pixels     =%d\n", __FUNCTION__, pixels);
  DBG (DBG_io2, "%s: depth      =%d\n", __FUNCTION__, depth);
  DBG (DBG_io2, "%s: dev->bpl   =%lu\n", __FUNCTION__, (unsigned long) dev->bpl);
  DBG (DBG_io2, "%s: dev->len   =%lu\n", __FUNCTION__, (unsigned long)dev->len);
  DBG (DBG_io2, "%s: dev->dist  =%lu\n", __FUNCTION__, (unsigned long)dev->dist);

  words_per_line *= channels;
  dev->wpl = words_per_line;

  /* MAXWD is expressed in 2 words unit */
  /* nousedspace = (mem_bank_range * 1024 / 256 -1 ) * 4; */
  sanei_genesys_set_triple(reg,REG_MAXWD,(words_per_line)>>1);
  DBG (DBG_io2, "%s: words_per_line used=%d\n", __FUNCTION__, words_per_line);

  sanei_genesys_set_double(reg,REG_LPERIOD,exposure_time);
  DBG (DBG_io2, "%s: exposure_time used=%d\n", __FUNCTION__, exposure_time);

  r = sanei_genesys_get_address (reg, REG_DUMMY);
  r->value = dev->sensor.dummy_pixel/factor;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}


static int
gl843_get_led_exposure (Genesys_Device * dev)
{
  int d, r, g, b, m;
  if (!dev->model->is_cis)
    return 0;
  d = dev->reg[reg_0x19].value;
  r = dev->sensor.regs_0x10_0x1d[1] | (dev->sensor.regs_0x10_0x1d[0] << 8);
  g = dev->sensor.regs_0x10_0x1d[3] | (dev->sensor.regs_0x10_0x1d[2] << 8);
  b = dev->sensor.regs_0x10_0x1d[5] | (dev->sensor.regs_0x10_0x1d[4] << 8);

  m = r;
  if (m < g)
    m = g;
  if (m < b)
    m = b;

  return m + d;
}


/* set up registers for an actual scan
 *
 * this function sets up the scanner to scan in normal or single line mode
 */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_init_scan_regs (Genesys_Device * dev,
                      Genesys_Register_Set * reg,
                      float xres,	/*dpi */
		      float yres,	/*dpi */
		      float startx,	/*optical_res, from dummy_pixel+1 */
		      float starty,	/*base_ydpi, from home! */
		      float pixels,
		      float lines,
		      unsigned int depth,
		      unsigned int channels,
		      int color_filter, unsigned int flags)
{
  int used_res;
  int start, used_pixels;
  int bytes_per_line;
  int move;
  unsigned int lincnt;          /**> line count to scan */
  unsigned int oflags, mflags;  /**> optical and motor flags */
  int exposure_time;
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
       "gl843_init_scan_regs settings:\n"
       "Resolution    : %gDPI/%gDPI\n"
       "Lines         : %g\n"
       "PPL           : %g\n"
       "Startpos      : %g/%g\n"
       "Depth/Channels: %u/%u\n"
       "Flags         : %x\n\n",
       xres, yres, lines, pixels, startx, starty, depth, channels, flags);


  /* we have 2 domains for ccd: xres below or above half ccd max dpi */
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
  DBG (DBG_info, "gl843_init_scan_regs : stagger=%d lines\n", stagger);

  /** @brief compute used resolution */
  if (flags & SCAN_FLAG_USE_OPTICAL_RES)
    {
      used_res = optical_res;
    }
  else
    {
      /* resolution is choosen from a fixed list and can be used directly
       * unless we have ydpi higher than sensor's maximum one */
      if(xres>optical_res)
        used_res=optical_res;
      else
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
  used_pixels = (pixels * optical_res) / xres;
  DBG (DBG_info, "%s: used_pixels=%d\n", __FUNCTION__, used_pixels);

  /* round up pixels number if needed */
  if (used_pixels * xres < pixels * optical_res)
    used_pixels++;

  /* we want even number of pixels here */
  if(used_pixels & 1)
    used_pixels++;

  dummy = 0;

  /* slope_dpi */
  /* cis color scan is effectively a gray scan with 3 gray lines per color line and a FILTER of 0 */
  if (dev->model->is_cis)
    slope_dpi = yres * channels;
  else
    slope_dpi = yres;

  /* scan_step_type */
  if(flags & SCAN_FLAG_FEEDING)
    {
      scan_step_type=gl843_compute_step_type (dev, sanei_genesys_get_lowest_ydpi(dev));
      exposure_time=gl843_compute_exposure (dev, sanei_genesys_get_lowest_ydpi(dev));
    }
  else
    {
      scan_step_type = gl843_compute_step_type(dev, slope_dpi);
      exposure_time = gl843_compute_exposure (dev, used_res);
    }

  DBG (DBG_info, "gl843_init_scan_regs : exposure_time=%d pixels\n", exposure_time);
  DBG (DBG_info, "gl843_init_scan_regs : scan_step_type=%d\n", scan_step_type);

  /*** optical parameters ***/
  /* in case of dynamic lineart, we use an internal 8 bit gray scan
   * to generate 1 lineart data */
  if ((flags & SCAN_FLAG_DYNAMIC_LINEART)
      && (dev->settings.scan_mode == SCAN_MODE_LINEART))
    {
      depth = 8;
    }
  /* no 16 bit gamma for this ASIC */
  if (depth == 16)
    flags |= SCAN_FLAG_DISABLE_GAMMA;

  /* we enable true gray for cis scanners only, and just when doing 
   * scan since color calibration is OK for this mode
   */
  oflags = 0;
  if (flags & SCAN_FLAG_DISABLE_SHADING)
    oflags |= OPTICAL_FLAG_DISABLE_SHADING;
  if (flags & SCAN_FLAG_DISABLE_GAMMA)
    oflags |= OPTICAL_FLAG_DISABLE_GAMMA;
  if (flags & SCAN_FLAG_DISABLE_LAMP)
    oflags |= OPTICAL_FLAG_DISABLE_LAMP;
  if (flags & SCAN_FLAG_CALIBRATION)
    oflags |= OPTICAL_FLAG_DISABLE_DOUBLE;

  /* now _LOGICAL_ optical values used are known, setup registers */
  status = gl843_init_optical_regs_scan (dev,
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

  /* lines to scan */
  lincnt = lines + max_shift + stagger;

  /* add tl_y to base movement */
  move = starty;
  DBG (DBG_info, "gl843_init_scan_regs: move=%d steps\n", move);


  mflags=0;
  if(flags & SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE)
    mflags|=MOTOR_FLAG_DISABLE_BUFFER_FULL_MOVE;
  if(flags & SCAN_FLAG_FEEDING)
    mflags|=MOTOR_FLAG_FEED;

    status = gl843_init_motor_regs_scan (dev,
					 reg,
					 exposure_time,
					 slope_dpi,
					 scan_step_type,
					 dev->model->is_cis ? lincnt * channels : lincnt,
					 dummy,
					 move,
					 scan_power_mode,
					 mflags);
  if (status != SANE_STATUS_GOOD)
    return status;

  /*** prepares data reordering ***/

  /* words_per_line */
  bytes_per_line = (used_pixels * used_res) / optical_res;
  bytes_per_line = (bytes_per_line * channels * depth) / 8;

  /* since we don't have sheetfed scanners to handle,
   * use huge read buffer */
  /* TODO find the best size according to settings */
  requested_buffer_size = 16 * bytes_per_line;

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
       "gl843_init_scan_regs: physical bytes to read = %lu\n",
       (u_long) dev->read_bytes_left);
  dev->read_active = SANE_TRUE;


  dev->current_setup.pixels = (used_pixels * used_res) / optical_res;
  DBG (DBG_info, "%s: current_setup.pixels=%d\n", __FUNCTION__, dev->current_setup.pixels);
  dev->current_setup.lines = lincnt;
  dev->current_setup.depth = depth;
  dev->current_setup.channels = channels;
  dev->current_setup.exposure_time = exposure_time;
  dev->current_setup.xres = used_res;
  dev->current_setup.yres = yres;
  dev->current_setup.half_ccd = half_ccd;
  dev->current_setup.stagger = stagger;
  dev->current_setup.max_shift = max_shift + stagger;

  dev->total_bytes_read = 0;
  if (depth == 1 || dev->settings.scan_mode == SCAN_MODE_LINEART)
    dev->total_bytes_to_read =
      ((dev->settings.pixels * dev->settings.lines) / 8 +
       (((dev->settings.pixels * dev->settings.lines) % 8) ? 1 : 0)) *
      channels;
  else
    dev->total_bytes_to_read =
      dev->settings.pixels * dev->settings.lines * channels * (depth / 8);

  DBG (DBG_info, "gl843_init_scan_regs: total bytes to send = %lu\n",
       (u_long) dev->total_bytes_to_read);

  DBG (DBG_proc, "gl843_init_scan_regs: completed\n");
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl843_calculate_current_setup (Genesys_Device * dev)
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
  unsigned int lincnt;
  int exposure_time;
  int stagger;

  int slope_dpi = 0;
  int dummy = 0;
  int scan_step_type = 1;
  int scan_power_mode = 0;
  int max_shift;

  SANE_Bool half_ccd;		/* false: full CCD res is used, true, half max CCD res is used */
  int optical_res;

  DBG (DBG_info,
       "gl843_calculate_current_setup settings:\n"
       "Resolution: %ux%uDPI\n"
       "Lines     : %u\n"
       "PPL       : %u\n"
       "Startpos  : %.3f/%.3f\n"
       "Scan mode : %d\n\n",
       dev->settings.xres,
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


  xres = dev->settings.xres;
  yres = dev->settings.yres;
  startx = start;
  pixels = dev->settings.pixels;
  lines = dev->settings.lines;
  color_filter = dev->settings.color_filter;


  DBG (DBG_info,
       "gl843_calculate_current_setup settings:\n"
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
  if (half_ccd)
    optical_res /= 2;

  /* stagger */
  if ((!half_ccd) && (dev->model->flags & GENESYS_FLAG_STAGGERED_LINE))
    stagger = (4 * yres) / dev->motor.base_ydpi;
  else
    stagger = 0;
  DBG (DBG_info, "%s: stagger=%d lines\n", __FUNCTION__, stagger);

  if(xres<=optical_res)
    used_res = xres;
  else
    used_res=optical_res;

  /* compute scan parameters values */
  /* pixels are allways given at half or full CCD optical resolution */
  /* use detected left margin  and fixed value */

  /* compute correct pixels number */
  used_pixels = (pixels * optical_res) / xres;
  DBG (DBG_info, "%s: used_pixels=%d\n", __FUNCTION__, used_pixels);
  dummy = 0;

  /* slope_dpi */
  /* cis color scan is effectively a gray scan with 3 gray lines per color
   line and a FILTER of 0 */
  if (dev->model->is_cis)
    slope_dpi = yres * channels;
  else
    slope_dpi = yres;

  /* scan_step_type */
  scan_step_type = gl843_compute_step_type(dev, yres);

  exposure_time = sanei_genesys_exposure_time2 (dev,
						slope_dpi,
						scan_step_type,
						start + used_pixels + 258,
						gl843_get_led_exposure (dev),
						scan_power_mode);

  DBG (DBG_info, "%s : exposure_time=%d pixels\n", __FUNCTION__, exposure_time);

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
  DBG (DBG_info, "%s: current_setup.pixels=%d\n", __FUNCTION__, dev->current_setup.pixels);
  dev->current_setup.lines = lincnt;
  dev->current_setup.depth = depth;
  dev->current_setup.channels = channels;
  dev->current_setup.exposure_time = exposure_time;
  dev->current_setup.xres = used_res;
  dev->current_setup.yres = yres;
  dev->current_setup.half_ccd = half_ccd;
  dev->current_setup.stagger = stagger;
  dev->current_setup.max_shift = max_shift + stagger;

  DBG (DBG_proc, "gl843_calculate_current_setup: completed\n");
  return SANE_STATUS_GOOD;
}

static void
gl843_set_motor_power (Genesys_Register_Set * regs, SANE_Bool set)
{

  DBG (DBG_proc, "gl843_set_motor_power\n");

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
gl843_set_lamp_power (Genesys_Device * dev,
		      Genesys_Register_Set * regs, SANE_Bool set)
{
  Genesys_Register_Set *r;
  int i;

  if (set)
    {
      sanei_genesys_set_reg_from_set (regs, 0x03,
				      sanei_genesys_read_reg_from_set (regs,
								       0x03)
				      | REG03_LAMPPWR);

      for (i = 0; i < 6; i++)
	{
	  r = sanei_genesys_get_address (dev->calib_reg, 0x10 + i);
	  r->value = dev->sensor.regs_0x10_0x1d[i];
	}
    }
  else
    {
      sanei_genesys_set_reg_from_set (regs, 0x03,
				      sanei_genesys_read_reg_from_set (regs,
								       0x03)
				      & ~REG03_LAMPPWR);

      for (i = 0; i < 6; i++)
	{
	  r = sanei_genesys_get_address (dev->calib_reg, 0x10 + i);
	  r->value = 0x00;
	}
    }
}

/**
 * for fast power saving methods only, like disabling certain amplifiers
 * @param device device to use
 * @param enable true to set inot powersaving
 * */
static SANE_Status
gl843_save_power (Genesys_Device * dev, SANE_Bool enable)
{
  uint8_t val;
  SANE_Status status;

  DBG (DBG_proc, "gl843_save_power: enable = %d\n", enable);
  if (dev == NULL)
    return SANE_STATUS_INVAL;

  /* switch KV-SS080 lamp off */
  if (dev->model->gpo_type == GPO_KVSS080) 
    {
      RIE(sanei_genesys_read_register (dev, REG6C, &val));
      if(enable)
        val &= 0xef;
      else
        val |= 0x10;
      RIE(sanei_genesys_write_register(dev,REG6C,val));
    }

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

static SANE_Status
gl843_set_powersaving (Genesys_Device * dev, int delay /* in minutes */ )
{
  SANE_Status status = SANE_STATUS_GOOD;

  DBG (DBG_proc, "gl843_set_powersaving (delay = %d)\n", delay);
  if (dev == NULL)
    return SANE_STATUS_INVAL;

  DBGCOMPLETED;
  return status;
}

#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_start_action (Genesys_Device * dev)
{
  return sanei_genesys_write_register (dev, 0x0f, 0x01);
}

static SANE_Status
gl843_stop_action (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t val40, val;
  unsigned int loop;

  DBG (DBG_proc, "%s\n", __FUNCTION__);

  status = sanei_genesys_get_status (dev, &val);
  if (DBG_LEVEL >= DBG_io)
    {
      sanei_genesys_print_status (val);
    }

  val40 = 0;
  status = sanei_genesys_read_register (dev, REG40, &val40);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "%s: failed to read home sensor: %s\n", __FUNCTION__,
	   sane_strstatus (status));
      DBG (DBG_proc, "%s: completed\n", __FUNCTION__);
      return status;
    }

  /* only stop action if needed */
  if (!(val40 & REG40_DATAENB) && !(val40 & REG40_MOTMFLG))
    {
      DBG (DBG_info, "%s: already stopped\n", __FUNCTION__);
      DBG (DBG_proc, "%s: completed\n", __FUNCTION__);
      return SANE_STATUS_GOOD;
    }

  /* ends scan 646  */
  val = sanei_genesys_read_reg_from_set (dev->reg, REG01);
  val &= ~REG01_SCAN;
  sanei_genesys_set_reg_from_set (dev->reg, REG01, val);
  status = sanei_genesys_write_register (dev, REG01, val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "end_scan: failed to write register 01: %s\n",
	   sane_strstatus (status));
      return status;
    }
  usleep (100 * 1000);

  loop = 10;
  while (loop > 0)
    {
      status = sanei_genesys_get_status (dev, &val);
      if (DBG_LEVEL >= DBG_io)
	{
	  sanei_genesys_print_status (val);
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

static SANE_Status
gl843_get_paper_sensor (Genesys_Device * dev, SANE_Bool * paper_loaded)
{
  SANE_Status status;
  uint8_t val;

  status = sanei_genesys_read_register (dev, REG6D, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_get_paper_sensor: failed to read gpio: %s\n",
	   sane_strstatus (status));
      return status;
    }
  *paper_loaded = (val & 0x1) == 0;
  return SANE_STATUS_GOOD;

  return SANE_STATUS_INVAL;
}

static SANE_Status
gl843_eject_document (Genesys_Device * dev)
{
  DBG (DBG_proc, "%s: not implemented \n", __FUNCTION__);
  if (dev == NULL)
    return SANE_STATUS_INVAL;
  return SANE_STATUS_GOOD;
}


static SANE_Status
gl843_load_document (Genesys_Device * dev)
{
  DBG (DBG_proc, "%s: not implemented \n", __FUNCTION__);
  if (dev == NULL)
    return SANE_STATUS_INVAL;
  return SANE_STATUS_GOOD;
}

/**
 * detects end of document and adjust current scan
 * to take it into account
 * used by sheetfed scanners
 */
static SANE_Status
gl843_detect_document_end (Genesys_Device * dev)
{
  SANE_Status status = SANE_STATUS_GOOD;
  SANE_Bool paper_loaded;
  unsigned int scancnt = 0;
  int flines, channels, depth, bytes_remain, sublines,
    bytes_to_flush, lines, sub_bytes, tmp, read_bytes_left;
  DBG (DBG_proc, "%s: begin\n", __FUNCTION__);

  RIE (gl843_get_paper_sensor (dev, &paper_loaded));

  /* sheetfed scanner uses home sensor as paper present */
  if ((dev->document == SANE_TRUE) && !paper_loaded)
    {
      DBG (DBG_info, "%s: no more document\n", __FUNCTION__);
      dev->document = SANE_FALSE;

      channels = dev->current_setup.channels;
      depth = dev->current_setup.depth;
      read_bytes_left = (int) dev->read_bytes_left;
      DBG (DBG_io, "gl843_detect_document_end: read_bytes_left=%d\n",
	   read_bytes_left);

      /* get lines read */
      status = sanei_genesys_read_scancnt (dev, &scancnt);
      if (status != SANE_STATUS_GOOD)
	{
	  flines = 0;
	}
      else
	{
	  /* compute number of line read */
	  tmp = (int) dev->total_bytes_read;
	  if (depth == 1 || dev->settings.scan_mode == SCAN_MODE_LINEART)
	    flines = tmp * 8 / dev->settings.pixels / channels;
	  else
	    flines = tmp / (depth / 8) / dev->settings.pixels / channels;

	  /* number of scanned lines, but no read yet */
	  flines = scancnt - flines;

	  DBG (DBG_io,
	       "gl843_detect_document_end: %d scanned but not read lines\n",
	       flines);
	}

      /* adjust number of bytes to read 
       * we need to read the final bytes which are word per line * number of last lines
       * to have doc leaving feeder */
      lines =
	(SANE_UNFIX (dev->model->post_scan) * dev->current_setup.yres) /
	MM_PER_INCH + flines;
      DBG (DBG_io, "gl843_detect_document_end: adding %d line to flush\n",
	   lines);

      /* number of bytes to read from scanner to get document out of it after
       * end of document dectected by hardware sensor */
      bytes_to_flush = lines * dev->wpl;

      /* if we are already close to end of scan, flushing isn't needed */
      if (bytes_to_flush < read_bytes_left)
	{
	  /* we take all these step to work around an overflow on some plateforms */
	  tmp = (int) dev->total_bytes_read;
	  DBG (DBG_io, "gl843_detect_document_end: tmp=%d\n", tmp);
	  bytes_remain = (int) dev->total_bytes_to_read;
	  DBG (DBG_io, "gl843_detect_document_end: bytes_remain=%d\n",
	       bytes_remain);
	  bytes_remain = bytes_remain - tmp;
	  DBG (DBG_io, "gl843_detect_document_end: bytes_remain=%d\n",
	       bytes_remain);

	  /* remaining lines to read by frontend for the current scan */
	  if (depth == 1 || dev->settings.scan_mode == SCAN_MODE_LINEART)
	    {
	      flines = bytes_remain * 8 / dev->settings.pixels / channels;
	    }
	  else
	    flines = bytes_remain / (depth / 8)
	      / dev->settings.pixels / channels;
	  DBG (DBG_io, "gl843_detect_document_end: flines=%d\n", flines);

	  if (flines > lines)
	    {
	      /* change the value controlling communication with the frontend :
	       * total bytes to read is current value plus the number of remaining lines 
	       * multiplied by bytes per line */
	      sublines = flines - lines;

	      if (depth == 1 || dev->settings.scan_mode == SCAN_MODE_LINEART)
		sub_bytes =
		  ((dev->settings.pixels * sublines) / 8 +
		   (((dev->settings.pixels * sublines) % 8) ? 1 : 0)) *
		  channels;
	      else
		sub_bytes =
		  dev->settings.pixels * sublines * channels * (depth / 8);

	      dev->total_bytes_to_read -= sub_bytes;

	      /* then adjust the physical bytes to read */
	      if (read_bytes_left > sub_bytes)
		{
		  dev->read_bytes_left -= sub_bytes;
		}
	      else
		{
		  dev->total_bytes_to_read = dev->total_bytes_read;
		  dev->read_bytes_left = 0;
		}

	      DBG (DBG_io, "gl843_detect_document_end: sublines=%d\n",
		   sublines);
	      DBG (DBG_io, "gl843_detect_document_end: subbytes=%d\n",
		   sub_bytes);
	      DBG (DBG_io,
		   "gl843_detect_document_end: total_bytes_to_read=%lu\n",
		   (unsigned long) dev->total_bytes_to_read);
	      DBG (DBG_io,
		   "gl843_detect_document_end: read_bytes_left=%d\n",
		   read_bytes_left);
	    }
	}
      else
	{
	  DBG (DBG_io, "gl843_detect_document_end: no flushing needed\n");
	}
    }

  DBG (DBG_proc, "%s: finished\n", __FUNCTION__);
  return SANE_STATUS_GOOD;
}

/* Send the low-level scan command */
/* todo : is this that useful ? */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_begin_scan (Genesys_Device * dev, Genesys_Register_Set * reg,
		  SANE_Bool start_motor)
{
  SANE_Status status;
  uint8_t val;

  DBGSTART;
  if (reg == NULL)
    return SANE_STATUS_INVAL;

  /* set up GPIO for scan */
  /* KV case */
  if (dev->model->gpo_type == GPO_KVSS080)
    {
      RIE (sanei_genesys_write_register (dev, REGA9, 0x00));
      RIE (sanei_genesys_write_register (dev, REGA6, 0xf6));
      /* blinking led */
      RIE(sanei_genesys_write_register(dev,0x7e,0x04)); 
    }
  if (dev->model->gpo_type == GPO_G4050)
    {
      RIE (sanei_genesys_write_register (dev, REGA6, 0x44));
      RIE (sanei_genesys_write_register (dev, REGA7, 0xfe));
      RIE (sanei_genesys_write_register (dev, REGA8, 0x3e));
      RIE (sanei_genesys_write_register (dev, REGA9, 0x06));
      /* blinking led */
      RIE(sanei_genesys_write_register(dev,0x7e,0x01)); 
    }

  /* clear scan and feed count */
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRLNCNT | REG0D_CLRMCNT));

  /* enable scan and motor */
  RIE (sanei_genesys_read_register (dev, REG01, &val));
  val |= REG01_SCAN;
  RIE (sanei_genesys_write_register (dev, REG01, val));

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
gl843_end_scan (Genesys_Device * dev, Genesys_Register_Set * reg,
		SANE_Bool check_stop)
{
  SANE_Status status;

  DBG (DBG_proc, "gl843_end_scan (check_stop = %d)\n", check_stop);
  if (reg == NULL)
    return SANE_STATUS_INVAL;

  /* post scan gpio */
  RIE(sanei_genesys_write_register(dev,0x7e,0x00));

  if (dev->model->is_sheetfed == SANE_TRUE)
    {
      status = SANE_STATUS_GOOD;
    }
  else				/* flat bed scanners */
    {
      status = gl843_stop_action (dev);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_end_scan: failed to stop: %s\n",
	       sane_strstatus (status));
	  return status;
	}
    }

  DBGCOMPLETED;
  return status;
}


/** @brief Moves the slider to the home (top) position slowly
 * */
#ifndef UNIT_TESTING
static
#endif
  SANE_Status
gl843_slow_back_home (Genesys_Device * dev, SANE_Bool wait_until_home)
{
  Genesys_Register_Set local_reg[GENESYS_GL843_MAX_REGS];
  SANE_Status status;
  Genesys_Register_Set *r;
  uint8_t val;
  float resolution;
  int loop = 0;

  DBG (DBG_proc, "gl843_slow_back_home (wait_until_home = %d)\n",
       wait_until_home);

  dev->scanhead_position_in_steps = 0;

  /* first read gives HOME_SENSOR true */
  status = sanei_genesys_get_status (dev, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl124_slow_back_home: failed to read home sensor: %s\n",
	   sane_strstatus (status));
      return status;
    }
  usleep (100000);		/* sleep 100 ms */

  /* second is reliable */
  status = sanei_genesys_get_status (dev, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_slow_back_home: failed to read home sensor: %s\n",
	   sane_strstatus (status));
      return status;
    }
  if (DBG_LEVEL >= DBG_io)
    {
      sanei_genesys_print_status (val);
    }
  if (val & HOMESNR)	/* is sensor at home? */
    {
      DBGCOMPLETED;
      return SANE_STATUS_GOOD;
    }

  memset (local_reg, 0, sizeof (local_reg));
  memcpy (local_reg, dev->reg, GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));
  resolution=sanei_genesys_get_lowest_ydpi(dev);

  gl843_init_scan_regs (dev,
			local_reg,
			resolution,
			resolution,
			100,
			40000,
			100,
			100,
			8,
			1,
			dev->settings.color_filter,
			SCAN_FLAG_DISABLE_SHADING |
			SCAN_FLAG_DISABLE_GAMMA |
			SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE |
			SCAN_FLAG_IGNORE_LINE_DISTANCE);

  /* clear scan and feed count */
  RIE (sanei_genesys_write_register (dev, REG0D, REG0D_CLRLNCNT | REG0D_CLRMCNT));
  
  /* set up for reverse and no scan */
  r = sanei_genesys_get_address (local_reg, REG02);
  r->value |= REG02_MTRREV;
  r = sanei_genesys_get_address (local_reg, REG01);
  r->value &= ~REG01_SCAN;

  RIE (gl843_bulk_write_register (dev, local_reg, GENESYS_GL843_MAX_REGS));

  status = gl843_start_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_slow_back_home: failed to start motor: %s\n",
	   sane_strstatus (status));
      gl843_stop_action (dev);
      /* restore original registers */
      gl843_bulk_write_register (dev, dev->reg, GENESYS_GL843_MAX_REGS);
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
		   "gl843_slow_back_home: failed to read home sensor: %s\n",
		   sane_strstatus (status));
	      return status;
	    }
          if (DBG_LEVEL >= DBG_io2)
            {
              sanei_genesys_print_status (val);
            }

	  if (val & REG41_HOMESNR)	/* home sensor */
	    {
	      DBG (DBG_info, "gl843_slow_back_home: reached home position\n");
	      DBG (DBG_proc, "gl843_slow_back_home: finished\n");
	      return SANE_STATUS_GOOD;
	    }
	  usleep (100000);	/* sleep 100 ms */
	  ++loop;
	}

      /* when we come here then the scanner needed too much time for this, so we better stop the motor */
      gl843_stop_action (dev);
      DBG (DBG_error,
	   "gl843_slow_back_home: timeout while waiting for scanhead to go home\n");
      return SANE_STATUS_IO_ERROR;
    }

  DBG (DBG_info, "gl124_slow_back_home: scanhead is still moving\n");
  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/* Automatically set top-left edge of the scan area by scanning a 200x200 pixels
   area at 600 dpi from very top of scanner */
static SANE_Status
gl843_search_start_position (Genesys_Device * dev)
{
  int size;
  SANE_Status status;
  uint8_t *data;
  Genesys_Register_Set local_reg[GENESYS_GL843_MAX_REGS];
  int steps;

  int pixels = 600;
  int dpi = 300;

  DBG (DBG_proc, "gl843_search_start_position\n");

  memset (local_reg, 0, sizeof (local_reg));
  memcpy (local_reg, dev->reg,
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  /* sets for a 200 lines * 600 pixels */
  /* normal scan with no shading */

  status = gl843_init_scan_regs (dev, local_reg, dpi, dpi, 0, 0,	/*we should give a small offset here~60 steps */
				 600, dev->model->search_lines, 8, 1, 1,	/*green */
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE |
				 SCAN_FLAG_DISABLE_BUFFER_FULL_MOVE);

  /* send to scanner */
  status = gl843_bulk_write_register (dev, local_reg, GENESYS_GL843_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_search_start_position: failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  size = pixels * dev->model->search_lines;

  data = malloc (size);
  if (!data)
    {
      DBG (DBG_error,
	   "gl843_search_start_position: failed to allocate memory\n");
      return SANE_STATUS_NO_MEM;
    }

  status = gl843_begin_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl843_search_start_position: failed to begin scan: %s\n",
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
	   "gl843_search_start_position: failed to read data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  if (DBG_LEVEL >= DBG_data)
    sanei_genesys_write_pnm_file ("search_position.pnm", data, 8, 1, pixels,
				  dev->model->search_lines);

  status = gl843_end_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl843_search_start_position: failed to end scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* update regs to copy ASIC internal state */
  memcpy (dev->reg, local_reg,
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  status =
    sanei_genesys_search_reference_point (dev, data, 0, dpi, pixels,
					  dev->model->search_lines);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl843_search_start_position: failed to set search reference point: %s\n",
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
gl843_init_regs_for_coarse_calibration (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t channels;
  uint8_t cksel;
  Genesys_Register_Set *r;

  DBGSTART;
  cksel = (dev->calib_reg[reg_0x18].value & REG18_CKSEL) + 1;	/* clock speed = 1..4 clocks */

  /* set line size */
  if (dev->settings.scan_mode == SCAN_MODE_COLOR)	/* single pass color */
    channels = 3;
  else
    channels = 1;

  status = gl843_init_scan_regs (dev,
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
	   "gl843_init_register_for_coarse_calibration: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }
  r = sanei_genesys_get_address (dev->calib_reg, REG02);
  r->value &= ~REG02_MTRPWR;

  DBG (DBG_info,
       "gl843_init_register_for_coarse_calibration: optical sensor res: %d dpi, actual res: %d\n",
       dev->sensor.optical_res / cksel, dev->settings.xres);

  status =
    gl843_bulk_write_register (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_init_register_for_coarse_calibration: failed to bulk write registers: %s\n",
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
gl843_feed (Genesys_Device * dev, unsigned int steps)
{
  Genesys_Register_Set local_reg[GENESYS_GL843_MAX_REGS];
  SANE_Status status;
  Genesys_Register_Set *r;
  float resolution;
  uint8_t val;

  DBGSTART;

  /* prepare local registers */
  memset (local_reg, 0, sizeof (local_reg));
  memcpy (local_reg, dev->reg, GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  resolution=sanei_genesys_get_lowest_ydpi(dev);
  gl843_init_scan_regs (dev,
			local_reg,
			resolution,
			resolution,
			0,
			steps,
			100,
			3,
			8,
			3,
			0,
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
  RIE (gl843_bulk_write_register (dev, local_reg, GENESYS_GL843_MAX_REGS));

  status = gl843_start_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error, "%s: failed to start motor: %s\n", __FUNCTION__, sane_strstatus (status));
      gl843_stop_action (dev);

      /* restore original registers */
      gl843_bulk_write_register (dev, dev->reg, GENESYS_GL843_MAX_REGS);
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
/* shading calibration is done at dpihw */
static SANE_Status
gl843_init_regs_for_shading (Genesys_Device * dev)
{
  SANE_Status status;
  int move, resolution, dpihw, factor;

  DBGSTART;
  
  /* initial calibration reg values */
  memcpy (dev->calib_reg, dev->reg, GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  dev->calib_channels = 3;
  dev->calib_lines = dev->model->shading_lines;
  dpihw=sanei_genesys_compute_dpihw(dev,dev->settings.xres);
  factor=dev->sensor.optical_res/dpihw;
  resolution=dpihw;
  dev->calib_resolution = resolution;
  dev->calib_pixels = dev->sensor.sensor_pixels/factor;

  /* distance to move to reach white target */
  move = SANE_UNFIX (dev->model->y_offset_calib);
  move = (move * resolution) / MM_PER_INCH;

  status = gl843_init_scan_regs (dev,
				 dev->calib_reg,
				 resolution,
				 resolution,
				 0,
				 move,
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
      DBG (DBG_error,
	   "gl843_init_registers_for_shading: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  dev->scanhead_position_in_steps += dev->calib_lines + move;

  status = gl843_bulk_write_register (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_init_registers_for_shading: failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** @brief set up registers for the actual scan
 */
static SANE_Status
gl843_init_regs_for_scan (Genesys_Device * dev)
{
  int channels;
  int flags;
  int depth;
  float move;
  int move_dpi;
  float start;

  SANE_Status status;

  DBG (DBG_info,
       "gl843_init_regs_for_scan settings:\nResolution: %ux%uDPI\n"
       "Lines     : %u\npixels    : %u\nStartpos  : %.3f/%.3f\nScan mode : %d\n\n",
       dev->settings.xres,
       dev->settings.yres,
       dev->settings.lines,
       dev->settings.pixels,
       dev->settings.tl_x,
       dev->settings.tl_y,
       dev->settings.scan_mode);

  /* ensure head is parked in case of calibration */
  gl843_slow_back_home (dev, SANE_TRUE);

  /* channels */
  if (dev->settings.scan_mode == SCAN_MODE_COLOR)
    channels = 3;
  else
    channels = 1;

  /* depth */
  depth = dev->settings.depth;
  if (dev->settings.scan_mode == SCAN_MODE_LINEART)
    depth = 1;

  move_dpi = dev->motor.base_ydpi;

  move = SANE_UNFIX (dev->model->y_offset);
  move += dev->settings.tl_y;
  move = (move * move_dpi) / MM_PER_INCH;
  DBG (DBG_info, "gl843_init_regs_for_scan: move=%f steps\n", move);

  /* start */
  start = SANE_UNFIX (dev->model->x_offset);
  start += dev->settings.tl_x;
  start = (start * dev->sensor.optical_res) / MM_PER_INCH;

  flags = 0;

  /* enable emulated lineart from gray data */
  if(dev->settings.scan_mode == SCAN_MODE_LINEART 
     && dev->settings.dynamic_lineart)
    {
      flags |= SCAN_FLAG_DYNAMIC_LINEART;
    }

  status = gl843_init_scan_regs (dev,
				 dev->reg,
				 dev->settings.xres,
				 dev->settings.yres,
				 start,
				 move,
				 dev->settings.pixels,
				 dev->settings.lines,
				 depth,
				 channels, dev->settings.color_filter, flags);

  if (status != SANE_STATUS_GOOD)
    return status;

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/*
 * this function sends generic gamma table (ie linear ones)
 * or the Sensor specific one if provided
 */
static SANE_Status
gl843_send_gamma_table (Genesys_Device * dev, SANE_Bool generic)
{
  int size;
  int status;
  uint8_t *gamma;
  int i, gmmval;

  DBG (DBG_proc, "gl843_send_gamma_table\n");

  /* don't send anything if no specific gamma table defined */
  if (!generic
      && (dev->sensor.red_gamma_table == NULL
	  || dev->sensor.green_gamma_table == NULL
	  || dev->sensor.blue_gamma_table == NULL))
    {
      DBG (DBG_proc, "gl843_send_gamma_table: nothing to send, skipping\n");
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

  /* send address */
  status = gl843_set_buffer_address (dev, 0x0000);
  if (status != SANE_STATUS_GOOD)
    {
      free (gamma);
      DBG (DBG_error,
	   "gl843_send_gamma_table: failed to set buffer address: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* send data */
  status = gl843_bulk_write_data (dev, 0x28, (uint8_t *) gamma, size * 2 * 3);
  if (status != SANE_STATUS_GOOD)
    {
      free (gamma);
      DBG (DBG_error,
	   "gl843_send_gamma_table: failed to send gamma table: %s\n",
	   sane_strstatus (status));
      return status;
    }

  DBG (DBG_proc, "gl843_send_gamma_table: completed\n");
  free (gamma);
  return SANE_STATUS_GOOD;
}

/* this function does the led calibration by scanning one line of the calibration
   area below scanner's top on white strip.

-needs working coarse/gain
*/
static SANE_Status
gl843_led_calibration (Genesys_Device * dev)
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
  Genesys_Register_Set *r;

  SANE_Bool acceptable = SANE_FALSE;

  DBG (DBG_proc, "gl843_led_calibration\n");

  /* offset calibration is always done in color mode */
  channels = 3;
  depth = 16;
  used_res = dev->sensor.optical_res;
  num_pixels =
    (dev->sensor.sensor_pixels * used_res) / dev->sensor.optical_res;

  /* initial calibration reg values */
  memcpy (dev->calib_reg, dev->reg,
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  status = gl843_init_scan_regs (dev,
				 dev->calib_reg,
				 used_res,
				 dev->motor.base_ydpi,
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
	   "gl843_led_calibration: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  RIE (gl843_bulk_write_register
       (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));


  total_size = num_pixels * channels * (depth / 8) * 1;	/* colors * bytes_per_color * scan lines */

  line = malloc (total_size);
  if (!line)
    return SANE_STATUS_NO_MEM;

/* 
   we try to get equal bright leds here:

   loop:
     average per color
     adjust exposure times
 */

  expr = (dev->sensor.regs_0x10_0x1d[0] << 8) | dev->sensor.regs_0x10_0x1d[1];
  expg = (dev->sensor.regs_0x10_0x1d[2] << 8) | dev->sensor.regs_0x10_0x1d[3];
  expb = (dev->sensor.regs_0x10_0x1d[4] << 8) | dev->sensor.regs_0x10_0x1d[5];

  turn = 0;

  do
    {

      dev->sensor.regs_0x10_0x1d[0] = (expr >> 8) & 0xff;
      dev->sensor.regs_0x10_0x1d[1] = expr & 0xff;
      dev->sensor.regs_0x10_0x1d[2] = (expg >> 8) & 0xff;
      dev->sensor.regs_0x10_0x1d[3] = expg & 0xff;
      dev->sensor.regs_0x10_0x1d[4] = (expb >> 8) & 0xff;
      dev->sensor.regs_0x10_0x1d[5] = expb & 0xff;

      for (i = 0; i < 6; i++)
	{
	  r = sanei_genesys_get_address (dev->calib_reg, 0x10 + i);
	  r->value = dev->sensor.regs_0x10_0x1d[i];
	}

      RIE (gl843_bulk_write_register
	   (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));

      DBG (DBG_info, "gl843_led_calibration: starting first line reading\n");
      RIE (gl843_begin_scan (dev, dev->calib_reg, SANE_TRUE));
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

      DBG (DBG_info, "gl843_led_calibration: average: "
	   "%d,%d,%d\n", avg[0], avg[1], avg[2]);

      acceptable = SANE_TRUE;

      if (avg[0] < avg[1] * 0.95 || avg[1] < avg[0] * 0.95 ||
	  avg[0] < avg[2] * 0.95 || avg[2] < avg[0] * 0.95 ||
	  avg[1] < avg[2] * 0.95 || avg[2] < avg[1] * 0.95)
	acceptable = SANE_FALSE;

      if (!acceptable)
	{
	  avga = (avg[0] + avg[1] + avg[2]) / 3;
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

      RIE (gl843_stop_action (dev));

      turn++;

    }
  while (!acceptable && turn < 100);

  DBG (DBG_info, "gl843_led_calibration: acceptable exposure: %d,%d,%d\n",
       expr, expg, expb);

  /* cleanup before return */
  free (line);

  gl843_slow_back_home (dev, SANE_TRUE);

  DBG (DBG_proc, "gl843_led_calibration: completed\n");
  return status;
}


/**
 * average dark pixels of a 8 bits scan
 */
static int
dark_average (uint8_t * data, unsigned int pixels, unsigned int lines,
	      unsigned int channels, unsigned int black)
{
  unsigned int i, j, k, average, count;
  unsigned int avg[3];
  uint8_t val;

  /* computes average value on black margin */
  for (k = 0; k < channels; k++)
    {
      avg[k] = 0;
      count = 0;
      for (i = 0; i < lines; i++)
	{
	  for (j = 0; j < black; j++)
	    {
	      val = data[i * channels * pixels + j + k];
	      avg[k] += val;
	      count++;
	    }
	}
      if (count)
	avg[k] /= count;
      DBG (DBG_info, "dark_average: avg[%d] = %d\n", k, avg[k]);
    }
  average = 0;
  for (i = 0; i < channels; i++)
    average += avg[i];
  average /= channels;
  DBG (DBG_info, "dark_average: average = %d\n", average);
  return average;
}

/** @brief calibrate AFE offset
 * Iterate doing scans at target dpi until AFE offset if correct. One
 * color line is scanned at a time. Scanning head doesn't move.
 * @param dev device to calibrate
 */
static SANE_Status
gl843_offset_calibration (Genesys_Device * dev)
{
  Genesys_Register_Set *r;
  SANE_Status status = SANE_STATUS_GOOD;
  uint8_t *first_line, *second_line;
  unsigned int channels, bpp;
  char title[32];
  int pass = 0, avg, total_size;
  int topavg, bottomavg, resolution, lines;
  int top, bottom, black_pixels, pixels, factor, dpihw;

  DBGSTART;

  /* offset calibration is always done in color mode */
  channels = 3;
  lines=1;
  bpp=8;

  /* compute divider factor to compute final pixels number */
  dpihw=sanei_genesys_compute_dpihw(dev,dev->settings.xres);
  factor=dev->sensor.optical_res/dpihw;
  resolution=dpihw;
  pixels = dev->sensor.sensor_pixels/factor;
  black_pixels = dev->sensor.black_pixels / factor;
  DBG (DBG_io, "gl843_offset_calibration: dpihw       =%d\n", dpihw);
  DBG (DBG_io, "gl843_offset_calibration: factor      =%d\n", factor);
  DBG (DBG_io, "gl843_offset_calibration: resolution  =%d\n", resolution);
  DBG (DBG_io, "gl843_offset_calibration: pixels      =%d\n", pixels);
  DBG (DBG_io, "gl843_offset_calibration: black_pixels=%d\n", black_pixels);

  status = gl843_init_scan_regs (dev,
				 dev->calib_reg,
				 resolution,
				 resolution,
				 0,
				 0,
				 pixels,
				 lines,
				 bpp,
				 channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_SINGLE_LINE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_offset_calibration: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }
  r = sanei_genesys_get_address (dev->calib_reg, REG02);
  r->value &= ~REG02_MTRPWR;

  /* allocate memory for scans */
  total_size = pixels * channels * lines * (bpp/8);	/* colors * bytes_per_color * scan lines */

  first_line = malloc (total_size);
  if (!first_line)
    return SANE_STATUS_NO_MEM;

  second_line = malloc (total_size);
  if (!second_line)
    {
      free (first_line);
      return SANE_STATUS_NO_MEM;
    }

  /* init gain */
  dev->frontend.gain[0] = 0;
  dev->frontend.gain[1] = 0;
  dev->frontend.gain[2] = 0;

  /* scan with no move */
  bottom = 10;
  dev->frontend.offset[0] = bottom;
  dev->frontend.offset[1] = bottom;
  dev->frontend.offset[2] = bottom;

  RIE (gl843_set_fe(dev, AFE_SET));
  RIE (gl843_bulk_write_register (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));
  DBG (DBG_info, "gl843_offset_calibration: starting first line reading\n");
  RIE (gl843_begin_scan (dev, dev->calib_reg, SANE_TRUE));
  RIE (sanei_genesys_read_data_from_scanner (dev, first_line, total_size));
  if (DBG_LEVEL >= DBG_data)
   {
      snprintf(title,20,"offset%03d.pnm",bottom);
      sanei_genesys_write_pnm_file (title, first_line, bpp, channels, pixels, lines);
   }
     
  bottomavg = dark_average (first_line, pixels, lines, channels, black_pixels);
  DBG (DBG_io2, "gl843_offset_calibration: bottom avg=%d\n", bottomavg);

  /* now top value */
  top = 255;
  dev->frontend.offset[0] = top;
  dev->frontend.offset[1] = top;
  dev->frontend.offset[2] = top;
  RIE (gl843_set_fe(dev, AFE_SET));
  RIE (gl843_bulk_write_register (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));
  DBG (DBG_info, "gl843_offset_calibration: starting second line reading\n");
  RIE (gl843_begin_scan (dev, dev->calib_reg, SANE_TRUE));
  RIE (sanei_genesys_read_data_from_scanner (dev, second_line, total_size));
      
  topavg = dark_average (second_line, pixels, lines, channels, black_pixels);
  DBG (DBG_io2, "gl843_offset_calibration: top avg=%d\n", topavg);

  /* loop until acceptable level */
  while ((pass < 32) && (top - bottom > 1))
    {
      pass++;

      /* settings for new scan */
      dev->frontend.offset[0] = (top + bottom) / 2;
      dev->frontend.offset[1] = (top + bottom) / 2;
      dev->frontend.offset[2] = (top + bottom) / 2;

      /* scan with no move */
      RIE(gl843_set_fe(dev, AFE_SET));
      RIE (gl843_bulk_write_register (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));
      DBG (DBG_info, "gl843_offset_calibration: starting second line reading\n");
      RIE (gl843_begin_scan (dev, dev->calib_reg, SANE_TRUE));
      RIE (sanei_genesys_read_data_from_scanner (dev, second_line, total_size));

      if (DBG_LEVEL >= DBG_data)
	{
	  sprintf (title, "offset%03d.pnm", dev->frontend.offset[1]);
	  sanei_genesys_write_pnm_file (title, second_line, bpp, channels, pixels, lines);
	}

      avg = dark_average (second_line, pixels, lines, channels, black_pixels);
      DBG (DBG_info, "gl843_offset_calibration: avg=%d offset=%d\n", avg,
	   dev->frontend.offset[1]);

      /* compute new boundaries */
      if (topavg == avg)
	{
	  topavg = avg;
	  top = dev->frontend.offset[1];
	}
      else
	{
	  bottomavg = avg;
	  bottom = dev->frontend.offset[1];
	}
    }
  DBG (DBG_info, "gl843_offset_calibration: offset=(%d,%d,%d)\n", dev->frontend.offset[0], dev->frontend.offset[1], dev->frontend.offset[2]);

  /* cleanup before return */
  free (first_line);
  free (second_line);

  DBGCOMPLETED;
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
gl843_coarse_gain_calibration (Genesys_Device * dev, int dpi)
{
  int pixels, factor, dpihw;
  int total_size;
  uint8_t *line;
  int i, j, channels;
  SANE_Status status = SANE_STATUS_GOOD;
  int max[3];
  float gain[3],coeff;
  int val, code, lines;
  int resolution;
  Genesys_Register_Set *r;
  int bpp;

  DBG (DBG_proc, "gl843_coarse_gain_calibration: dpi = %d\n", dpi);
  dpihw=sanei_genesys_compute_dpihw(dev,dev->settings.xres);
  factor=dev->sensor.optical_res/dpihw;

  /* coarse gain calibration is always done in color mode */
  channels = 3;
  /* follow CKSEL */
  if(dev->settings.xres<dev->sensor.optical_res)
    {
      coeff=0.9;
    }
  else
    {
      coeff=1.0;
    }
  resolution=dpihw;
  lines=10;
  bpp=8;
  pixels = dev->sensor.sensor_pixels / factor;

  status = gl843_init_scan_regs (dev,
				 dev->calib_reg,
				 resolution,
				 resolution,
				 0,
				 0,
				 pixels,
                                 lines,
                                 bpp,
                                 channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_SINGLE_LINE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);
  r = sanei_genesys_get_address (dev->calib_reg, REG02);
  r->value &= ~REG02_MTRPWR;

  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_coarse_calibration: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  RIE (gl843_bulk_write_register
       (dev, dev->calib_reg, GENESYS_GL843_MAX_REGS));

  total_size = pixels * channels * (16/bpp) * lines;

  line = malloc (total_size);
  if (!line)
    return SANE_STATUS_NO_MEM;

  RIE (gl843_set_fe(dev, AFE_SET));
  RIE (gl843_begin_scan (dev, dev->calib_reg, SANE_TRUE));
  RIE (sanei_genesys_read_data_from_scanner (dev, line, total_size));

  if (DBG_LEVEL >= DBG_data)
    sanei_genesys_write_pnm_file ("coarse.pnm", line, bpp, channels, pixels, lines);

  /* average value on each channel */
  for (j = 0; j < channels; j++)
    {
      max[j] = 0;
      for (i = pixels/4; i < (pixels*3/4); i++)
	{
          if(bpp==16)
            {
	  if (dev->model->is_cis)
	    val =
	      line[i * 2 + j * 2 * pixels + 1] * 256 +
	      line[i * 2 + j * 2 * pixels];
	  else
	    val =
	      line[i * 2 * channels + 2 * j + 1] * 256 +
	      line[i * 2 * channels + 2 * j];
            }
          else
            {
	  if (dev->model->is_cis)
	    val = line[i + j * pixels];
	  else
	    val = line[i * channels + j];
            }

	    max[j] += val;
	}
      max[j] = max[j] / (pixels/2);

      gain[j] = ((float) dev->sensor.gain_white_ref*coeff) / max[j];

      /* turn logical gain value into gain code, checking for overflow */
      code = 283 - 208 / gain[j];
      if (code > 255)
	code = 255;
      else if (code < 0)
	code = 0;
      dev->frontend.gain[j] = code;

      DBG (DBG_proc,
	   "gl843_coarse_gain_calibration: channel %d, max=%d, gain = %f, setting:%d\n",
	   j, max[j], gain[j], dev->frontend.gain[j]);
    }

  if (dev->model->is_cis)
    {
      if (dev->frontend.gain[0] > dev->frontend.gain[1])
	dev->frontend.gain[0] = dev->frontend.gain[1];
      if (dev->frontend.gain[0] > dev->frontend.gain[2])
	dev->frontend.gain[0] = dev->frontend.gain[2];
      dev->frontend.gain[2] = dev->frontend.gain[1] = dev->frontend.gain[0];
    }

  if (channels == 1)
    {
      dev->frontend.gain[0] = dev->frontend.gain[1];
      dev->frontend.gain[2] = dev->frontend.gain[1];
    }

  free (line);

  RIE (gl843_stop_action (dev));

  gl843_slow_back_home (dev, SANE_TRUE);

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/*
 * wait for lamp warmup by scanning the same line until difference
 * between 2 scans is below a threshold
 */
static SANE_Status
gl843_init_regs_for_warmup (Genesys_Device * dev,
			    Genesys_Register_Set * reg,
			    int *channels, int *total_size)
{
  int num_pixels;
  SANE_Status status = SANE_STATUS_GOOD;
  Genesys_Register_Set *r;

  DBGSTART;
  if (dev == NULL || reg == NULL || channels == NULL || total_size == NULL)
    return SANE_STATUS_INVAL;
  
  *channels=3;

  memcpy (reg, dev->reg, (GENESYS_GL843_MAX_REGS + 1) * sizeof (Genesys_Register_Set));
  status = gl843_init_scan_regs (dev,
				 reg,
				 dev->sensor.optical_res,
				 dev->motor.base_ydpi,
				 dev->sensor.sensor_pixels/4,
				 0,
				 dev->sensor.sensor_pixels/2,
				 1,
				 8,
				 *channels,
				 dev->settings.color_filter,
				 SCAN_FLAG_DISABLE_SHADING |
				 SCAN_FLAG_DISABLE_GAMMA |
				 SCAN_FLAG_SINGLE_LINE |
				 SCAN_FLAG_IGNORE_LINE_DISTANCE);

  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_init_regs_for_warmup: failed to setup scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  num_pixels = dev->current_setup.pixels;

  *total_size = num_pixels * 3 * 1;	/* colors * bytes_per_color * scan lines */

  r = sanei_genesys_get_address (reg, REG02);
  r->value &= ~REG02_MTRPWR;
  RIE (gl843_bulk_write_register (dev, reg, GENESYS_GL843_MAX_REGS));

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/** 
 * set up GPIO/GPOE for idle state
WRITE GPIO[17-21]= GPIO19
WRITE GPOE[17-21]= GPOE21 GPOE20 GPOE19 GPOE18
genesys_write_register(0xa8,0x3e)
GPIO(0xa8)=0x3e
 */
static SANE_Status
gl843_init_gpio (Genesys_Device * dev)
{
  SANE_Status status = SANE_STATUS_GOOD;
  int i;

  DBGSTART;

  RIE (sanei_genesys_write_register (dev, REG6E, dev->gpo.enable[0]));
  RIE (sanei_genesys_write_register (dev, REG6F, dev->gpo.enable[1]));
  RIE (sanei_genesys_write_register (dev, REG6C, dev->gpo.value[0]));
  RIE (sanei_genesys_write_register (dev, REG6D, dev->gpo.value[1]));
  if ((strcmp (dev->model->name, "hewlett-packard-scanjet-g4010") == 0)
   || (strcmp (dev->model->name, "hewlett-packard-scanjet-g4050") == 0))
    {
      i = 0;
    }
  else
    {
      i = 1;
    }
  RIE (sanei_genesys_write_register (dev, 0xa6, gpios[i].ra6));
  RIE (sanei_genesys_write_register (dev, 0xa7, gpios[i].ra7));
  RIE (sanei_genesys_write_register (dev, 0xa8, gpios[i].ra8));
  RIE (sanei_genesys_write_register (dev, 0xa9, gpios[i].ra9));

  DBGCOMPLETED;
  return status;
}


/* *
 * initialize ASIC from power on condition
 */
static SANE_Status
gl843_cold_boot (Genesys_Device * dev)
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
      DBG (DBG_info,
	   "gl843_cold_boot: reported version for genesys chip is 0x%02x\n",
	   val);
    }

  /* Set default values for registers */
  gl843_init_registers (dev);

  RIE (sanei_genesys_write_register (dev, REG6B, 0x02));

  /* Write initial registers */
  RIE (gl843_bulk_write_register (dev, dev->reg, GENESYS_GL843_MAX_REGS));

  /* Enable DRAM by setting a rising edge on bit 3 of reg 0x0b */
  val = dev->reg[reg_0x0b].value & REG0B_DRAMSEL;
  val = (val | REG0B_ENBDRAM);
  RIE (sanei_genesys_write_register (dev, REG0B, val));
  dev->reg[reg_0x0b].value = val;
  /* URB    14  control  0x40 0x0c 0x8c 0x10 len     1 wrote 0xb4 */
  RIE (write_end_access (dev, 0x10, 0xb4));

  /* CLKSET */
  val = (dev->reg[reg_0x0b].value & ~REG0B_CLKSET) | REG0B_48MHZ;
  RIE (sanei_genesys_write_register (dev, REG0B, val));
  dev->reg[reg_0x0b].value = val;

  /* prevent further writings by bulk write register */
  dev->reg[reg_0x0b].address = 0x00;

  /* set up end access */
  sanei_genesys_write_register (dev, REGA7, 0x04);
  sanei_genesys_write_register (dev, REGA9, 0x00);

  /* set RAM read address */
  RIE (sanei_genesys_write_register (dev, REG29, 0x00));
  RIE (sanei_genesys_write_register (dev, REG2A, 0x00));
  RIE (sanei_genesys_write_register (dev, REG2B, 0x00));

  /* setup gpio */
  RIE (gl843_init_gpio (dev));

  DBGCOMPLETED;
  return SANE_STATUS_GOOD;
}

/* *
 * initialize backend and ASIC : registers, motor tables, and gamma tables
 * then ensure scanner's head is at home
 */
#ifndef UNIT_TESTING
static
#endif
SANE_Status
gl843_init (Genesys_Device * dev)
{
  SANE_Status status;
  uint8_t val;
  SANE_Bool cold = SANE_TRUE;
  int size;

  DBG_INIT ();
  DBGSTART;

  /* URB    16  control  0xc0 0x0c 0x8e 0x0b len     1 read  0x00 */
  status =
    sanei_usb_control_msg (dev->dn, REQUEST_TYPE_IN, REQUEST_REGISTER,
			   VALUE_GET_REGISTER, 0x0b, 1, &val);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_init: request register failed %s\n",
	   sane_strstatus (status));
      return status;
    }
  DBG (DBG_io2, "gl843_init: value=0x%02x\n", val);
  DBG (DBG_info, "%s: device is %s\n", __FUNCTION__,
       (val & 0x08) ? "USB 1.0" : "USB2.0");
  if (val & 0x08)
    {
      /* URB    17  control  0x40 0x0c 0x8c 0x0f len     1 wrote 0x14  */
      dev->usb_mode = 1;
      val = 0x14;
    }
  else
    {
      /* URB    17  control  0x40 0x0c 0x8c 0x0f len     1 wrote 0x11  */
      dev->usb_mode = 2;
      val = 0x11;
    }
  RIE (write_end_access (dev, 0x0f, val));

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

  /* don't do anything if backend is initialized and hardware hasn't been
   * replug */
  if (dev->already_initialized && !cold)
    {
      DBG (DBG_info, "gl843_init: already initialized, nothing to do\n");
      return SANE_STATUS_GOOD;
    }

  /* set up hardware and registers */
  RIE (gl843_cold_boot (dev));

  /* move head away from park position */
  gl843_feed (dev, 300);

  /* now hardware part is OK, set up device struct */
  FREE_IFNOT_NULL (dev->white_average_data);
  FREE_IFNOT_NULL (dev->dark_average_data);
  FREE_IFNOT_NULL (dev->sensor.red_gamma_table);
  FREE_IFNOT_NULL (dev->sensor.green_gamma_table);
  FREE_IFNOT_NULL (dev->sensor.blue_gamma_table);

  dev->settings.color_filter = 0;

  memcpy (dev->calib_reg, dev->reg, GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  /* Set analog frontend */
  RIE (gl843_set_fe (dev, AFE_INIT));

  /* init gamma tables */
  size = 256;
  if (dev->sensor.red_gamma_table == NULL)
    {
      dev->sensor.red_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl843_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.red_gamma_table, size, 65535, 65535, dev->sensor.red_gamma);
    }
  if (dev->sensor.green_gamma_table == NULL)
    {
      dev->sensor.green_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl843_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.green_gamma_table, size, 65535, 65535, dev->sensor.green_gamma);
    }
  if (dev->sensor.blue_gamma_table == NULL)
    {
      dev->sensor.blue_gamma_table = (uint16_t *) malloc (2 * size);
      if (dev->sensor.red_gamma_table == NULL)
	{
	  DBG (DBG_error,
	       "gl843_init: could not allocate memory for gamma table\n");
	  return SANE_STATUS_NO_MEM;
	}
      sanei_genesys_create_gamma_table (dev->sensor.blue_gamma_table, size, 65535, 65535, dev->sensor.blue_gamma);
    }

  dev->oe_buffer.buffer = NULL;
  dev->already_initialized = SANE_TRUE;

  /* Move home if needed */
  RIE (gl843_slow_back_home (dev, SANE_TRUE));
  dev->scanhead_position_in_steps = 0;

  /* Set powersaving (default = 15 minutes) */
  RIE (gl843_set_powersaving (dev, 15));

  DBGCOMPLETED;
  return status;
}

static SANE_Status
gl843_update_hardware_sensors (Genesys_Scanner * s)
{
  /* do what is needed to get a new set of events, but try to not lose
     any of them.
   */
  SANE_Status status = SANE_STATUS_GOOD;
  uint8_t val;

  RIE (sanei_genesys_read_register (s->dev, REG6D, &val));

  if (s->dev->model->gpo_type == GPO_KVSS080) 
    {
      if (s->val[OPT_SCAN_SW].b == s->last_val[OPT_SCAN_SW].b)
        s->val[OPT_SCAN_SW].b = (val & 0x04) == 0;
    }
  else
    {
      if (s->val[OPT_SCAN_SW].b == s->last_val[OPT_SCAN_SW].b)
        s->val[OPT_SCAN_SW].b = (val & 0x01) == 0;
      if (s->val[OPT_FILE_SW].b == s->last_val[OPT_FILE_SW].b)
        s->val[OPT_FILE_SW].b = (val & 0x02) == 0;
      if (s->val[OPT_EMAIL_SW].b == s->last_val[OPT_EMAIL_SW].b)
        s->val[OPT_EMAIL_SW].b = (val & 0x04) == 0;
      if (s->val[OPT_COPY_SW].b == s->last_val[OPT_COPY_SW].b)
        s->val[OPT_COPY_SW].b = (val & 0x08) == 0;
    }

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
gl843_search_strip (Genesys_Device * dev, SANE_Bool forward, SANE_Bool black)
{
  unsigned int pixels, lines, channels;
  SANE_Status status;
  Genesys_Register_Set local_reg[GENESYS_GL843_MAX_REGS];
  size_t size;
  uint8_t *data;
  int steps, depth, dpi;
  unsigned int pass, count, found, x, y;
  char title[80];
  Genesys_Register_Set *r;

  DBG (DBG_proc, "gl843_search_strip %s %s\n", black ? "black" : "white",
       forward ? "forward" : "reverse");

  gl843_set_fe (dev, AFE_SET);
  status = gl843_stop_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_search_strip: failed to stop: %s\n",
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
      DBG (DBG_error, "gl843_search_strip: failed to allocate memory\n");
      return SANE_STATUS_NO_MEM;
    }
  dev->scanhead_position_in_steps = 0;

  memcpy (local_reg, dev->reg,
	  GENESYS_GL843_MAX_REGS * sizeof (Genesys_Register_Set));

  status = gl843_init_scan_regs (dev,
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
	   "gl843_search_strip: failed to setup for scan: %s\n",
	   sane_strstatus (status));
      return status;
    }

  /* set up for reverse or forward */
  r = sanei_genesys_get_address (local_reg, REG02);
  if (forward)
    r->value &= ~REG02_MTRREV;
  else
    r->value |= REG02_MTRREV;


  status = gl843_bulk_write_register (dev, local_reg, GENESYS_GL843_MAX_REGS);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (DBG_error,
	   "gl843_search_strip: failed to bulk write registers: %s\n",
	   sane_strstatus (status));
      return status;
    }

  status = gl843_begin_scan (dev, local_reg, SANE_TRUE);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error,
	   "gl843_search_strip: failed to begin scan: %s\n",
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
	   "gl843_search_start_position: failed to read data: %s\n",
	   sane_strstatus (status));
      return status;
    }

  status = gl843_stop_action (dev);
  if (status != SANE_STATUS_GOOD)
    {
      free (data);
      DBG (DBG_error, "gl843_search_strip: gl843_stop_action failed\n");
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
	gl843_bulk_write_register (dev, local_reg, GENESYS_GL843_MAX_REGS);
      if (status != SANE_STATUS_GOOD)
	{
	  DBG (DBG_error,
	       "gl843_search_strip: failed to bulk write registers: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      /* now start scan */
      status = gl843_begin_scan (dev, local_reg, SANE_TRUE);
      if (status != SANE_STATUS_GOOD)
	{
	  free (data);
	  DBG (DBG_error,
	       "gl843_search_strip: failed to begin scan: %s\n",
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
	       "gl843_search_start_position: failed to read data: %s\n",
	       sane_strstatus (status));
	  return status;
	}

      status = gl843_stop_action (dev);
      if (status != SANE_STATUS_GOOD)
	{
	  free (data);
	  DBG (DBG_error, "gl843_search_strip: gl843_stop_action failed\n");
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
		       "gl843_search_strip: strip found forward during pass %d at line %d\n",
		       pass, y);
		}
	      else
		{
		  DBG (DBG_data,
		       "gl843_search_strip: pixels=%d, count=%d (%d%%)\n",
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
		   "gl843_search_strip: strip found backward during pass %d \n",
		   pass);
	    }
	  else
	    {
	      DBG (DBG_data,
		   "gl843_search_strip: pixels=%d, count=%d (%d%%)\n",
		   pixels, count, (100 * count) / pixels);
	    }
	}
      pass++;
    }
  free (data);
  if (found)
    {
      status = SANE_STATUS_GOOD;
      DBG (DBG_info, "gl843_search_strip: %s strip found\n",
	   black ? "black" : "white");
    }
  else
    {
      status = SANE_STATUS_UNSUPPORTED;
      DBG (DBG_info, "gl843_search_strip: %s strip not found\n",
	   black ? "black" : "white");
    }

  DBG (DBG_proc, "gl843_search_strip: completed\n");
  return status;
}

/** the gl843 command set */
static Genesys_Command_Set gl843_cmd_set = {
  "gl843-generic",		/* the name of this set */

  gl843_init,
  gl843_init_regs_for_warmup,
  gl843_init_regs_for_coarse_calibration,
  gl843_init_regs_for_shading,
  gl843_init_regs_for_scan,

  gl843_get_filter_bit,
  gl843_get_lineart_bit,
  gl843_get_bitset_bit,
  gl843_get_gain4_bit,
  gl843_get_fast_feed_bit,
  gl843_test_buffer_empty_bit,
  gl843_test_motor_flag_bit,

  gl843_bulk_full_size,

  gl843_set_fe,
  gl843_set_powersaving,
  gl843_save_power,

  gl843_set_motor_power,
  gl843_set_lamp_power,

  gl843_begin_scan,
  gl843_end_scan,

  gl843_send_gamma_table,

  gl843_search_start_position,

  gl843_offset_calibration,
  gl843_coarse_gain_calibration,
  gl843_led_calibration,

  gl843_slow_back_home,

  gl843_bulk_write_register,
  gl843_bulk_write_data,
  gl843_bulk_read_data,

  gl843_update_hardware_sensors,

  gl843_load_document,
  gl843_detect_document_end,
  gl843_eject_document,
  gl843_search_strip,

  sanei_genesys_is_compatible_calibration,
  NULL,
  NULL, /* gl843_send_shading_data */
  gl843_calculate_current_setup
};

SANE_Status
sanei_gl843_init_cmd_set (Genesys_Device * dev)
{
  dev->model->cmd_set = &gl843_cmd_set;
  return SANE_STATUS_GOOD;
}

/* vim: set sw=2 cino=>2se-1sn-1s{s^-1st0(0u0 smarttab expandtab: */
