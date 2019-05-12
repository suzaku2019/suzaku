/*
 * config.h - ietd plain file-based configuration
 *
 * Copyright (C) 2004-2005 FUJITA Tomonori <tomof at acm dot org>
 * Copyright (C) 2004-2010 VMware, Inc. All Rights Reserved.
 * Copyright (C) 2007-2010 Ross Walker <rswwalker at gmail dot com>
 *
 * This file is part of iSCSI Enterprise Target software.
 *
 * Released under the terms of the GNU GPL v2.0.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __ISCSI_CONFIG_H__
#define __ISCSI_CONFIG_H__

#include "types.h"

#define ISCSI_CMD_RECORD 0
#define ENABLE_ISCSI_VIP 0
#define ENABLE_ISCSI_CHAP 1
#define ENABLE_ISCSI_MEM 0
#define ENABLE_ISER 0
#define ENABLE_ISCSI_CONN_LIST 0
#define ENABLE_VAAI 0
#define ISER_LISTEN_PORT 32600


#define SDFS_SYSTEM_ATTR_VAAI     "__sdfs_vaai__"
#define SDFS_SYSTEM_ATTR_ISCSI     "__sdfs_iscsi__"
#define SDFS_SYSTEM_ATTR_THIN     "__sdfs_provisioning__"        //defined by Mr. wang
#define SDFS_SYSTEM_ATTR_SCSI_ID     "scsi_id"

#define ISCSI_LUN_MAX           254

#define ISCSI_LUN_NAME_MAX      4
//#define ISCSI_TGT_NAME_MAX      1024
#define ISCSI_IQN_NAME_MAX      223
#define ISCSI_TGT_NAME_MAX      200
#define ISCSI_CHECK_TARGET_CTIME TRUE

#define yiscsi_tgt_magic_key    "iscsi.is_target"
#define yiscsi_lun_alias_key    "iscsi.lun_alias"
#define yiscsi_lun_block_key    "iscsi.blk_shift"

/*
 * The `raw_removexattr' is not impliment now, use a special value
 * to express this.
 */
#define yiscsi_none_value       "____NONE____"


#endif
