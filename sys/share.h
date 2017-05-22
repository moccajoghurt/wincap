/*
This file is responsible for sharing the packet data with the usermode
-- */


#ifndef _TL_SHARE_H_
#define _TL_SHARE_H_

NTSTATUS shareClonedNetBufferList(PNET_BUFFER_LIST clonedNetBufferList, BOOLEAN isOutbound);

#endif // _TL_SHARE_H_
