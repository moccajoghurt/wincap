/*
This file is responsible for sharing the packet data with the usermode
-- */


#ifndef _TL_SHARE_H_
#define _TL_SHARE_H_

NTSTATUS shareClonedNetBufferList(PNET_BUFFER_LIST clonedNetBufferList);

#endif // _TL_SHARE_H_
