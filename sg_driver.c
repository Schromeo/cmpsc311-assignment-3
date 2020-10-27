////////////////////////////////////////////////////////////////////////////////
//
//  File           : sg_driver.c
//  Description    : This file contains the driver code to be developed by
//                   the students of the 311 class.  See assignment details
//                   for additional information.
//
//   Author        : ????
//   Last Modified : ????
//

// Include Files
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
// Project Includes 
#include "sg_driver.h"
#include "sg_service.h"
// Defines
#define UNIT_TEST_NUM 50

// Global Data
int sgDriverInitialized = 0; // The flag indicating the driver initialized
SG_Block_ID sgLocalNodeId;   // The local node identifier
SG_SeqNum sgLocalSeqno;      // The local sequence number

FILE* sgPathPtrs[20] = { NULL };
SgFHandle sgPathPtrsIndex = 0;

// Driver support functions
int sgInitEndpoint( void ); // Initialize the endpoint

//
// Functions

//
// File system interface implementation

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgopen
// Description  : Open the file for for reading and writing
//
// Inputs       : path - the path/filename of the file to be read
// Outputs      : file handle if successful test, -1 if failure

SgFHandle sgopen(const char *path) {

    // First check to see if we have been initialized
    if (!sgDriverInitialized) {

        // Call the endpoint initialization 
        if ( sgInitEndpoint() ) {
            logMessage( LOG_ERROR_LEVEL, "sgopen: Scatter/Gather endpoint initialization failed." );
            return( -1 );
        }

        // Set to initialized
        sgDriverInitialized = 1;
    }

	// FILL IN THE REST OF THE CODE
	
	if ((sgPathPtrs[sgPathPtrsIndex] = fopen(path, "w+"))==NULL)	//wb+ 读写二进制文件
	{
		logMessage(LOG_ERROR_LEVEL, "sgopen: Scatter/Gather open file error.");
	}

    // Return the file handle
	return sgPathPtrsIndex++;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgread
// Description  : Read data from the file
//
// Inputs       : fh - file handle for the file to read from
//                buf - place to put the data
//                len - the length of the read
// Outputs      : number of bytes read, -1 if failure

int sgread(SgFHandle fh, char *buf, size_t len) {
	if (checkFH(fh)!=0)
	{
		return -1;
	}
	size_t i = 0;
	while (i<len && !feof(sgPathPtrs[fh]))
	{
		buf[i++] = fgetc(sgPathPtrs[fh]);
	}

	len = i;
    // Return the bytes processed
    return( len );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgwrite
// Description  : write data to the file
//
// Inputs       : fh - file handle for the file to write to
//                buf - pointer to data to write
//                len - the length of the write
// Outputs      : number of bytes written if successful test, -1 if failure

int sgwrite(SgFHandle fh, char *buf, size_t len) {
	if (checkFH(fh) != 0)
	{
		return -1;
	}
	fwrite(buf, sizeof(char), len, sgPathPtrs[fh]);
    // Log the write, return bytes written
	//logMessage(LOG_INFO_LEVEL, "sgwrite: Scatter/Gather write file success.");
    return( len );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgseek
// Description  : Seek to a specific place in the file
//
// Inputs       : fh - the file handle of the file to seek in
//                off - offset within the file to seek to
// Outputs      : new position if successful, -1 if failure

int sgseek(SgFHandle fh, size_t off) {
	if (checkFH(fh) != 0)
	{
		return -1;
	}
	if (fseek(sgPathPtrs[fh], off, 0)!=0)
	{
		return -1;
	}
    // Return new position
    return off;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgclose
// Description  : Close the file
//
// Inputs       : fh - the file handle of the file to close
// Outputs      : 0 if successful test, -1 if failure

int sgclose(SgFHandle fh) {
	if (checkFH(fh))
	{
		return -1;
	}
	fclose(sgPathPtrs[fh]);
	sgPathPtrs[fh] = NULL;
    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgshutdown
// Description  : Shut down the filesystem
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

int sgshutdown(void) {
	for(int i=0;i<sgPathPtrsIndex;++i)
	{
		sgclose(i);
	}
    // Log, return successfully
    logMessage( LOG_INFO_LEVEL, "Shut down Scatter/Gather driver." );
    return( 0 );
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : serialize_sg_packet
// Description  : Serialize a ScatterGather packet (create packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status serialize_sg_packet( SG_Node_ID loc, SG_Node_ID rem, SG_Block_ID blk, 
        SG_System_OP op, SG_SeqNum sseq, SG_SeqNum rseq, char *data, 
        char *packet, size_t *plen ) {
	//Check
    if (loc==0)
    {
        return SG_PACKT_LOCID_BAD;
    }
    if (rem == 0)
    {
        return SG_PACKT_REMID_BAD;
    }
    if (blk==0)
    {
        return SG_PACKT_BLKID_BAD;
    }
	if (op >= SG_MAXVAL_OP)
	{
		return SG_PACKT_OPERN_BAD;
	}
	if (sseq == 0)
	{
		return SG_PACKT_SNDSQ_BAD;
	}
	if (rseq == 0)
	{
		return SG_PACKT_RCVSQ_BAD;
	}
    if (data==NULL)
    {
        return SG_PACKT_BLKDT_BAD;
    }
	
	/* Init */
	uint32_t magicValue = SG_MAGIC_VALUE;
    SG_Packet_Info* packInfo = (SG_Packet_Info*)malloc(sizeof(SG_Packet_Info));
    packInfo->locNodeId = loc;
    packInfo->remNodeId = rem;
    packInfo->blockID = blk;
    packInfo->operation = op;
    packInfo->sendSeqNo = sseq;
    packInfo->recvSeqNo = rseq;
	//packInfo->data=(SG_Data_Block*)malloc(sizeof(SG_Data_Block));
	//memcpy(*(packInfo->data),data,strlen(data)*sizeof(char));
	packInfo->data=NULL;
	//logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad op code (212)." );
	
	
	/*packet*/
	memcpy(packet, &magicValue, sizeof(magicValue));
	
	//logMessage( LOG_INFO_LEVEL, "test");
	//logMessage( LOG_INFO_LEVEL, *(packInfo->data) );
	char* infoPtr = packet + sizeof(magicValue);
	memcpy(infoPtr, packInfo, sizeof(SG_Packet_Info));
	//logMessage( LOG_INFO_LEVEL, *(((SG_Packet_Info*)infoPtr)->data));
	//logMessage( LOG_INFO_LEVEL, "test\n\n");
	char* dataPtr=infoPtr + sizeof(SG_Packet_Info);
	memcpy(dataPtr,data,strlen(data)+1);
	char* endMagicPtr = dataPtr + strlen(data)+1;

	memcpy(endMagicPtr, &magicValue, sizeof(magicValue));
	//(char*)(*((SG_Packet_Info*)infoPtr)->data)=dataPtr;

	/* plen */
	*plen = sizeof(SG_Packet_Info)+sizeof(magicValue)*2+strlen(data)+1;


	if(*((uint32_t*)(packet+*plen-sizeof(uint32_t))) == SG_MAGIC_VALUE)
	{
		logMessage( LOG_INFO_LEVEL, "SG_MAGIC_VALUE Success:%d %d %x", packet, *plen,*((uint32_t*)(packet+*plen-sizeof(uint32_t))));
	}

	return SG_PACKT_OK;
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : checkPacket
// Description  : check packet is  legality
//
// Inputs       : packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure
int checkPacket(char* packet,int plen)
{
	if(plen==0)
	{
		return -1;
	}
	if (packet==NULL)
	{
		return -1;
	}
	//MagicValue_start
	if (*(uint32_t*)packet != SG_MAGIC_VALUE)
	{
		return -1;
	}
	//MagicValue_end
    if(*(uint32_t*)(packet+plen-sizeof(uint32_t))!=SG_MAGIC_VALUE)
    {
        return -1;
    }
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : deserialize_sg_packet
// Description  : De-serialize a ScatterGather packet (unpack packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - UNIT_TEST_NUM the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status deserialize_sg_packet( SG_Node_ID *loc, SG_Node_ID *rem, SG_Block_ID *blk, 
        SG_System_OP *op, SG_SeqNum *sseq, SG_SeqNum *rseq, char *data, 
        char *packet, size_t plen ) {
	//if (packet==NULL)
	//{
		//logMessage( LOG_INFO_LEVEL, "1" );
	//	return SG_PACKT_PDATA_BAD;
	//}
	//if(plen==0)
	//{
		//logMessage( LOG_INFO_LEVEL, "2" );
		//return SG_PACKT_PDATA_BAD;
	//}
	if (checkPacket(packet,plen))
	{
		return SG_PACKT_PDATA_BAD;
	}
	SG_Packet_Info* packInfo = (SG_Packet_Info*)(packet+sizeof(uint32_t));
    *loc = packInfo->locNodeId;
	*rem = packInfo->remNodeId;
	*blk = packInfo->blockID;
	*op = packInfo->operation;
	*sseq = packInfo->sendSeqNo;
	*rseq = packInfo->recvSeqNo;
    
	memcpy(data,packet+sizeof(uint32_t)+sizeof(SG_Packet_Info),plen - sizeof(uint32_t)*2-sizeof(SG_Packet_Info));
	
	return SG_PACKT_OK;
}
        
////////////////////////////////////////////////////////////////////////////////
//
// Function     : checkFH
// Description  : Check fh is legality
//
// Inputs       : fh - the local node identifier
//                
// Outputs      : 0 if successfully created, -1 if failure
int checkFH(SgFHandle fh)
{
	if (fh<sgPathPtrsIndex&&sgPathPtrs[fh]!=NULL)
	{
		return 0;
	}
	return -1;
}

//isSerialize: 1:serialize 0:deserialize
void PrintPacketStatusInfo(SG_Packet_Status status,int isSerialize)
{
	switch (status)
		{
		case SG_PACKT_OK:
		{
			logMessage( LOG_INFO_LEVEL, "sg_packet proccessing worked correctly (single packet)." );
		}
		break;
		case SG_PACKT_LOCID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad local ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad local ID [0]." );
		}
		break;
		case SG_PACKT_REMID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad remote ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad remote ID [0]." );
		}
		break;
		case SG_PACKT_BLKID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block ID [0]." );
		}
		break;
		case SG_PACKT_OPERN_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad op code (212)." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad op code (212)." );
		}
		break;
		case SG_PACKT_SNDSQ_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad sender sequence number [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad sender sequence number [0]." );
		}
		break;
		case SG_PACKT_RCVSQ_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad receiver sequence number [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad receiver sequence number [0]." );
		}
		break;
		case SG_PACKT_BLKDT_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block data [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block data [0]." );
        }
		break;
		case SG_PACKT_BLKLN_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block length [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block length [0]." );
		}
		break;
        case SG_PACKT_PDATA_BAD:
        {
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad packet data [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad packet data [0]." );
        }
        break;

		}
}



////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgInitEndpoint
// Description  : Initialize the endpoint
//
// Inputs       : none
// Outputs      : 0 if successfull, -1 if failure

int sgInitEndpoint( void ) {

    // Local variables
    char initPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
    size_t pktlen, rpktlen;
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    // Local and do some initial setup
    logMessage( LOG_INFO_LEVEL, "Initializing local endpoint ..." );
    sgLocalSeqno = SG_INITIAL_SEQNO;

    // Setup the packet
    pktlen = SG_BASE_PACKET_SIZE;
    if ( (ret = serialize_sg_packet( SG_NODE_UNKNOWN, // Local ID
                                    SG_NODE_UNKNOWN,   // Remote ID
                                    SG_BLOCK_UNKNOWN,  // Block ID
                                    SG_INIT_ENDPOINT,  // Operation
                                    sgLocalSeqno++,    // Sender sequence number
                                    SG_SEQNO_UNKNOWN,  // Receiver sequence number
                                    NULL, initPacket, &pktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed serialization of packet [%d].", ret );
        return( -1 );
    }

    // Send the packet
    rpktlen = SG_BASE_PACKET_SIZE;
    if ( sgServicePost(initPacket, &pktlen, recvPacket, &rpktlen) ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed packet post" );
        return( -1 );
    }

    // Unpack the recieived data
    if ( (ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc, 
                                    &srem, NULL, recvPacket, rpktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed deserialization of packet [%d]", ret );
        return( -1 );
    }

    // Sanity check the return value
    if ( loc == SG_NODE_UNKNOWN ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: bad local ID returned [%ul]", loc );
        return( -1 );
    }

    // Set the local node ID, log and return successfully
    sgLocalNodeId = loc;
    logMessage( LOG_INFO_LEVEL, "Completed initialization of node (local node ID %lu", sgLocalNodeId );
    return( 0 );
}

int packetUnitTest(void)
{
	//One
#if 0
	srand(time(NULL));

	for (int i=0;i<UNIT_TEST_NUM;++i)
	{
		SG_Node_ID loc = rand()%20;
		SG_Node_ID rem = rand() % 20;
		SG_Block_ID blk = rand() % 10;
		SG_System_OP op = rand() % 7;
		SG_SeqNum sseq = rand() % 20;
		SG_SeqNum rseq = rand() % 20;
		char *data=NULL;
		char *packet=(char*)malloc(SG_DATA_PACKET_SIZE);
		size_t plen=0;
		
		if (loc<18)
		{
			data = (char*)malloc(5);
			data[0] = 'd';
			data[1] = 'a';
			data[2] = 't';
			data[3] = 'a';
			data[4] = '\0';
		}

      SG_Packet_Status status= serialize_sg_packet(loc,rem,blk,op,sseq,rseq,data,packet,&plen);
		PrintPacketStatusInfo(status,1);

		free(data);
		data=(char*)malloc(plen - sizeof(uint32_t)*2-sizeof(SG_Packet_Info));

		char* infoPtr = packet + sizeof(uint32_t)+sizeof(SG_Packet_Info);
		//if(status==SG_PACKT_OK)
		//{
			//logMessage( LOG_INFO_LEVEL, "test");
			//logMessage( LOG_INFO_LEVEL, infoPtr);
			//1.dlogMessage( LOG_INFO_LEVEL, *(((SG_Packet_Info*)infoPtr)->data));
			//logMessage( LOG_INFO_LEVEL, "test\n\n");
		//}
		status= deserialize_sg_packet(&loc,&rem,&blk,&op,&sseq,&rseq,data,packet,plen);
		PrintPacketStatusInfo(status,0);

		if (data!=NULL)
		{
			free(data);
		}
		if (packet!=NULL)
		{
			free(packet);
		}
	}
#endif
//Two
	char buff[1024];
	SgFHandle temp_fh = sgopen("cmpsc311-assign3-workload.txt");

	if(sgread(temp_fh,buff,1024)!=-1)
	{
		logMessage( LOG_INFO_LEVEL, "read is success.");
	}
	
	sgclose(temp_fh);
    return 0;
}   


//
//sg_service.h
int sgServicePost( char *packet, size_t *len, char *rpacket, size_t *rlen )
{
	if (checkPacket(packet, *len))
	{
		return -1;
	}
	memcpy(rpacket, packet,*len);
	*rlen = *len;
    return 0;
}