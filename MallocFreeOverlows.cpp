#include "FuzzingPinTool.h"
#include <vector>
#include <string.h>

UINT32
// Watch where RtlAllocateHeap returns allocated base
RtlAllocateHeapReturnAddress = 0,
RtlAllocateHeapHandle = 0,
RtlAllocateHeapSize = 0,

// Watch where free returns to know about success
FreeReturnAddress = 0,

// Remember what base is gonna be cleared
MonitoringFreeAddress = 0;

// Structure with allocated base and allocated base + size of allocated area and alloc-flag
struct HeapAllocated
{
	UINT32 Handle;
	UINT32 Min;
	UINT32 Max;
	std::vector<std::pair<UINT32, UINT32>> Borders;
};

std::vector<HeapAllocated> Heaps;

VOID RtlCreateHeap_handle(void * base, UINT32 resSize, UINT32 comSize)
{
	if (base != NULL)
	{
		printf("base is 0x%08x\n", base);
	}
	else
	{
		printf("'HeapBase' arg is NULL\n");
	}

	if (resSize == 0 && comSize == 0)
	{
		resSize = 64 * PAGE_SIZE;
		comSize = PAGE_SIZE;
	}
	else if (resSize == 0 && comSize != 0)
	{
		if (comSize % (PAGE_SIZE * 16) == 0)
		{
			resSize = comSize;
		}
		else if (comSize % PAGE_SIZE == 0)
		{
			resSize = comSize;
			while (resSize % (PAGE_SIZE * 16) != 0)
				resSize += PAGE_SIZE;
		}
		else
		{
			UINT32 mod = comSize % PAGE_SIZE;
			resSize = comSize + (comSize - mod);
			while (resSize % (PAGE_SIZE * 16) != 0)
				resSize += PAGE_SIZE;
		}
		
	}
	else if (resSize != 0 && comSize == 0)
	{
		comSize = PAGE_SIZE;
	}
	else
	{
		if (comSize > resSize)
			comSize = resSize;
	}

	printf("Reserved size is %d bytes\nCommited Size is %d bytes\n", resSize, comSize);
}

VOID RtlAllocateHeap_openHandle(UINT32 handle, UINT32 size, UINT32 rtnAddr)
{
	RtlAllocateHeapReturnAddress = rtnAddr;
	RtlAllocateHeapHandle = handle;
	RtlAllocateHeapSize = size;
}

VOID RtlAllocateHeap_closeHandle(UINT32 addr)
{
	// Optimize ???
	if (Heaps.empty())
	{
		HeapAllocated head;
		head.Handle = RtlAllocateHeapHandle;
		head.Min = addr;
		head.Max = addr + RtlAllocateHeapSize - 1;
		head.Borders.push_back(std::make_pair(head.Min, head.Max));
		Heaps.push_back(head);
	}
	else
	{
		std::vector<HeapAllocated>::iterator iter;
		for (iter = Heaps.begin(); iter != Heaps.end(); iter++)
		{
			if (iter->Handle == RtlAllocateHeapHandle)
				break;
		}

		if (iter != Heaps.end())
		{
			UINT32 rightBorder = addr + RtlAllocateHeapSize - 1;
			iter->Borders.push_back(std::make_pair(addr, rightBorder));
			if (addr < iter->Min)
				iter->Min = addr;
			if (rightBorder > iter->Max)
				iter->Max = rightBorder;
		}
		else
		{
			HeapAllocated head;
			head.Handle = RtlAllocateHeapHandle;
			head.Min = addr;
			head.Max = addr + RtlAllocateHeapSize - 1;
			head.Borders.push_back(std::make_pair(head.Min, head.Max));
			Heaps.push_back(head);
		}
	}

	RtlAllocateHeapHandle = 0;
	RtlAllocateHeapReturnAddress = 0;
	RtlAllocateHeapSize = 0;
}

// Searching mallocs
VOID MallocFreeOverflows_Image(IMG img, void *)
{
	//RTN RtlCreateHeap_rtn = RTN_FindByName(img, "RtlCreateHeap");
	RTN RtlAllocateHeap_rtn = RTN_FindByName(img, "RtlAllocateHeap");
	RTN RtlFreeHeap_rtn = RTN_FindByName(img, "RtlFreeHeap");

	/*if (RTN_Valid(RtlCreateHeap_rtn))
	{
		RTN_Open(RtlCreateHeap_rtn);
		RTN_InsertCall
		(
			RtlCreateHeap_rtn,
			IPOINT_BEFORE, (AFUNPTR)RtlCreateHeap_handle,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END
		);
		RTN_Close(RtlCreateHeap_rtn);
	}*/

	if (RTN_Valid(RtlAllocateHeap_rtn))
	{
		RTN_Open(RtlAllocateHeap_rtn);

		RTN_InsertCall
		(
			RtlAllocateHeap_rtn, 
			IPOINT_BEFORE, (AFUNPTR)RtlAllocateHeap_openHandle, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
			IARG_RETURN_IP,
			IARG_END
		);

		RTN_Close(RtlAllocateHeap_rtn);
	}

	if (RTN_Valid(RtlFreeHeap_rtn))
	{
		RTN_Open(RtlFreeHeap_rtn);
		//RTN_InsertCall(RtlFreeHeap_rtn, IPOINT_BEFORE, (AFUNPTR)RtlFreeHeap_handle, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
		RTN_Close(RtlFreeHeap_rtn);
	}
}

void MallocFreeOverflows_Instruction(INS ins, void*)
{
	if (INS_Address(ins) == RtlAllocateHeapReturnAddress)
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RtlAllocateHeap_closeHandle,
			IARG_REG_VALUE, REG_EAX,
			IARG_END
		);
	}
	// if we've got writting some data to memory, let's check for storing into heap
	/*else if ((UINT32)INS_Address(ins) < 0x70000000 && INS_MemoryOperandIsWritten(ins, 0))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)CheckHeapStore,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryWriteSize(ins),
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new std::string(INS_Disassemble(ins)),
			IARG_END
		);
	}*/
}

VOID MallocFreeOverflows_Fini(INT32 code, VOID *)
{
	if (Heaps.empty())
	{
		printf("No heaps found out\n");
		printf("bye\n");
		return;
	}
	std::vector<HeapAllocated>::iterator iter1;
	for (iter1 = Heaps.begin(); iter1 != Heaps.end(); iter1++)
	{
		printf("Heap 0x%08x with min allocated address 0x%08x and max allocated address 0x%08x\n", iter1->Handle, iter1->Min, iter1->Max);
		printf("Allocations:\n");
		std::vector<std::pair<UINT32, UINT32>>::iterator iter2;
		for (iter2 = iter1->Borders.begin(); iter2 != iter1->Borders.end(); iter2++)
		{
			printf("\t0x%08x: 0x%08x (%d bytes)\n", iter2->first, iter2->second, iter2->second - iter2->first + 1);
		}
	}

	printf("bye\n");
}