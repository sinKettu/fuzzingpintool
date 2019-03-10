#include "FuzzingPinTool.h"
#include <vector>
#include <string.h>

/* -=== DEFINES ===- */

#define		AllocatedArea					std::pair<UINT32, UINT32>
#define		HeapIterator					std::vector<HeapAllocated>::iterator
#define		AreaBordersIterator				std::vector<AllocatedArea>::iterator
#define		MakeAllocatedArea(left, right)	std::make_pair((UINT32) left, (UINT32) right)
#define		ForFree(iter1, iter2)			std::make_pair((HeapIterator)iter1, (AreaBordersIterator)iter2)

/* -=== STRUCTURES ===- */

struct HeapAllocated
{
	UINT32 Handle;
	UINT32 Min;
	UINT32 Max;
	std::vector<AllocatedArea> Area;
};

struct HeapOverflow
{
	UINT32 InsAddr;
	UINT32 StoreBase;
	UINT32 StoreEdge;
};

/* -=== GLOBALS ===- */

UINT32
// Watch where RtlAllocateHeap returns allocated base
RtlAllocateHeapReturnAddress = 0,

// What handle of heap is
RtlAllocateHeapHandle = 0,

// And size of allocated area
RtlAllocateHeapSize = 0,

// Watch where RtlFreeHeap returns to know about success
FreeReturnAddress = 0;

// What area is gonna be freed
std::pair<HeapIterator, AreaBordersIterator> ReferencesForFree;

// Rewrite with Map
// Container for Heaps info
std::vector<HeapAllocated> Heaps;

// Container for overflows info
std::vector<HeapOverflow> HeapOverflows;

/* -=== ROUTINES ===- */

/*VOID RtlCreateHeap_handle(void * base, UINT32 resSize, UINT32 comSize)
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
}*/

VOID RtlAllocateHeap_openHandle(UINT32 handle, UINT32 size, UINT32 rtnAddr)
{
	RtlAllocateHeapReturnAddress = rtnAddr;
	RtlAllocateHeapHandle		 = handle;
	RtlAllocateHeapSize			 = size;
}

VOID RtlAllocateHeap_closeHandle(UINT32 addr)
{
	if (!(RtlAllocateHeapHandle | RtlAllocateHeapReturnAddress | RtlAllocateHeapSize))
		return;

	// Optimize ???
	if (Heaps.empty())
	{
		HeapAllocated head;
		head.Handle = RtlAllocateHeapHandle;
		head.Min = addr;
		head.Max = addr + RtlAllocateHeapSize - 1;
		head.Area.push_back(MakeAllocatedArea(head.Min, head.Max));
		Heaps.push_back(head);
	}
	else
	{
		HeapIterator heap;
		for (heap = Heaps.begin(); heap != Heaps.end(); heap++)
		{
			if (heap->Handle == RtlAllocateHeapHandle)
				break;
		}

		if (heap != Heaps.end())
		{
			AreaBordersIterator area;
			UINT32 rightBorder = addr + RtlAllocateHeapSize - 1;
			bool flag = false;
			for (area = heap->Area.begin(); area != heap->Area.end(); area++)
			{
				if (area->first == addr)
				{
					flag = true;
					break;
				}
			}

			if (flag)	// Do not know why this is right way
			{
				area->second = rightBorder;
			}
			else
			{
				heap->Area.push_back(MakeAllocatedArea(addr, rightBorder));
			}

			if (addr < heap->Min)
				heap->Min = addr;
			if (rightBorder > heap->Max)
				heap->Max = rightBorder;
		}
		else
		{
			HeapAllocated head;
			head.Handle = RtlAllocateHeapHandle;
			head.Min = addr;
			head.Max = addr + RtlAllocateHeapSize - 1;
			head.Area.push_back(MakeAllocatedArea(head.Min, head.Max));
			Heaps.push_back(head);
		}
	}

	RtlAllocateHeapHandle = 0;
	RtlAllocateHeapReturnAddress = 0;
	RtlAllocateHeapSize = 0;
}

VOID RtlFreeHeap_handle(UINT32 handle, UINT32 base, UINT32 rtnAddr)
{
	if (!Heaps.empty())
	{
		HeapIterator heap;
		for (heap = Heaps.begin(); heap != Heaps.end(); heap++)
		{
			if (heap->Handle == handle)
			{
				AreaBordersIterator area;
				for (area = heap->Area.begin(); area != heap->Area.end(); area++)
				{
					if (area->first == base)
						break;
				}

				if (area != heap->Area.end())
				{
					ReferencesForFree = ForFree(heap, area);
					FreeReturnAddress = rtnAddr;
				}
			}
		}
	}
}

// Searching mallocs
VOID MallocFreeOverflows_Image(IMG img, void *)
{
	//RTN RtlCreateHeap_rtn = RTN_FindByName(img, "RtlCreateHeap");
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

	RTN RtlAllocateHeap_rtn = RTN_FindByName(img, "RtlAllocateHeap");
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

	RTN RtlFreeHeap_rtn = RTN_FindByName(img, "RtlFreeHeap");
	if (RTN_Valid(RtlFreeHeap_rtn))
	{
		RTN_Open(RtlFreeHeap_rtn);
		RTN_InsertCall
		(
			RtlFreeHeap_rtn, 
			IPOINT_BEFORE, (AFUNPTR)RtlFreeHeap_handle, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
			IARG_RETURN_IP, 
			IARG_END
		);
		RTN_Close(RtlFreeHeap_rtn);
	}
}

VOID RtlFreeHeap_closeHandle(UINT32 eax)
{
	if (ReferencesForFree.first->Min == ReferencesForFree.second->first || ReferencesForFree.first->Max == ReferencesForFree.second->second)
	{
		UINT32 Max = 0, Min = UINT32_MAX;
		AreaBordersIterator area;
		for (area = ReferencesForFree.first->Area.begin(); area != ReferencesForFree.first->Area.end(); area++)
		{
			if (area->first < Min && area != ReferencesForFree.second)
				Min = area->first;
			if (area->second > Max && area != ReferencesForFree.second)
				Max = area->second;
		}
		ReferencesForFree.first->Min = Min;
		ReferencesForFree.first->Max = Max;
	}

	ReferencesForFree.first->Area.erase(ReferencesForFree.second);
	FreeReturnAddress = 0;
	// printf("[FREE] 0x%08x\n", ReferencesForFree.second->first);
}

VOID CheckHeapStore(UINT32 storeAddr, UINT32 wrtSize, UINT32 insAddr)
{
	HeapIterator heap;
	for (heap = Heaps.begin(); heap != Heaps.end(); heap++)
	{
		if (storeAddr >= heap->Min && storeAddr <= heap->Max)
		{
			break;
		}
	}

	if (heap != Heaps.end())
	{
		AreaBordersIterator area;
		UINT32 rightEdge = storeAddr + wrtSize - 1;
		bool success = false;
		for (area = heap->Area.begin(); area != heap->Area.end(); area++)
		{
			if (storeAddr >= area->first && rightEdge <= area->second)
			{
				//printf("0x%08x 0x%08x 0x%08x\n", storeAddr, area->first, area->second);
				success = true;
				break;
			}
		}

		if (!success)
		{
			HeapOverflow hpo;
			hpo.InsAddr = insAddr;
			hpo.StoreBase = storeAddr;
			hpo.StoreEdge = rightEdge;
			HeapOverflows.push_back(hpo);
		}
	}
}

void MallocFreeOverflows_Instruction(INS ins, void*)
{
	if (INS_Address(ins) == RtlAllocateHeapReturnAddress && RtlAllocateHeapHandle != 0)
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RtlAllocateHeap_closeHandle,
			IARG_REG_VALUE, REG_EAX,
			IARG_END
		);
	}
	else if (INS_Address(ins) == FreeReturnAddress)
	{
		INS_InsertCall
		(
			ins, 
			IPOINT_BEFORE, (AFUNPTR)RtlFreeHeap_closeHandle, 
			IARG_REG_VALUE, REG_EAX, 
			IARG_END
		);
	}
	// if we've got writting some data to memory, let's check for storing into heap
	else if ((UINT32)INS_Address(ins) < 0x70000000 && INS_MemoryOperandIsWritten(ins, 0) && !INS_IsStackWrite(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)CheckHeapStore,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryWriteSize(ins),
			IARG_ADDRINT, INS_Address(ins),
			// IARG_PTR, new std::string(INS_Disassemble(ins)),
			IARG_END
		);
	}
}

VOID MallocFreeOverflows_Fini(INT32 code, VOID *)
{
	if (HeapOverflows.empty())
	{
		printf("No overflows in heap were detected\n");
	}
	else
	{
		printf("Overflow possible:\n");
		std::vector<HeapOverflow>::iterator overflow;
		for (overflow = HeapOverflows.begin(); overflow != HeapOverflows.end(); overflow++)
		{
			printf("\t0x%08x:\n", overflow->InsAddr);
			printf("\t\tStore from 0x%08x to 0x%08x (%d bytes)\n", overflow->StoreBase, overflow->StoreEdge, overflow->StoreEdge - overflow->StoreBase + 1);
		}
		printf("\n");
	}

	if (Heaps.empty())
	{
		printf("No heaps found out\n");
		printf("bye\n");
		return;
	}
	HeapIterator heap;
	for (heap = Heaps.begin(); heap != Heaps.end(); heap++)
	{
		printf("Heap 0x%08x with min allocated address 0x%08x and max allocated address 0x%08x\n", heap->Handle, heap->Min, heap->Max);
		printf("Allocations:\n");
		AreaBordersIterator area;
		for (area = heap->Area.begin(); area != heap->Area.end(); area++)
		{
			printf("\t0x%08x: 0x%08x (%d bytes)\n", area->first, area->second, area->second - area->first + 1);
		}
	}

	printf("\nbye\n");
}