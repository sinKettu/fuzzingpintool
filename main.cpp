
#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string.h>

// Watch where malloc returns allocated base
UINT32 MallocReturnAddress = 0;

// Watch where free returns to know about success
UINT32 FreeReturnAddress = 0;

// Remember what base is gonna be cleared
UINT32 MonitoringFreeAddress = 0;

// Structure with allocated base and allocated base + size of allocated area and alloc-flag
struct HeapAllocated
{
	UINT32 Begin;
	UINT32 End;
	BOOL Allocated;
};

// Neew to monitor storing to allocated heap areas
std::vector<HeapAllocated> MemoryWatch;

// Instrumenting with this call all mallocs
void ForMallocBefore(int size, int rtnaddr)
{	
	HeapAllocated next;
	next.Begin = 0;
	next.End = size;
	MemoryWatch.push_back(next);

	MallocReturnAddress = rtnaddr;
	
	printf("[ALLOCATION] Found out a malloc: 0x%08x, size: %d,", (uint32_t)rtnaddr, (UINT32)size);

}

// Instrumenting free calls
void ForFreeBefore(UINT32 free_addr, UINT32 rtn_addr)
{
	MonitoringFreeAddress = free_addr;
	FreeReturnAddress = rtn_addr;
}

// Searching mallocs
VOID Image(IMG img, void *)
{
	RTN malloc_rtn = RTN_FindByName(img, "malloc");
	RTN free_rtn = RTN_FindByName(img, "free");

	if (RTN_Valid(malloc_rtn))
	{
		RTN_Open(malloc_rtn);

		RTN_InsertCall
		(
			malloc_rtn,
			IPOINT_BEFORE, (AFUNPTR)ForMallocBefore,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_RETURN_IP,
			IARG_END
		);

		RTN_Close(malloc_rtn);
	}

	if (RTN_Valid(free_rtn))
	{
		RTN_Open(free_rtn);

		RTN_InsertCall
		(
			free_rtn,
			IPOINT_BEFORE, (AFUNPTR) ForFreeBefore,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_RETURN_IP,
			IARG_END
		);

		RTN_Close(free_rtn);
	}
}

// Memory allocated in heap
void GetAllocatedArea(REG eax) 
{
	size_t last = MemoryWatch.size() - 1;
	MemoryWatch[last].Begin = (UINT32)eax;
	MemoryWatch[last].End += (UINT32)eax - 1;
	MemoryWatch[last].Allocated = true;

	printf(" start from 0x%08x\n", (UINT32)eax);

	MallocReturnAddress = 0;
}

// Is the instruction a storing into allocated heap areas?
void CheckHeapStore(int addr, UINT32 mws) 
{
	for (size_t i = 0; i < MemoryWatch.size(); i++)
	{
		if ((UINT32)addr >= MemoryWatch[i].Begin && (UINT32)addr <= MemoryWatch[i].End)
		{
			printf("[STRORE] Storing %d bytes into %d area, address is 0x%08x\n", mws, i + 1, (UINT32)addr);
		}
	}
}

void ConfirmFree(void)
{
	for (size_t i = 0; i < MemoryWatch.size(); i++)
	{
		if (MonitoringFreeAddress == MemoryWatch[i].Begin)
		{
			MemoryWatch[i].Allocated = false;
			printf("[FREE] Area %d with base 0x%08x is released\n", i + 1, MonitoringFreeAddress);
			break;
		}
	}

	MonitoringFreeAddress = 0;
	FreeReturnAddress = 0;
}

void Instruction(INS ins, void*)
{
	// if mallocs returning to this instructions, we can find out base of allocated memory area in RAX(EAX)
	if (INS_Address(ins) == MallocReturnAddress)
	{
		INS_InsertCall
		(
			ins, 
			IPOINT_BEFORE, (AFUNPTR)GetAllocatedArea, 
			IARG_REG_VALUE, 
			REG_EAX, 
			IARG_END
		);
	}
	// Confirm that free is successful
	else if (INS_Address(ins) == FreeReturnAddress && MonitoringFreeAddress != 0)
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)ConfirmFree,
			IARG_END
		);
	}
	// if we've got 'mov' some data to memory, let's check for storing into heap
	else if (/*INS_Address(ins) < 0x70000000 && */INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryWrite(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)CheckHeapStore,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryWriteSize(ins),
			IARG_END
		);
	}
}

int main(int argc, char *argv[])
{
	printf("Hello\n\n");

	PIN_InitSymbols();                            // ����������, ����� ���� ����������� ������ ������� � ������
	if (PIN_Init(argc, argv)) 
	{
		return -1;
	}

	PIN_SetSyntaxIntel();
	IMG_AddInstrumentFunction(Image, 0);
	INS_AddInstrumentFunction(Instruction, 0);

//	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}

// INS_IsStackWrite