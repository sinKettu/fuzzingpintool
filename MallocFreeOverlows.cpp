#include "MallocFreeOverlows.h"
#include <vector>
#include <string.h>

UINT32
// Watch where malloc returns allocated base
MallocReturnAddress = 0,

// Watch where free returns to know about success
FreeReturnAddress = 0,

// Remember what base is gonna be cleared
MonitoringFreeAddress = 0,

// Min allocated base and max end of allocated area
HeapMin = UINT32_MAX,
HeapMax = 0;

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
	if (rtnaddr < 0x700000000)
	{
		HeapAllocated next;
		next.Begin = 0;
		next.End = size;
		MemoryWatch.push_back(next);

		MallocReturnAddress = rtnaddr;

		printf("[ALLOCATION] 0x%08x: Found out an allocation of %d bytes", (uint32_t)rtnaddr, (UINT32)size);
	}
}

// Instrumenting free calls
void ForFreeBefore(UINT32 free_addr, UINT32 rtn_addr)
{
	MonitoringFreeAddress = free_addr;
	FreeReturnAddress = rtn_addr;
}

// Searching mallocs
VOID MallocFreeOverflows_Image(IMG img, void *)
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
			IPOINT_BEFORE, (AFUNPTR)ForFreeBefore,
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

	if (HeapMin > MemoryWatch[last].Begin)
		HeapMin = MemoryWatch[last].Begin;
	if (HeapMax < MemoryWatch[last].End)
		HeapMax = MemoryWatch[last].End;

	printf(", starting from 0x%08x : %d\n", (UINT32)eax, last + 1);

	MallocReturnAddress = 0;
}

// Is the instruction a storing into allocated heap areas?
void CheckHeapStore(int addr, UINT32 mws, int ins_addr, const std::string *s)
{
	if (!(addr >= HeapMin - 1 && addr <= HeapMax + 1))
		return;

	if (addr == HeapMin - 1 || addr == HeapMax + 1)
	{
		printf("[HEAP OVERFLOW] 0x%08x: Overflow possible\n", ins_addr);
		printf("[HEAP OVERFLOW] 0x%08x: %s\n", ins_addr, (*s).c_str());
		return;
	}

	for (size_t i = 0; i < MemoryWatch.size(); i++)
	{
		if ((UINT32)addr >= MemoryWatch[i].Begin && (UINT32)addr <= MemoryWatch[i].End)
		{
			if (MemoryWatch[i].Allocated)
			{
				printf("[STRORE] 0x%08x: Storing %d bytes into %d area, address is 0x%08x\n", ins_addr, mws, i + 1, (UINT32)addr);
				if ((UINT32)addr + mws - 1 > MemoryWatch[i].End)
				{
					printf("\t[HEAP OVERFLOW] 0x%08x: Overflow possible\n", ins_addr);
					printf("\t[HEAP OVERFLOW] 0x%08x: %s\n", ins_addr, (*s).c_str());
				}
			}
			else
			{
				printf("[HEAP OVERFLOW] 0x%08x: Reuse released data possible\n", ins_addr);
				printf("[HEAP OVERFLOW] 0x%08x: %s\n", ins_addr, (*s).c_str());
			}
			return;
		}

		// One not very successful method to detect overflow
		/*if (i > 0)
		{
			UINT32 left = min(MemoryWatch[i - 1].End, MemoryWatch[i].Begin);
			UINT32 right = max(MemoryWatch[i - 1].End, MemoryWatch[i].Begin);
			if ((UINT32)addr > left && (UINT32)addr < right)
			{
				printf("\t[HEAP OVERFLOW] Overflow possible. Instruction address is 0x%08x\n", ins_addr);
				printf("\t[HEAP OVERFLOW] %s\n", (*s).c_str());
				return;
			}
		}*/
	}

	printf("[HEAP OVERFLOW] 0x%08x: Overflow possible\n", ins_addr);
	printf("[HEAP OVERFLOW] 0x%08x: %s\n", ins_addr, (*s).c_str());
}

void ConfirmFree(int ins_addr)
{
	for (size_t i = 0; i < MemoryWatch.size(); i++)
	{
		if (MonitoringFreeAddress == MemoryWatch[i].Begin)
		{
			MemoryWatch[i].Allocated = false;
			if (MemoryWatch[i].Begin == HeapMin || MemoryWatch[i].Begin == HeapMax)
			{
				for (int i = 0; i < MemoryWatch.size(); i++)
				{
					if (MemoryWatch[i].Allocated)
					{
						if (MemoryWatch[i].Begin < HeapMin)
							HeapMin = MemoryWatch[i].Begin;
						if (MemoryWatch[i].End > HeapMax)
							HeapMax = MemoryWatch[i].End;
					}
				}
			}

			printf("[FREE] 0x%08x: Area %d with base 0x%08x is released\n", ins_addr, i + 1, MonitoringFreeAddress);
			break;
		}
	}

	MonitoringFreeAddress = 0;
	FreeReturnAddress = 0;
}

void MallocFreeOverflows_Instruction(INS ins, void*)
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
			IARG_ADDRINT, INS_Address(ins),
			IARG_END
		);
	}
	// if we've got writting some data to memory, let's check for storing into heap
	else if ((UINT32)INS_Address(ins) < 0x70000000 /*&& INS_Opcode(ins) == XED_ICLASS_MOV*/ && INS_MemoryOperandIsWritten(ins, 0))
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
	}
}
