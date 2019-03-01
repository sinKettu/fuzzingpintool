//
//  Jonathan Salwan - Copyright (C) 2013-09
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string.h>

int MallocReturnAddress = 0;

struct HeapAllocated
{
	UINT32 Begin;
	UINT32 End;
};

std::vector<HeapAllocated> MemoryWatch;

void ForMallocBefore(int size, int rtnaddr)
{	
	MallocReturnAddress = rtnaddr;
	HeapAllocated next;
	next.Begin = 0;
	next.End = size;
	MemoryWatch.push_back(next);
	printf("[ALLOCATION] Found out a malloc: 0x%08x, size: %d,", (uint32_t)rtnaddr, (UINT32)size);

}

void ForMallocAfter(int* addr) 
{
	printf("New memory space is available from 0x%08x\n", (UINT32)addr);
}

VOID ImageA(IMG img, void *)
{
	RTN malloc_rtn = RTN_FindByName(img, "malloc");
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
}

void GetMallocSize(REG eax) 
{
	size_t last = MemoryWatch.size() - 1;
	MemoryWatch[last].Begin = (UINT32)eax;
	MemoryWatch[last].End += (UINT32)eax - 1;
	printf(" start from 0x%08x\n", (UINT32)eax);
}

void CheckHeapStore(int addr) 
{

	for (int i = 0; i < MemoryWatch.size(); i++)
	{
		if ((UINT32)addr >= MemoryWatch[i].Begin && (UINT32)addr <= MemoryWatch[i].End)
		{
			printf("[STRORE] Storing into %d area, address is 0x%08x\n", i + 1, (UINT32)addr);
		}
	}
}

void Instruction(INS ins, void*)
{
	if (INS_Address(ins) == MallocReturnAddress)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)GetMallocSize, IARG_REG_VALUE, REG_EAX, IARG_END);
	}
	else if (/*INS_Address(ins) < 0x70000000 && */INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryWrite(ins))
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)CheckHeapStore,
			IARG_MEMORYWRITE_EA,
			IARG_END
		);
	}
}

int main(int argc, char *argv[])
{
	printf("Hello\n\n");

	PIN_InitSymbols();                            // Необходима, чтобы была возможность искать функции в образе
	if (PIN_Init(argc, argv)) 
	{
		return -1;
	}

	PIN_SetSyntaxIntel();
	IMG_AddInstrumentFunction(ImageA, 0);
	INS_AddInstrumentFunction(Instruction, 0);

//	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}

// INS_IsStackWrite