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
	printf("Found out a malloc: 0x%08x, size: %d,", (uint32_t)rtnaddr, (UINT32)size);

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

		/*RTN_InsertCall
		(
			malloc_rtn,
			IPOINT_AFTER, AFUNPTR(ForMallocAfter),
			IARG_FUNCRET_EXITPOINT_REFERENCE,
			IARG_END
		);*/

		RTN_Close(malloc_rtn);
	}
}

void GetMallocSize(REG eax) 
{
	MemoryWatch.end()->Begin = (UINT32)eax;
	MemoryWatch.end()->End += (UINT32)eax - 1;
	printf(" start from 0x%08x\n", (UINT32)eax);
}

void CheckHeapStore(int addr) 
{
	/*PIN_LockClient();
	IMG img = IMG_FindByAddress(addr);
	PIN_UnlockClient();*/
	//printf("0x%08x\n", addr);
	for (int i = 0; i < MemoryWatch.size(); i++)
	{
		if ((UINT32)addr >= MemoryWatch[i].Begin && (UINT32)addr <= MemoryWatch[i].End)
		{
			printf("Storing into %d area, address is 0x%08x\n", i + 1, (UINT32)addr);
		}
	}
}

void Instruction(INS ins, void*)
{
	if (INS_Address(ins) == MallocReturnAddress)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)GetMallocSize, IARG_REG_VALUE, REG_EAX, IARG_END);
	}
	else if (INS_MemoryOperandIsWritten(ins, 0) && INS_OperandCount(ins) > 1)
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)CheckHeapStore,
			IARG_MEMORYOP_EA, 0,
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
#ifdef DEBUG
	PIN_AddFiniFunction(Fini, 0);
#endif
	PIN_StartProgram();

	return 0;
}

// D:\Source\pin-3.7-97619-g0d0c92f4f-msvc-windows\intel64\bin\pin.exe -t D:\Source\pin-3.7-97619-g0d0c92f4f-msvc-windows\source\tools\MyPinTool\x64\Debug\MyPinTool.dll -- D:\Source\TestForPin\x64\Debug\TestForPin.exe