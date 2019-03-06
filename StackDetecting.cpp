#pragma once

#include "pin.H"
#include "asm/unistd.h"
#include "FuzzingPinTool.h"

#include <string>
#include <vector>
#include <map>

typedef std::map<UINT32, UINT32> VariablesMap;

struct Store
{
	UINT32 StoreAddress;
	UINT32 InstructionAddress;
	UINT32 Size;
};

struct Routine
{
	std::string Name;
	UINT32 StackBegin;
	UINT32 StackEnd;
	BOOL Empty;
	VariablesMap Variables;
};

std::vector<Routine> rtnStack;
std::vector<Store> doubtfulStores;

VOID RtnBegin()
{
	Routine current;
	current.Empty = true;
	rtnStack.push_back(current);
}

VOID RtnEnd()
{
	if (!rtnStack.empty())
	{
		if (!rtnStack.back().Empty && !rtnStack.back().Variables.empty())
		{
			printf("[STACK] Routine \"%s\" with stack 0x%08x:0x%08x has variables:\n", rtnStack.back().Name.c_str(), rtnStack.back().StackEnd, rtnStack.back().StackBegin);
			VariablesMap::iterator iter;

			for (int i = 0; i < doubtfulStores.size(); i++)
			{
				bool overflow = false;
				for (UINT32 addr = doubtfulStores[i].StoreAddress + 1; addr < doubtfulStores[i].StoreAddress + doubtfulStores[i].Size; addr++)
				{
					iter = rtnStack.back().Variables.find(addr);
					if (iter != rtnStack.back().Variables.end())
					{
						overflow = true;
						break;
					}
				}
				if (overflow)
					printf("\t\t[Doubtful] Storing %d bytes at 0x%08x into 0x%08x\n", doubtfulStores[i].Size, doubtfulStores[i].InstructionAddress, doubtfulStores[i].StoreAddress);
				else if (doubtfulStores[i].Size > rtnStack.back().Variables[doubtfulStores[i].StoreAddress])
				{
					rtnStack.back().Variables[doubtfulStores[i].StoreAddress] = doubtfulStores[i].Size;
				}

			}
			doubtfulStores.clear();

			for (iter = rtnStack.back().Variables.begin(); iter != rtnStack.back().Variables.end(); iter++)
			{
				printf("\t0x%08x: %d bytes\n", iter->first, iter->second);
			}
		}
		rtnStack.pop_back();
	}

}

VOID StackWriteHandle(RTN *rtn, UINT32 storeAddr, UINT32 insAddr, UINT32 opSize, UINT32 ebp, UINT32 esp)
{
	if (!rtnStack.empty())
	{
		if (rtnStack.back().Empty && RTN_Valid(*rtn) && ebp > esp)
		{
			rtnStack.back().Name = RTN_Name(*rtn);
			rtnStack.back().StackBegin = ebp;
			rtnStack.back().StackEnd = esp;
			rtnStack.back().Empty = false;
		}
		else if (!rtnStack.back().Empty && storeAddr >= rtnStack.back().StackEnd && storeAddr <= rtnStack.back().StackBegin)
		{
			VariablesMap::iterator iter = rtnStack.back().Variables.find(storeAddr);
			if (iter == rtnStack.back().Variables.end())
			{
				rtnStack.back().Variables.insert(std::pair<UINT32, UINT32>(storeAddr, opSize));
			}
			else if (opSize > iter->second)
			{
				Store store;
				store.InstructionAddress = insAddr;
				store.StoreAddress = storeAddr;
				store.Size = opSize;
				doubtfulStores.push_back(store);
			}
		}
	}
}

VOID StackOverflows_Instruction(INS ins, void*)
{
	if (INS_IsCall(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RtnBegin,
			IARG_END
		);
	}
	else if (INS_IsRet(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RtnEnd,
			IARG_END
		);
	}
	else if (INS_IsMemoryWrite(ins) && INS_OperandCount(ins) == 2)
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)StackWriteHandle,
			IARG_PTR, new RTN(INS_Rtn(ins)),
			IARG_MEMORYWRITE_EA,
			IARG_ADDRINT, INS_Address(ins),
			IARG_MEMORYWRITE_SIZE,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_END
		);
	}
	else
	{
		//
	}
}
