#pragma once
#include "FuzzingPinTool.h"
using namespace std;

VOID OutputContext(ofstream *fout, CONTEXT *ctxt)
{
	*fout << "EAX: " << hexstr(PIN_GetContextReg(ctxt, REG_EAX)) << endl;
	*fout << "EBX: " << hexstr(PIN_GetContextReg(ctxt, REG_EBX)) << endl;
	*fout << "ECX: " << hexstr(PIN_GetContextReg(ctxt, REG_ECX)) << endl;
	*fout << "EDX: " << hexstr(PIN_GetContextReg(ctxt, REG_EDX)) << endl;
	*fout << "ESI: " << hexstr(PIN_GetContextReg(ctxt, REG_ESI)) << endl;
	*fout << "EDI: " << hexstr(PIN_GetContextReg(ctxt, REG_EDI)) << endl;
	*fout << "ESP: " << hexstr(PIN_GetContextReg(ctxt, REG_ESP)) << endl;
	*fout << "EBP: " << hexstr(PIN_GetContextReg(ctxt, REG_EBP)) << endl;
}

VOID ParseForRoutine(string str, string &imgName, string &rtnName)
{
	UINT32 index = str.find(' ');
	if (index == string::npos)
	{
		imgName = "";
		rtnName = "";
	}
	else
	{
		imgName = str.substr(0, index);
		rtnName = str.substr(index + 1, str.length() - index - 1);
	}
}

VOID ParseForRange(string str, string &imgName, ADDRINT &s, ADDRINT &e)
{
	UINT32 index = str.find(' ');
	if (index != string::npos)
	{
		imgName = str.substr(0, index);
		index++;
		char *c;
		s = static_cast<ADDRINT>(strtoul(str.c_str() + index, &c, 16));
		if (errno == ERANGE)
		{
			s = 0;
			return;
		}
		e = static_cast<ADDRINT>(strtoul(c, nullptr, 16));
		if (errno == ERANGE)
		{
			e = 0;
			return;
		}
	}
}