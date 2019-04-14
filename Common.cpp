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