#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include "FuzzingPinTool.h"
using namespace std;

#define		BASIC_BLOCK_EDGES	pair<UINT32, UINT32>
#define		BASIC_BLOCKS		map<BASIC_BLOCK_EDGES, UINT32>
#define		ROUTINES			map<const char*, BASIC_BLOCKS>
#define		SECTIONS			map<const char*, ROUTINES>
#define		IMAGES				map<const char*, SECTIONS>

FILE *outdata = fopen("trace.txt", "ab");

IMAGES images;
UINT64 bblCount = 0;

VOID BblInstrumentation(const char *rtnName, const char *secName, const char *imgName, UINT32 head, UINT32 tail)
{
	bblCount++;
	BASIC_BLOCK_EDGES newEdges = make_pair(head, tail);
	
	BASIC_BLOCKS bbl_tmp;
	bbl_tmp.insert(make_pair(newEdges, 1));
	ROUTINES rtn_tmp;
	rtn_tmp.insert(make_pair(rtnName, bbl_tmp));
	SECTIONS sec_tmp;
	sec_tmp.insert(make_pair(secName, rtn_tmp));
	IMAGES img_tmp;
	img_tmp.insert(make_pair(imgName, sec_tmp));

	IMAGES::iterator image = images.find(imgName);
	if (image != images.end())
	{
		SECTIONS::iterator section = image->second.find(secName);
		if (section != images[imgName].end())
		{
			ROUTINES::iterator routine = section->second.find(rtnName);
			if (routine != section->second.end())
			{
				BASIC_BLOCKS::iterator bbl = routine->second.find(newEdges);
				if (bbl != routine->second.end())
				{
					bbl->second++;
				}
				else
				{
					routine->second.insert(make_pair(newEdges, 1));
				}
			}
			else
			{
				BASIC_BLOCKS bbl_tmp;
				bbl_tmp.insert(make_pair(newEdges, 1));
				section->second.insert(make_pair(rtnName, bbl_tmp));
			}
		}
		else
		{
			BASIC_BLOCKS bbl_tmp;
			bbl_tmp.insert(make_pair(newEdges, 1));
			ROUTINES rtn_tmp;
			rtn_tmp.insert(make_pair(rtnName, bbl_tmp));
			image->second.insert(make_pair(secName, rtn_tmp));
		}
	}
	else
	{
		BASIC_BLOCKS bbl_tmp;
		bbl_tmp.insert(make_pair(newEdges, 1));
		ROUTINES rtn_tmp;
		rtn_tmp.insert(make_pair(rtnName, bbl_tmp));
		SECTIONS sec_tmp;
		sec_tmp.insert(make_pair(secName, rtn_tmp));
		images.insert(make_pair(imgName, sec_tmp));
	}
}

VOID Tracer_Trace(TRACE trace, void*)
{
	RTN *rtn = &TRACE_Rtn(trace);
	if (!RTN_Valid(*rtn)) return;
	const char *rtnName = RTN_Name(*rtn).c_str();

	SEC *sec = &RTN_Sec(*rtn);
	const char *secName = SEC_Name(*sec).c_str();

	IMG *img = &SEC_Img(*sec);
	const char *imgName = IMG_Name(*img).c_str();

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		BBL_InsertCall(
			bbl,
			IPOINT_BEFORE, (AFUNPTR)BblInstrumentation,
			IARG_PTR, rtnName,
			IARG_PTR, secName,
			IARG_PTR, imgName,
			IARG_ADDRINT, BBL_InsHead(bbl),
			IARG_ADDRINT, BBL_InsTail(bbl),
			IARG_END
		);
	}
}