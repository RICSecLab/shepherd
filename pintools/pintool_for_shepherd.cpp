/*
 * Copyright (C) 2007-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <set>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

// #define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
static std::set<std::pair<ADDRINT, ADDRINT>> flows;
static ADDRINT IMAGEBASE;
static ADDRINT GHIDRA_BASE;
static int edge_fd;

/*!
 *  Print out help message.
 */
INT32 Usage() {
  std::cerr << "This tool prints out the number of dynamically executed "
            << std::endl
            << "instructions, basic blocks and threads in the application."
            << std::endl
            << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

  return -1;
}

BOOL flows_reset(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler,
                 const EXCEPTION_INFO *pExceptInfo, VOID *v) {
  flows.clear();
  return FALSE;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

static void record_edge(ADDRINT from, ADDRINT to) {
  flows.insert(std::make_pair(from, to));
}

static void record_bb(ADDRINT bb_addr, BOOL boring_terminal) {
  static ADDRINT last_bb = 0;
  if (last_bb) // record branch
    record_edge(last_bb, bb_addr);

  last_bb = boring_terminal ? 0 : bb_addr;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID InstrumentTrace(TRACE trace, VOID *v) {
  IMG img = IMG_FindByAddress(TRACE_Address(trace));
  if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
    return;

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    ADDRINT bbl_addr = BBL_Address(bbl);
    INS head_ins = BBL_InsHead(bbl);
    INS tail_ins = BBL_InsTail(bbl);

    BOOL is_call = INS_IsCall(tail_ins);
    BOOL is_ret = INS_IsRet(tail_ins);
    if (is_call) { // call-terminating bbs fallthrough
      ADDRINT fall_through_addr = INS_Address(tail_ins) + INS_Size(tail_ins);
      INS_InsertPredicatedCall(tail_ins, IPOINT_BEFORE, (AFUNPTR)record_edge,
                               IARG_ADDRINT, bbl_addr, IARG_ADDRINT,
                               fall_through_addr, IARG_END);
    }

    // BB transition by call/ret is uninteresting
    BOOL boring_terminal = is_call || is_ret;
    INS_InsertPredicatedCall(head_ins, IPOINT_BEFORE, (AFUNPTR)record_bb,
                             IARG_ADDRINT, bbl_addr, IARG_BOOL, boring_terminal,
                             IARG_END);
  }
}

VOID ImageLoad(IMG img, VOID *v) {
  if (IMG_IsMainExecutable(img)) {
    IMAGEBASE = IMG_LowAddress(img);
    // printf("Imagebase: %lx\n", IMAGEBASE);
  }
}

VOID pin_finish(INT32 code, VOID *v) {
  static_assert(sizeof(ADDRINT) == sizeof(uint64_t));
  for (auto &edge : flows) {
    ADDRINT from = edge.first - IMAGEBASE + GHIDRA_BASE;
    ADDRINT to = edge.second - IMAGEBASE + GHIDRA_BASE;
    write(edge_fd, &from, sizeof(from));
    write(edge_fd, &to, sizeof(to));
    /*
    std::cerr << "0x" << std::hex << from << " -> "
              << "0x" << std::hex << to << std::endl;
    */
  }
  close(edge_fd);
  exit(0);
}

VOID InstrumentInsn(INS ins, VOID *v) {
  IMG img = IMG_FindByAddress(INS_Address(ins));
  if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
    return;

  if (INS_IsBranch(ins))
    INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)record_edge,
                             IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);

  if (INS_HasFallThrough(ins)) // records every fallthrough
    INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)record_edge,
                             IARG_INST_PTR, IARG_FALLTHROUGH_ADDR, IARG_END);
}
/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet
 * started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[]) {
  if (PIN_Init(argc, argv)) {
    return Usage();
  }

  // https://software.intel.com/sites/landingpage/pintool/docs/98547/Pin/html/group__PIN__CONTROL.html#ga3463df5a1390b87e8a4568d6f2f43df9
  PIN_InterceptSignal(SIGUSR1, flows_reset, NULL);

  IMG_AddInstrumentFunction(ImageLoad, NULL);
  // TRACE_AddInstrumentFunction(InstrumentTrace, NULL);
  INS_AddInstrumentFunction(InstrumentInsn, NULL);
  PIN_AddFiniFunction(pin_finish, NULL);

  { // destroy unused objects before starting the program
    pid_t pid = getpid();
    std::string edge_fn = "/tmp/edges/edge_" + std::to_string(pid);
    edge_fd = open(edge_fn.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (edge_fd < 0) {
      std::cerr << "open failed" << std::endl;
      exit(-1);
    }
    // read env var for the ghidra's elf base address: hex string
    const char *ghidra_base = getenv("GHIDRA_ELF_BASE");
    if (ghidra_base) {
      GHIDRA_BASE = std::stoul(ghidra_base, nullptr, 16);
      // printf("Ghidra Imagebase: %lx\n", GHIDRA_BASE);
    } else {
      GHIDRA_BASE = 0x100000;
    }
  }

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
