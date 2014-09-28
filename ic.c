/*
   Copyright (c) 2014, Cosmin Gorgovan <cosmin {at} linux-geek {dot} org>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#include "dr_api.h"
#include "utils.h"

unsigned int crackme_version;

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag,
                                         instrlist_t *bb, bool for_trace, bool translating) {
  instr_t *instr;
  for (instr = instrlist_first_app(bb); instr != NULL; instr = instr_get_next_app(instr)) {
    
    switch(crackme_version) {
      case 0:
        if (instr_get_app_pc(instr) == (app_pc)0x08048470) {
          instr_set_opcode(instr, OP_jmp);
        }
        break;
      case 1:
        if (instr_get_app_pc(instr) == (app_pc)0x08048432) {
          instr_set_opcode(instr, OP_jmp);
        }
        break;
      case 2:
        if (instr_get_app_pc(instr) == (app_pc)0x08048451) {
          instr_set_branch_target_pc(instr, (app_pc)0x08048453);
        }
        break;
      case 3:
        if (instr_get_app_pc(instr) == (app_pc)0x0804847a) {
          instr_set_opcode(instr, OP_jmp);
        }
        break;
      case 4:
        if (instr_get_app_pc(instr) == (app_pc)0x080484da) {
          instr_set_branch_target_pc(instr, (app_pc)0x080484dc);
        }
        break;
      case 5:
        switch((unsigned int)instr_get_app_pc(instr)) {
          case 0x0804851e:
            instr_set_branch_target_pc(instr, (app_pc)0x08048520);
            break;
          case 0x080484ac:
            instr_set_branch_target_pc(instr, (app_pc)0x080484ae);
            break;
        }
      case 6:
        switch((unsigned int)instr_get_app_pc(instr)) {
          case 0x08048503:
            instr_set_branch_target_pc(instr, (app_pc)0x08048505);
            break;
          case 0x08048565:
            instr_set_branch_target_pc(instr, (app_pc)0x08048567);
            break;
          case 0x080485de:
            instr_set_branch_target_pc(instr, (app_pc)0x080485e0);
            break;
        }
        break;
      case 7:
      case 8:
        switch((unsigned int)instr_get_app_pc(instr)) {
          case 0x08048503:
            instr_set_branch_target_pc(instr, (app_pc)0x08048505);
            break;
          case 0x804858d:
            instr_set_branch_target_pc(instr, (app_pc)0x804858f);
            break;
          case 0x804860f:
            instr_set_branch_target_pc(instr, (app_pc)0x8048611);
            break;
        }
        break;
      case 9:
        switch((unsigned int)instr_get_app_pc(instr)) {
          case 0x8048531:
            instr_set_branch_target_pc(instr, (app_pc)0x8048533);
            break;
          case 0x804867a:
            instr_set_branch_target_pc(instr, (app_pc)0x804867c);
            break;
          case 0x80485e2:
            instr_set_branch_target_pc(instr, (app_pc)0x80485e4);
            break;
        }
    }
  }
  return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_init(client_id_t id) {
  int ret;
  
  ret = dr_sscanf(dr_get_application_name(), "crackme0x%u", &crackme_version);
  if (ret != 1 || crackme_version > 9) {
    dr_printf("Unknown application, exiting\n");
    dr_exit_process(EXIT_FAILURE);
  }
  
  dr_register_bb_event(event_basic_block);
}
