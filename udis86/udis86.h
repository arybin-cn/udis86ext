/* udis86 - udis86.h
 *
 * Copyright (c) 2002-2009 Vivek Thampi
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UDIS86_H
#define UDIS86_H

#include "types.h"
#include "extern.h"
#include "itab.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
* udis86ext structs & apis
* =============================================================================
*/

#define UD_MATCH_NONE 0
#define UD_MATCH_LOW 1
#define UD_MATCH_MID 2
#define UD_MATCH_HIGH 3
#define UD_MATCH_ALL 4

#define SIG_WILDCARD 0xFFFF
#define DEF_THRESHOLD_DISP 0x50
#define DEF_THRESHOLD_IMM 0x100

typedef struct {
    ud_t ud;
    uint8_t* mem_buffer;
    size_t mem_buffer_size;
    size_t load_base;
}udx_t;
 
uint64_t udx_abs(int64_t src);
size_t udx_rnd(size_t a, size_t b);
void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode);
size_t udx_valid_addr(udx_t* udx, size_t addr);
size_t udx_blk_gen_sig(struct udx_blk* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);
size_t udx_blks_gen_sig(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);
size_t udx_blks_gen_sig_rnd(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold);
size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, size_t match_lvl);
size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size);
size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, size_t* ret_buffer, size_t ret_buffer_size);
size_t udx_gen_blks(udx_t* udx, size_t target_addr, struct udx_blk* blks_buffer, size_t blks_size);

size_t ud_gen_sig(struct ud* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl);

#ifdef __cplusplus
}
#endif

#endif
