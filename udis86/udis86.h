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
#include "../uthash.h"

#define ARYBIN 0x46724672

#define UD_MATCH_NONE 0
#define UD_MATCH_LOW 1
#define UD_MATCH_MID 2
#define UD_MATCH_HIGH 3
#define UD_MATCH_ALL 4

#define SIG_WILDCARD 0xFFFF

#define DEF_THRESHOLD_DISP 0x50
#define DEF_THRESHOLD_IMM 0x100

#define RES_DISTANCE_DIMENSION 128
#define RES_PROB_MIN 50.0 //%

#define EXTRA_INSN_RADIUS 10
#define AVERAGE_INSN_LENGTH 7
#define AVERAGE_DISTANCE_BETWEEN_CALLS 30

typedef struct {
    ud_t ud;
    uint8_t* mem_buffer;
    size_t mem_buffer_size;
    size_t load_base;
}udx_t;

#define SCAN_RES_SIZE 8192-3
typedef struct {
    size_t addrs_count;
    size_t addrs[SCAN_RES_SIZE];
    size_t mark_index;
    udx_t* udx;
}udx_scan_result_t;

typedef struct {
    size_t address;
    size_t hit;
    float similarity;
    float prob;
}udx_addr_t;

typedef struct {
    size_t address;
    size_t hit;
    float similarity;
    UT_hash_handle hh;
}udx_hashed_addr_t;

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode);
void udx_free(void* ptr);

uint64_t udx_abs(int64_t src);
size_t udx_rnd(size_t a, size_t b);
size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr);
ud_mnemonic_code_t udx_insn_mnemonic(udx_t* udx, size_t addr);

size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count, size_t skip_count);
size_t udx_blk_gen_sig(struct udx_blk* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);
size_t udx_blks_gen_sig(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);
size_t udx_blks_gen_sig_rnd(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold);

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, size_t match_lvl);
size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size);
size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count, size_t skip_count);
size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, udx_scan_result_t* result, size_t mark_addr);

size_t udx_gen_addr(size_t address, float similarity, udx_addr_t** paddr);
size_t udx_gen_hashed_addr(size_t address, float similarity, udx_hashed_addr_t** paddr);
size_t udx_migrate_scan_result(udx_scan_result_t* res_src, udx_scan_result_t* res_dst, udx_addr_t** paddrs);
size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t src_addr, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count);

size_t ud_gen_sig(struct ud* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl);

#ifdef __cplusplus
}
#endif

#endif
