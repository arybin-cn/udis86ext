#include "../uthash.h"
#include <stdlib.h>
#include <string.h>

#include "udis86.h" 

uint64_t udx_abs(int64_t src) {
    int64_t const mask = src >> ((sizeof(int) * 8) - 1);
    return (src ^ mask) - mask;
}

size_t udx_rnd(size_t a, size_t b) {
    if (a >= b) return a;
    return a + (rand() % (b - a + 1));
}

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode) {
    ud_init(&udx->ud);
    ud_set_mode(&udx->ud, mode);
    udx->load_base = load_base;
    udx->mem_buffer = mem_buffer;
    udx->mem_buffer_size = mem_buffer_size;
}

size_t udx_blk_gen_sig(struct udx_blk* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    uint8_t i, j;
    char* origin_sig_buffer = sig_buffer; 
    size_t sig_length = 0;
     
    for (i = 0; i < blk->insn_length; i++) {
        if (sig_buffer_size < 3 + 1) return 0;
        sprintf_s(sig_buffer, sig_buffer_size, "%02X ", blk->insn_bytes[i]);
        sig_buffer += 3;
        sig_buffer_size -= 3;
    } 
    sig_length = sig_buffer - origin_sig_buffer;
    sig_buffer = origin_sig_buffer;
    
    if (match_lvl == UD_MATCH_ALL) return sig_length;
    if (match_lvl == UD_MATCH_NONE) {
        for (i = 0, j = 0; j < blk->insn_length; i += 3, j++) {
            sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
        }
        return sig_length;
    }
    if (blk->have_modrm) {
        if (match_lvl < UD_MATCH_MID || (match_lvl < UD_MATCH_HIGH && !blk->modrm_stb)) {
            i = blk->modrm_offset * 3;
            sig_buffer[i] = '?';
            sig_buffer[i + 1] = '?';
        }
    }
    if (blk->have_sib && match_lvl < UD_MATCH_HIGH) {
        i = blk->sib_offset * 3;
        sig_buffer[i] = '?';
        sig_buffer[i + 1] = '?';
    }
    if (blk->have_disp) {
        if (udx_abs(blk->disp) > disp_threshold || match_lvl < UD_MATCH_MID) {
            for (i = blk->disp_offset * 3, j = 0; j < blk->disp_size; i += 3, j++) {
                sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
            }
        }
    }
    if (blk->have_imm) {
        if (udx_abs(blk->imm) > imm_threshold || match_lvl < UD_MATCH_MID) {
            for (i = blk->imm_offset * 3, j = 0; j < blk->imm_size; i += 3, j++) {
                sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
            }
        }
    }

    return sig_length;
}

size_t udx_blks_gen_sig(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    size_t insns_size = blks_size / sizeof(struct udx_blk);
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < insns_size; i++) {
        blk_sig_length = udx_blk_gen_sig(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;
     
}

size_t udx_blks_gen_sig_rnd(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold)
{
    size_t insns_size = blks_size / sizeof(struct udx_blk);
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < insns_size; i++) {
        blk_sig_length = udx_blk_gen_sig(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;

}

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, size_t match_lvl) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    size_t insn_sig_size, sig_size = 0, insn_size_readed = 0;
    while (ud_disassemble(&udx->ud)) {
        insn_sig_size = ud_gen_sig(&udx->ud, sig_buffer, sig_buffer_size, match_lvl);
        if (!insn_sig_size) return 0;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        sig_size += insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);

    size_t insn_sig_size, sig_size = 0, insn_size_readed = 0;
    while (ud_disassemble(&udx->ud)) {
        insn_sig_size = ud_gen_sig(&udx->ud, sig_buffer, sig_buffer_size, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!insn_sig_size) return 0;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        sig_size += insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, size_t* ret_buffer, size_t ret_buffer_size) {
    uint16_t real_sig[256] = { 0 };
    uint8_t real_sig_size = 0;
    size_t i, ret_size = 0;
    ret_buffer_size /= sizeof(size_t);

    if (sig_buffer_size / 3 > sizeof(real_sig) / sizeof(uint16_t)) return 0;

    for (i = 0; i < sig_buffer_size; i += 3) {
        while (sig_buffer[i] == ' ') i++;
        if (sig_buffer[i] == 0) break;
        if (sig_buffer[i] == '?') {
            real_sig[real_sig_size++] = SIG_WILDCARD;
        }
        else {
            sscanf_s(&sig_buffer[i], "%hx", &real_sig[real_sig_size++]);
        }
    } 
     
    uint8_t* start_addr = udx->mem_buffer;
    uint8_t* end_addr = start_addr + udx->mem_buffer_size - real_sig_size;

    while (start_addr < end_addr && ret_size < ret_buffer_size) {
        for (i = 0; i < real_sig_size; i++) {
            if (real_sig[i] == SIG_WILDCARD) continue;
            if (start_addr[i] != (uint8_t)real_sig[i]) break;
        }
        if (i >= real_sig_size) {
            ret_buffer[ret_size++] = (size_t)(start_addr - udx->mem_buffer + udx->load_base);
        }
        start_addr++;
    }

    return ret_size;
}

size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count, size_t skip_count) {
    if (insns_count < 1) return 0;
    *pblks = 0;
    size_t blks_count_generated = 0;
    udx_blk_t* blks = (udx_blk_t*)malloc(insns_count * sizeof(udx_blk_t));
    if (!blks) return 0;
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    while (ud_disassemble(&udx->ud)) {
        if (skip_count > 0) {
            skip_count--;
            continue;
        }
        memcpy_s(blks + (blks_count_generated++), sizeof(struct udx_blk), &udx->ud.blk, sizeof(struct udx_blk));
        if (blks_count_generated >= insns_count) break;
    } 
    if (blks_count_generated != insns_count) {
        udx_free_blks(blks);
        return 0;
    }
    *pblks = blks;
    return blks_count_generated;
}

#define EXTRA_INSN_RADIUS 5
#define AVERAGE_INSN_LENGTH 8
size_t udx_gen_blks_radius(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count_radius) {
    if (insns_count_radius < 1) return 0;
    size_t target_addr_start = target_addr - AVERAGE_INSN_LENGTH * (insns_count_radius + EXTRA_INSN_RADIUS), addr_count;
    while ((addr_count = udx_insn_count(udx, target_addr_start, target_addr)) < insns_count_radius + EXTRA_INSN_RADIUS)
        target_addr_start -= AVERAGE_INSN_LENGTH * EXTRA_INSN_RADIUS;
    return udx_gen_blks(udx, target_addr_start, pblks, insns_count_radius * 2 + 1, addr_count - insns_count_radius);
}

void udx_free_blks(udx_blk_t* blks) {
    free(blks);
}

//return number of insns in [start_addr, end_addr)
size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr) {
    if (start_addr >= end_addr) return 0;
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, start_addr - udx->load_base);
    ud_set_pc(&udx->ud, start_addr);
    size_t insns_size = 0;
    while (ud_disassemble(&udx->ud)) {
        insns_size++;
        start_addr += ud_insn_len(&udx->ud);
        if (start_addr >= end_addr) break;
    }
    return insns_size;
}

ud_mnemonic_code_t udx_insn_mnemonic(udx_t* udx, size_t addr) {
    ud_mnemonic_code_t mnemonic = 0;
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, addr - udx->load_base);
    ud_set_pc(&udx->ud, addr); 
    if (ud_disassemble(&udx->ud)) {
        mnemonic = ud_insn_mnemonic(&udx->ud);
    }
    return mnemonic;
}

typedef struct {
    size_t addr;
    size_t count;
    UT_hash_handle hh;
} addr_counter_t;

#define POSSIBLE_ADDR_BUFFER_SIZE 16
#define CACHE_ADDRS_SIZE 256
size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t src_addr, size_t sample_insns_radius, size_t confidence) {
    if (confidence < 1) return 0;
    addr_counter_t* possible_addrs = NULL, * possible_addr, * tmp;
    addr_counter_t possible_addr_buffer[POSSIBLE_ADDR_BUFFER_SIZE]; size_t possible_addr_buffer_length = 0;
    size_t most_possible_addr = 0, sig_size, sig_length;
    size_t src_addrs[CACHE_ADDRS_SIZE], src_addrs_size;
    size_t dst_addrs[CACHE_ADDRS_SIZE], dst_addrs_size;
    size_t signatures_count = 0;
    ud_mnemonic_code_t src_addr_mnemonic = udx_insn_mnemonic(udx_src, src_addr);

    udx_blk_t* blks;
    size_t blks_length = udx_gen_blks_radius(udx_src, src_addr, &blks, sample_insns_radius);
    if (!blks_length) return 0;
    do { 
        sig_size = (blks_length + EXTRA_INSN_RADIUS) * AVERAGE_INSN_LENGTH * 3;
        char* sig = (char*)malloc(sig_size);
        if (!sig) break;
        printf("Migrate started for address: %08X, sample_insns_radius: %d, sig_buffer_size: %d\n", src_addr, sample_insns_radius, sig_size);
        while (1) {
            size_t rnd_insns_size = udx_rnd(3, blks_length);
            size_t rnd_insns_start = udx_rnd(0, blks_length - rnd_insns_size);
            int32_t src_offset = src_addr - blks[rnd_insns_start].insn_addr;
            sig_length = udx_blks_gen_sig_rnd(blks + rnd_insns_start, rnd_insns_size*sizeof(udx_blk_t), sig, sig_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM);
            if (!sig_length) {
                printf("Failed to generate signature...(%d, %d, %d)\n", rnd_insns_start, rnd_insns_size, blks_length);
                continue;
            }
            signatures_count++;
            dst_addrs_size = udx_scan_sig(udx_dst, sig, sig_length, dst_addrs, CACHE_ADDRS_SIZE * sizeof(size_t));
            if (dst_addrs_size == 0 || dst_addrs_size == CACHE_ADDRS_SIZE) continue;
            src_addrs_size = udx_scan_sig(udx_src, sig, sig_length, src_addrs, CACHE_ADDRS_SIZE * sizeof(size_t));
            if (src_addrs_size != dst_addrs_size) continue;
            printf("\nSignature hit [%d : %d] (offset: %d) ->\n%s\n\n", src_addrs_size, dst_addrs_size, src_offset, sig);
            int32_t ind_of_src_addrs = -1;
            for (size_t i = 0; i < src_addrs_size; i++)
            {
                if (src_addrs[i] == blks[rnd_insns_start].insn_addr) {
                    ind_of_src_addrs = i;
                    break;
                }
            }
            if (ind_of_src_addrs == -1) {
                //should never happen
                printf("Failed to find src_addr in scanned src_addrs...\n");
                continue;
            }
            size_t dst_addr = dst_addrs[ind_of_src_addrs] + src_offset;
            if (udx_insn_mnemonic(udx_dst, dst_addr) != src_addr_mnemonic) {
                printf("Instruction opcode changed!\n");
                continue;
            }
            possible_addr = NULL;
            HASH_FIND_INT(possible_addrs, &dst_addr, possible_addr);
            if (possible_addr) {
                possible_addr->count += 1;
            }
            else {
                if (possible_addr_buffer_length >= POSSIBLE_ADDR_BUFFER_SIZE) continue;
                possible_addr = possible_addr_buffer + (possible_addr_buffer_length++);
                possible_addr->count = 1;
                possible_addr->addr = dst_addr;
                HASH_ADD_INT(possible_addrs, addr, possible_addr);
            }
            if (possible_addr->count >= confidence) {
                most_possible_addr = possible_addr->addr;
                break;
            }
        }
        free(sig);
    } while (0); 
    udx_free_blks(blks);
    HASH_ITER(hh, possible_addrs, possible_addr, tmp) {
        printf("Possible addr: %08X, count: %d\n", possible_addr->addr, possible_addr->count);
        HASH_DEL(possible_addrs, possible_addr);
    }
    printf("Migrate completed for address: %08X, %d signatures checked!\n", src_addr, signatures_count);
    return most_possible_addr;
}

size_t ud_gen_sig(struct ud* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl)
{
    return udx_blk_gen_sig(&u->blk, sig_buffer, sig_buffer_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM, match_lvl);
}