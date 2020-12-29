#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "udis86ext.h"

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode) {
    udx->mode = mode;
    udx->load_base = load_base;
    udx->mem_buffer = mem_buffer;
    udx->mem_buffer_size = mem_buffer_size;
}

size_t udx_init_ud(udx_t* udx, ud_t* ud, size_t address) {
    if (address - udx->load_base > udx->mem_buffer_size) return 0;
    ud_init(ud);
    ud_set_mode(ud, udx->mode);
    ud_set_input_buffer(ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(ud, address - udx->load_base);
    ud_set_pc(ud, address);
    return 1;
}

void udx_free(void* ptr) {
    free(ptr);
}

int8_t udx_byte(udx_t* udx, size_t address) {
    return *(uint8_t*)(udx->mem_buffer + (address - udx->load_base));
}

int16_t udx_word(udx_t* udx, size_t address) {
    return *(uint16_t*)(udx->mem_buffer + (address - udx->load_base));
}

int32_t udx_dword(udx_t* udx, size_t address) {
    return *(uint32_t*)(udx->mem_buffer + (address - udx->load_base));
}

int64_t udx_qword(udx_t* udx, size_t address) {
    return *(uint64_t*)(udx->mem_buffer + (address - udx->load_base));
}

uint64_t udx_abs(int64_t src) {
    int64_t const mask = src >> ((sizeof(int) * 8) - 1);
    return (src ^ mask) - mask;
}

size_t udx_rnd(size_t a, size_t b) {
    if (a >= b) return b;
    return a + (rand() % (b - a + 1));
}

size_t ud_gen_sig(ud_t* u, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    return udx_gen_sig_blk(&u->blk, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
}

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size,
    size_t disp_threshold, size_t imm_threshold, size_t insn_size, size_t match_lvl) {
    ud_t ud;
    udx_init_ud(udx, &ud, target_addr);
    size_t insn_sig_size, sig_size = 0, insn_size_readed = 0;
    while (ud_disassemble(&ud)) {
        insn_sig_size = ud_gen_sig(&ud, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
        if (!insn_sig_size) return 0;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        sig_size += insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_gen_sig_blk(udx_blk_t* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
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

size_t udx_gen_sig_blks(udx_blk_t* blks, size_t blks_count, char* sig_buffer, size_t sig_buffer_size,
    size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{ 
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < blks_count; i++) {
        blk_sig_length = udx_gen_sig_blk(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;

}

size_t udx_gen_sig_blks_sample(udx_blk_t* blks, size_t blks_count, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t* target_addr) {
    size_t rnd_insns_size = udx_rnd(min(RND_SIG_INSNS_SIZE_MIN, blks_count), min(RND_SIG_INSNS_SIZE_MAX, blks_count));
    size_t rnd_insns_start = udx_rnd(0, blks_count - rnd_insns_size);
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < rnd_insns_size; i++) {
        blk_sig_length = udx_gen_sig_blk(blks + rnd_insns_start + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    *target_addr = blks[rnd_insns_start].insn_addr;
    return sig_length;
}

size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count, size_t skip_count) {
    if (offsets_buffer_size / sizeof(int32_t) < count) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, target_addr);

    size_t length = 0;
    while (length < count && ud_disassemble(&ud)) {
        if (skip_count > 0) {
            skip_count--;
            continue;
        }
        if (ud_insn_mnemonic(&ud) == UD_Icall) {
            if (ud.blk.have_imm) {
                offsets_buffer[length++] = (int32_t)ud.blk.imm;
            }
            else if (ud.blk.have_disp) {
                offsets_buffer[length++] = (int32_t)ud.blk.disp;
            }
        }
    }
    if (length != count) return 0;
    return length;
}


size_t udx_scan_sig(udx_t* udx, char* sig, udx_scan_result_t* result) {
    if (!result) return 0;
    result->addrs_count = 0;
    result->udx = udx;

    size_t* ret_buffer = result->addrs;
    size_t ret_buffer_length = sizeof(result->addrs) / sizeof(size_t);
    size_t sig_buffer_size = strlen(sig);

    uint16_t real_sig[256] = { 0 };
    uint8_t real_sig_size = 0;
    size_t i;
      
    for (i = 0; i < sig_buffer_size; i += 3) {
        while (sig[i] == ' ') i++;
        if (sig[i] == 0) break;
        if (sig[i] == '?') {
            real_sig[real_sig_size++] = SIG_WILDCARD;
        }
        else {
            sscanf_s(&sig[i], "%hx", &real_sig[real_sig_size++]);
        }
    }

    uint8_t* start_addr = udx->mem_buffer;
    uint8_t* end_addr = start_addr + udx->mem_buffer_size - real_sig_size;

    while (start_addr < end_addr && result->addrs_count < ret_buffer_length) {
        size_t cur_addr = (size_t)(start_addr - udx->mem_buffer + udx->load_base);
        for (i = 0; i < real_sig_size; i++) {
            if (real_sig[i] == SIG_WILDCARD) continue;
            if (start_addr[i] != (uint8_t)real_sig[i]) break;
        }
        if (i >= real_sig_size) {
            ret_buffer[result->addrs_count++] = cur_addr;
        }
        start_addr++;
    }

    return result->addrs_count;
}

size_t udx_gen_addr(size_t address, float similarity, udx_addr_t** paddr) {
    udx_addr_t* addr = (udx_addr_t*)malloc(sizeof(udx_addr_t));
    if (!addr) return 0;
    addr->address = address;
    addr->similarity = similarity;
    addr->hit = 1;
    *paddr = addr;
    return 1;
}
size_t udx_gen_hashed_addr(size_t address, float similarity, udx_hashed_addr_t** paddr) {
    udx_hashed_addr_t* addr = (udx_hashed_addr_t*)malloc(sizeof(udx_hashed_addr_t));
    if (!addr) return 0;
    addr->address = address;
    addr->similarity = similarity;
    addr->hit = 1;
    *paddr = addr;
    return 1;
}

size_t udx_migrate_scan_result(udx_scan_result_t* res_src, udx_scan_result_t* res_dst, size_t addr_src, udx_addr_t** paddrs) {
    size_t addr_src_index = ARYBIN;
    for (size_t i = 0; i < res_src->addrs_count; i++) {
        if (res_src->addrs[i] == addr_src) {
            addr_src_index = i;
            break;
        }
    }
    if (addr_src_index == ARYBIN) return 0;
    if (res_dst->addrs_count == 0) return 0;
    //if (res_dst->addrs_count == res_src->addrs_count) return udx_gen_addr(res_dst->addrs[addr_src_index], 100.0, paddrs);

    udx_t* udx_src = res_src->udx, * udx_dst = res_dst->udx;
    size_t src_addr = res_src->addrs[addr_src_index], dst_addr = 0;
    double distance_min = DBL_MAX, distance_tmp, distance_avg = 0, tmp, correct_rate;

    int32_t origin_offsets[RES_DISTANCE_DIMENSION], tmp_offsets[RES_DISTANCE_DIMENSION];
    if (!udx_gen_offsets(udx_src, src_addr - (AVERAGE_DISTANCE_BETWEEN_CALLS * RES_DISTANCE_DIMENSION / 2),
        origin_offsets, sizeof(origin_offsets), RES_DISTANCE_DIMENSION, EXTRA_INSN_RADIUS)) {
        return 0;
    }
    for (size_t i = 0; i < res_dst->addrs_count; i++) {
        if (!udx_gen_offsets(udx_dst, res_dst->addrs[i] - (AVERAGE_DISTANCE_BETWEEN_CALLS * RES_DISTANCE_DIMENSION / 2),
            tmp_offsets, sizeof(tmp_offsets), RES_DISTANCE_DIMENSION, EXTRA_INSN_RADIUS)) {
            continue;
        }
        distance_tmp = 0;
        for (size_t j = 0; j < sizeof(origin_offsets) / sizeof(int32_t); j++) {
            tmp = (double)(origin_offsets[j] - tmp_offsets[j]);
            distance_tmp += tmp * tmp;
        }
        if (distance_tmp < distance_min) {
            distance_min = distance_tmp;
            dst_addr = res_dst->addrs[i];
        }
        distance_avg += distance_tmp;
        ///printf("(%.4zd) %08zX->%.2lf\n", i, res_dst->addrs[i], distance_tmp);
    }
    distance_avg /= res_dst->addrs_count;
    correct_rate = (distance_avg - distance_min) * 100 / distance_avg;
    if (correct_rate < RES_PROB_MIN) return 0;
    return udx_gen_addr(dst_addr, (float)correct_rate, paddrs);
}


size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count, size_t skip_count) {
    if (insns_count < 1) return 0;
    *pblks = 0;
    size_t blks_count_generated = 0;
    udx_blk_t* blks = (udx_blk_t*)malloc(insns_count * sizeof(udx_blk_t));
    if (!blks) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, target_addr);
    while (ud_disassemble(&ud)) {
        if (skip_count > 0) {
            skip_count--;
            continue;
        }
        memcpy_s(blks + (blks_count_generated++), sizeof(udx_blk_t), &ud.blk, sizeof(udx_blk_t));
        if (blks_count_generated >= insns_count) break;
    }
    if (blks_count_generated != insns_count) {
        udx_free(blks);
        return 0;
    }

    *pblks = blks;
    return blks_count_generated;
}
size_t udx_gen_blks_radius(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count_radius) {
    if (insns_count_radius < 1) return 0;
    size_t target_addr_start = target_addr - AVERAGE_INSN_LENGTH * (insns_count_radius + EXTRA_INSN_RADIUS), addr_count;
    while ((addr_count = udx_insn_count(udx, target_addr_start, target_addr)) < insns_count_radius + EXTRA_INSN_RADIUS)
        target_addr_start -= AVERAGE_INSN_LENGTH * EXTRA_INSN_RADIUS;
    return udx_gen_blks(udx, target_addr_start, pblks, insns_count_radius * 2 + 1, addr_count - insns_count_radius);
}

//return number of insns in [start_addr, end_addr)
size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr) {
    if (start_addr >= end_addr) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, start_addr);
    size_t insns_size = 0;
    while (ud_disassemble(&ud)) {
        insns_size++;
        start_addr += ud_insn_len(&ud);
        if (start_addr >= end_addr) break;
    }
    return insns_size;
}

ud_mnemonic_code_t udx_insn_mnemonic(udx_t* udx, size_t addr) {
    ud_t ud;
    udx_init_ud(udx, &ud, addr);
    ud_mnemonic_code_t mnemonic = 0;
    if (ud_disassemble(&ud)) {
        mnemonic = ud_insn_mnemonic(&ud);
    }
    return mnemonic;
}

size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count) {
    udx_hashed_addr_t* hashed_addrs = NULL, * hashed_addr, * tmp;
    size_t sig_size, sig_length;
    udx_scan_result_t src_scan_result, dst_scan_result;
    size_t count = 0;
    ud_mnemonic_code_t mnemonic_src = udx_insn_mnemonic(udx_src, addr_src);
    udx_blk_t* blks;
    size_t blks_count = udx_gen_blks_radius(udx_src, addr_src, &blks, sample_radius);
    if (!blks_count) return 0;
    do {
        sig_size = (blks_count + EXTRA_INSN_RADIUS) * AVERAGE_INSN_LENGTH * 3;
        char* sig = (char*)malloc(sig_size);
        if (!sig) break;
        while (count++ < sample_count) {
            size_t addr_src_tmp;
            sig_length = udx_gen_sig_blks_sample(blks, blks_count, sig, sig_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM, &addr_src_tmp);
            if (!sig_length) {
                //printf("Failed to generate signature...(%d, %d, %d)\n", rnd_insns_start, rnd_insns_size, blks_length);
                continue;
            }
            int32_t src_offset = (int32_t)(addr_src - addr_src_tmp);

            udx_scan_sig(udx_dst, sig, &dst_scan_result); 
            if (dst_scan_result.addrs_count == 0 || dst_scan_result.addrs_count == sizeof(dst_scan_result.addrs) / sizeof(size_t)) continue;
            udx_scan_sig(udx_src, sig, &src_scan_result);
            udx_addr_t* addrs_per_round;
            size_t count_addrs_per_round = udx_migrate_scan_result(&src_scan_result, &dst_scan_result, addr_src_tmp, &addrs_per_round);
            if (!count_addrs_per_round) continue;

             
            for (size_t i = 0; i < count_addrs_per_round; i++)
            {
                size_t addr_dst = addrs_per_round[i].address + src_offset;
                if (udx_insn_mnemonic(udx_dst, addr_dst) != mnemonic_src) {
                    printf("Instruction opcode changed! %X->%X(%08zX) (%.2lf%%)\n", mnemonic_src,
                        udx_insn_mnemonic(udx_dst, addr_dst), addr_dst, addrs_per_round->similarity);
                    continue;
                }
                printf("\nSignature hit [%zd : %zd] (%08zX, offset:%X) -> %08zX(%.2lf%%)\n%s\n\n",
                    src_scan_result.addrs_count, dst_scan_result.addrs_count,addr_src_tmp + src_offset,
                    src_offset, addr_dst, addrs_per_round[i].similarity, sig);
                hashed_addr = NULL;
                HASH_FIND_INT(hashed_addrs, &addr_dst, hashed_addr);
                if (hashed_addr) { 
                    hashed_addr->similarity = (hashed_addr->similarity * hashed_addr->hit + addrs_per_round[i].similarity * addrs_per_round[i].hit)
                        / (hashed_addr->hit + addrs_per_round[i].hit);
                    hashed_addr->hit += addrs_per_round[i].hit;
                }
                else {
                    udx_gen_hashed_addr(addr_dst, addrs_per_round[i].similarity, &hashed_addr);
                    if (!hashed_addr) continue;
                    HASH_ADD_INT(hashed_addrs, address, hashed_addr);
                }
            }
            udx_free(addrs_per_round);
        }
        free(sig);
    } while (0);
    udx_free(blks);

    size_t count_addrs = HASH_CNT(hh, hashed_addrs), length_addrs = 0;
    *paddrs = (udx_addr_t*)malloc(count_addrs * sizeof(udx_addr_t));
    if (!*paddrs) return 0;
    float prob_base = 0;
    HASH_ITER(hh, hashed_addrs, hashed_addr, tmp) {
        HASH_DEL(hashed_addrs, hashed_addr);
        (*paddrs)[length_addrs].address = hashed_addr->address;
        (*paddrs)[length_addrs].hit = hashed_addr->hit;
        (*paddrs)[length_addrs].similarity = hashed_addr->similarity;
        length_addrs++;
        prob_base += hashed_addr->hit * hashed_addr->similarity;
        udx_free(hashed_addr);
    }
    for (size_t i = 0; i < length_addrs; i++) (*paddrs)[i].prob = (*paddrs)[i].hit * (*paddrs)[i].similarity * 100 / prob_base;
    return length_addrs;
}