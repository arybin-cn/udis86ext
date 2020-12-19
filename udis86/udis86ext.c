#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "udis86.h" 

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode) {
    ud_init(&udx->ud);
    ud_set_mode(&udx->ud, mode);
    udx->load_base = load_base;
    udx->mem_buffer = mem_buffer;
    udx->mem_buffer_size = mem_buffer_size;
}

void udx_free(void* ptr) {
    free(ptr);
}

uint64_t udx_abs(int64_t src) {
    int64_t const mask = src >> ((sizeof(int) * 8) - 1);
    return (src ^ mask) - mask;
}

size_t udx_rnd(size_t a, size_t b) {
    if (a >= b) return b;
    return a + (rand() % (b - a + 1));
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

size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count, size_t skip_count) {
    if (offsets_buffer_size / sizeof(size_t) > count) return 0;
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    size_t length = 0;
    while (length < count && ud_disassemble(&udx->ud)) {
        if (skip_count > 0) {
            skip_count--;
            continue;
        }
        if (ud_insn_mnemonic(&udx->ud) == UD_Icall) {
            if (udx->ud.blk.have_imm) {
                offsets_buffer[length++] = (int32_t)udx->ud.blk.imm;
            }
            else if (udx->ud.blk.have_disp) {
                offsets_buffer[length++] = (int32_t)udx->ud.blk.disp;
            }
        }
    }
    if (length != count) return 0;
    return length;
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

size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, udx_scan_result_t* result, size_t mark_addr) {
    if (!result) return 0;
    result->addrs_count = 0;
    result->mark_index = ARYBIN;
    result->udx = udx;

    size_t* ret_buffer = result->addrs;
    size_t ret_buffer_length = sizeof(result->addrs) / sizeof(size_t);

    uint16_t real_sig[256] = { 0 };
    uint8_t real_sig_size = 0;
    size_t i;

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

    while (start_addr < end_addr && result->addrs_count < ret_buffer_length) {
        size_t cur_addr = (size_t)(start_addr - udx->mem_buffer + udx->load_base);

        if (mark_addr == cur_addr) {
            ret_buffer[result->addrs_count] = cur_addr;
            result->mark_index = result->addrs_count++;
            start_addr++;
            continue;
        }
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

size_t udx_migrate_scan_result(udx_scan_result_t* res_src, udx_scan_result_t* res_dst, udx_addr_t** paddrs) {
    if (res_src->mark_index >= res_src->addrs_count) return 0;
    if (res_dst->addrs_count == res_src->addrs_count) return udx_gen_addr(res_dst->addrs[res_src->mark_index], 100.0, paddrs);
    udx_t* udx_src = res_src->udx, * udx_dst = res_dst->udx;
    size_t src_addr = res_src->addrs[res_src->mark_index], dst_addr = 0;
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

size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t src_addr, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count) {
    udx_hashed_addr_t* hashed_addrs = NULL, * hashed_addr, * tmp;
    size_t sig_size, sig_length;
    udx_scan_result_t src_scan_result, dst_scan_result;

    size_t count = 0;
    ud_mnemonic_code_t mnemonic_src = udx_insn_mnemonic(udx_src, src_addr);

    udx_blk_t* blks;
    size_t blks_length = udx_gen_blks_radius(udx_src, src_addr, &blks, sample_radius);
    if (!blks_length) return 0;
    do {
        sig_size = (blks_length + EXTRA_INSN_RADIUS) * AVERAGE_INSN_LENGTH * 3;
        char* sig = (char*)malloc(sig_size);
        if (!sig) break;
        //printf("Migrate started for address: %08zX, sample_insns_radius: %zd, sig_buffer_size: %zd\n", src_addr, sample_radius, sig_size);
        while (count < sample_count) {
            count++;
            size_t rnd_insns_size = udx_rnd(5, max(15, blks_length));
            size_t rnd_insns_start = udx_rnd(0, blks_length - rnd_insns_size);
            int src_offset = (int)(src_addr - blks[rnd_insns_start].insn_addr);
            sig_length = udx_blks_gen_sig_rnd(blks + rnd_insns_start, rnd_insns_size * sizeof(udx_blk_t), sig, sig_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM);
            if (!sig_length) {
                //printf("Failed to generate signature...(%d, %d, %d)\n", rnd_insns_start, rnd_insns_size, blks_length);
                continue;
            }
            udx_scan_sig(udx_dst, sig, sig_length, &dst_scan_result, 0);
            if (dst_scan_result.addrs_count == 0 || dst_scan_result.addrs_count == sizeof(dst_scan_result.addrs) / sizeof(size_t)) continue;
            udx_scan_sig(udx_src, sig, sig_length, &src_scan_result, blks[rnd_insns_start].insn_addr);

            if (src_scan_result.mark_index == ARYBIN) {
                //should never happen
                //printf("Failed to find marked address in src results...\n");
                exit(1);
            }

            udx_addr_t* addrs_per_round;
            size_t count_addrs_per_round = udx_migrate_scan_result(&src_scan_result, &dst_scan_result, &addrs_per_round);
            if (!count_addrs_per_round) continue;

            for (size_t i = 0; i < count_addrs_per_round; i++)
            {
                size_t addr_dst = addrs_per_round[i].address + src_offset;
                if (udx_insn_mnemonic(udx_dst, addr_dst) != mnemonic_src) {
                    //printf("Instruction opcode changed! %X->%X(%08zX)\n", mnemonic_src, udx_insn_mnemonic(udx_dst, addr_dst), addr_dst);
                    continue;
                }
                printf("\nSignature hit [%zd : %zd] (%zd:%08zX, offset:%d) -> %08zX(%.2lf%%)\n%s\n\n",
                    src_scan_result.addrs_count, dst_scan_result.addrs_count,
                    src_scan_result.mark_index, dst_scan_result.addrs[src_scan_result.mark_index] + src_offset,
                    src_offset, addr_dst, addrs_per_round[i].similarity, sig);
                hashed_addr = NULL;
                HASH_FIND_INT(hashed_addrs, &addr_dst, hashed_addr);
                if (hashed_addr) {
                    /*if (hashed_addr->similarity < addrs_per_round[i].similarity) {*/
                        hashed_addr->similarity = (hashed_addr->similarity * hashed_addr->hit + addrs_per_round[i].similarity * addrs_per_round[i].hit)
                            / (hashed_addr->hit + addrs_per_round[i].hit);
                    /*}*/
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

size_t ud_gen_sig(struct ud* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl)
{
    return udx_blk_gen_sig(&u->blk, sig_buffer, sig_buffer_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM, match_lvl);
}