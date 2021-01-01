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

//void udx_free(void* ptr) {
//    free(ptr);
//}

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

size_t udx_abs(intptr_t src) {
    intptr_t const mask = src >> ((sizeof(size_t) * 8) - 1);
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

size_t udx_gen_sig_blks(udx_blk_t* blks, size_t insn_cnt, char* sig_buffer, size_t sig_buffer_size,
    size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < insn_cnt; i++) {
        blk_sig_length = udx_gen_sig_blk(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;
}

size_t udx_gen_sig_blks_rnd(udx_blk_t* blks, size_t insn_cnt, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold) {
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < insn_cnt; i++) {
        blk_sig_length = udx_gen_sig_blk(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;
}


size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count) {
    if (offsets_buffer_size / sizeof(int32_t) < count) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, target_addr);

    size_t length = 0;
    while (length < count && ud_disassemble(&ud)) {
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

size_t udx_gen_offsets_radius(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t radius) {
    size_t offsets_count = radius * 2;
    if (radius < 1 || (offsets_buffer_size / sizeof(int32_t)) < offsets_count) return 0;
    size_t start_addr = udx_insn_reverse_of(udx, target_addr, radius, UD_Icall);
    return udx_gen_offsets(udx, start_addr, offsets_buffer, offsets_buffer_size, offsets_count);
}

size_t udx_scan_sig(udx_t* udx, char* sig, udx_scan_result_t* result) {
    if (!result) return 0;
    result->addrs_count = 0;
    result->udx = udx;

    size_t* ret_buffer = result->addrs;
    size_t ret_buffer_length = sizeof(result->addrs) / sizeof(size_t);
    intptr_t sig_buffer_size = strlen(sig);

    intptr_t i;
    uint16_t real_sig[256] = { 0 };
    uint8_t real_sig_size = 0;
    
    size_t prefix_wildcard_len = 0;
    BOOL prefix_wildcard = 1;
    for (i = 0; i < sig_buffer_size; i += 3) {
        while (sig[i] == ' ') i++;
        if (sig[i] == 0) break;
        if (sig[i] == '?') {
            if (prefix_wildcard) prefix_wildcard_len++; //eliminate prefix wildcards
            else real_sig[real_sig_size++] = SIG_WILDCARD;
        }
        else {
            prefix_wildcard = 0;
            sscanf_s(&sig[i], "%hx", &real_sig[real_sig_size++]);
        }
    }

    for (i = real_sig_size - 1; i > -1; i--) {
        if (real_sig[i] != SIG_WILDCARD) break;
        real_sig_size--; //eliminate suffix wildcards
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
            ret_buffer[result->addrs_count++] = cur_addr - prefix_wildcard_len;
        }
        start_addr++;
    }

    return result->addrs_count;
}

size_t udx_gen_addr(size_t address, float stability, udx_addr_t* addr) {
    addr->address = address;
    addr->stability = stability;
    addr->hit = 1;
    return 1;
}

size_t udx_gen_hashed_addr(size_t address, float stability, udx_hashed_addr_t* addr) {
    addr->address = address;
    addr->stability = stability;
    addr->hit = 1;
    return 1;
}

size_t udx_migrate_scan_result(udx_t* udx_src, size_t addr_src, size_t addr_src_origin, udx_scan_result_t* res_dst, udx_addr_t* addrs_buffer, size_t addrs_buffer_size) {
    if (addrs_buffer_size / sizeof(udx_addr_t) < 1) return 0;
    if (res_dst->addrs_count == 0) return 0;

    int32_t addr_src_offset = (int32_t)(addr_src_origin - addr_src);
    for (size_t i = 0; i < res_dst->addrs_count; i++) res_dst->addrs[i] += addr_src_offset;
    udx_t* udx_dst = res_dst->udx;

    ud_mnemonic_code_t mnemonic_origin = udx_insn_mnemonic(udx_src, addr_src_origin);
    if (res_dst->addrs_count == 1) {
        if (udx_insn_mnemonic(udx_dst, res_dst->addrs[0]) != mnemonic_origin) return 0;
        return udx_gen_addr(res_dst->addrs[0], 100.0f, addrs_buffer);
    }

    size_t addr_dst = 0;
    double distance_min = DBL_MAX, distance_tmp, distance_avg = 0, tmp, correct_rate;
    int32_t origin_offsets[OFFSETS_DIMENSION], tmp_offsets[OFFSETS_DIMENSION];

    if (!udx_gen_offsets_radius(udx_src, addr_src, origin_offsets, sizeof(origin_offsets), OFFSETS_DIMENSION / 2)) {
        return 0;
    }
    for (size_t i = 0; i < res_dst->addrs_count; i++) {
        if (udx_insn_mnemonic(udx_dst, res_dst->addrs[i]) != mnemonic_origin) {
            continue;
        }
        if (!udx_gen_offsets_radius(udx_dst, res_dst->addrs[i] - addr_src_offset, tmp_offsets, sizeof(tmp_offsets), OFFSETS_DIMENSION / 2)) {
            continue;
        }
        distance_tmp = 0;
        for (size_t j = 0; j < sizeof(origin_offsets) / sizeof(int32_t); j++) {
            tmp = (double)(origin_offsets[j] - tmp_offsets[j]);
            distance_tmp += tmp * tmp;
        }
        if (distance_tmp < distance_min) {
            distance_min = distance_tmp;
            addr_dst = res_dst->addrs[i];
        }
        distance_avg += distance_tmp;
        ///printf("(%.4zd) %08zX->%.2lf\n", i, res_dst->addrs[i], distance_tmp);
    }
    distance_avg /= res_dst->addrs_count;
    correct_rate = (distance_avg - distance_min) * 100 / distance_avg;
    if (correct_rate < RES_PROB_MIN) return 0;
    return udx_gen_addr(addr_dst, (float)correct_rate, addrs_buffer);
}

size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t* blks_buffer, size_t blks_buffer_size, size_t insn_cnt) {
    if (insn_cnt < 1 || (blks_buffer_size / sizeof(udx_blk_t)) < insn_cnt) return 0;
    size_t blks_count_generated = 0;
    ud_t ud;
    udx_init_ud(udx, &ud, target_addr);
    while (ud_disassemble(&ud)) {
        memcpy_s(blks_buffer + (blks_count_generated++), sizeof(udx_blk_t), &ud.blk, sizeof(udx_blk_t));
        if (blks_count_generated >= insn_cnt) break;
    }
    if (blks_count_generated != insn_cnt) return 0;
    return blks_count_generated;
}

size_t udx_gen_blks_radius(udx_t* udx, size_t target_addr, udx_blk_t* blks_buffer, size_t blks_buffer_size, size_t radius) {
    size_t insn_cnt = radius * 2 + 1;
    if (radius < 1 || (blks_buffer_size / sizeof(udx_blk_t)) < insn_cnt) return 0;
    size_t start_addr = udx_insn_reverse(udx, target_addr, radius);
    return udx_gen_blks(udx, start_addr, blks_buffer, blks_buffer_size, insn_cnt);
}

size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr, ud_mnemonic_code_t mnemonic) {
    if (start_addr >= end_addr) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, start_addr);
    size_t insns_size = 0;
    while (ud_disassemble(&ud)) {
        start_addr += ud_insn_len(&ud);
        if (start_addr > end_addr) break;
        if (mnemonic == UD_Iall || mnemonic == ud_insn_mnemonic(&ud)) insns_size++;
    }
    return insns_size;
}

size_t udx_insn_align(udx_t* udx, size_t target_addr) {
    size_t start_addr = target_addr - AVERAGE_INSN_LENGTH * PROBE_INSN_COUNT, insn_count;
    while ((insn_count = udx_insn_count(udx, start_addr, target_addr, UD_Iall)) <= PROBE_INSN_COUNT)
        start_addr -= AVERAGE_INSN_LENGTH * PROBE_INSN_COUNT;
    ud_t ud;
    udx_init_ud(udx, &ud, start_addr);
    while (ud_disassemble(&ud)) {
        if (insn_count > 0) {
            insn_count--;
            continue;
        }
        break;
    }
    return (size_t)ud_insn_off(&ud);
}

size_t udx_insn_reverse_of(udx_t* udx, size_t end_addr, size_t reversed_insn_count, ud_mnemonic_code_t mnemonic) {
    size_t start_addr = end_addr, insn_count, skip_count = ARYBIN;
    while (start_addr > udx->load_base) {
        start_addr = start_addr - AVERAGE_INSN_LENGTH * PROBE_INSN_COUNT;
        start_addr = udx_insn_align(udx, start_addr);
        insn_count = udx_insn_count(udx, start_addr, end_addr, mnemonic);
        if (insn_count >= reversed_insn_count) {
            skip_count = insn_count - reversed_insn_count;
            break;
        }
        end_addr = start_addr;
        reversed_insn_count -= insn_count;
    }
    if (skip_count == ARYBIN) return 0;
    ud_t ud;
    udx_init_ud(udx, &ud, start_addr);
    while (ud_disassemble(&ud)) {
        if (mnemonic == UD_Iall || mnemonic == ud_insn_mnemonic(&ud)) {
            if (skip_count > 0) {
                skip_count--;
                continue;
            }
            break;
        }
    }
    return (size_t)ud_insn_off(&ud);
}

size_t udx_insn_reverse(udx_t* udx, size_t end_addr, size_t reversed_insn_count) {
    return udx_insn_reverse_of(udx, end_addr, reversed_insn_count, UD_Iall);
}

size_t udx_insn_search(udx_t* udx, size_t target_addr, ud_mnemonic_code_t mnemonic, int32_t direction) {
    if (direction == 0) return udx_insn_align(udx, target_addr);
    if (direction < 0) return udx_insn_reverse_of(udx, target_addr, -direction, mnemonic);
    size_t start_addr = udx_insn_align(udx, target_addr);
    ud_t ud;
    udx_init_ud(udx, &ud, start_addr);
    ud_disassemble(&ud); //skip current
    while (direction > 0 && ud_disassemble(&ud)) {
        if (mnemonic == UD_Iall || mnemonic == ud_insn_mnemonic(&ud)) direction--;
    }
    return (size_t)ud_insn_off(&ud);
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

size_t udx_sample(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_sample_result_t* sample_res, size_t disp_threshold, size_t imm_threshold) {
    sample_res->samples_count = 0;
    size_t addr_src_aligned;
    int32_t addr_src_aligned_offset;
    udx_blk_t* cached_blks = sample_res->cached_blks;
    if (addr_src != sample_res->cached_addr_src) {
        addr_src_aligned = udx_insn_align(udx_src, addr_src);
        if (!addr_src_aligned) return 0;
        sample_res->cached_addr_src_aligned = addr_src_aligned;
        size_t addr_last_int3 = udx_insn_search(udx_src, addr_src_aligned, UD_Iint3, -1);
        if (!addr_last_int3) return 0;
        size_t insn_count_below_last_int3 = udx_insn_count(udx_src, addr_last_int3 + 1, addr_src_aligned, UD_Iall);
        size_t addr_blks_start = udx_insn_search(udx_src, addr_src_aligned, UD_Iall,
            -(int32_t)min(insn_count_below_last_int3, SAMPLE_SIG_INSN_CNT_MAX));
        size_t blks_count = udx_gen_blks(udx_src, addr_blks_start, cached_blks,
            sizeof(sample_res->cached_blks), 2 * SAMPLE_SIG_INSN_CNT_MAX + 1);
        if (!blks_count) return 0;
        sample_res->cached_addr_src = addr_src;
    }
    addr_src_aligned = sample_res->cached_addr_src_aligned;
    addr_src_aligned_offset = (int32_t)(addr_src - addr_src_aligned);
    size_t sig_insn_cnt = udx_rnd(SAMPLE_SIG_INSN_CNT_MIN, SAMPLE_SIG_INSN_CNT_MAX);
    size_t sig_insn_start = udx_rnd(0, 2 * SAMPLE_SIG_INSN_CNT_MAX + 1 - 1 - sig_insn_cnt);
    size_t sig_len = udx_gen_sig_blks_rnd(cached_blks + sig_insn_start, sig_insn_cnt,
        sample_res->sig, sizeof(sample_res->sig), disp_threshold, imm_threshold);
    if (!sig_len) return 0;
    sample_res->addr_sig = cached_blks[sig_insn_start].insn_addr;
    size_t res_cnt = udx_scan_sig(udx_dst, sample_res->sig, &sample_res->scan_result);
    if (res_cnt == 0 || res_cnt == (sizeof(sample_res->scan_result.addrs) / sizeof(size_t))) return 0;
    size_t sample_cnt = udx_migrate_scan_result(udx_src, sample_res->addr_sig, addr_src_aligned,
        &sample_res->scan_result, sample_res->samples, sizeof(sample_res->samples));
    sample_res->samples_count = sample_cnt;
    for (size_t i = 0; i < sample_cnt; i++)  sample_res->samples[i].address += addr_src_aligned_offset;
    return sample_cnt;
}

size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_migrate_result_t* mig_res,
    size_t disp_threshold, size_t imm_threshold, size_t sample_cnt) {
    mig_res->mig_count = 0;
    mig_res->hit = 0;
    mig_res->total = sample_cnt;
    if (sample_cnt < 1) return 0;
    size_t total_hit_cnt = 0;
    udx_hashed_addr_t* cached_addrs = NULL, * cached_addr, * not_used;
    udx_hashed_addr_t addr_buffer[MIGRATE_RES_SIZE]; size_t addr_cnt = 0, addr_cnt_tmp;
    udx_sample_result_t sample_res = { ARYBIN }; 
    for (size_t i = 0; i < sample_cnt; i++) {
        addr_cnt_tmp = udx_sample(udx_src, udx_dst, addr_src, &sample_res, disp_threshold, imm_threshold);
        if (!addr_cnt_tmp) continue;
        total_hit_cnt++;

        printf("\n(%zd) Sig of %s%X hit %zd results, stability: %.2lf%%, %08zX -> %08zX\n%s\n", total_hit_cnt,
            (int32_t)(sample_res.addr_sig - sample_res.cached_addr_src) >= 0 ? " 0x" : "-0x",
            (int32_t)udx_abs(sample_res.addr_sig - sample_res.cached_addr_src), 
            sample_res.scan_result.addrs_count,
            sample_res.samples[0].stability, addr_src, sample_res.samples[0].address,
            sample_res.sig);

        for (size_t j = 0; j < addr_cnt_tmp; j++) {
            udx_addr_t* addr_sample = sample_res.samples + j;
            cached_addr = NULL;
            HASH_FIND_INT(cached_addrs, &addr_sample->address, cached_addr);
            if (cached_addr) {
                cached_addr->stability = (cached_addr->stability * cached_addr->hit + addr_sample->stability) / (cached_addr->hit + 1);
                cached_addr->hit++;
            }
            else {
                if (addr_cnt >= MIGRATE_RES_SIZE) continue;
                cached_addr = addr_buffer + addr_cnt++;
                udx_gen_hashed_addr(addr_sample->address, addr_sample->stability, cached_addr);
                HASH_ADD_INT(cached_addrs, address, cached_addr);
            }
        }
    }
    mig_res->hit = total_hit_cnt; 
    mig_res->mig_count = addr_cnt;
    addr_cnt = 0;
    cached_addr = NULL;
    float total_probability = 0;
    HASH_ITER(hh, cached_addrs, cached_addr, not_used) {
        HASH_DEL(cached_addrs, cached_addr);
        udx_addr_t* mig_addr = mig_res->migs + addr_cnt++;
        mig_addr->address = cached_addr->address;
        mig_addr->hit = cached_addr->hit;
        mig_addr->stability = cached_addr->stability;
        mig_addr->similarity = 100.0f * cached_addr->hit / sample_cnt;
        mig_addr->probability = mig_addr->stability * mig_addr->hit * mig_addr->hit;
        total_probability += mig_addr->probability;
    }
    if (addr_cnt == 1)  mig_res->migs[0].probability = mig_res->migs[0].stability * mig_res->migs[0].similarity / 100;
    else for (size_t i = 0; i < addr_cnt; i++) 
        mig_res->migs[i].probability = mig_res->migs[i].similarity * mig_res->migs[i].probability / total_probability;
    return addr_cnt;
}

//size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count) {
//    udx_hashed_addr_t* hashed_addrs = NULL, * hashed_addr, * tmp;
//    size_t sig_size, sig_length;
//    udx_scan_result_t dst_scan_result;
//    size_t count = 0;
//    ud_mnemonic_code_t mnemonic_src = udx_insn_mnemonic(udx_src, addr_src);
//    udx_blk_t* blks;
//    size_t blks_count = udx_gen_blks_radius(udx_src, addr_src, &blks, sample_radius);
//    if (!blks_count) return 0;
//    do {
//        sig_size = (blks_count + EXTRA_INSN_RADIUS) * AVERAGE_INSN_LENGTH * 3;
//        char* sig = (char*)malloc(sig_size);
//        if (!sig) break;
//        while (count++ < sample_count) {
//            size_t addr_src_tmp;
//            sig_length = udx_gen_sig_blks_sample(blks, blks_count, sig, sig_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM, &addr_src_tmp);
//            if (!sig_length) {
//                //printf("Failed to generate signature...(%d, %d, %d)\n", rnd_insns_start, rnd_insns_size, blks_length);
//                continue;
//            }
//            int32_t src_offset = (int32_t)(addr_src - addr_src_tmp);
//
//            udx_scan_sig(udx_dst, sig, &dst_scan_result); 
//            if (dst_scan_result.addrs_count == 0 || dst_scan_result.addrs_count == sizeof(dst_scan_result.addrs) / sizeof(size_t)) continue;
//             
//            udx_addr_t* addrs_per_round;
//            size_t count_addrs_per_round = udx_migrate_scan_result(udx_src, addr_src_tmp, &dst_scan_result, &addrs_per_round);
//            if (!count_addrs_per_round) continue;
//
//             
//            for (size_t i = 0; i < count_addrs_per_round; i++)
//            {
//                size_t addr_dst = addrs_per_round[i].address + src_offset;
//                if (udx_insn_mnemonic(udx_dst, addr_dst) != mnemonic_src) {
//                    printf("Instruction opcode changed! %X->%X(%08zX) (%.2lf%%)\n", mnemonic_src,
//                        udx_insn_mnemonic(udx_dst, addr_dst), addr_dst, addrs_per_round->stability);
//                    continue;
//                }
//                printf("\nSignature hit [? : %zd] (%08zX, offset:%X) -> %08zX(%.2lf%%)\n%s\n\n",
//                    dst_scan_result.addrs_count, addr_src_tmp + src_offset,
//                    src_offset, addr_dst, addrs_per_round[i].stability, sig);
//                hashed_addr = NULL;
//                HASH_FIND_INT(hashed_addrs, &addr_dst, hashed_addr);
//                if (hashed_addr) { 
//                    hashed_addr->stability = (hashed_addr->stability * hashed_addr->hit + addrs_per_round[i].stability * addrs_per_round[i].hit)
//                        / (hashed_addr->hit + addrs_per_round[i].hit);
//                    hashed_addr->hit += addrs_per_round[i].hit;
//                }
//                else {
//                    udx_gen_hashed_addr(addr_dst, addrs_per_round[i].stability, &hashed_addr);
//                    if (!hashed_addr) continue;
//                    HASH_ADD_INT(hashed_addrs, address, hashed_addr);
//                }
//            }
//            udx_free(addrs_per_round);
//        }
//        free(sig);
//    } while (0);
//    udx_free(blks);
//
//    size_t count_addrs = HASH_CNT(hh, hashed_addrs), length_addrs = 0;
//    *paddrs = (udx_addr_t*)malloc(count_addrs * sizeof(udx_addr_t));
//    if (!*paddrs) return 0;
//    float prob_base = 0;
//    HASH_ITER(hh, hashed_addrs, hashed_addr, tmp) {
//        HASH_DEL(hashed_addrs, hashed_addr);
//        (*paddrs)[length_addrs].address = hashed_addr->address;
//        (*paddrs)[length_addrs].hit = hashed_addr->hit;
//        (*paddrs)[length_addrs].stability = hashed_addr->stability;
//        length_addrs++;
//        prob_base += hashed_addr->hit * hashed_addr->stability;
//        udx_free(hashed_addr);
//    }
//    for (size_t i = 0; i < length_addrs; i++) (*paddrs)[i].prob = (*paddrs)[i].hit * (*paddrs)[i].stability * 100 / prob_base;
//    return length_addrs;
//}