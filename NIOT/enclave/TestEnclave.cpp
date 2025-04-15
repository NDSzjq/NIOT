/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <random>
#include <cstdint>
#include <inttypes.h>



#include "pthread.h"


#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>


using namespace std;

unsigned int seedU = 12345;
unsigned int seedZ = 123;
unsigned int seedV = 123456;
unsigned int seedE = 1357;
int lengthU = 40;
int lengthZ = 32;
int lengthV = 30;
int lengthH = 20;
int lengthE = 30;

void* status;


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

class SimpleLCG {
private:
    uint64_t state;
    static constexpr uint64_t a = 1664525;
    static constexpr uint64_t c = 1013904223;
    static constexpr uint64_t m = 4294967296; // 2^32

public:
    explicit SimpleLCG(uint64_t seed) : state(seed) {}

    uint64_t next32() {
        state = (a * state + c) % m;
        return state;
    }

    uint64_t next() {
        uint64_t upper = next32(); // 32 bits
        uint64_t lower = next32(); // 32 bits
        return (upper << 32) | lower; // Combine the two 32-bit values to form a 64-bit number
    }

    int64_t nextInRange(int64_t minVal, int64_t maxVal) {
        return minVal + (next() % (maxVal - minVal + 1));
    }
};


std::vector<int64_t> generateRandomNumbers(unsigned int seed, int bitLength, int count) {
    SimpleLCG rng(seed);
    int64_t minVal = -(1LL << (bitLength - 1));
    int64_t maxVal = (1LL << (bitLength - 1)) - 1;
    
    std::vector<int64_t> randomNumbers;
    for (int i = 0; i < count; ++i) {
        randomNumbers.push_back(rng.nextInRange(minVal, maxVal));
    }
    return randomNumbers;
}



void ecall_parameters(int64_t* threshold, int64_t* weights, int* trees_num_nodes){
    int idx = 0;
    
    for (size_t t = 0; trees_num_nodes[t]!=-1; ++t) {
        std::vector<int64_t> randomUS = generateRandomNumbers(seedU+t, lengthU, trees_num_nodes[t]);
        std::vector<int64_t> randomZS = generateRandomNumbers(seedZ+t, lengthZ, trees_num_nodes[t]);
        std::vector<int64_t> randomVS = generateRandomNumbers(seedV+t, lengthV, trees_num_nodes[t]);
        std::vector<int64_t> randomES = generateRandomNumbers(seedE+t, lengthE, trees_num_nodes[t]);

        for (size_t m = 0; m < trees_num_nodes[t]; ++m)
        {

            if(threshold[idx] != -13224)
            {
                threshold[idx] = randomUS[m] * threshold[idx] + randomVS[m] + randomZS[m];
            }
            else
            {
                weights[idx] = weights[idx] + randomES[m];
            }
            idx+=1;
        }


    }




    // unsigned int seed = 12345;
    // int bitLength = 3;
    // int count = 10; // Generate 10 random numbers
    // std::vector<int64_t> randomNumbers = generateRandomNumbers(seed, bitLength, count);
    
    // for (const auto &num : randomNumbers) {
    //     printf("Value: %" PRId64 "\n", num);
    // }
    
}