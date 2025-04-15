/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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


#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX
#define PLAIN_BITS 10

#include "sgx_urts.h"
#include "TestApp.h"
#include "TestEnclave_u.h"

#include <vector>
#include <iostream>
#include <fstream>
#include <mutex>
#include <sstream>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <chrono>

#include <sys/time.h>
#include <random>
#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <unistd.h>
#include <thread>
#include <omp.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "she.hpp"
#include "paillier.h"

using namespace std;



int keyLength = 1024;
unsigned int seedU = 12345;
unsigned int seedZ = 123;
unsigned int seedV = 123456;
unsigned int seedE = 1357;
unsigned int seedA = 2456;
unsigned int seedB = 13789;
int lengthU = 40;
int lengthZ = 32;
int lengthV = 30;
int lengthH = 20;
int lengthE = 30;
int lengthA = 25;
int lengthB = 40;
int weight_scale = 1000;
int data_scale = 1000;





struct DecisionTreeInfo {
    int num_nodes;
    float base_score;
    vector<int> internal_nodes;
    vector<int> split_features;
    vector<float>split_conditions;
    vector<int> leaf_nodes;
    vector<int> left_children;
    vector<int> right_children;
    vector<float> weights;
};



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(TESTENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}



/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    // fflush(stdout);
}

std::mutex bn_mutex;

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

void encryptBatch(Paillier &paillier, BIGNUM *value, std::vector<BIGNUM*> &ciphertexts, int start, int end) {
    for (int i = start; i < end; i++) {
        BIGNUM *cipher = BN_new();
        {
            std::lock_guard<std::mutex> lock(bn_mutex);
            paillier.encrypt(cipher, value);
        }
        ciphertexts[i] = cipher;
    }
}

void generateEncryptedValues(Paillier &paillier, int N, std::vector<BIGNUM*> &zeroCiphertexts, std::vector<BIGNUM*> &oneCiphertexts) {
    BIGNUM *zero = BN_new();
    BIGNUM *one = BN_new();
    BN_set_word(zero, 0);
    BN_set_word(one, 1);
    
    zeroCiphertexts.resize(N, nullptr);
    oneCiphertexts.resize(N, nullptr);
    
    int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;
    std::vector<std::thread> threads;
    int batchSize = N / numThreads;
    
    for (int i = 0; i < numThreads; i++) {
        int start = i * batchSize;
        int end = (i == numThreads - 1) ? N : start + batchSize;
        threads.emplace_back(encryptBatch, std::ref(paillier), zero, std::ref(zeroCiphertexts), start, end);
        threads.emplace_back(encryptBatch, std::ref(paillier), one, std::ref(oneCiphertexts), start, end);
    }
    
    for (auto &t : threads) {
        t.join();
    }
    
    BN_free(zero);
    BN_free(one);
}

std::vector<std::string> readCSVHeader(std::ifstream &file) {
    std::vector<std::string> header;
    std::string line;
    if (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, ',')) {
            header.push_back(cell);
        }
    }
    return header;
}

std::vector<std::vector<double>> readCSV(const std::string &filename, std::vector<std::string> &header) {
    std::vector<std::vector<double>> data;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return data;
    }

    header = readCSVHeader(file);
    std::string line;
    while (std::getline(file, line)) {
        std::vector<double> row;
        std::stringstream ss(line);
        std::string cell;
        
        while (std::getline(ss, cell, ',')) {
            try {
                row.push_back(std::stod(cell));
            } catch (const std::invalid_argument &e) {
                std::cerr << "Warning: Invalid number in CSV file: " << cell << std::endl;
                row.push_back(0.0); // Default to 0.0 if conversion fails
            }
        }
        data.push_back(row);
    }

    file.close();
    return data;
}


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


using json = nlohmann::json;

vector<DecisionTreeInfo> parseDecisionTrees(const string& filename) {
    ifstream file(filename);
    json j;
    file >> j;
    
    vector<DecisionTreeInfo> treesInfo;
    const auto& model = j["learner"];
    const auto& trees = model["gradient_booster"]["model"]["trees"];
    string base_score_str = model["learner_model_param"].value("base_score", "0.0");
    float base_score = stof(base_score_str);

    for (const auto& tree : trees) {
        DecisionTreeInfo treeInfo;
        treeInfo.base_score = base_score;
        const auto& left_children = tree["left_children"];
        const auto& right_children = tree["right_children"];
        const auto& split_indices = tree["split_indices"];
        const auto& split_conditions = tree["split_conditions"];



        const auto& base_weights = tree["base_weights"];
        
        treeInfo.num_nodes = left_children.size();
        
        for (size_t i = 0; i < left_children.size(); ++i) {
            if (left_children[i] == -1 && right_children[i] == -1) {
                treeInfo.leaf_nodes.push_back(i);
                treeInfo.split_features.push_back(0);
                treeInfo.split_conditions.push_back(0);
            } else {
                treeInfo.internal_nodes.push_back(i);
                treeInfo.split_features.push_back(split_indices[i]);
                treeInfo.split_conditions.push_back(split_conditions[i]);
            }
            treeInfo.left_children.push_back(left_children[i]);
            treeInfo.right_children.push_back(right_children[i]);
            treeInfo.weights.push_back(base_weights[i]);
        }
        
        
        treesInfo.push_back(treeInfo);
    }
    return treesInfo;
}



bool inVector(int value, const std::vector<int>& vec) {
    return std::find(vec.begin(), vec.end(), value) != vec.end();
}


int64_t BIGNUM_to_int64(BIGNUM *BN_plain) {
    BIGNUM *mod_val = BN_new();
    BIGNUM *two_64 = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // two_64 = 2^64
    BN_lshift(two_64, BN_value_one(), 64);

    // mod_val = BN_plain % 2^64
    BN_mod(mod_val, BN_plain, two_64, ctx);

    // 转换为 uint64_t
    uint64_t plain = BN_get_word(mod_val);


    // 释放 BIGNUM 资源
    BN_free(mod_val);
    BN_free(two_64);
    BN_CTX_free(ctx);

    // 如果 plain >= 2^63，计算 plain = 2^64 - plain，并转换为负数
    if (plain >= (1ULL << 63)) {
        return static_cast<int64_t>(plain - (1ULL << 64));
    }


    
    return static_cast<int64_t>(plain);
}




void evaluatePaths(int node, vector<BIGNUM*>& pathCtree, Paillier &paillier,  BIGNUM*& current_pathY, const vector<int>& left_children, const vector<int>& right_children, vector<BIGNUM*>& pathYtree) {
    // current_path.push_back(node);
    BIGNUM* BN_value = BN_new();



    paillier.homomorphic_add(BN_value, current_pathY, pathCtree[node]);
    BN_copy(pathYtree[node], BN_value);
    
    // pathYtree.push_back(BN_value);

    // BIGNUM* tt = BN_new();
    //     paillier.decrypt(tt, BN_value);
    //     std::cout << node << ": " << BIGNUM_to_int64(tt) << std::endl;


    if (left_children[node] == -1 && right_children[node] == -1) {
        ;
    } else {
        if (left_children[node] != -1) {
            evaluatePaths(left_children[node], pathCtree, paillier, BN_value, left_children, right_children, pathYtree);
        }
        if (right_children[node] != -1) {
            evaluatePaths(right_children[node], pathCtree, paillier, BN_value, left_children, right_children, pathYtree);
        }
    }
    // pathYtree.pop_back();
}

double sigmoid(double x) {
    return 1.0 / (1.0 + std::exp(-x));
}

vector<int> generate_random_vector(int N) {
    std::vector<int> vec(N);
    for (int i = 0; i < N; ++i) {
        vec[i] = i;
    }
    
    std::random_device rd;
    std::mt19937 g(rd());
    
    std::shuffle(vec.begin(), vec.end(), g);
    
    return vec;
}


double computeMSE(const vector<double>& y_pred, const vector<vector<double>>& y_test) {

    
    double sum = 0.0;
    for (size_t i = 0; i < y_pred.size(); ++i) {
        double diff = y_pred[i] - y_test[i][0];
        sum += diff * diff;
    }
    
    return sum / y_pred.size();
}


/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

// precalculation
    Paillier paillier(1024);
    int ciphersNum = 1000;
    vector<BIGNUM*> zeroCiphertexts, oneCiphertexts;
    generateEncryptedValues(paillier, ciphersNum, zeroCiphertexts, oneCiphertexts);
    std::string filename = "app/arti_x.csv";
    std::vector<std::string> header;
    std::vector<std::vector<double>> query_data = readCSV(filename, header);
    filename = "app/arti_y.csv";
    std::vector<std::vector<double>> labels = readCSV(filename, header);
    int query_num = labels.size();
    int true_predcitions = 0;

    string treefile = "app/features60.json";
    vector<DecisionTreeInfo> treesInfo = parseDecisionTrees(treefile);
    vector<double> y_pred;

    int total_num_nodes = 0;
    int* trees_num_nodes = new int(treesInfo.size()+1);
    for (size_t t = 0; t < treesInfo.size(); ++t) {
        total_num_nodes += treesInfo[t].num_nodes;
        trees_num_nodes[t] =  treesInfo[t].num_nodes;
    }
    trees_num_nodes[treesInfo.size()] =  -1;

    /* Initialize the enclave */
        if (initialize_enclave() < 0){
            return 1; 
        }

    // 记录起始时间
        std::chrono::duration<double, std::milli> CSP3inside(0.0);
        std::chrono::duration<double, std::milli> CSP3outside(0.0);
        std::chrono::duration<double, std::milli> CSP4(0.0);
        std::chrono::duration<double, std::milli> U4(0.0);


    auto start1 = std::chrono::high_resolution_clock::now();



    for (size_t sidx = 0; sidx < query_num; ++sidx) {


        vector<vector<int64_t>> perturbedX;
        vector<vector<BIGNUM*>> perturbedC;
        int64_t* in_threshold = new int64_t[total_num_nodes];
        int64_t* in_weights = new int64_t[total_num_nodes];

        auto start = std::chrono::high_resolution_clock::now();

        int idx = 0;
        for (size_t t = 0; t < treesInfo.size(); ++t) {
            std::vector<int64_t> randomUS = generateRandomNumbers(seedU+t, lengthU, treesInfo[t].num_nodes);
            std::vector<int64_t> randomZS = generateRandomNumbers(seedZ+t, lengthZ, treesInfo[t].num_nodes);
            vector<int64_t> perturbedXtree;
            vector<BIGNUM*> perturbedCtree;
            for (size_t m = 0; m < treesInfo[t].num_nodes; ++m)
            {
                if(inVector(m, treesInfo[t].internal_nodes))
                {
                    in_threshold[idx] = int(treesInfo[t].split_conditions[m]*data_scale-1);
                    in_weights[idx] = -13224;
                    uint64_t px = randomUS[m]*(query_data[sidx][treesInfo[t].split_features[m]]*data_scale) + randomZS[m];
                    perturbedXtree.push_back(px);
                    BIGNUM *pc = BN_new();

                        if(randomUS[m]>0) {
                            BN_copy(pc, zeroCiphertexts[abs(randomUS[m]) % ciphersNum]);
                            perturbedCtree.push_back(pc);
                        }
                        else {
                            BN_copy(pc, oneCiphertexts[abs(randomUS[m]) % ciphersNum]);

                            perturbedCtree.push_back(pc);
                        }
                    
                }
                else{   
                    perturbedXtree.push_back(0);
                    perturbedCtree.push_back(0);
                    if(t == 0)
                    {
                    in_weights[idx] = int((treesInfo[t].weights[m]+treesInfo[t].base_score)*weight_scale);
                    }
                    else
                    {
                    in_weights[idx] = int((treesInfo[t].weights[m])*weight_scale);
                    }


                    in_threshold[idx] = -13224;
                }
                idx += 1;
            }
            perturbedX.push_back(perturbedXtree);
            perturbedC.push_back(perturbedCtree);
        }

        auto end = std::chrono::high_resolution_clock::now();

        CSP3outside += end - start;

        start = std::chrono::high_resolution_clock::now();
        
        ecall_parameters(global_eid, in_threshold, in_weights, trees_num_nodes);

        end = std::chrono::high_resolution_clock::now();

        CSP3inside += end - start;

        start = std::chrono::high_resolution_clock::now();
        

    

        vector<vector<BIGNUM*>> pathC;

        BIGNUM* BN_one = BN_new();
        BN_copy(BN_one, BN_value_one());  // 复制 BN_value_one() 的值



        idx = 0;
        for (size_t t = 0; t < treesInfo.size(); ++t) {
            vector<BIGNUM*> pathCtree;
            pathCtree.push_back(BN_one);
            for (size_t m = 0; m < treesInfo[t].num_nodes; ++m)
            {
                
                std::vector<int64_t> randomBS = generateRandomNumbers(seedB+t, lengthB, treesInfo[t].num_nodes*2);
                if(inVector(m, treesInfo[t].internal_nodes))
                {
                    BIGNUM* flipC = BN_new();
                    BIGNUM* tmp = BN_new();
                    BN_set_word(tmp, -randomBS[m*2]);
                    paillier.homomorphic_mult(flipC, perturbedC[t][m], tmp);
                    BN_set_word(tmp, randomBS[m*2]);
                    paillier.simple_encrypt(tmp, tmp);
                    paillier.homomorphic_add(flipC, flipC, tmp);
                    BN_set_word(tmp, randomBS[m*2+1]);
                    paillier.homomorphic_mult(perturbedC[t][m], perturbedC[t][m], tmp);
                    if(in_threshold[idx] < perturbedX[t][m])
                    {
                        pathCtree.push_back(flipC);
                        pathCtree.push_back(perturbedC[t][m]);
                        

                    }
                    else{
                        pathCtree.push_back(perturbedC[t][m]);
                        pathCtree.push_back(flipC);
                        
                    }

                }

                idx += 1;
            }
            pathC.push_back(pathCtree);
        }

        end = std::chrono::high_resolution_clock::now();
        CSP3outside += end - start;
        start = std::chrono::high_resolution_clock::now();




        


        vector<vector<BIGNUM*>> pathY;


        std::vector<int64_t> randomAS = generateRandomNumbers(seedA, lengthA, treesInfo.size());
        randomAS[0] = randomAS[0] - std::accumulate(randomAS.begin(), randomAS.end(), int64_t(0));

        for (size_t t = 0; t < treesInfo.size(); ++t) {
            vector<BIGNUM*> pathYtree;
            for (size_t m = 0; m < treesInfo[t].num_nodes; ++m){
                pathYtree.push_back(BN_new());
            }
            BIGNUM* current_pathY = BN_new();
            BN_set_word(current_pathY, randomAS[t]);
            paillier.simple_encrypt(current_pathY,current_pathY);
            evaluatePaths(0, pathC[t], paillier, current_pathY, treesInfo[t].left_children, treesInfo[t].right_children, pathYtree);
            pathY.push_back(pathYtree);
        }

        



         idx = 0;
         BIGNUM* cipherWeight = BN_new();
        for (size_t t = 0; t < treesInfo.size(); ++t) {
            for (size_t m = 0; m < treesInfo[t].num_nodes; ++m)
            {
                if(inVector(m, treesInfo[t].internal_nodes) == 0)
                {
                    
                    BN_set_word(cipherWeight, in_weights[idx]);
                    paillier.simple_encrypt(cipherWeight,cipherWeight);
                    paillier.homomorphic_add(pathY[t][m], pathY[t][m], cipherWeight);
                }

                idx += 1;

            }
        }

        end = std::chrono::high_resolution_clock::now();

        CSP4 += end - start;

        start = std::chrono::high_resolution_clock::now();


        vector<int64_t> treeY;



        int64_t maxRA = (1ULL << lengthA+1) - 1;  // 2^32 - 1
        for (size_t t = 0; t < treesInfo.size(); ++t) {
            std::vector<int64_t> randomES = generateRandomNumbers(seedE+t, lengthE, trees_num_nodes[t]);
            vector<int> ridx = generate_random_vector(treesInfo[t].num_nodes);
            for (size_t m = 0; m < treesInfo[t].num_nodes; ++m)
            {
                if(inVector(ridx[m], treesInfo[t].internal_nodes) == 0)
                {
                    int64_t yValue;
                    paillier.decrypt(pathY[t][ridx[m]], pathY[t][ridx[m]]);
                    yValue = BIGNUM_to_int64(pathY[t][ridx[m]]);
                    yValue -= randomES[ridx[m]];
                    if(abs(yValue) < maxRA)
                    {
                        treeY.push_back(yValue);
                        break;

                    }  

                        
                }
            }
        }

        



        double y = std::accumulate(treeY.begin(), treeY.end(), int64_t(0));
        y = y / weight_scale;
        y_pred.push_back(y);

        end = std::chrono::high_resolution_clock::now();

        U4 += end - start;

        // std::cout << y << std::endl;

        y = sigmoid(y);

        if(y>=0.5 && int(labels[sidx][0]) == 1)
            true_predcitions += 1;
        if(y<0.5 && int(labels[sidx][0]) == 0)
            true_predcitions += 1;
    }
    auto end1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end1 - start1;

    std::cout << "总运行时间: " << duration.count() / query_num << std::endl;


    // cout << computeMSE(y_pred, labels) << endl;

    // cout << true_predcitions << endl;
    cout << query_num << endl;
    cout << "阶段3CSP外部运行时间: " <<  CSP3outside.count() / query_num<< endl;
    cout << "阶段3Enclave内部运行时间: " << CSP3inside.count() / query_num<< endl;
    cout << "阶段4CSP运行时间: " << CSP4.count() / query_num<< endl;
    cout << "阶段4U运行时间: " << U4.count() / query_num<< endl;




    cout << double(true_predcitions)/query_num << endl;
    // 记录结束时间
    // auto end = std::chrono::high_resolution_clock::now();

    // // 计算运行时间（单位：毫秒）
    // std::chrono::duration<double, std::milli> duration = end - start;

    // std::cout << "程序运行时间: " << duration.count() << " 毫秒" << std::endl;

    for (BIGNUM* c : zeroCiphertexts) BN_free(c);
    for (BIGNUM* c : oneCiphertexts) BN_free(c);


    return 0;
}
