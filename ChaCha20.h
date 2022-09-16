/*
 * @Author: LinJiasheng
 * @Date: 2022-09-06 11:26:11
 * @LastEditors: LinJiasheng
 * @LastEditTime: 2022-09-16 10:18:03
 * @Description:
 *
 * Copyright (c) 2022 by LinJiasheng, All Rights Reserved.
 */
#include <iostream>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <cstdio>

using namespace std;

int round_index[8][4] = {
    {0, 4, 8, 12},
    {1, 5, 9, 13},
    {2, 6, 10, 14},
    {3, 7, 11, 15},
    {0, 5, 10, 15},
    {1, 6, 11, 12},
    {2, 7, 8, 13},
    {3, 4, 9, 14}};

uint32_t magic[] = {
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

class ChaCha20
{
public:
    typedef struct kn
    {
        const char *type;
        int size;
    } KN;
    void encrypt_decrypt(ifstream &text, ifstream &key, ofstream &output, uint32_t counter);
    void creat_key_nonce(ChaCha20::KN kn); // transform input to key;
    void cmd_server(int argc, char *argv[]);
    KN key = {"key", 32};
    KN nonce = {"nonce", 12};

private:
    vector<uint32_t> matrix;
    uint32_t key_nonce[11]; // key and nonce
    const char *key_file_name = "_temp_key_file.key";
    void QuarterRound(vector<uint32_t> &matrix, int x, int y, int z, int w)
    {
        uint32_t a = matrix[x], b = matrix[y], c = matrix[z], d = matrix[w];
        a = (a + b);
        d = d ^ a;
        d = (d << 16) | (d >> 16);
        c = (c + d);
        b = b ^ c;
        b = (b << 12) | (b >> 20);
        a = (a + b);
        d = d ^ a;
        d = (d << 8) | (d >> 24);
        c = (c + d);
        b = b ^ c;
        b = (b << 7) | (b >> 25);
        matrix[x] = a;
        matrix[y] = b;
        matrix[z] = c;
        matrix[w] = d;
    }

    void Round(vector<uint32_t> &matrix)
    {
        for (int i = 0; i < 8; i++)
        {
            QuarterRound(matrix, round_index[i][0], round_index[i][1], round_index[i][2], round_index[i][3]);
        }
    }
    // init the matrix
    void Matrix(ifstream &key_nonce_stream)
    {
        for (int i = 0; i < 4; i++)
        {
            this->matrix.insert(this->matrix.end(), magic[i]);
        }
        char buf[4];
        int ind = 0;
        while (ind < 11)
        {
            key_nonce_stream.read(buf, 4);
            this->key_nonce[ind++] = buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
        }
        for (int i = 0; i < 8; i++)
        {
            this->matrix.insert(this->matrix.end(), this->key_nonce[i]);
        }
        this->matrix.insert(this->matrix.end(), (uint32_t)0);
        for (int i = 8; i < 11; i++)
        {
            this->matrix.insert(this->matrix.end(), this->key_nonce[i]);
        }
    }
    // creat key stream
    void KeyStream(uint32_t counter, vector<uint32_t> &key)
    {
        this->matrix[12] = counter;
        vector<uint32_t> block(this->matrix);
        vector<uint32_t> &ptr = block;
        for (int i = 0; i < 10; i++)
        {
            Round(ptr);
        }
        for (int i = 0; i < block.size(); i++)
        {
            block[i] = block[i] + this->matrix[i];
        }
        int a = 0;
        // divide block into word in little-endian
        for (int i = 0; i < block.size(); i++)
        {
            key.push_back(block[i] & 0x000000ff);
            key.push_back((block[i] & 0x0000ff00) >> 8);
            key.push_back((block[i] & 0x00ff0000) >> 16);
            key.push_back((block[i] & 0xff000000) >> 24);
        }
    }
    // transform input to uint32
    uint32_t Transform(char h, char l)
    {
        uint32_t uh, ul;
        sscanf(&h, "%x", &uh);
        sscanf(&l, "%x", &ul);
        return (uh * 16 + ul);
    }
    inline bool file_exist(const string &name)
    {
        return (access(name.c_str(), F_OK) != -1);
    }
};

void ChaCha20::encrypt_decrypt(ifstream &text, ifstream &key, ofstream &output, uint32_t counter)
{
    vector<uint32_t> key_stream;
    vector<uint32_t> &ptr_key = key_stream;
    char buf[64] = {'\0'};

    // build chachMatrix(key);
    Matrix(key);

    // get file size
    text.seekg(0, ios::end);
    int size = text.tellg();
    text.seekg(0, ios::beg);

    // insert key and nonce

    for (uint32_t i = 0; i < (uint32_t)(size / 64); i++)
    {
        text.read(buf, 64);
        KeyStream(counter + i, ptr_key); // creat the key stream
        for (int j = 0; j < 64; j++)
        {
            uint32_t a = buf[j] ^ key_stream[j];
            output.write((char *)&a, 1);
        }
        key_stream.clear();
    }
    if (size % 64 != 0)
    {
        int i = size / 64;
        text.read(buf, size % 64);
        KeyStream(counter + i, ptr_key);
        for (int j = 0; j < size % 64; j++)
        {
            uint32_t a = buf[j] ^ key_stream[j];
            output.write((char *)&a, 1);
        }
    }
    return;
}

void ChaCha20::creat_key_nonce(ChaCha20::KN kn)
{
    const char *key_nonce = kn.type;
    int size = kn.size;
    string key;
    int l;
    int length = size * 3 - 1;
    uint32_t single_key;
    ofstream key_file;
    if (kn.type == "nonce")
    {
        key_file.open(this->key_file_name, ios::app | ios::binary | ios::out); // open temp file to sort key
    }
    else
    {
        key_file.open(this->key_file_name, ios::out | ios::binary); // open temp file to sort key
    }

    cout << "please input your " << size << "bit " << key_nonce << " spaced by \":\":" << endl;
    cin >> key;
    l = (int)key.length();
    while (l != length)
    {
        if (l < length)
        {
            cout << key_nonce << " too short!" << endl;
        }
        else if (l > length)
        {
            cout << key_nonce << " too long!" << endl;
        }
        cout << "please input your " << size << "bit " << key_nonce << " spaced by \":\"  :" << endl;
        cin >> key;
        l = (int)key.length();
    }
    for (int i = 0; i < size; i++)
    {
        single_key = Transform(key[3 * i], key[3 * i + 1]);
        key_file.write((char *)&single_key, 1);
    }
    key_file.close();
}

void ChaCha20::cmd_server(int argc, char *argv[])
{
    const char *optstring = "i:k:o:d";
    char opt;
    extern int optopt;
    extern char *optarg;
    ifstream input, key;
    ofstream output;
    bool has_key = false,del_temp = false;
    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
        switch (opt)
        {
            case 'i':
            {
                if (!file_exist(optarg))
                {
                    fprintf(stderr, "%s: file %s doesn't exist!\n", argv[0], optarg);
                    exit(EXIT_FAILURE);
                }
                input.open(optarg, ios::in | ios::binary);
                break;
            }
            case 'k':
            {
                has_key = true;
                if (!file_exist(optarg))
                {
                    fprintf(stderr, "%s: file %s doesn't exist!\n", argv[0], optarg);
                    exit(EXIT_FAILURE);
                }
                key.open(optarg, ios::in | ios::binary);
                break;
            }
            case 'o':
            {
                output.open(optarg, ios::out | ios::binary);
                break;
            }
            case 'd':
            {
                del_temp = true;
                break;
            }
            default:
            {
                exit(EXIT_FAILURE);
            }
        }
    }
    if (!has_key)
    {
        ChaCha20::creat_key_nonce(ChaCha20::key);
        ChaCha20::creat_key_nonce(ChaCha20::nonce);
        key.open(this->key_file_name, ios::in | ios::binary);
    }
    ChaCha20::encrypt_decrypt(input, key, output, 1);
    input.close();
    output.close();
    key.close();
    if(del_temp){
        if(file_exist(this->key_file_name)){
            if(remove(this->key_file_name)!=0){
                fprintf(stderr,"delete temp file failed\n");
            }
        }
    }
    printf("over, enjoy yourself :)\n");
}