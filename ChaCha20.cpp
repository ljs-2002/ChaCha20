/*
 * @Author: LinJiasheng
 * @Date: 2022-09-06 11:26:11
 * @LastEditors: LinJiasheng
 * @LastEditTime: 2022-09-07 21:54:52
 * @Description: 
 * 
 * Copyright (c) 2022 by LinJiasheng, All Rights Reserved. 
 */
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>

using namespace std;

int round_index[8][4]={
    {0,4,8,12},
    {1,5,9,13},
    {2,6,10,14},
    {3,7,11,15},
    {0,5,10,15},
    {1,6,11,12},
    {2,7,8,13},
    {3,4,9,14}
};

uint32_t magic[]={
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
};

class ChaCha20
{
public:
    void encrypt(ifstream& text,ifstream& key,ofstream& output,uint32_t counter);
    void decrypt(ifstream& text,ofstream& output,uint32_t counter=1);
    
private:
    vector<uint32_t> matrix;
    uint32_t key_nonce[11];//key and nonce

    void QuarterRound(vector<uint32_t>& matrix,int x,int y,int z,int w)
    {
        uint32_t a=matrix[x],b=matrix[y],c=matrix[z],d=matrix[w];
        a = (a + b) ;
        d = d ^ a;
        d = (d << 16) | (d >> 16) ;
        c = (c + d) ;
        b = b ^ c;
        b = (b << 12) | (b >> 20) ;
        a = (a + b) ;
        d = d ^ a;
        d = (d << 8) | (d >> 24) ;
        c = (c + d) ;
        b = b ^ c;
        b = (b << 7) | (b >> 25) ;
        matrix[x]=a;
        matrix[y]=b;
        matrix[z]=c;
        matrix[w]=d;
    }

    void Round(vector<uint32_t>& matrix)
    {
        for(int i=0;i<8;i++){
            QuarterRound(matrix,round_index[i][0],round_index[i][1],round_index[i][2],round_index[i][3]);
        }
    }
    //init the matrix
    void Matrix(ifstream& key_nonce_stream)
    {
        for(int i=0;i<4;i++){
            this->matrix.insert(this->matrix.end(),magic[i]);
        }
        char buf[4];
        int ind=0;
        while(ind<11){
            key_nonce_stream.read(buf,4);
            this->key_nonce[ind++]=buf[0]|buf[1]<<8|buf[2]<<16|buf[3]<<24;
        }
        for(int i=0;i<8;i++){
            this->matrix.insert(this->matrix.end(),this->key_nonce[i]);
        }
        this->matrix.insert(this->matrix.end(),(uint32_t)0);
        for(int i=8;i<11;i++){
            this->matrix.insert(this->matrix.end(),this->key_nonce[i]);
        }
    }
    //creat key stream
    void KeyStream(uint32_t counter, vector<uint32_t>& key){
        this->matrix[12]=counter;
        vector<uint32_t> block(this->matrix);
        vector<uint32_t>& ptr=block;
        for(int i=0;i<10;i++){
            Round(ptr);
        }
        for(int i=0;i<block.size();i++){
            block[i]=block[i] + this->matrix[i];
        }
        int a=0;
        //divide block into word in little-endian
        for(int i=0;i<block.size();i++){
            key.push_back(block[i]&0x000000ff);
            key.push_back((block[i]&0x0000ff00)>>8);
            key.push_back((block[i]&0x00ff0000)>>16);
            key.push_back((block[i]&0xff000000)>>24);
        }
    }
};

void ChaCha20::encrypt(ifstream& text,ifstream& key,ofstream& output,uint32_t counter){
    vector<uint32_t> key_stream;
    vector<uint32_t>& ptr_key=key_stream;
    char buf[64]={'\0'};
    //get file size
    text.seekg(0,ios::end);
    int size = text.tellg();
    text.seekg(0,ios::beg);
    //build chacha20 matrix
    Matrix(key);
    //insert key and nonce
    for(int i=0;i<11;i++){
        uint32_t a,b,c,d;
        a=this->key_nonce[i]&0x000000ff;
        b=(this->key_nonce[i]&0x0000ff00)>>8;
        c=(this->key_nonce[i]&0x00ff0000)>>16;
        d=(this->key_nonce[i]&0xff000000)>>24;
        output.write((char*)&a,1);//write in binary
        output.write((char*)&b,1);
        output.write((char*)&c,1);
        output.write((char*)&d,1);
    }

    for(uint32_t i=0;i<(uint32_t)(size/64);i++)
    {
        text.read(buf,64);
        KeyStream(counter+i,ptr_key);//creat the key stream
        for(int j=0;j<64;j++)
        {
            uint32_t a=buf[j] ^ key_stream[j];
            output.write((char*)&a,1);
        }
        key_stream.clear();
    } 
    if(size%64!=0)
    {
        int i = size/64;
        text.read(buf,size%64);
        KeyStream(counter+i,ptr_key);
        for(int j=0;j<size%64;j++)
        {
            uint32_t a=buf[j] ^ key_stream[j];
            output.write((char*)&a,1);
        }
    }
    return;
}

int main()
{
    ChaCha20 cc;
    ifstream file,key;
    ofstream out;
    ifstream file2;
    ofstream out2;
    file.open("test.txt",ios::in|ios::binary);
    key.open("key.txt",ios::in|ios::binary);
    out.open("output.txt",ios::out|ios::binary);
    //file2.open("output.txt",ios::in|ios::binary);
    //out2.open("decrypt.txt",ios::out|ios::binary);
    cc.encrypt(file,key,out,1);
    //ChaCha20 cc2;
    //cc2.decrypt(file2,out2,1);
    file.close();
    key.close();
    out.close();
    file2.close();
    out2.close();
    return 0;
}