#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>

/// This file implements a dictionary and brute-force solution 
/// to cracking the µCTF Hollywood password hash. And it worked!

using namespace std;

uint32_t hashPass(const char* pass, int size)
{
    assert((size&1) == 0);
    size /= 2;
    uint16_t r4=0, r6=0;
    const uint16_t* r5=(uint16_t*)pass;

    for (int i=0; i<size; i++)
    {
        r4 += r5[i];
        r4 = ((r4>>8)&0xFF) + ((r4&0xFF)<<8);
        r6 ^= r5[i];
        r6 ^= r4;
        r4 ^= r6;
        r6 ^= r4;
    }

    return (((uint32_t)r4)<<16) + r6;
}

/// WARNING: Requires a null word-aligned word at the end of the pass!
/// That's 2-3 null bytes, to be clear
uint32_t hashPass2(const char* pass)
{
    uint16_t r4=0, r6=0;
    const uint16_t* r5=(uint16_t*)pass;

    do {
        r4 += *r5;
        r4 = ((r4>>8)&0xFF) + ((r4&0xFF)<<8);
        r6 ^= *r5++;
        r6 ^= r4;
        r4 ^= r6;
        r6 ^= r4;
    } while (*r5);

    return (((uint32_t)r4)<<16) + r6;
}

/// WARNING: Requires a null word-aligned word at the end of the pass!
/// That's 2-3 null bytes, to be clear
bool hashPass3(const char* pass)
{
    uint16_t r4=0, r6=0;
    const uint16_t* r5=(uint16_t*)pass;

    do {
        r4 += *r5;
        r4 = __builtin_bswap16(r4);
        r6 ^= *r5++;
        swap(r6, r4);

    } while (*r5);

    return r4==0xFEB1 && r6==0x9298;
}

void dictBruteforce()
{
    cout << "Reading dictionnary file..."<<endl;
    ifstream f("/opt/dict/rockyou.txt");
    vector<string> lines;
    {
        std::string line;
        while (std::getline(f, line))
            lines.push_back(line);
    }
    f.close();

    const uint32_t target = 0xFEB19298;
    //const uint32_t target = 0xED0015F1; // hash of "password", as a test

    for (size_t i=0; i<lines.size(); i++)
    {
        char line[100];
        memset(line, 0, sizeof(line));
        memcpy(line, lines[i].data(), lines[i].size());
        cout << "Hashing pass "<<i<<'/'<<lines.size()<<endl;

        const uint32_t hash = hashPass(line, strlen(line));

        if (target == hash)
        {
            cout << "SUCCESS: Password is "<<line<<endl;
            cout << "Hash is 0x"<<hex<<hash<<", expected 0x"<<target<<endl;
            exit(0);
        }
    }
}

void incbuf(uint16_t* buf)
{
    while (++*buf == 0)
        buf++;
}

void printbuf(const uint16_t* buf)
{
    cout << "Trying pass: " << hex;
    for (;*buf; buf++)
        printf("%04x",*buf);
    cout << endl;
}

// Quickly thrown together and unoptimized single core brute force. It'll do.
void bruteforce()
{
    unsigned print=0x10000000;

    uint16_t buf[6]={0};
    buf[2]=0x0096; // Resume position close to the result

    for (;;incbuf(buf))
    {
        if (--print==0)
        {
            print=0x10000000;
            printbuf(buf);
        }

        if (hashPass3((const char*)buf))
        {
            cout << "SUCCESS!!! Remember to fix the endianness! Solution on next line:"<<endl;
            printbuf(buf);
            exit(0);
        }
    }
}

int main()
{
    cout << "µCTF Hollywood bruteforce solver" << endl;

    //dictBruteforce(); // Was worth a try. Didn't work.
    bruteforce();

    return 0;
}

