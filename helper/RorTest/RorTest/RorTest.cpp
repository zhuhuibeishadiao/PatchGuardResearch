// RorTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>

#define __ROL64(x, n) (((x) << ((( n & 0xFF) % 64))) | ((x) >> (64 - (( n & 0xFF) % 64))))
#define __ROR64(x, n) (((x) >> ((( n & 0xFF) % 64))) | ((x) << (64 - (( n & 0xFF) % 64))))

EXTERN_C ULONG_PTR __ror64(ULONG_PTR x, ULONG_PTR n);
EXTERN_C ULONG_PTR __btc64(ULONG_PTR x1);
EXTERN_C ULONG_PTR __btr64(ULONG_PTR x1);

void test(ULONG_PTR ContextKey)
{
    auto TempSize = 0x1024;    //context的尺寸
    auto FollowContextKey = ContextKey;
    std::cout << ContextKey << std::endl;

    PULONG_PTR pTempMem = (PULONG_PTR)malloc(0x1024 * 1024);

    int i = 0;
    //解密剩下的部分
    do {
        pTempMem[TempSize] ^= FollowContextKey;
        auto RorBit = static_cast<UCHAR>(TempSize);
        FollowContextKey = __ROR64(FollowContextKey, RorBit);
        printf("i:%d, temp:%d:%x, RotBit:%d 0x%x, %lld\n", i, TempSize, TempSize, RorBit, RorBit, FollowContextKey);
        i++;

        if (FollowContextKey == ContextKey)
            system("pause");

    } while (--TempSize);
}

void test2()
{
    ULONG_PTR key = 0x123456789;
    ULONG_PTR crypt = 0x987654321;
    auto rorKey = __ror64(key, 0x123);

    printf("rorkey:0x%llx\n", rorKey);

    auto btcKey = __btc64(rorKey);

    printf("btckey:0x%llx\n", btcKey);

    auto btckeyCrypt = crypt ^ btcKey;


    printf("btckeyCrypt:0x%llx\n", btckeyCrypt);




    /*auto btrKey = __btr64(btcKey);

    printf("btrkey:0x%llx\n", btrKey);*/

    system("pause");
}

int main()
{
    /*std::cout << "Hello World!\n"; 
    test(1234567890123);   
    system("pause");*/
    test2();
}

