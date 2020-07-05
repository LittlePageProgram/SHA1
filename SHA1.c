// Copyright 2020 Steve Yu. All rights reserved.

#include <stdint.h> //contains the uint32_t, uint8_t, int_least16_t
#include <stdio.h>
#include <string.h>

#define SHA1HashSize 20

/**
 * SHA1Context的结构体
 */
typedef struct SHA1Context
{
    /**
     * 5个32bit的连接变量，保存160位中间结果和最终结果。
     */
    uint32_t Intermediate_Hash[SHA1HashSize/4];
    uint32_t Length_Low;
    uint32_t Length_High;
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];
} SHA1Context;

void SHA1Reset(SHA1Context *context);
void SHA1Input( SHA1Context *context,const uint8_t *message_array,unsigned length);
void SHA1Result( SHA1Context *context,uint8_t Message_Digest[SHA1HashSize]);
void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

/**
 * 初始化SHA1Context
 */
void SHA1Reset(SHA1Context *context)
{
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;
    /**
     * 初始化连接变量
     */
    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;
}

/*
 * * SHA1Result
 * */
void SHA1Result( SHA1Context *context,uint8_t Message_Digest[SHA1HashSize])
{
    int i;
    SHA1PadMessage(context);
    /**
     * 清楚块和context->Length_Low和context->Length_High
     */
    for(i=0; i<64; ++i)
    {
        context->Message_Block[i] = 0;
    }
    context->Length_Low = 0; /* and clear length */
    context->Length_High = 0;

    for(i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
        >> 8 * ( 3 - ( i & 0x03 ) );
    }
}


/**
 * SHA1输入进Message_Block
 */
void SHA1Input( SHA1Context *context,const uint8_t *message_array,unsigned length)
{
    while(length--)
    {
        context->Message_Block[context->Message_Block_Index++] = *message_array;
        context->Length_Low += 8;
        if (context->Message_Block_Index == 64)
        {
            /**
             * 处理压缩函数
             */
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
}


/*
 * * word<<<bits
 */
#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

/**
 * SHA1ProcessMessageBlock
 * 核心：压缩函数
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const uint32_t K[] = { /* Constants defined in SHA-1 */
            0x5A827999,
            0x6ED9EBA1,
            0x8F1BBCDC,
            0xCA62C1D6
    };
    int t; /* Loop counter */
    uint32_t temp; /* Temporary word value */
    uint32_t W[80]; /* Word sequence */
    uint32_t A, B, C, D, E; /* Word buffers */

    /**
     * 512位分成16个32位进行位拓展
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }
    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    /**
     * 取出ABCDE
     */
    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];
    for(t = 0; t < 20; t++)
    {
                temp = SHA1CircularShift(5,A) +
                        ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
            ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Message_Block_Index = 0;
}


/*
 * * SHA1PadMessage
 */
void SHA1PadMessage(SHA1Context *context)
{
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
        SHA1ProcessMessageBlock(context);
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
    * Store the message length as the last 8 octets
    */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;
    SHA1ProcessMessageBlock(context);
}

/*
 * * 进行sha1算法运算
*/
void sha1(const char *input, uint8_t output[20], unsigned size)
{
    SHA1Context sha;
    SHA1Reset(&sha);//初始化SHA1Context（主要初始化连接变量）
    SHA1Input(&sha,(const unsigned char *) input, size);//处理输入
    SHA1Result(&sha, output);//处理输出
}

int main(int argc,char* argv[])
{
    int i;
    uint8_t Message_Digest[20];
    if(argc == 1){
        printf("SHA1: fatal error: no input string\n"
               "compilation terminated.\n");
        return 1;
    }
    sha1(argv[1], Message_Digest, strlen(argv[1]));
    for(i = 0; i < 20 ; ++i)
    {
        printf("%02x", Message_Digest[i]);
    }
    printf("\n");
    return 0;
}
