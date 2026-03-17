#include <stdio.h>

unsigned char xf(unsigned char p)
{
    unsigned char temp = p << 1;
    if (p >> 7 == 1)  
        temp ^= 0x1b;
    return temp;
}

void mixcolumn(unsigned char s[4])
{
    unsigned char temp[4];
    for (int i = 0; i < 4; i++) 
        temp[i] = s[i];

    s[0] = xf(temp[0]) ^ (xf(temp[1]) ^ temp[1]) ^ temp[2] ^ temp[3];
    s[1] = temp[0] ^ xf(temp[1]) ^ (xf(temp[2]) ^ temp[2]) ^ temp[3];
    s[2] = temp[0] ^ temp[1] ^ xf(temp[2]) ^ (xf(temp[3]) ^ temp[3]);
    s[3] = (xf(temp[0]) ^ temp[0]) ^ temp[1] ^ temp[2] ^ xf(temp[3]);
}

int main()
{
    unsigned char vec[4] = {0x63, 0x47, 0xa2, 0xf0};

    mixcolumn(vec);

    for (int i = 0; i < 4; i++)
        printf("%x ", vec[i]);
    printf("\n");

    mixcolumn(vec);
    for (int i = 0; i < 4; i++)
        printf("%x ", vec[i]);
    printf("\n");
    mixcolumn(vec);
    for (int i = 0; i < 4; i++)
        printf("%x ", vec[i]);
    printf("\n");
    
    mixcolumn(vec);
    for (int i = 0; i < 4; i++)
        printf("%x ", vec[i]);
    printf("\n");

    return 0;
}