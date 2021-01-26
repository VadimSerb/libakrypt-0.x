/*  Файл ak_keccak.c                                                                               */
/*  - содержит реализацию алгоритмов SHA3-224, SHA3-256, SHA3-384, SHA3-512.
    Основано на документации NIST https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf         */
/* ----------------------------------------------------------------------------------------------- */

#include <libakrypt.h>

//Набор констант. Применяются на шаге IOTA
static const ak_uint64 keccak_rc[24] = {
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008
};


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление модуля - на случай, когда a < 0. Применяется на шаге THETA                   */
/* ----------------------------------------------------------------------------------------------- */
static int mod(int a, int b) {

    int c;
    if (a >= 0) c = a % b;
    else {
        c = (a / b) * (-1);
        c = b * (c + 1);
        c = c + a;
    }
    return c;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Циклический сдвиг. Применяется на шагах THETA, RO.                                      */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint64 rotation(ak_uint64 x, int numBits) {
    return ((x << numBits) | (x >> (64 - numBits)));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Первый шаг функции перестановки алгоритма - θ, THETA. Описание:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 3.2.1 Specification of θ стр. 11-12.    */
/* ----------------------------------------------------------------------------------------------- */

static inline void Theta(ak_uint64 A[5][5]) {

    int x, y;
    ak_uint64 C[5];
    ak_uint64 D[5];
    for (x = 0; x < 5; x++) {
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
    }

    for (x = 0; x < 5; x++) {
        D[x] = C[mod(x - 1, 5)] ^ rotation(C[mod(x + 1, 5)], 1);
    }

    for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
            A[x][y] = A[x][y] ^ D[x];
        }
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Второй шаг функции перестановки алгоритма -  ρ, RO. Описание:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 3.2.2 Specification of ρ стр. 12-13.    */
/* ----------------------------------------------------------------------------------------------- */

static inline void Ro(ak_uint64 A[5][5]) {
    int x = 1;
    int y = 0;
    int x1;
    for (int t = 0; t < 24; t++) {
        A[x][y] = rotation(A[x][y], ((t + 1) * (t + 2) / 2) % 64);
        x1 = x;
        x = y;
        y = mod(2 * x1 + 3 * y, 5);
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Третий шаг функции перестановки алгоритма - π, PI. Описание:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 3.2.3 Specification of π стр. 14.       */
/* ----------------------------------------------------------------------------------------------- */

static inline void Pi(ak_uint64 A[5][5]) {

    int x, y;
    ak_uint64 A1[5][5];
    for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
            A1[x][y] = A[x][y];
        }
    }

    for (x = 0; x < 5; x++) {

        for (y = 0; y < 5; y++) {
            A[x][y] = A1[mod(x + 3 * y, 5)][x];
        }

    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Четвертый шаг функции перестановки алгоритма - χ, CHI. Описание:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 3.2.4 Specification of χ стр. 15.       */
/* ----------------------------------------------------------------------------------------------- */

static inline void Chi(ak_uint64 A[5][5]) {

    int x, y;
    ak_uint64 A1[5][5];
    for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
            A1[x][y] = A[x][y];
        }
    }

    for (x = 0; x < 5; x++) {

        for (y = 0; y < 5; y++) {
            A[x][y] = A1[x][y] ^ ((~A1[mod((x + 1), 5)][y]) & A1[mod((x + 2), 5)][y]);
        }

    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Пятый шаг функции перестановки алгоритма - ι, IOTA. Описание:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 3.2.4 Specification of ι стр. 15-16. 
  Значения rc вычислены отдельно и сохранены в массиве ak_uint64 keccak_rc[24].                    */
/* ----------------------------------------------------------------------------------------------- */

static inline void Iota(ak_uint64 A[5][5], int i) {
    A[0][0] = A[0][0] ^ keccak_rc[i];
}



/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция "трансформирует" исходный блок сообщения, состоящий из последовательности байт, 
  (суммарно 200 элементов = 1600 бит) в трехмерный массив 5х5х64 бит, т.е. ak_uint64 [5][5], для 
  дальнейшего применения функции перестановки алгоритма                                            */
/* ----------------------------------------------------------------------------------------------- */
static inline void three_dimensional_array(ak_keccak sha, ak_uint64 A[5][5]) {
    int x, y, z;
    int bn = 199; 
    for (x = 4; x >= 0; x--) {

        for (y = 4; y >= 0; y--) {

            for (z = 0; z < 8; z++) {
                A[y][x] = ((A[y][x] << 8) | (sha.block[bn]));
                bn -= 1;
            }

        }
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция заполняет промежуточный блок в 1600 бит                                         */
/* ----------------------------------------------------------------------------------------------- */

static inline void block_filling(ak_keccak *sha, unsigned long long int N, int bl) {
    int i;
    for (i = 0; i < 200; i++) {
        if (i < bl) {
            if (sha->bn == sha->msg_size) sha->block[i] = 0x06; //байт = 0x06 добавляется как только сообщение закончилось. Обоснование:
                                                                   //https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf стр. 28, Table 6.
            if (sha->bn < sha->msg_size) sha->block[i] = sha->msg[sha->bn]; //пока сообщение не закончилось, считываем его байты и записываем в блок
            if (sha->bn > sha->msg_size) sha->block[i] = 0x00; //если сообщение закончилось и удалось записать единичный байт, остальные элементы будут равны 0х00
            sha->bn++;
            if (N == 1) sha->block[bl-1] = 0x80; //1 добавляется к концу сообщения только когда остается последний блок в 1600 бит
            if ((N==1)&(sha->msg_size % bl == (bl - 1))) sha->block[bl - 1] = 0x86; //случай, когда сообщение кончилось и не хватает одного байта для заполнения блока
        }
        else sha->block[i] = 0x00; //все байты от bl до 200 зануляются
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция применяет операцию XOR "исключающее или". Применяется после формирования итогового
  блока на каждом этапе цикла: блок, полученный ранее XOR новый блок из нового куска сообщения     */
/* ----------------------------------------------------------------------------------------------- */
static inline void xor_block(ak_keccak* sha) {
    int i;
    for (i = 0; i < 200; i++) {
        sha->block[i] = sha->block[i] ^ sha->res[i];
        sha->res[i] = 0x00;
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция обновляет результирующий блок sha->res, который применяется для xor_block       */
/* ----------------------------------------------------------------------------------------------- */
static inline void res_update(ak_keccak* sha, ak_uint64 A[5][5]) {
    int x, y, z;
    int i = 0;
    for (x = 0; x < 5; x++) {

        for (y = 0; y < 5; y++) {

            for (z = 0; z < 8; z++) {
                sha->block[i] = 0x00;
                sha->res[i] = A[y][x] >> z * 8;
                i = i + 1;
            }

        }

    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Непосредственно функция хеширования, которая записывает в sha.res итоговый блок, из     
  которого вычленяется итоговый хеш нужной длины                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_sha3_function(ak_keccak sha, ak_uint8 answer[]) {
    
    unsigned long long int N; //На сколько блоков будет разбито сообщение
    int bl;                   //
    ak_uint64 A[5][5] = { 0 };
    int r;

    switch ( sha.ftype ) {    //Инициализация нужной функции хеширования: SHA-224, 256, 384, 512?
    case 512:
        bl = 72;              //Соответствующая SHA-512 длина блока (изымаемая из сообщения) в 576 бит 
                              //подробнее https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 
                              //стр. 22: "Table 3: Input block sizes for HMAC".

        N = 1 + sha.msg_size / bl; //Если нельзя добавить ни одного байта от сообщения в блок => 
                                   //нужно увеличить количество блоков на 1
        break;
    case 384:
        bl = 104;
        N = 1 + sha.msg_size / bl;
        break;
    case 256:
        bl = 136;
        N = 1 + sha.msg_size / bl;
        break;
    case 224:
        bl = 144;
        N = 1 + sha.msg_size / bl;
        break;
    default:
        return(-1);
    }

    //После инициализации параметров нужной функции хеширования выполняется Keccak
    while(N > 0) {
        block_filling(&sha, N, bl);
        xor_block(&sha);
        three_dimensional_array(sha, A);

        //Функция перестановок алгоритма
        for (r = 0; r < 24; r++) {
            Theta(A);
            Ro(A);
            Pi(A);
            Chi(A);
            Iota(A, r);
        }
        res_update(&sha, A);
        N--;
    }

    //Запись итогового хеша в массив байтов для дальнейшей работы с ним при необходимости
    for (r = 0; r < sha.ftype / 8; r++) answer[r] = sha.res[r];
   
    return ak_error_ok;
}



/*! \brief Константы-ответы для проведения тестирования работоспособности SHA-512, 384, 256, 224.
  Первые два массива с хешем - примеры из Википедии, третий - опубликованный NIST, четвертый -
  сгенерирован вручную с онлайн сервиса                                                         */

//--------------------------------------SHA-512-------------------------------------------------
static ak_uint8 lazy_dog_512[64] = {
    0x01, 0xde, 0xdd, 0x5d, 0xe4, 0xef, 0x14, 0x64, 0x24, 0x45, 0xba, 0x5f, 0x5b, 0x97, 0xc1, 0x5e,
    0x47, 0xb9, 0xad, 0x93, 0x13, 0x26, 0xe4, 0xb0, 0x72, 0x7c, 0xd9, 0x4c, 0xef, 0xc4, 0x4f, 0xff,
    0x23, 0xf0, 0x7b, 0xf5, 0x43, 0x13, 0x99, 0x39, 0xb4, 0x91, 0x28, 0xca, 0xf4, 0x36, 0xdc, 0x1b,
    0xde, 0xe5, 0x4f, 0xcb, 0x24, 0x02, 0x3a, 0x08, 0xd9, 0x40, 0x3f, 0x9b, 0x4b, 0xf0, 0xd4, 0x50
};

static ak_uint8 lazy_dog_512_point[64] = {
   0x18, 0xf4, 0xf4, 0xbd, 0x41, 0x96, 0x03, 0xf9, 0x55, 0x38, 0x83, 0x70, 0x03, 0xd9, 0xd2, 0x54,
   0xc2, 0x6c, 0x23, 0x76, 0x55, 0x65, 0x16, 0x22, 0x47, 0x48, 0x3f, 0x65, 0xc5, 0x03, 0x03, 0x59,
   0x7b, 0xc9, 0xce, 0x4d, 0x28, 0x9f, 0x21, 0xd1, 0xc2, 0xf1, 0xf4, 0x58, 0x82, 0x8e, 0x33, 0xdc,
   0x44, 0x21, 0x00, 0x33, 0x1b, 0x35, 0xe7, 0xeb, 0x03, 0x1b ,0x5d, 0x38, 0xba, 0x64, 0x60, 0xf8
};

static ak_uint8 nist1600_512[64] = {
   0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1, 0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
   0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0, 0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
   0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3, 0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
   0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41, 0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
};

static ak_uint8 online_512[64] = {
   0xd0, 0xae, 0x2c, 0xd5, 0x16, 0xd3, 0xf1, 0x72, 0xb0, 0xd3, 0x8e, 0x5f, 0x6e, 0x03, 0x70, 0xb7,
   0x8a, 0x43, 0x75, 0x99, 0xeb, 0xf4, 0x52, 0x9f, 0x1d, 0x56, 0xd1, 0x12, 0x8f, 0x3f, 0x73, 0xb7,
   0xb2, 0x41, 0x5f, 0x78, 0xa4, 0x2b, 0x64, 0x8e, 0xfe, 0xdc, 0x30, 0xba, 0x43, 0x68, 0x2f, 0x17,
   0x9c, 0xab, 0x6a, 0xd7, 0x3d, 0x85, 0xa3, 0x7e, 0x18, 0x50, 0xcf, 0x10, 0xbe, 0xd9, 0xa2, 0xf8
};
//--------------------------------------SHA-384-------------------------------------------------
static ak_uint8 lazy_dog_384[48] = {
   0x70, 0x63, 0x46, 0x5e, 0x08, 0xa9, 0x3b, 0xce, 0x31, 0xcd, 0x89, 0xd2, 0xe3, 0xca, 0x8f, 0x60,
   0x24, 0x98, 0x69, 0x6e, 0x25, 0x35, 0x92, 0xed, 0x26, 0xf0, 0x7b, 0xf7, 0xe7, 0x03, 0xcf, 0x32,
   0x85, 0x81, 0xe1, 0x47, 0x1a, 0x7b, 0xa7, 0xab, 0x11, 0x9b, 0x1a, 0x9e, 0xbd, 0xf8, 0xbe, 0x41
};

static ak_uint8 lazy_dog_384_point[48] = {
   0x1a, 0x34, 0xd8, 0x16, 0x95, 0xb6, 0x22, 0xdf, 0x17, 0x8b, 0xc7, 0x4d, 0xf7, 0x12, 0x4f, 0xe1,
   0x2f, 0xac, 0x0f, 0x64, 0xba, 0x52, 0x50, 0xb7, 0x8b, 0x99, 0xc1, 0x27, 0x3d, 0x4b, 0x08, 0x01,
   0x68, 0xe1, 0x06, 0x52, 0x89, 0x4e, 0xca, 0xd5, 0xf1, 0xf4, 0xd5, 0xb9, 0x65, 0x43, 0x7f, 0xb9
};

static ak_uint8 nist1600_384[48] = {
   0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9, 0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
   0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e, 0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
   0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98, 0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
};

static ak_uint8 online_384[48] = {
   0x73, 0x82, 0x9f, 0x17, 0xe2, 0x25, 0x75, 0x86, 0x51, 0x11, 0xb3, 0x42, 0x3c, 0xb2, 0xcb, 0x9b,
   0x74, 0x1c, 0xec, 0x2e, 0x5d, 0x70, 0x2e, 0x37, 0x31, 0x99, 0x1f, 0xc9, 0xfd, 0x53, 0x66, 0x88,
   0xca, 0x6d, 0x6e, 0xce, 0x71, 0x8b, 0x95, 0x92, 0x28, 0x59, 0x2e, 0x48, 0x0f, 0xb8, 0xc8, 0x46
};
//--------------------------------------SHA-256-------------------------------------------------
static ak_uint8 lazy_dog_256[32] = {
   0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c, 0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2, 0x82, 0x39,
   0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4, 0xcb, 0x22, 0x59, 0xa0, 0x89, 0x7d, 0xfc, 0x04
};

static ak_uint8 lazy_dog_256_point[32] = {
   0xa8, 0x0f, 0x83, 0x9c, 0xd4, 0xf8, 0x3f, 0x6c, 0x3d, 0xaf, 0xc8, 0x7f, 0xea, 0xe4, 0x70, 0x04,
   0x5e, 0x4e, 0xb0, 0xd3, 0x66, 0x39, 0x7d, 0x5c, 0x6c, 0xe3, 0x4b, 0xa1, 0x73, 0x9f, 0x73, 0x4d
};

static ak_uint8 nist1600_256[32] = {
   0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07, 0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
   0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73, 0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
};

static ak_uint8 online_256[32] = {
  0x07, 0x23, 0x8f, 0x99, 0x26, 0xe3, 0xd8, 0x66, 0x30, 0x1e, 0x3c, 0x51, 0x67, 0xea, 0xeb, 0x9a,
  0x3b, 0x8b, 0x13, 0xba, 0xd6, 0x66, 0x0e, 0x49, 0xb0, 0xb0, 0x23, 0x33, 0x6e, 0x17, 0x34, 0x26
};
//--------------------------------------SHA-224-------------------------------------------------
static ak_uint8 lazy_dog_224[28] = {
  0xd1, 0x5d, 0xad, 0xce, 0xaa, 0x4d, 0x5d, 0x7b, 0xb3, 0xb4, 0x8f, 0x44, 0x64, 0x21, 0xd5, 0x42,
  0xe0, 0x8a, 0xd8, 0x88, 0x73, 0x05, 0xe2, 0x8d, 0x58, 0x33, 0x57, 0x95
};

static ak_uint8 lazy_dog_224_point[28] = {
  0x2d, 0x07, 0x08, 0x90, 0x38, 0x33, 0xaf, 0xab, 0xdd, 0x23, 0x2a, 0x20, 0x20, 0x11, 0x76, 0xe8,
  0xb5, 0x8c, 0x5b, 0xe8, 0xa6, 0xfe, 0x74, 0x26, 0x5a, 0xc5, 0x4d, 0xb0
};

static ak_uint8 nist1600_224[28] = {
  0x93, 0x76, 0x81, 0x6a, 0xba, 0x50, 0x3f, 0x72, 0xf9, 0x6c, 0xe7, 0xeb, 0x65, 0xac, 0x09, 0x5d,
  0xee, 0xe3, 0xbe, 0x4b, 0xf9, 0xbb, 0xc2, 0xa1, 0xcb, 0x7e, 0x11, 0xe0
};

static ak_uint8 online_224[28] = {
   0xed, 0xa4, 0x87, 0xbe, 0xbf, 0xf3, 0xf4, 0x93, 0xad, 0xb0, 0x91, 0x6a, 0x14, 0xcc, 0x1b, 0xbf, 
   0xde, 0x40, 0x5a, 0xe8, 0x98, 0x2c, 0x31, 0x9c, 0x8f, 0xc0, 0x3a, 0x05
};


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мини-функция для проведения тестов. Сравнивает получившийся хеш-массив с хеш-ответом    */
/* ----------------------------------------------------------------------------------------------- */

static int comparation(ak_uint8 answer[], ak_uint8 result[], int arraysize) {
    int i;
    for (i = 0; i < arraysize; i++) {
        if (result[i] != answer[i]) {
            printf("%s\n", "ERROR, TEST NOT PASSED");
            exit(0);
        }
    }
    printf("%s\n", "OK, TEST PASSED");
    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование работоспособности функций хеширования SHA-512, SHA-384, SHA-256, SHA-224   */
/* ----------------------------------------------------------------------------------------------- */
int ak_sha3_tests() {

    int i;

    //Следующие два примера из Википедии https://ru.wikipedia.org/wiki/SHA-3#%D0%A2%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D1%8B%D0%B5_%D0%B2%D0%B5%D0%BA%D1%82%D0%BE%D1%80%D1%8B
    ak_uint8 lazy_dog[43] = "The quick brown fox jumps over the lazy dog"; 
    ak_uint8 lazy_dog_point[44] = "The quick brown fox jumps over the lazy dog.";

    ak_uint8 nist1600[200]; //200 байтов со значением 0хА3 - 4-ый пример (Secure Hashing -> FIPS 202 - SHA-3 Standard)
                            // https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    for (i = 0; i < 200; i++) nist1600[i] = 0xA3;

    //Следующий пример - случайный набор символов. Проверка - онлайн генератор https://emn178.github.io/online-tools/sha3_512.html 
    //Соответсвенный выбор нужной функции хеширования на сайте
    ak_uint8 online[71] = "absdaudwuwdhawfLsiefdifhdshgfefsefSdhfdsfhyytrtytghshdhfghrhwhsjjfjJerz";


    //Инициализация структуры
    ak_uint8 answer[64];
    ak_keccak sha;
    sha.bn = 0;
    for (i = 0; i < 200; i++) {
        sha.block[i] = 0;
        sha.res[i] = 0;
    }

    printf("%s\n", "-----------------------------SHA-512 TESTING-----------------------------");
    //4 теста для SHA-512
    sha.ftype = 512;

    sha.msg = lazy_dog;
    sha.msg_size = sizeof(lazy_dog);
    printf("%s\n", "SHA-512 TEST 1: The quick brown fox jumps over the lazy dog");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_512, answer, 64);

    sha.msg = lazy_dog_point;
    sha.msg_size = sizeof(lazy_dog_point);
    printf("%s\n", "SHA-512 TEST 2: The quick brown fox jumps over the lazy dog.");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_512_point, answer, 64);

    sha.msg = nist1600;
    sha.msg_size = sizeof(nist1600);
    printf("%s\n", "SHA-512 TEST 3: 200 bytes = 0xA3");
    ak_sha3_function(sha, answer);
    comparation(nist1600_512, answer, 64);

    sha.msg = online;
    sha.msg_size = sizeof(online);
    printf("%s\n", "SHA-512 TEST 4: absdaudwuwdhawfLsiefdifhdshgfefsefSdhfdsfhyytrtytghshdhfghrhwhsjjfjJerz");
    ak_sha3_function(sha, answer);
    comparation(online_512, answer, 64);

    printf("%s\n", "-----------------------------SHA-384 TESTING-----------------------------");
    //4 теста для SHA-384
    sha.ftype = 384;

    sha.msg = lazy_dog;
    sha.msg_size = sizeof(lazy_dog);
    printf("%s\n", "SHA-384 TEST 1: The quick brown fox jumps over the lazy dog");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_384, answer, 48);

    sha.msg = lazy_dog_point;
    sha.msg_size = sizeof(lazy_dog_point);
    printf("%s\n", "SHA-384 TEST 2: The quick brown fox jumps over the lazy dog.");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_384_point, answer, 48);

    sha.msg = nist1600;
    sha.msg_size = sizeof(nist1600);
    printf("%s\n", "SHA-384 TEST 3: 200 bytes = 0xA3");
    ak_sha3_function(sha, answer);
    comparation(nist1600_384, answer, 48);

    sha.msg = online;
    sha.msg_size = sizeof(online);
    printf("%s\n", "SHA-384 TEST 4: absdaudwuwdhawfLsiefdifhdshgfefsefSdhfdsfhyytrtytghshdhfghrhwhsjjfjJerz");
    ak_sha3_function(sha, answer);
    comparation(online_384, answer, 48);

    printf("%s\n", "-----------------------------SHA-256 TESTING-----------------------------");
    //4 теста для SHA-256
    sha.ftype = 256;

    sha.msg = lazy_dog;
    sha.msg_size = sizeof(lazy_dog);
    printf("%s\n", "SHA-256 TEST 1: The quick brown fox jumps over the lazy dog");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_256, answer, 32);

    sha.msg = lazy_dog_point;
    sha.msg_size = sizeof(lazy_dog_point);
    printf("%s\n", "SHA-256 TEST 2: The quick brown fox jumps over the lazy dog.");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_256_point, answer, 32);

    sha.msg = nist1600;
    sha.msg_size = sizeof(nist1600);
    printf("%s\n", "SHA-256 TEST 3: 200 bytes = 0xA3");
    ak_sha3_function(sha, answer);
    comparation(nist1600_256, answer, 32);

    sha.msg = online;
    sha.msg_size = sizeof(online);
    printf("%s\n", "SHA-256 TEST 4: absdaudwuwdhawfLsiefdifhdshgfefsefSdhfdsfhyytrtytghshdhfghrhwhsjjfjJerz");
    ak_sha3_function(sha, answer);
    comparation(online_256, answer, 32);

    printf("%s\n", "-----------------------------SHA-224 TESTING-----------------------------");
    //4 теста для SHA-224
    sha.ftype = 224;

    sha.msg = lazy_dog;
    sha.msg_size = sizeof(lazy_dog);
    printf("%s\n", "SHA-224 TEST 1: The quick brown fox jumps over the lazy dog");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_224, answer, 28);

    sha.msg = lazy_dog_point;
    sha.msg_size = sizeof(lazy_dog_point);
    printf("%s\n", "SHA-224 TEST 2: The quick brown fox jumps over the lazy dog.");
    ak_sha3_function(sha, answer);
    comparation(lazy_dog_224_point, answer, 28);

    sha.msg = nist1600;
    sha.msg_size = sizeof(nist1600);
    printf("%s\n", "SHA-224 TEST 3: 200 bytes = 0xA3");
    ak_sha3_function(sha, answer);
    comparation(nist1600_224, answer, 28);

    sha.msg = online;
    sha.msg_size = sizeof(online);
    printf("%s\n", "SHA-224 TEST 4: absdaudwuwdhawfLsiefdifhdshgfefsefSdhfdsfhyytrtytghshdhfghrhwhsjjfjJerz");
    ak_sha3_function(sha, answer);
    comparation(online_224, answer, 28);

    //for (int i = 0; i < 64; i++) printf("%0x\n", answer[i]);


    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мини-функция для вывода результата хеширования на консоль: выводит байты, разделенные 
   между собой пробелом                                                                            */
/* ----------------------------------------------------------------------------------------------- */
/*
void ak_sha3_get_hash(ak_keccak sha, ak_uint8 answer[]) {
    ak_sha3_function(sha, answer);
    int i;
    for(i=0; i< sha.ftype / 8; i++) printf("%0x\", answer[i]);
}
*/
