Сербаев Вадим, СКБ 172. Реализация и встраивание хэш-функций SHA-3-512, SHA-3-384, SHA-3-256, SHA-3-224.

Литература, применявшаяся при реализации алгоритма: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
Собственная реализация с нуля. В процессе написания кода ориентировался только на литературу.

В библиотеку был добавлен файл #### ak_keccak.c #### , включающий функции хэширования семейства SHA-3, а также функцию для их тестирования.
В заголовочный файл #### ak_libakrypt.h #### (строки 830-863) была добавлена структура для хранения внутренних данных функции хеширования, а также объявлены: функция, вычисляющая хэш-значение от имеющихся данный, и функция тестирования для оценки работоспособности функций SHA-3-512...SHA-3-224.  

В комментариях постарался подробно описать назначение каждой функции.

--------------------------------------------------------------------
Функции, определенные в #### ak_keccak.c #### : 

static int mod(int a, int b)

static ak_uint64 rotation(ak_uint64 x, int numBits) 

static inline void Theta(ak_uint64 A[5][5])

static inline void Ro(ak_uint64 A[5][5])

static inline void Pi(ak_uint64 A[5][5])

static inline void Chi(ak_uint64 A[5][5])

static inline void Iota(ak_uint64 A[5][5], int i)

static inline void three_dimensional_array(ak_keccak sha, ak_uint64 A[5][5])

static inline void block_filling(ak_keccak *sha, unsigned long long int N, int bl)

static inline void xor_block(ak_keccak* sha)

static inline void res_update(ak_keccak* sha, ak_uint64 A[5][5])

int ak_sha3_function(ak_keccak sha, ak_uint8 answer[]) - включает в себя реализации SHA-3-512, SHA-3-384, SHA-3-256, SHA-3-224 в зависимости от начальных параметров структуры

static int comparation(ak_uint8 answer[], ak_uint8 result[], int arraysize)

int ak_sha3_tests() - функция тестирования, выполняющая по 4 теста для каждой функции (SHA-3-512, SHA-3-384, SHA-3-256, SHA-3-224)

--------------------------------------------------------------------
В качестве тестовых векторов было взято два примера из Википедии ("The quick brown fox jumps over the lazy dog" с точкой в конце и без), один непосредственно от csrc.nist.gov на 1600 бит (остальные примеры включают в себя не кратное 8 количество бит (30, 1605б 1630) - в данной реализации принимается, что на вход подаются целые байты), один - определенный через онлайн генератор хэша - https://emn178.github.io/online-tools/sha3_512.html 

