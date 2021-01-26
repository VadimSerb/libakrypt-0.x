Сербаев Вадим, СКБ 172. Реализация и встраивание хеш-функций SHA-3-512, SHA-3-384, SHA-3-256, SHA-3-224.

Литература, применявшаяся при реализации алгоритма: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

Собственная реализация с нуля. В процессе написания кода ориентировался только на литературу стандарта.

В библиотеку был добавлен файл ``` ak_keccak.c ``` , включающий функции хеширования семейства SHA-3, а также функцию для их тестирования.
В заголовочный файл ``` ak_libakrypt.h ``` (строки 830-863) была добавлена структура для хранения внутренних данных функции хеширования, были объявлены: функция, вычисляющая хеш-значение от имеющихся данны], а также функция тестирования для оценки работоспособности функций SHA-3-512, SHA-3-384, SHA-3-256, SHA-3-224.  

В комментариях постарался подробно описать назначение каждой функции.

--------------------------------------------------------------------
Функции, определенные в #### ak_keccak.c ####

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
В качестве тестовых векторов было взято два примера из Википедии ("The quick brown fox jumps over the lazy dog" с точкой в конце и без), один непосредственно с https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values на 1600 бит (остальные примеры включают в себя не кратное 8-ми количество бит (5, 30, 1605, 1630) - в данной реализации принимается, что на вход подаются целые байты), один - определенный через онлайн генератор хеша - https://emn178.github.io/online-tools/sha3_512.html 

--------------------------------------------------------------------

Инструкция по сборке: (проверял на Ubuntu 64)
1. Компиляция и сборка библиотеки
mkdir build
cd build
cmake -DCMAKE_C_FLAGS="-march=native" ../libakrypt-0.x
make

2. Создание си-файла следующего содержания:

```
#include <stdio.h>    
#include <libakrypt.h>


int main()                  
{                

    ak_sha3_tests();


    return 0;
}
```
3. Компиляция и линковка со статической библиотекой:
```
    gcc /путь/к/main.c /путь/к/библиотеке/libakrypt.a

    ./a.out
```

--------------------------------------------------------------------

Скриншоты с результатами работы программы:

![Альтернативный текст](https://sun9-47.userapi.com/impg/L-e3no50oGHDcwjKFek12yvwbTAw3gfLIG9PMw/I0D-SijQJE4.jpg?size=795x598&quality=96&proxy=1&sign=beb3fec1ee1e3d7c713113fea7bceab4&type=album)

![Альтернативный текст](https://sun9-28.userapi.com/impg/HdZiAC65JXysdKvTeRNl6EE4VQDghf1vFn0sOQ/7kaQanlc7VE.jpg?size=797x598&quality=96&proxy=1&sign=4ac642876f15679f70c420a46ebf7d94&type=album)

![Альтернативный текст](https://sun9-53.userapi.com/impg/m9tzXIrACVUZy-4vQk4ROnFt2QMkZcHfk-LZvg/9ayXUWVrm_Q.jpg?size=668x611&quality=96&proxy=1&sign=d1ea46ee4441e6f5ee48712ce99661ee&type=album)

