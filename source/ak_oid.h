/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_oid.h                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_OID_H__
#define    __AK_OID_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс функций без параметра */
 typedef ak_pointer ( ak_function_void )( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения идентификаторов объектов (криптографических механизмов) и их данных. */
/*! OID (Object IDentifier) это уникальная последовательность чисел, разделенных точками.

    OID'ы могут быть присвоены любому криптографическому механизму (алгоритму,
    схеме, протоколу), а также параметрам этих механизмов.
    Использование OID'в позволяет однозначно определять тип криптографического механизма или
    значения его параметров на этапе выполнения программы, а также
    однозначно связывать данные (как правило ключевые) с алгоритмами, в которых эти данные
    используются.

    Примеры использования OID приводятся в разделе \ref toid.                                      */
/* ----------------------------------------------------------------------------------------------- */
 struct oid {
  /*! \brief криптографический механизм   */
   ak_oid_engine engine;
  /*! \brief режим использования криптографического алгоритма */
   ak_oid_mode mode;
  /*! \brief читаемое имя (для пользователя) */
   const char *name;
  /*! \brief собственно OID (cтрока чисел, разделенных точками) */
   const char *id;
  /*! \brief указатель на данные */
   ak_pointer *data;
  /*! \brief указатель на производящую функцию*/
   ak_function_void *func;
};
/*! \brief Контекст идентификатора объекта. */
 typedef struct oid *ak_oid;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая указатели на два однотипных преобразования - одно прямое, другое обратное. */
 typedef struct two_pointers {
  /*! \brief Прямое преобразование. */
   ak_function_void *direct;
  /*! \brief Обратное преобразование. */
   ak_function_void *reverse;
 } *ak_two_pointers;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Поиск OID его имени. */
 ak_oid ak_oid_find_by_name( const char *name );
/*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками). */
 ak_oid ak_oid_find_by_id( const char *id );
/*! \brief Поиск OID по типу криптографического механизма. */
 ak_oid ak_oid_find_by_engine( ak_oid_engine );
/*! \brief Продолжение поиска OID по типу криптографического механизма. */
 ak_oid ak_oid_findnext_by_engine( ak_oid, ak_oid_engine );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.h  */
/* ----------------------------------------------------------------------------------------------- */

