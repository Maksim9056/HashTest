﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace HashTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //"FD47AE52B163CE6AF07B6421B787C97658CCD092D540D78689F7DE94E322AFBF" "Кандидат 2, 13:35:25 21-03-2024"
            //22AF6F4C418437931AFCBFEAB941F221464F91851F815F79CC9A32283E2BE619 Кандидат 1, 13:35:25 21-03-2024
            //B5BC1B88037899FA9D1511C12C89B11D3776FC741BAC9C0C5ED042104ACF6C75 Кандидат 1

            string message = "Кандидат 1";
            SHA256 sha256 = new SHA256();
            var hash_value = sha256.ComputeHash(message);

            Console.WriteLine(hash_value);

            //
            int[] A = new int[] {67, 13, 49, 24, 40, 33, 58 };
            
            //Не сгенироровать
            //for (int i = 0; i < 100; i++)
            //{
            //    A[i] = i;
            //}

            Console.WriteLine("Закрытая адресация:");
            List<List<int>> resultClosedAddressing = ClosedAddressing(A);
            foreach (List<int> bucket in resultClosedAddressing)
            {
                Console.WriteLine($"[{string.Join(", ", bucket)}]");
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine();
            
            Console.WriteLine("Открытая  адресация:");
            List<List<int>> openAddressing = OpenAddressing(A);
            foreach (List<int> buckets in openAddressing)
            {
                Console.WriteLine($"[{string.Join(", ", buckets)}]");
            }





            //1.Функция DuplicatesBruteForce выполняет проверку наличия дубликатов в массиве, перебирая все возможные пары элементов
            //.Она имеет сложность O(n^2) из - за двух вложенных циклов, каждый из которых выполняется от 0 до n-1 итераций.

            //2.Функция DuplicatesNLogN сначала сортирует массив, а затем проверяет соседние элементы на наличие дубликатов
            //.Сортировка массива занимает O(n log n) времени, а затем проход по отсортированному массиву выполняется за O(n - 1) времени
            //.Итоговая сложность составляет O(n log n).

            //3.Функция DuplicatesLinearExpected использует HashSet для отслеживания посещенных элементо
            //в.Она проходит по массиву и проверяет, содержит ли HashSet текущий элемент.
            //Если содержит, то есть дубликат, и функция возвращает true.Если элемент не найден в HashSet, он добавляется, чтобы в дальнейшем отслеживать его.
            //Из - за использования HashSet, сложность этой функции составляет O(n).

            //4.Функция DuplicatesK использует массив count, чтобы подсчитывать количество вхождений каждого элемента.Она проходит по массиву A и увеличивает соответствующий счетчик в массиве count.
            //Если счетчик превысит 1, это означает наличие дубликата.
            //Время выполнения этой функции похоже на O(n), но на самом деле она имеет сложность O(k), где k -это диапазон значений элементов в массиве.
            //Это потому, что операция инкремента и проверка на > 0 выполняются за O(1) времени.


//  1. `DuplicatesBruteForce`:
//   -Сложность: O(n ^ 2)(квадратичная сложность).
//   - Объяснение: Функция использует два вложенных цикла `for`,
//   каждый из которых проходит по всем элементам массива `A`.
//   Внутренний цикл сравнивает текущий элемент с каждым элементом массива после него.
//   Это приводит к выполнению n(n - 1) / 2 операций сравнения, где n - количество элементов в массиве
//   .Таким образом, время работы этой функции пропорционально n ^ 2 приближенно.

//2. `DuplicatesNLogN`:
//   -Сложность: O(n log n)(сортировка logарифмическая сложность).
//   - Объяснение: Функция сначала сортирует массив `A` с использованием `OrderBy`, что имеет сложность O(n log n).
//   Затем она проходит по сортированному массиву и находит пары соседних элементов, которые равны друг другу
//   .Функция останавливается при первой паре дубликатов и возвращает `true`, иначе возвращает `false`.
//3. `DuplicatesLinearExpected`:
//   -Сложность: O(n)(линейная сложность).
//   - Объяснение: В этой функции используется `HashSet` (`HashSet<int>`), который предоставляет почти константное время для операций добавления, поиска и удаления элементов.Функция проходит по массиву `A`
//   и добавляет каждый элемент в `HashSet`. При обнаружении дубликата, функция немедленно возвращает `true`.
//   Если во всем массиве не найдено дубликатов, функция возвращает `false`. Время выполнения зависит от количества элементов в массиве и времени добавления в `HashSet`, но ожидается, что оно будет линейным.

//4. `DuplicatesK`:
//   -Сложность: O(n + k)(линейная сложность).
//   - Объяснение: В этой функции используется массив `count`, который хранит количество вхождений каждого элемента `num` из массива `A`.
//   Функция проходит по массиву `A` и увеличивает `count[num]`,
//   чтобы отслеживать количество вхождений каждого элемента. Если `count[num]` становится больше 1, функция сразу же возвращает `true`, иначе она возвращает `false`.
//   Время выполнения зависит от количества элементов в массиве и размера массива `count`, то есть времени чтения и записи O(n + k).

            int[] b={ 4, 2, 7, 1, 10, 9, 5, 2 }; // Есть повторения

            Console.WriteLine("Наивный алгоритм (brute-force):");
            bool resultBruteForce = DuplicatesBruteForce(b);
            Console.WriteLine(resultBruteForce);

            Console.WriteLine("Алгоритм, работающий за O(n log n):");
            bool resultNLogN = DuplicatesNLogN(b);
            Console.WriteLine(resultNLogN);

            Console.WriteLine("Алгоритм с ожидаемым (средним) временем работы O(n):");
            bool resultLinearExpected = DuplicatesLinearExpected(b);
            Console.WriteLine(resultLinearExpected);

            Console.WriteLine("Алгоритм с ожидаемым (средним) временем работы O(k):");
            int k = 10;
            bool resultK = DuplicatesK(b, k);
            Console.WriteLine(resultK);
            //var origin_block = "";
            //var origin_time = DateTime.Now;
            //var origin_previous_hash = "";
            //var origin_current_hash = GetHash($"{origin_block}{origin_time}{origin_previous_hash}");
            //Console.WriteLine(origin_current_hash);

            //var data_for_block_chain = new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            //var timestamps_for_block_chain = new[] { 11, 22, 33, 44, 55, 66, 77, 88, 99 };
            //var prev_hash_place_holder = "";

            //for (int i = 0; i < data_for_block_chain.Length; i++)
            //{
            //    var calc_time = timestamps_for_block_chain[i];
            //    var curr_hash = GetHash($"{data_for_block_chain[i]}{calc_time}{prev_hash_place_holder}");
            //    Console.WriteLine($"data: {data_for_block_chain[i]}, timestamp: {calc_time}, prev_hash: {prev_hash_place_holder}, current_hash: {curr_hash}");
            //    prev_hash_place_holder = curr_hash;
            //}



            Console.ReadLine();
            }

        static bool DuplicatesBruteForce(int[] A)
        {
            int n = A.Length;
            for (int i = 0; i < n; i++)
            {
                for (int j = i + 1; j < n; j++)
                {
                    if (A[i] == A[j])
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        static bool DuplicatesNLogN(int[] A)
        {
            int[] sorted_A = A.OrderBy(x => x).ToArray();
            int n = sorted_A.Length;
            for (int i = 0; i < n - 1; i++)
            {
                if (sorted_A[i] == sorted_A[i + 1])
                {
                    return true;
                }
            }
            return false;
        }

        static bool DuplicatesLinearExpected(int[] A)
        {
            var seen = new HashSet<int>();
            foreach (int num in A)
            {
                if (seen.Contains(num))
                {
                    return true;
                }
                seen.Add(num);
            }
            return false;
        }

        static bool DuplicatesK(int[] A, int k)
        {
            int[] count = new int[k + 1];
            foreach (int num in A)
            {
                if (count[num] > 0)
                {
                    return true;
                }
                count[num]++;
            }
            return false;
        }



        static List<List<int>> OpenAddressing(int[] A)
        {
            //Сколько задать ?
            int size = 9;// Простое число, ближайшее к удвоенному размеру списка A
            List<List<int>> hashtable = new List<List<int>>();

            for (int i = 0; i < size; i++)
            {
                hashtable.Add(new List<int>());  // Используем пустые списки для обозначения пустых ячеек
            }

            int HashFunction(int key)
            {
                return (11 * key + 4) % size;
            }

            foreach (int key in A)
            {
                int index = HashFunction(key);

                while (hashtable[index].Count > 0)
                {
                    index = (index + 1) % size;
                }

                hashtable[index].Add(key);
            }

            return hashtable;
        }

        static List<List<int>> ClosedAddressing(int[] A)
            {
                int size = 9;
                List<List<int>> hashtable = new List<List<int>>();

                int HashFunction(int key)
                {
                    return (11 * key + 4) % size;
                }

                for (int i = 0; i < size; i++)
                {
                    hashtable.Add(new List<int>());
                }

                foreach (int key in A)
                {
                    int index = HashFunction(key);
                    hashtable[index].Add(key);
                }

                return hashtable;
            }


        }

        public class SHA256
        {
            private uint[] K = new uint[]
            {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };

            private uint RightRotate(uint num, int n)
            {
                return ((num >> n) | (num << (32 - n))) & 0xFFFFFFFF;
            }

            //  message = bytearray(message, 'utf-8')
            //  ml = len(message) * 8  # message length in bits

            // # Padding
            // message.append(0x80)
            // while (len(message)* 8) % 512 != 448:
            //      message.append(0x00)
            // message += ml.to_bytes(8, 'big')  # append original message length
            //        return message


            private byte[] Padding(string message)
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);



                uint ml = (uint)(messageBytes.Length * 8);  // message length in bits

                // Padding
                List<byte> paddedMessage = new List<byte>(messageBytes);
                paddedMessage.Add(0x80);
                while ((paddedMessage.Count * 8) % 512 != 448)
                {
                    paddedMessage.Add(0x00);
                }
                paddedMessage.AddRange(BitConverter.GetBytes(ml).Reverse());  // append original message length

                return paddedMessage.ToArray();
            }


            private uint[] Compression(byte[] chunk, uint[] h)
            {

                if (chunk.Length < 16)
                {
                    // Обработка ошибки или возврат из функции, в зависимости от вашей логики
                    return null;
                }

                uint[] w = new uint[64];
                for (int j = 0; j < chunk.Length / 4; j++)
                {
                    w[j] = BitConverter.ToUInt32(chunk, j * 4);
                }

                for (int j = 16; j < 64; j++)
                {
                    uint s0 = RightRotate(w[j - 15], 7) ^ RightRotate(w[j - 15], 18) ^ (w[j - 15] >> 3);
                    uint s1 = RightRotate(w[j - 2], 17) ^ RightRotate(w[j - 2], 19) ^ (w[j - 2] >> 10);
                    w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF;
                }

                uint a = h[0];
                uint b = h[1];
                uint c = h[2];
                uint d = h[3];
                uint e = h[4];
                uint f = h[5];
                uint g = h[6];
                uint hh = h[7];

                for (int j = 0; j < 64; j++)
                {
                    uint S1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint temp1 = (hh + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF;
                    uint S0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = (S0 + maj) & 0xFFFFFFFF;

                    hh = g;
                    g = f;
                    f = e;
                    e = (d + temp1) & 0xFFFFFFFF;
                    d = c;
                    c = b;
                    b = a;
                    a = (temp1 + temp2) & 0xFFFFFFFF;
                }

                return new uint[] { (h[0] + a) & 0xFFFFFFFF, (h[1] + b) & 0xFFFFFFFF, (h[2] + c) & 0xFFFFFFFF, (h[3] + d) & 0xFFFFFFFF, (h[4] + e) & 0xFFFFFFFF, (h[5] + f) & 0xFFFFFFFF, (h[6] + g) & 0xFFFFFFFF, (h[7] + hh) & 0xFFFFFFFF };
            }


            public string ComputeHash(string message)
            {
                byte[] paddedMessage = Padding(message);


                uint[] hash = new uint[]
                {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                };

                for (int i = 0; i < paddedMessage.Length; i += 64)
                {
                    int chunkSize = Math.Min(64, paddedMessage.Length - i);
                    byte[] chunk = new byte[chunkSize];
                    Array.Copy(paddedMessage, i, chunk, 0, chunkSize);
                    hash = Compression(chunk, hash);
                }

                StringBuilder sb = new StringBuilder();
                foreach (uint h in hash)
                {
                    sb.Append(h.ToString("X8"));
                }

                string result = sb.ToString();

                //     var strin   = sb.
                return result;
            }

        }
    }



