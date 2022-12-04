﻿/*
   Copyright 2021 Nils Kopal, CrypTool Team

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using System;

namespace AES_All
{
    
    public class AES
    {

        #region Helper functions

        public static string ToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes);
        }

        #endregion

        #region SBox

        /// <summary>
        /// The Rijndael SBox. See https://en.wikipedia.org/wiki/Rijndael_S-box
        /// </summary>
        public static readonly byte[] SBox =
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        /// <summary>
        /// The inverse Rijndael SBox. See https://en.wikipedia.org/wiki/Rijndael_S-box
        /// </summary>

        public static readonly byte[] SBoxInverse =
        {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        #endregion

        #region Galois multiplication lookup tables        

        /// <summary>
        /// Galois multiplication lookup table 2. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult2 =
        {
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
            0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
            0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
            0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
            0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
            0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
            0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
            0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
            0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
            0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
            0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
            0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
            0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
            0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
            0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
        };

        /// <summary>
        /// Galois multiplication lookup table 3. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult3 =
        {
            0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
            0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
            0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
            0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
            0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
            0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
            0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
            0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
            0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
            0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
            0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
            0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
            0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
            0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
            0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
            0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
        };

        /// <summary>
        /// Galois multiplication lookup table 9. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult9 =
        {
            0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
            0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
            0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
            0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
            0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
            0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
            0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
            0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
            0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
            0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
            0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
            0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
            0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
            0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
            0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
            0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
        };

        /// <summary>
        /// Galois multiplication lookup table 11. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult11 =
        {
            0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
            0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
            0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
            0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
            0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
            0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
            0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
            0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
            0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
            0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
            0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
            0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
            0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
            0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
            0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
            0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
        };

        /// <summary>
        /// Galois multiplication lookup table 13. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult13 =
        {
            0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
            0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
            0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
            0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
            0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
            0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
            0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
            0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
            0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
            0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
            0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
            0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
            0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
            0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
            0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
            0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
        };

        /// <summary>
        /// Galois multiplication lookup table 14. See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        public static readonly byte[] GaloisMult14 =
        {
            0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
            0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
            0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
            0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
            0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
            0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
            0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
            0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
            0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
            0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
            0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
            0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
            0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
            0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
            0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
            0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
        };

        #endregion

        #region AES primitives
        /// <summary>
        /// XORes the given round key with the data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="roundkey"></param>
        /// <returns></returns>
        public void AddRoundKey(byte[] data, byte[] roundkey)
        {
            for (var i = 0; i < 16; i++)
            {
                data[i] ^= roundkey[i];
            }
        }

        /// <summary>
        /// Applies the SBox of AES to the data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void SubBytes(byte[] data)
        {
            for (var i = 0; i < 16; i++)
            {
                data[i] = SBox[data[i]];
            }
        }

        /// <summary>
        /// Applies the inverse SBox of AES to the data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void SubBytesInverse(byte[] data)
        {
            for (var i = 0; i < 16; i++)
            {
                data[i] = SBoxInverse[data[i]];
            }
        }

        /// <summary>
        /// Performs ShiftRows operation of AES
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void ShiftRows(byte[] data)
        {
            // 0   4   8  12
            // 1   5   9  13 <- 1 byte to left circular shift
            // 2   6  10  14 <- 2 byte to left circular shift
            // 3   7  11  15 <- 3 byte to left circular shift

            byte swap;

            //1. row: remains unshifted (do nothing)

            //2. row: shift one to the left
            swap = data[1];
            data[1] = data[5];
            data[5] = data[9];
            data[9] = data[13];
            data[13] = swap;

            //3. row: shift two to the left = exchange every 2nd
            swap = data[2];
            data[2] = data[10];
            data[10] = swap;
            swap = data[6];
            data[6] = data[14];
            data[14] = swap;

            //4. row: shift three to the left = shift to the right
            swap = data[15];
            data[15] = data[11];
            data[11] = data[7];
            data[7] = data[3];
            data[3] = swap;
        }

        /// <summary>
        /// Performs inverse ShiftRows operation of AES
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void ShiftRowsInverse(byte[] data)
        {
            // 0   4   8  12
            // 1   5   9  13 <- 1 byte to right circular shift
            // 2   6  10  14 <- 2 byte to right circular shift
            // 3   7  11  15 <- 3 byte to right circular shift

            byte swap;

            //1. row: remains unshifted (do nothing)

            //2. row: shift one to the right
            swap = data[13];
            data[13] = data[9];
            data[9] = data[5];
            data[5] = data[1];
            data[1] = swap;

            //3. row: shift two to the right = exchange every 2nd
            swap = data[2];
            data[2] = data[10];
            data[10] = swap;
            swap = data[6];
            data[6] = data[14];
            data[14] = swap;

            //4. row: shift three to the right = shift to the left
            swap = data[3];
            data[3] = data[7];
            data[7] = data[11];
            data[11] = data[15];
            data[15] = swap;
        }

        /// <summary>
        /// Performs AES MixColumns operation
        /// See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void MixColumns(byte[] data)
        {
            byte b0, b1, b2, b3;

            // 0   4   8  12
            // 1   5   9  13
            // 2   6  10  14
            // 3   7  11  15

            // Matrix multiplication:
            // [ d0 ]   [ 2 3 1 1 ]   [ b0 ]
            // [ d1 ] = [ 1 2 3 1 ] * [ b1 ]
            // [ d2 ]   [ 1 1 2 3 ]   [ b2 ]
            // [ d3 ]   [ 3 1 1 2 ]   [ b3 ]

            //Matrix multiplication is performed for each column vector
            for (var i = 0; i < 16; i += 4)
            {
                b0 = data[i + 0];
                b1 = data[i + 1];
                b2 = data[i + 2];
                b3 = data[i + 3];
                data[i + 0] = (byte)(GaloisMult2[b0] ^ GaloisMult3[b1] ^ b2 ^ b3);
                data[i + 1] = (byte)(b0 ^ GaloisMult2[b1] ^ GaloisMult3[b2] ^ b3);
                data[i + 2] = (byte)(b0 ^ b1 ^ GaloisMult2[b2] ^ GaloisMult3[b3]);
                data[i + 3] = (byte)(GaloisMult3[b0] ^ b1 ^ b2 ^ GaloisMult2[b3]);
            }
        }

        /// <summary>
        /// Performs inverse AES MixColumns operation
        /// See https://en.wikipedia.org/wiki/Rijndael_MixColumns
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void MixColumnsInverse(byte[] data)
        {
            byte b0, b1, b2, b3;

            // 0   4   8  12
            // 1   5   9  13
            // 2   6  10  14
            // 3   7  11  15

            // Matrix multiplication:
            // [ d0 ]   [ 14 11 13  9 ]   [ b0 ]
            // [ d1 ] = [  9 14 11 13 ] * [ b1 ]
            // [ d2 ]   [ 13  9 14 11 ]   [ b2 ]
            // [ d3 ]   [ 11 13  9 14 ]   [ b3 ]

            //Matrix multiplication is performed for each column vector
            for (int i = 0; i < 16; i += 4)
            {
                b0 = data[i + 0];
                b1 = data[i + 1];
                b2 = data[i + 2];
                b3 = data[i + 3];
                data[i + 0] = (byte)(GaloisMult14[b0] ^ GaloisMult11[b1] ^ GaloisMult13[b2] ^ GaloisMult9[b3]);
                data[i + 1] = (byte)(GaloisMult9[b0] ^ GaloisMult14[b1] ^ GaloisMult11[b2] ^ GaloisMult13[b3]);
                data[i + 2] = (byte)(GaloisMult13[b0] ^ GaloisMult9[b1] ^ GaloisMult14[b2] ^ GaloisMult11[b3]);
                data[i + 3] = (byte)(GaloisMult11[b0] ^ GaloisMult13[b1] ^ GaloisMult9[b2] ^ GaloisMult14[b3]);
            }
        }

        #endregion

        #region AES Key schedule

        /// <summary>
        /// Implementation of AES key expansion. See https://en.wikipedia.org/wiki/AES_key_schedule
        /// Returns all round keys in one byte array
        /// </summary>
        /// <param name="K"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public byte[] KeyExpansion(byte[] K, int R)
        {
            var N = K.Length / 4;
            var W = new byte[4 * 4 * R];

            for (int i = 0; i < 4 * R; i++)
            {
                if (i < N)
                {
                    SetWord(W, GetWord(K, i), i);
                }
                else if (i >= N && i % N == 0)
                {
                    var word = XOR(GetWord(W, i - N), SubWord(RotWord(GetWord(W, i - 1))));
                    word = XOR(word, rcon(i / N));
                    SetWord(W, word, i);
                }
                else if (i >= N && N > 6 && i % N == 4)
                {
                    var word = XOR(GetWord(W, i - N), SubWord(GetWord(W, i - 1)));
                    SetWord(W, word, i);
                }
                else
                {
                    var word = XOR(GetWord(W, i - N), GetWord(W, i - 1));
                    SetWord(W, word, i);
                }
            }

            return W;

            /// AES round constants
            byte[] rcon(int i)
            {
                /*
                //Pre-calculated rci values. See https://en.wikipedia.org/wiki/AES_key_schedule
                var rci = new byte[] { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 
                                       0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 
                                       0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 
                                       0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5 };
                return new byte[] { rci[i], 0x00, 0x00, 0x00 };*/
                int rc = 1;
                for (var j = 2; j <= i; j++)
                {
                    if (rc < 0x80)
                    {
                        rc = 2 * rc;
                    }
                    else
                    {
                        rc = (byte)((2 * rc) ^ 0x11b);
                    }
                }
                return new byte[] { (byte)rc, 0x00, 0x00, 0x00 };
            }

            ///Extract a 4 byte word from the given offset
            byte[] GetWord(byte[] data, int offset)
            {
                var word = new byte[4];
                word[0] = data[offset * 4 + 0];
                word[1] = data[offset * 4 + 1];
                word[2] = data[offset * 4 + 2];
                word[3] = data[offset * 4 + 3];
                return word;
            }

            ///Set a 4 byte word at the given offset
            void SetWord(byte[] data, byte[] word, int offset)
            {
                data[offset * 4 + 0] = word[0];
                data[offset * 4 + 1] = word[1];
                data[offset * 4 + 2] = word[2];
                data[offset * 4 + 3] = word[3];
            }

            ///XORes two given 4 byte words
            byte[] XOR(byte[] w1, byte[] w2)
            {
                var word = new byte[4];
                word[0] = (byte)(w1[0] ^ w2[0]);
                word[1] = (byte)(w1[1] ^ w2[1]);
                word[2] = (byte)(w1[2] ^ w2[2]);
                word[3] = (byte)(w1[3] ^ w2[3]);
                return word;
            }

            /// <summary>
            /// RotWord operation of keyschedule of AES. See https://en.wikipedia.org/wiki/AES_key_schedule
            /// </summary>
            /// <param name="data"></param>
            byte[] RotWord(byte[] data)
            {
                var ret = new byte[4];
                ret[0] = data[1];
                ret[1] = data[2];
                ret[2] = data[3];
                ret[3] = data[0];
                return ret;
            }

            /// <summary>
            /// SubWord operation of keyschedule of AES. See https://en.wikipedia.org/wiki/AES_key_schedule
            /// </summary>
            /// <param name="data"></param>
            byte[] SubWord(byte[] data)
            {
                var ret = new byte[4];
                ret[0] = SBox[data[0]];
                ret[1] = SBox[data[1]];
                ret[2] = SBox[data[2]];
                ret[3] = SBox[data[3]];
                return ret;
            }
        }

        #endregion

        #region AES 128, 192, 256 encryption and decryption

        /// <summary>
        /// AES-128 encryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Encrypt128(byte[] text, byte[] key)
        {
            return Encrypt(text, key, 10);
        }

        /// <summary>
        /// AES-128 decryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Decrypt128(byte[] text, byte[] key)
        {
            return Decrypt(text, key, 10);
        }

        /// <summary>
        /// AES-192 encryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Encrypt192(byte[] text, byte[] key)
        {
            return Encrypt(text, key, 12);
        }

        /// <summary>
        /// AES-192 decryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Decrypt192(byte[] text, byte[] key)
        {
            return Decrypt(text, key, 12);
        }

        /// <summary>
        /// AES-256 encryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Encrypt256(byte[] text, byte[] key)
        {
            return Encrypt(text, key, 14);
        }

        /// <summary>
        /// AES-256 decryption
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Decrypt256(byte[] text, byte[] key)
        {
            return Decrypt(text, key, 14);
        }

        /// <summary>
        /// Encrypt using R rounds
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] text, byte[] key, int R)
        {
            //key expansion --> make multiple out of the given key
            var roundkeys = KeyExpansion(key, R + 1);

            //XOR 0 key
            AddRoundKey(text, GetRoundKey(roundkeys, 0));

            //perform rounds
            for (var r = 1; r < R; r++)
            {
                SubBytes(text);
                ShiftRows(text);
                MixColumns(text);
                AddRoundKey(text, GetRoundKey(roundkeys, r));
            }

            //final round without mix columns
            SubBytes(text);
            ShiftRows(text);
            AddRoundKey(text, GetRoundKey(roundkeys, R));

            //return encrypted text
            return text;

            ///Get a round key from the round keys array
            byte[] GetRoundKey(byte[] data, int offset)
            {
                var word = new byte[16];
                word[0] = data[offset * 16 + 0];
                word[1] = data[offset * 16 + 1];
                word[2] = data[offset * 16 + 2];
                word[3] = data[offset * 16 + 3];
                word[4] = data[offset * 16 + 4];
                word[5] = data[offset * 16 + 5];
                word[6] = data[offset * 16 + 6];
                word[7] = data[offset * 16 + 7];
                word[8] = data[offset * 16 + 8];
                word[9] = data[offset * 16 + 9];
                word[10] = data[offset * 16 + 10];
                word[11] = data[offset * 16 + 11];
                word[12] = data[offset * 16 + 12];
                word[13] = data[offset * 16 + 13];
                word[14] = data[offset * 16 + 14];
                word[15] = data[offset * 16 + 15];
                return word;
            }
        }

        /// <summary>
        /// Decrypt using R rounds
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] text, byte[] key, int R)
        {
            //key expansion --> make multiple out of the given key
            var roundkeys = KeyExpansion(key, R + 1);

            //final round without mix columns
            AddRoundKey(text, GetRoundKey(roundkeys, R));
            ShiftRowsInverse(text);
            SubBytesInverse(text);

            //perform rounds
            for (var r = R - 1; r >= 1; r--)
            {
                AddRoundKey(text, GetRoundKey(roundkeys, r));
                MixColumnsInverse(text);
                ShiftRowsInverse(text);
                SubBytesInverse(text);
            }

            //XOR 0 key
            AddRoundKey(text, GetRoundKey(roundkeys, 0));

            //return decrypted text
            return text;

            ///Get a round key from the round keys array
            byte[] GetRoundKey(byte[] data, int offset)
            {
                var word = new byte[16];
                word[0] = data[offset * 16 + 0];
                word[1] = data[offset * 16 + 1];
                word[2] = data[offset * 16 + 2];
                word[3] = data[offset * 16 + 3];
                word[4] = data[offset * 16 + 4];
                word[5] = data[offset * 16 + 5];
                word[6] = data[offset * 16 + 6];
                word[7] = data[offset * 16 + 7];
                word[8] = data[offset * 16 + 8];
                word[9] = data[offset * 16 + 9];
                word[10] = data[offset * 16 + 10];
                word[11] = data[offset * 16 + 11];
                word[12] = data[offset * 16 + 12];
                word[13] = data[offset * 16 + 13];
                word[14] = data[offset * 16 + 14];
                word[15] = data[offset * 16 + 15];
                return word;
            }
        }
        #endregion
    }
}