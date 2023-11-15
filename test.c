/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#include <stdio.h>
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <time.h>

#include "pkcs.h"

static char *poet = "윤동주";
static char *poem =
    "죽는 날까지 하늘을 우러러 한 점 부끄럼이 없기를, 잎새에 이는 바람에도 "
    "나는 괴로워했다. 별을 노래하는 마음으로 모든 죽어 가는 것을 사랑해야지 "
    "그리고 나한테 주어진 길을 걸어가야겠다. 오늘 밤에도 별이 바람에 스치운다.";
static char poet_e[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01};
static char poet_d[256] = {
    0x21, 0x62, 0x69, 0xaa, 0xe2, 0xcf, 0x14, 0x8c, 0x05, 0xd6, 0xf3, 0x09,
    0x1b, 0xed, 0x43, 0x0b, 0x6f, 0xfe, 0x65, 0xaf, 0x57, 0x51, 0xe5, 0xd2,
    0xb7, 0x46, 0x80, 0xee, 0x28, 0xbe, 0xe7, 0x9e, 0x79, 0xf6, 0xd2, 0x41,
    0xa7, 0x76, 0xb7, 0xb1, 0x93, 0x3f, 0x5b, 0xe0, 0x69, 0x11, 0x27, 0xf8,
    0x19, 0x2e, 0x6d, 0x87, 0x4f, 0x81, 0x62, 0xbf, 0xc6, 0xf9, 0x45, 0x41,
    0xe0, 0x52, 0x39, 0xf9, 0x7f, 0xad, 0x3d, 0x58, 0x75, 0xab, 0x9b, 0x88,
    0x8f, 0x74, 0x73, 0xf9, 0x2f, 0x12, 0xba, 0xa6, 0x0c, 0x1e, 0xed, 0xd7,
    0x7e, 0xfa, 0x50, 0x3a, 0xe8, 0xcf, 0x50, 0x6e, 0x1b, 0x07, 0xe6, 0xac,
    0xd2, 0x24, 0x66, 0x36, 0x5a, 0x8a, 0x26, 0xbd, 0x47, 0x12, 0x50, 0x9b,
    0xdf, 0xe6, 0xc0, 0x8a, 0xda, 0xe8, 0xf2, 0x02, 0x7a, 0xd0, 0x3e, 0x5c,
    0xdb, 0x7b, 0xb7, 0xc1, 0xa5, 0xc2, 0x6d, 0xe4, 0x50, 0xdd, 0xef, 0x6d,
    0x65, 0xf7, 0x7c, 0x05, 0xbb, 0xa2, 0xd3, 0x31, 0x63, 0x19, 0xdd, 0xbf,
    0x8b, 0x56, 0xa5, 0xf4, 0xf0, 0x50, 0x04, 0x51, 0x8a, 0xbe, 0x7f, 0x2b,
    0xd2, 0x71, 0x2e, 0x2b, 0x82, 0x6f, 0xff, 0x2e, 0xc5, 0xf9, 0x44, 0x28,
    0x43, 0x8c, 0xda, 0x54, 0x6b, 0x0e, 0xc9, 0xb6, 0x64, 0xb9, 0x02, 0x6a,
    0xe4, 0x09, 0x60, 0x2b, 0x05, 0x72, 0xe0, 0x4c, 0xe8, 0xa5, 0xee, 0x6a,
    0x17, 0xdf, 0x42, 0x06, 0x31, 0x13, 0x18, 0x82, 0x07, 0xb5, 0x8b, 0xa8,
    0x86, 0x15, 0x17, 0x67, 0xbd, 0xac, 0xcb, 0x94, 0x3f, 0xf4, 0x91, 0x90,
    0x11, 0x22, 0xcb, 0x36, 0x2c, 0x23, 0x1f, 0x4f, 0x7b, 0x0e, 0x25, 0xe2,
    0x6f, 0xe2, 0x6b, 0x29, 0xa6, 0x25, 0xb9, 0x59, 0x76, 0xae, 0x88, 0x07,
    0x94, 0x0f, 0x74, 0xdb, 0x54, 0x24, 0xd6, 0xd1, 0xa4, 0xd0, 0x55, 0x61,
    0xab, 0x74, 0xaa, 0xa9};
static char poet_n[256] = {
    0xb2, 0x4c, 0xb6, 0x1c, 0xc2, 0x0f, 0x37, 0x49, 0x76, 0xbf, 0x3d, 0xbb,
    0x82, 0x35, 0x6d, 0x6f, 0xd2, 0x79, 0xa9, 0x5f, 0xec, 0xaa, 0x6d, 0x1f,
    0x40, 0xed, 0x7f, 0xe0, 0xd3, 0x3b, 0x26, 0xe5, 0x24, 0x43, 0xc3, 0xd7,
    0xe5, 0xa3, 0x50, 0x03, 0x3b, 0x7f, 0x63, 0x1c, 0x89, 0xce, 0x7e, 0xa8,
    0xe1, 0xf2, 0xd4, 0x74, 0x84, 0x1d, 0x2b, 0xb0, 0x57, 0xa4, 0xa0, 0xdf,
    0x17, 0x6e, 0x2d, 0xee, 0xcd, 0x62, 0x02, 0xd4, 0xbb, 0x6d, 0x67, 0xd5,
    0xab, 0x9c, 0xd9, 0xd5, 0xe1, 0x54, 0xac, 0x81, 0x3c, 0x8a, 0xa6, 0x3d,
    0x24, 0xb1, 0x4f, 0xe8, 0x27, 0xc4, 0x9c, 0x3e, 0xe8, 0xbd, 0x21, 0x6a,
    0x5a, 0x06, 0x64, 0x27, 0x7c, 0xa9, 0x82, 0xdb, 0x4c, 0xa8, 0xfa, 0x24,
    0x44, 0xe6, 0x69, 0x4d, 0xdd, 0xfd, 0x8e, 0xb4, 0xcf, 0x17, 0xde, 0xba,
    0x16, 0x6b, 0x01, 0xd7, 0xef, 0x3a, 0x78, 0x30, 0x39, 0x24, 0x15, 0x38,
    0x59, 0x72, 0x74, 0x8e, 0xef, 0x4c, 0x6b, 0x1d, 0xef, 0xf0, 0xf8, 0x41,
    0xfa, 0x55, 0xfb, 0xef, 0x01, 0x7b, 0xd8, 0xe6, 0xa0, 0x54, 0x28, 0x0c,
    0x7c, 0xbe, 0x40, 0x8f, 0xde, 0x6a, 0x36, 0x09, 0x9e, 0x43, 0x05, 0x07,
    0x3e, 0x29, 0x01, 0x98, 0xfe, 0x04, 0x85, 0x84, 0x06, 0xdf, 0x09, 0xc3,
    0xf8, 0x4f, 0x19, 0x11, 0x07, 0x78, 0x4c, 0x90, 0x92, 0xba, 0xbb, 0xa5,
    0x63, 0xea, 0x60, 0x23, 0x11, 0xaa, 0x95, 0x8b, 0x97, 0xb3, 0x79, 0xeb,
    0x35, 0x5b, 0xe4, 0x60, 0x17, 0xb8, 0x82, 0x72, 0x1e, 0x94, 0xcb, 0xdb,
    0x67, 0x68, 0x1c, 0x88, 0x4d, 0x59, 0x9a, 0x29, 0x96, 0xa6, 0x2e, 0x34,
    0x3c, 0x1a, 0xcd, 0x7c, 0x5e, 0x7f, 0x4a, 0xff, 0xf4, 0x06, 0x4e, 0x60,
    0x01, 0x45, 0x76, 0x86, 0x8c, 0x1b, 0x31, 0x91, 0x24, 0x35, 0x75, 0x75,
    0xdf, 0xc2, 0x05, 0xdf};
static char poet_c[256] = {
    0x93, 0xba, 0xc2, 0xfd, 0x87, 0xf4, 0x29, 0x46, 0xac, 0x1b, 0x01, 0xb5,
    0x06, 0xe7, 0x5f, 0x32, 0xda, 0xc2, 0x9b, 0x30, 0x38, 0x09, 0xc8, 0x64,
    0x21, 0xa9, 0xd2, 0xea, 0xf2, 0xa9, 0x68, 0xb2, 0xda, 0x0c, 0xf2, 0xb7,
    0x49, 0x2d, 0x1c, 0x10, 0x6f, 0x08, 0x31, 0x25, 0x36, 0xb0, 0x4f, 0x2a,
    0x42, 0x23, 0x56, 0x53, 0xb3, 0x7b, 0x73, 0x5a, 0x53, 0x59, 0x36, 0xed,
    0x66, 0xb2, 0x07, 0x90, 0x89, 0x39, 0xd9, 0x98, 0x28, 0x11, 0x3b, 0x86,
    0x62, 0xc1, 0xdd, 0xec, 0x49, 0xd3, 0x62, 0x27, 0xe2, 0x6b, 0x1d, 0xcb,
    0x26, 0xad, 0x80, 0x8f, 0xff, 0xaa, 0x7b, 0xa1, 0x2e, 0xdf, 0x94, 0xfd,
    0x73, 0xbd, 0x78, 0xb8, 0x7c, 0x07, 0x66, 0xa8, 0x0d, 0xe3, 0xb5, 0xda,
    0x68, 0x63, 0x30, 0x87, 0x9d, 0x12, 0x34, 0x4e, 0x78, 0x2a, 0x3f, 0x94,
    0x7c, 0x2c, 0xd3, 0xd3, 0xbd, 0x65, 0xd0, 0x22, 0x96, 0x4e, 0xab, 0x04,
    0xd0, 0x8d, 0x75, 0x2a, 0xc6, 0x55, 0xce, 0x24, 0x8b, 0x7a, 0x3e, 0xd3,
    0x65, 0xcc, 0x77, 0x08, 0x0d, 0xfe, 0x61, 0x19, 0xe5, 0x9d, 0x5d, 0x45,
    0xe8, 0x34, 0x08, 0x63, 0x5d, 0x6d, 0xb3, 0x93, 0x4f, 0xa0, 0xf3, 0xc4,
    0xa0, 0x92, 0x64, 0x46, 0x82, 0x3f, 0x9c, 0xa7, 0x6e, 0x3e, 0x22, 0x79,
    0xf1, 0xd9, 0xc9, 0x08, 0x6b, 0x7e, 0x0f, 0x1b, 0xad, 0x3f, 0x17, 0xe9,
    0x29, 0x05, 0x4e, 0x5a, 0x07, 0x29, 0x00, 0x82, 0xbe, 0x8f, 0x9c, 0x57,
    0xc4, 0x26, 0x78, 0xa3, 0x7e, 0x78, 0x55, 0x35, 0x59, 0xf5, 0xbb, 0x99,
    0x63, 0x6e, 0xa7, 0xad, 0x07, 0x0a, 0x60, 0x3e, 0x68, 0xb0, 0x43, 0x30,
    0xa3, 0xe3, 0xca, 0x54, 0xd3, 0x5a, 0x1e, 0xb9, 0x41, 0xe9, 0xe7, 0x7a,
    0xa3, 0x4d, 0xd4, 0xe6, 0xc5, 0xcb, 0x5d, 0x21, 0xe0, 0xe4, 0xac, 0x2a,
    0xbb, 0xf3, 0x75, 0xef};
static char poem_s[256] = {
    0x8c, 0xc4, 0xf1, 0x86, 0xe7, 0x2c, 0x16, 0x01, 0xd5, 0x81, 0x6a, 0x21,
    0xc9, 0x5b, 0xcb, 0xcc, 0xc9, 0x28, 0x87, 0x4a, 0x3d, 0xc3, 0x75, 0xa7,
    0xf8, 0xcd, 0x9f, 0xf2, 0x9b, 0x84, 0xe1, 0xf9, 0x55, 0x3c, 0xcc, 0x52,
    0xb7, 0x45, 0x50, 0x7c, 0x29, 0xe7, 0x2f, 0x93, 0xbc, 0xff, 0x51, 0x42,
    0xb6, 0x9e, 0x4a, 0x01, 0x38, 0x2f, 0xc7, 0xd8, 0x20, 0xe6, 0x3a, 0xba,
    0xe5, 0xf2, 0x4d, 0x07, 0xd1, 0xde, 0x41, 0xc6, 0xb1, 0xd6, 0xfa, 0xd8,
    0xb6, 0xd5, 0x94, 0x25, 0x57, 0x05, 0x83, 0x3b, 0x06, 0xfe, 0xc7, 0x6c,
    0x28, 0xe2, 0x66, 0x4b, 0x45, 0xd8, 0xba, 0x31, 0x9a, 0x87, 0xea, 0xcf,
    0x72, 0x28, 0x16, 0x79, 0x1f, 0xe3, 0x0d, 0x18, 0xbf, 0xc7, 0xaa, 0xb7,
    0xf1, 0x2d, 0x10, 0x49, 0xef, 0xdd, 0x26, 0x2f, 0x68, 0x46, 0x93, 0x86,
    0xaa, 0xcc, 0xd5, 0xf8, 0xcb, 0xea, 0x6e, 0x6b, 0xde, 0x56, 0xeb, 0xb5,
    0x8c, 0x1c, 0x77, 0x17, 0x52, 0xce, 0x30, 0x8e, 0x4f, 0x61, 0x11, 0x2b,
    0x46, 0x98, 0xf5, 0xcb, 0xfd, 0xf8, 0x4a, 0x32, 0xb7, 0x25, 0xf4, 0xb4,
    0x16, 0x8c, 0x15, 0x6b, 0x3f, 0xf6, 0xe2, 0x9a, 0x08, 0x63, 0x80, 0x8a,
    0x24, 0x50, 0x2f, 0x7f, 0x32, 0x72, 0x15, 0x26, 0xb9, 0x4d, 0xec, 0x3e,
    0x47, 0x0c, 0x78, 0x53, 0x45, 0x21, 0xbd, 0x51, 0x2e, 0xc2, 0xa2, 0x4e,
    0x32, 0x11, 0xaf, 0x23, 0x7a, 0x3a, 0x0b, 0xfc, 0xb0, 0xaa, 0xc1, 0x60,
    0x5c, 0xfe, 0x5f, 0x0d, 0x3a, 0xee, 0x11, 0xec, 0xd0, 0x05, 0x12, 0x99,
    0xec, 0x1d, 0x93, 0xf9, 0x93, 0xfb, 0x59, 0x1a, 0xa5, 0x62, 0xe1, 0x26,
    0xbc, 0x86, 0x35, 0x7a, 0x87, 0x42, 0xad, 0xb7, 0xaf, 0x9c, 0xe4, 0xb0,
    0xf7, 0x63, 0x9e, 0x6e, 0x62, 0xc4, 0xd2, 0xfc, 0xda, 0x77, 0x66, 0x08,
    0xbc, 0x52, 0xe7, 0x72};
static char hidden[256] = {
    0x9e, 0x30, 0xaf, 0xde, 0xb6, 0x28, 0x3a, 0x34, 0xe1, 0xde, 0x6c, 0x4a,
    0xf0, 0x7f, 0x0b, 0x71, 0x95, 0xc8, 0x72, 0x1c, 0xed, 0xcc, 0xd4, 0x74,
    0x62, 0xed, 0xfb, 0x06, 0xb1, 0xc2, 0x86, 0x19, 0xdd, 0x03, 0xf2, 0xc6,
    0x86, 0x62, 0x4a, 0x65, 0x8a, 0xd9, 0x08, 0xa9, 0x6c, 0xf8, 0xf8, 0x31,
    0x03, 0xd9, 0x7b, 0x6d, 0x44, 0xa5, 0xce, 0x36, 0xd4, 0xd0, 0x35, 0x51,
    0x4f, 0x00, 0xab, 0x41, 0x26, 0x46, 0x7c, 0xc1, 0x54, 0x38, 0x0b, 0x46,
    0x53, 0x1a, 0x9a, 0x74, 0x91, 0xfd, 0x62, 0xe5, 0x32, 0xfa, 0x06, 0xf5,
    0xd9, 0xbe, 0x97, 0xb2, 0x49, 0x51, 0x1c, 0xdf, 0x6e, 0xdb, 0xde, 0x31,
    0xf3, 0x2d, 0x47, 0x96, 0x12, 0x23, 0x63, 0xbd, 0x27, 0x2f, 0xb0, 0x73,
    0x9b, 0xe6, 0xd6, 0x9c, 0x8b, 0x0e, 0xd8, 0x1b, 0xce, 0x49, 0xc6, 0x03,
    0xab, 0x97, 0x85, 0xbb, 0x54, 0x95, 0x4a, 0x79, 0x6f, 0x86, 0xfb, 0x09,
    0xb7, 0x24, 0x23, 0x8e, 0x34, 0x14, 0xd4, 0x99, 0x97, 0x1e, 0xa6, 0x76,
    0xd0, 0x47, 0xe0, 0x2b, 0xf1, 0x04, 0x5a, 0x03, 0x4e, 0xe5, 0xa8, 0xef,
    0xb0, 0xf6, 0x25, 0x74, 0x87, 0x25, 0xfd, 0x2d, 0xa2, 0xb5, 0x9b, 0xdb,
    0xcb, 0xe8, 0x16, 0xb9, 0xad, 0x53, 0x82, 0xfe, 0x1f, 0xe9, 0xed, 0xb2,
    0x3b, 0x32, 0x79, 0x91, 0xcd, 0x00, 0xbe, 0x8d, 0xf6, 0xcb, 0x5d, 0xb7,
    0x8e, 0xa2, 0x7e, 0x98, 0x65, 0xa8, 0x94, 0x31, 0x00, 0x2d, 0xa7, 0xd9,
    0x3d, 0x51, 0xc7, 0x86, 0x70, 0x38, 0x5c, 0x6a, 0xa9, 0x5c, 0x11, 0x13,
    0x71, 0xb9, 0xa2, 0x46, 0x4d, 0x88, 0x43, 0xdf, 0x02, 0x5a, 0x44, 0xb9,
    0xed, 0xc2, 0x25, 0x12, 0xac, 0x78, 0xc8, 0xdb, 0x8d, 0xc7, 0xb5, 0xf9,
    0x8e, 0xd4, 0x72, 0x4b, 0x8e, 0x05, 0x43, 0x48, 0xbd, 0x3f, 0x5a, 0x9b,
    0x70, 0xcd, 0xa8, 0xe4};

int main(void) {
    char e[RSAKEYSIZE / 8], d[RSAKEYSIZE / 8], n[RSAKEYSIZE / 8];
    char m[RSAKEYSIZE / 8], c[RSAKEYSIZE / 8], s[RSAKEYSIZE / 8];
    long x, y;
    int i, val, count;
    size_t len;
    clock_t start, end;
    double cpu_time;

    start = clock();
    /*
     * <RSA 키 생성 시험>
     * 길이는 RSAKEYSIZE 비트인 RSA 키를 생성한다.
     */
    rsa_generate_key(e, d, n, 1);
    printf("e = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", e[i]);
    printf("\nd = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", d[i]);
    printf("\nn = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", n[i]);
    printf("\n---\n");

    ////////////////////
    rsaes_oaep_encrypt("sample", 7, "", e, n, c, SHA224);
    return 0;
    ////////////////////
    /*
     * <기본 암복호화 시험>
     * 문자열 "sample data"를 암복호화한다. 널문자를 포함하여 길이가
     * 12바이트이다.
     */
    if ((val = rsaes_oaep_encrypt("sample data", 12, "", e, n, c,
                                  SHA512_224)) != 0) {
        printf("Encryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("c = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", c[i]);
    printf("\n");
    if ((val = rsaes_oaep_encrypt("sample data", 12, "", e, n, s,
                                  SHA512_224)) != 0) {
        printf("Encryption Error: %d -- FAILED\n", val);
        return 1;
    }
    if (memcmp(c, s, RSAKEYSIZE / 8) == 0) {
        printf("Seed may not be random -- FAILED\n");
        return 1;
    }
    if ((val = rsaes_oaep_decrypt(m, &len, "", d, n, c, SHA512_224)) != 0) {
        printf("Decryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("m = ");
    for (i = 0; i < (int)len; ++i) printf("%02hhx", m[i]);
    if (len == 12)
        printf("\nmsg = %s, len = %zu -- PASSED\n---\n", m, len);
    else {
        printf("\nmsg = %s, len = %zu -- FAILED\n", m, len);
        return 1;
    }

    /*
     * <긴 메시지 암복호화 시험>
     * RSA 키의 길이가 2048비트, 해시의 길이가 256비트일 때
     * 길이가 190바이트인 데이터를 암호화하고 복호화할 수 있어야 한다.
     */
    if ((val = rsaes_oaep_encrypt("max data", 190, "label", e, n, c,
                                  SHA512_256)) != 0) {
        printf("Encryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("c = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", c[i]);
    printf("\n");
    if ((val = rsaes_oaep_decrypt(m, &len, "label", d, n, c, SHA512_256)) !=
        0) {
        printf("Decryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("m = ");
    for (i = 0; i < (int)len; ++i) printf("%02hhx", m[i]);
    printf("\nmsg = %s, len = %zu -- PASSED\n---\n", m, len);

    /*
     * <너무 긴 메시지 암호화 시험>
     * RSA 키의 길이가 2048비트, 해시의 길이가 256비트일 때
     * 길이가 191바이트인 데이터를 암호화할 수 없다. PKCS_MSG_TOO_LONG 오류가
     * 발생해야 한다.
     */
    if ((val = rsaes_oaep_encrypt("max+ data", 191, "label", e, n, c,
                                  SHA256)) != 0)
        printf("Encryption Error: %d, message is too long -- PASSED\n---\n",
               val);
    else {
        printf("Fail to handle too long messages -- FAILED\n");
        exit(1);
    }

    /*
     * <빈 메시지 암호화 시험>
     * 빈 메시지를 암화화했다면 복호화할 때 메시지의 길이가 0이어야 한다.
     */
    if ((val = rsaes_oaep_encrypt("", 0, "label", e, n, c, SHA384)) != 0) {
        printf("Encryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("c = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", c[i]);
    printf("\n");
    if ((val = rsaes_oaep_decrypt(m, &len, "label", d, n, c, SHA384)) != 0) {
        printf("Decryption Error: %d -- FAILED\n", val);
        return 1;
    } else if (len != 0) {
        printf("Decryption Error: messgae length %zu is not zero -- FAILED\n",
               len);
        return 1;
    }
    printf("Empty message -- PASSED\n---\n");

    /*
     * <표준 방식을 준수했는지 검사하는 호환성 시험>
     * 암호문을 시인의 개인키로 복호화한 후 시인의 이름과 일치하는지 검사한다.
     * RSA 키의 길이는 2048비트이고, SHA224 해시함수를 사용해야 한다.
     */
    if ((val = rsaes_oaep_decrypt(m, &len, "korean poet", poet_d, poet_n,
                                  poet_c, SHA224)) != 0) {
        printf("Decryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("m = ");
    for (i = 0; i < (int)len; ++i) printf("%02hhx", m[i]);
    if (memcmp(m, poet, len)) {
        printf(" -- Compatibility Error -- FAILED\n");
        return 1;
    }
    m[len] = '\0';
    printf("\nmsg = %s, len = %zu -- PASSED\n", m, len);

    /*
     * 두번째 숨겨진 메시지를 복호화한다.
     * RSA 키의 길이는 2048비트이고, SHA512_224 해시함수를 사용해야 한다.
     */
    if ((val = rsaes_oaep_decrypt(m, &len, "Einstein", poet_d, poet_n, hidden,
                                  SHA512_224)) != 0) {
        printf("Decryption Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("msg = %s -- PASSED\n---\n", m);

    /*
     * <RSAES-OAEP 무작위 검사>
     */
    printf("RSAES-OAEP Random Testing");
    fflush(stdout);
    rsa_generate_key(e, d, n, 0);
    count = 0;
    do {
        arc4random_buf(&x, sizeof(long));
        if ((val = rsaes_oaep_encrypt(&x, sizeof(long), "label", e, n, c,
                                      count % 6)) != 0) {
            printf("Encryption Error: %d -- FAILED\n", val);
            return 1;
        }
        if ((val = rsaes_oaep_decrypt(&y, &len, "label", d, n, c, count % 6)) !=
            0) {
            printf("Decryption Error: %d -- FAILED\n", val);
            return 1;
        }
        if (x != y) {
            printf("Error: x is not equal to y -- FAILED\n");
            return 1;
        }
        if (len != sizeof(long)) {
            printf("Error: len = %zu -- FAILED\n", len);
            return 1;
        }
        if (++count % 0xff == 0) {
            printf(".");
            fflush(stdout);
        }
    } while (count < 0x5fff);
    printf("No error found! -- PASSED\n---\n");

    /*
     * <기본 서명 생성과 검증>
     * 문자열 "sample"을 개인키로 서명하고 공개키로 검증한다.
     */
    rsa_generate_key(e, d, n, 1);
    if ((val = rsassa_pss_sign("sample", 6, d, n, s, SHA512_224)) != 0) {
        printf("Signature Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("s = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", s[i]);
    printf("\n");
    if ((val = rsassa_pss_sign("sample", 6, d, n, c, SHA512_224)) != 0) {
        printf("Signature Error: %d -- FAILED\n", val);
        return 1;
    }
    if (memcmp(c, s, RSAKEYSIZE / 8) == 0) {
        printf("Salt may not be random -- FAILED\n");
        return 1;
    }
    if ((val = rsassa_pss_verify("sample", 6, e, n, s, SHA512_224)) != 0) {
        printf("Verification Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("Valid Signature! -- PASSED\n---\n");

    /*
     * <해시함수 입력 길이 검사>
     * 해시함수가 허용하는 메시지의 최대 길이를 초과한 경우를 시험한다.
     */
    if ((val = rsassa_pss_verify("sample", 0x2000000000000000, e, n, s,
                                 SHA256)) != 0)
        printf("Hash Input Error: %d -- PASSED\n---\n", val);
    else {
        printf("Hash Input Error -- FAILED\n");
        return 1;
    }
    /*
     * <서명과 검증 메시지 불일치 시험>
     * 서명은 문자열 "invalid sample"에 하고 검증은 "invalid_sample"에 한다.
     */
    if ((val = rsassa_pss_sign("invalid sample", 14, d, n, s, SHA512_256)) !=
        0) {
        printf("Signature Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("s = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", s[i]);
    printf("\n");
    if ((val = rsassa_pss_verify("invalid_sample", 14, e, n, s, SHA512_256)) !=
        0)
        printf("Verification Error: %d, invalid signature -- PASSED\n---\n",
               val);
    else {
        printf("Verification Error -- FAILED\n");
        return 1;
    }

    /*
     * <검증키 불일치 시험>
     * 올바르지 않은 검증키를 사용해서 서명 검증을 시도한다.
     */
    if ((val = rsassa_pss_sign("sample", 6, e, n, s, SHA384)) != 0) {
        printf("Signature Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("s = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", s[i]);
    printf("\n");
    if ((val = rsassa_pss_verify("sample", 6, e, n, s, SHA384)) != 0)
        printf("Verification Error: %d -- PASSED\n---\n", val);
    else {
        printf("Logic Error! -- FAILED\n");
        return 1;
    }

    /*
     * <변경된 서명 값 시험>
     * 서명 값을 생성한 후 앞부분 2바이트를 0으로 바꾼 후 검증을 시도한다.
     */
    if ((val = rsassa_pss_sign("It always seems impossible until it is done.",
                               44, d, n, s, SHA224)) != 0) {
        printf("Signature Error: %d -- FAILED\n", val);
        return 1;
    }
    s[0] = s[1] = 0;
    printf("s = ");
    for (i = 0; i < RSAKEYSIZE / 8; ++i) printf("%02hhx", s[i]);
    printf("\n");
    if ((val = rsassa_pss_verify("It always seems impossible until it is done.",
                                 44, e, n, s, SHA224)) != 0)
        printf("Verification Error: %d -- PASSED\n---\n", val);
    else {
        printf("Logic Error! -- FAILED\n");
        return 1;
    }

    /*
     * <표준 방식을 준수했는지 검사하는 호환성 시험>
     * 시인의 개인키로 서명된 시를 시인의 공개키로 검증한다.
     * RSA 키의 길이는 2048비트이고, SHA256 해시함수를 사용해야 한다.
     */
    if ((val = rsassa_pss_verify(poem, strlen(poem), poet_e, poet_n, poem_s,
                                 SHA256)) != 0) {
        printf("Compatibility Error: %d -- FAILED\n", val);
        return 1;
    }
    printf("Compatible Signature Verification! -- PASSED\n---\n");

    /*
     * <RSASSA-PSS 무작위 검사>
     */
    printf("RSASSA-PSS Random Testing");
    fflush(stdout);
    rsa_generate_key(e, d, n, 0);
    count = 0;
    do {
        arc4random_buf(&x, sizeof(long));
        if ((val = rsassa_pss_sign(&x, sizeof(long), d, n, s, count % 6)) !=
            0) {
            printf("Signature Error: %d -- terminated\n", val);
            return 1;
        }
        if ((val = rsassa_pss_verify(&x, sizeof(long), e, n, s, count % 6)) !=
            0) {
            printf("Verification Error: %d -- terminated\n", val);
            return 1;
        }
        if (++count % 0xff == 0) {
            printf(".");
            fflush(stdout);
        }
    } while (count < 0x5fff);
    printf("No error found! -- PASSED\n");

    end = clock();
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("CPU 사용시간 = %.4f초\n", cpu_time);

    return 0;
}
