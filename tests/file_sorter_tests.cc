/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **/

#include "couchstore_config.h"

#include "../src/file_sorter.h"
#include "macros.h"
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNSORTED_FILE_PATH "unsorted_file.data"
#define SORT_TMP_DIR "."

static const int data[] = {
        661,  900,  596,  881,  118,  494,  638,  814,  206,  1217, 160,  504,
        259,  1038, 125,  849,  168,  216,  1002, 438,  726,  1156, 1162, 1210,
        933,  320,  273,  1176, 516,  810,  957,  134,  348,  1173, 415,  266,
        920,  392,  213,  958,  135,  892,  171,  293,  829,  447,  524,  520,
        426,  866,  384,  562,  620,  1112, 220,  860,  446,  819,  1066, 508,
        375,  232,  947,  846,  127,  165,  759,  1196, 937,  421,  1005, 963,
        629,  1058, 35,   917,  636,  543,  938,  1021, 611,  582,  397,  329,
        648,  84,   1200, 1143, 1076, 1192, 27,   274,  1123, 1006, 46,   836,
        868,  1150, 718,  1061, 1171, 349,  450,  493,  1157, 970,  111,  668,
        178,  359,  692,  663,  1064, 100,  678,  1023, 150,  783,  1015, 62,
        1124, 506,  1168, 393,  1083, 894,  591,  529,  11,   51,   422,  475,
        200,  1195, 519,  408,  16,   761,  950,  869,  746,  922,  271,  439,
        433,  784,  141,  762,  749,  99,   1054, 872,  1087, 583,  828,  1216,
        117,  850,  419,  991,  891,  627,  835,  381,  391,  297,  202,  73,
        224,  1099, 223,  921,  733,  771,  197,  436,  1152, 727,  870,  357,
        1114, 343,  7,    729,  145,  308,  941,  1053, 1161, 276,  724,  1069,
        853,  734,  131,  987,  1081, 559,  1118, 91,   477,  976,  396,  1180,
        366,  874,  251,  635,  852,  622,  988,  693,  1075, 1085, 208,  1137,
        1154, 264,  647,  341,  962,  474,  56,   1197, 839,  1004, 268,  371,
        270,  766,  364,  52,   705,  90,   428,  1129, 1108, 672,  24,   862,
        1011, 96,   600,  986,  1145, 1194, 34,   104,  137,  69,   247,  218,
        20,   187,  885,  63,   186,  755,  687,  575,  775,  282,  602,  299,
        943,  53,   183,  978,  471,  122,  389,  40,   61,   1204, 592,  227,
        345,  334,  617,  742,  676,  1191, 683,  1078, 700,  1159, 103,  431,
        1105, 538,  456,  210,  21,   568,  350,  544,  710,  579,  1453, 1378,
        1348, 1319, 1425, 1261, 1333, 1419, 1482, 1499, 1360, 1267, 1451, 1417,
        1265, 1416, 1427, 1329, 1332, 1287, 1359, 1223, 1262, 1492, 1324, 1278,
        1318, 1235, 1286, 1420, 1219, 1367, 1382, 1328, 1229, 1237, 1396, 1409,
        1236, 1298, 1302, 1459, 1271, 1430, 1246, 1282, 1350, 1299, 1325, 1345,
        1322, 1323, 1234, 1245, 1424, 1291, 1486, 1500, 1357, 1394, 1468, 1444,
        1493, 1330, 1273, 1268, 1300, 1498, 1490, 1257, 1343, 1320, 1458, 1294,
        1386, 1308, 1230, 1281, 1392, 1341, 1411, 1388, 1475, 1445, 1311, 1403,
        1344, 1252, 1362, 1377, 1436, 1407, 1327, 1225, 1276, 1440, 1354, 1480,
        1387, 1421, 1331, 1321, 1503, 1402, 1240, 1375, 1438, 1347, 1342, 1264,
        1288, 1488, 1275, 1243, 1380, 1460, 1248, 1254, 1244, 1272, 1304, 1352,
        1452, 1485, 1233, 1253, 1435, 1469, 1307, 1431, 1358, 1462, 1434, 1501,
        1389, 1372, 1391, 1479, 1401, 1270, 1338, 1363, 1306, 1364, 1249, 1303,
        1406, 1450, 1353, 1222, 1274, 1484, 1346, 1335, 1231, 1494, 1412, 1463,
        1337, 1376, 1428, 1466, 1433, 1310, 1368, 1383, 1400, 1293, 1242, 1371,
        1393, 1260, 1442, 1220, 1283, 1258, 1477, 1361, 1351, 1285, 1495, 1226,
        1410, 1397, 1256, 1414, 1472, 1284, 1218, 1399, 1314, 1297, 1385, 1465,
        1390, 1443, 1461, 1301, 1464, 1384, 1449, 1266, 1446, 1478, 1405, 1356,
        1250, 1373, 1309, 1255, 1340, 1423, 1413, 1224, 1315, 1447, 1365, 1415,
        1355, 1239, 1317, 1374, 1277, 1238, 1221, 1296, 1251, 1336, 1269, 1489,
        1491, 1370, 1437, 1441, 1481, 1305, 1316, 1496, 1502, 1290, 1334, 1295,
        1471, 1448, 1422, 1247, 1487, 1455, 1483, 1408, 1395, 1418, 1432, 1404,
        1326, 1457, 1470, 1456, 1313, 1349, 1312, 1228, 1369, 1292, 1263, 1454,
        1280, 1381, 1474, 1289, 1476, 1426, 1279, 1429, 1473, 1467, 1366, 1398,
        1227, 1339, 1232, 1379, 1259, 1439, 1241, 1497, 157,  930,  702,  207,
        1084, 625,  1100, 542,  879,  573,  425,  188,  1012, 55,   344,  77,
        1107, 1207, 1103, 281,  123,  863,  847,  32,   1205, 806,  159,  757,
        6,    307,  1027, 1032, 237,  162,  598,  241,  563,  521,  72,   97,
        1203, 116,  696,  317,  453,  129,  969,  33,   777,  594,  115,  442,
        953,  511,  682,  476,  369,  310,  468,  164,  373,  763,  1160, 555,
        1174, 915,  532,  1048, 198,  1208, 557,  240,  1151, 858,  361,  1198,
        283,  518,  64,   840,  245,  721,  876,  1136, 951,  1018, 788,  296,
        838,  946,  925,  634,  539,  1127, 175,  483,  253,  1056, 86,   626,
        540,  756,  142,  708,  689,  646,  764,  1122, 203,  679,  398,  211,
        13,   531,  18,   1022, 66,   842,  1202, 400,  437,  1102, 816,  657,
        944,  1116, 509,  336,  410,  76,   798,  912,  904,  278,  688,  1172,
        1045, 979,  136,  934,  14,   968,  716,  738,  380,  588,  554,  399,
        1178, 205,  902,  230,  707,  737,  472,  671,  808,  57,   382,  286,
        666,  1164, 765,  871,  1098, 98,   536,  10,   413,  105,  1169, 313,
        458,  821,  658,  650,  301,  440,  25,   1063, 1167, 1155, 525,  38,
        945,  550,  774,  479,  1133, 723,  898,  703,  1109, 901,  172,  260,
        972,  394,  1209, 653,  769,  505,  748,  1187, 1072, 1179, 457,  499,
        1033, 466,  156,  1186, 526,  507,  189,  337,  940,  1094, 1029, 287,
        138,  124,  785,  985,  865,  631,  610,  395,  667,  939,  980,  590,
        1090, 368,  1214, 153,  409,  214,  1057, 95,   256,  451,  388,  948,
        151,  1211, 121,  387,  642,  1020, 551,  414,  864,  1034, 811,  363,
        226,  851,  444,  130,  492,  290,  435,  1039, 78,   1074, 107,  577,
        452,  548,  386,  490,  616,  952,  1016, 318,  607,  50,   1170, 621,
        706,  942,  751,  736,  155,  416,  424,  929,  877,  528,  574,  834,
        252,  491,  699,  1013, 262,  17,   429,  719,  656,  79,   385,  832,
        463,  924,  744,  1138, 996,  637,  911,  29,   147,  833,  1135, 725,
        109,  1183, 179,  166,  728,  12,   47,   31,   1095, 402,  931,  897,
        906,  9,    1163, 530,  244,  780,  500,  23,   903,  830,  354,  427,
        83,   586,  60,   106,  778,  487,  352,  303,  1128, 502,  54,   246,
        730,  571,  430,  709,  975,  1003, 152,  1043, 465,  560,  215,  861,
        608,  434,  263,  81,   1082, 1071, 460,  895,  731,  643,  695,  423,
        70,   997,  316,  527,  1017, 623,  248,  441,  404,  522,  101,  831,
        907,  919,  180,  691,  181,  279,  817,  845,  965,  379,  722,  319,
        793,  1014, 813,  886,  45,   752,  681,  698,  995,  1199, 584,  677,
        743,  561,  803,  28,   1126, 71,   974,  143,  1091, 908,  298,  374,
        792,  217,  645,  192,  501,  541,  510,  1077, 802,  254,  685,  82,
        110,  630,  534,  768,  1026, 790,  291,  228,  503,  280,  173,  229,
        328,  325,  690,  674,  149,  1131, 1041, 741,  85,   1111, 243,  1079,
        873,  406,  139,  1080, 119,  401,  332,  67,   546,  411,  893,  652,
        604,  300,  15,   512,  789,  641,  1134, 801,  1009, 796,  1132, 1067,
        1215, 570,  261,  1184, 747,  704,  250,  1110, 890,  959,  701,  1030,
        201,  883,  1093, 1042, 694,  495,  1181, 285,  322,  443,  480,  306,
        498,  132,  781,  578,  960,  30,   887,  321,  859,  174,  432,  1141,
        351,  8,    1140, 1130, 330,  448,  65,   484,  1146, 1125, 613,  1153,
        489,  185,  720,  128,  662,  5,    370,  1088, 339,  715,  896,  454,
        49,   234,  609,  212,  1001, 889,  204,  177,  779,  552,  684,  984,
        880,  473,  935,  405,  258,  566,  1051, 1189, 338,  74,   462,  1182,
        1044, 191,  993,  169,  805,  664,  1206, 1046, 221,  639,  44,   927,
        88,   1055, 323,  140,  309,  576,  1148, 717,  114,  928,  225,  327,
        824,  867,  606,  910,  844,  739,  2,    1201, 19,   269,  497,  797,
        488,  265,  644,  469,  856,  587,  331,  87,   649,  68,   916,  360,
        572,  1101, 376,  711,  1089, 955,  449,  564,  1139, 112,  353,  686,
        818,  1190, 712,  556,  651,  595,  1193, 144,  913,  1025, 787,  158,
        553,  558,  966,  346,  961,  1068, 753,  37,   983,  113,  120,  461,
        899,  1060, 760,  567,  284,  994,  378,  231,  990,  1147, 514,  655,
        800,  1121, 1028, 39,   619,  517,  654,  815,  754,  882,  614,  825,
        1113, 827,  355,  342,  549,  1000, 884,  513,  673,  714,  956,  812,
        182,  347,  1008, 804,  981,  1117, 1,    304,  547,  75,   184,  1024,
        971,  496,  1073, 597,  170,  255,  272,  1188, 275,  1175, 914,  823,
        445,  26,   1185, 219,  794,  242,  954,  92,   697,  633,  855,  470,
        1104, 982,  640,  1144, 786,  1050, 407,  89,   417,  22,   59,   848,
        277,  267,  669,  909,  412,  773,  888,  235,  176,  973,  964,  675,
        843,  601,  791,  199,  545,  593,  133,  324,  589,  660,  315,  193,
        467,  326,  875,  999,  167,  1019, 878,  1115, 478,  209,  1106, 126,
        239,  148,  770,  822,  998,  485,  305,  580,  1007, 1047, 809,  841,
        1177, 195,  826,  420,  356,  732,  455,  992,  758,  1086, 1120, 367,
        390,  335,  776,  362,  585,  857,  340,  767,  1092, 624,  713,  333,
        745,  1065, 196,  383,  1142, 807,  154,  236,  294,  257,  1035, 58,
        222,  967,  233,  249,  535,  820,  599,  481,  612,  618,  1031, 782,
        1166, 302,  837,  565,  605,  905,  94,   1037, 48,   108,  680,  1049,
        670,  936,  932,  1062, 36,   615,  750,  1165, 795,  194,  358,  3,
        163,  80,   288,  740,  1119, 311,  1040, 464,  1036, 581,  735,  372,
        923,  482,  537,  628,  289,  977,  1096, 295,  1097, 418,  93,   926,
        569,  949,  312,  772,  292,  41,   1149, 1070, 799,  4,    1212, 365,
        918,  190,  632,  102,  459,  533,  1010, 989,  523,  1213, 1059, 377,
        403,  515,  314,  1052, 665,  1158, 238,  43,   161,  486,  854,  659,
        42,   603,  146};

static int sorted_data[sizeof(data) / sizeof(data[0])];

static int read_record(FILE* f, void** buffer, void* ctx) {
    int* rec = (int*)cb_malloc(sizeof(int));
    (void)ctx;

    if (rec == nullptr) {
        return FILE_MERGER_ERROR_ALLOC;
    }

    if (fread(rec, sizeof(int), 1, f) != 1) {
        cb_free(rec);
        if (feof(f)) {
            return 0;
        } else {
            return FILE_MERGER_ERROR_FILE_READ;
        }
    }

    *buffer = rec;

    return sizeof(int);
}

static file_merger_error_t write_record(FILE* f, void* buffer, void* ctx) {
    (void)ctx;

    if (fwrite(buffer, sizeof(int), 1, f) != 1) {
        return FILE_MERGER_ERROR_FILE_WRITE;
    }

    return FILE_MERGER_SUCCESS;
}

static int compare_records(const void* rec1, const void* rec2, void* ctx) {
    (void)ctx;

    return *((const int*)rec1) - *((const int*)rec2);
}

static void free_record(void* rec, void* ctx) {
    (void)ctx;

    cb_free(rec);
}

static int check_file_sorted(const char* file_path) {
    FILE* f;
    void* record = nullptr;
    int record_size;
    unsigned nrecords = (unsigned)(sizeof(data) / sizeof(int));
    unsigned i;

    f = fopen(file_path, "rb");
    cb_assert(f != nullptr);

    for (i = 0; i < nrecords; ++i) {
        record_size = read_record(f, &record, nullptr);
        cb_assert(record_size == sizeof(int));
        if (*((int*)record) != sorted_data[i]) {
            fclose(f);
            free_record(record, nullptr);
            return 0;
        }
        free_record(record, nullptr);
    }

    /* Check file has no extra (duplicated or garbage) records. */
    cb_assert(read_record(f, &record, nullptr) == 0);

    fclose(f);

    return 1;
}

static void create_file() {
    unsigned i;
    FILE* f;

    remove(UNSORTED_FILE_PATH);
    f = fopen(UNSORTED_FILE_PATH, "ab");
    cb_assert(f != nullptr);

    for (i = 0; i < (sizeof(data) / sizeof(int)); ++i) {
        cb_assert(fwrite(&data[i], sizeof(int), 1, f) == 1);
    }

    fclose(f);
}

static file_merger_error_t check_sorted_callback(void* buf, void* ctx) {
    int *rec = (int*)buf, *i = (int*)ctx;
    cb_assert(sorted_data[*i] == *rec);
    (*i)++;

    return FILE_MERGER_SUCCESS;
}

static void test_file_sort(unsigned buffer_size,
                           unsigned temp_files,
                           file_merger_feed_record_t callback,
                           int skip_writeback) {
    file_sorter_error_t ret;
    int i = 0;
    create_file();

    ret = sort_file(UNSORTED_FILE_PATH,
                    SORT_TMP_DIR,
                    temp_files,
                    buffer_size,
                    read_record,
                    write_record,
                    callback,
                    compare_records,
                    free_record,
                    skip_writeback,
                    &i);

    cb_assert(ret == FILE_SORTER_SUCCESS);

    if (!skip_writeback) {
        cb_assert(check_file_sorted(UNSORTED_FILE_PATH));
    } else {
        cb_assert(check_file_sorted(UNSORTED_FILE_PATH) == 0);
    }

    remove(UNSORTED_FILE_PATH);
}

static int int_cmp(const void* a, const void* b) {
    return *((const int*)a) - *((const int*)b);
}

int main(void) {
    const unsigned temp_files[] = {2, 3, 4, 5, 6, 7, 8, 9, 10};
    const unsigned buffer_sizes[] = {sizeof(int) * 2,
                                     sizeof(int) * 3,
                                     (sizeof(int) - 1) * 7,
                                     sizeof(int) * 10,
                                     (sizeof(int) - 1) * 19,
                                     sizeof(int) * 33,
                                     (sizeof(int) - 1) * 99,
                                     sizeof(int) * 1000000};

    unsigned i, j;
    unsigned long nrecords = (unsigned long)(sizeof(data) / sizeof(int));

    fprintf(stderr, "Running file sorter tests...\n");

    memcpy(sorted_data, data, sizeof(data));
    qsort(sorted_data, nrecords, sizeof(int), int_cmp);

    for (i = 0; i < (sizeof(buffer_sizes) / sizeof(unsigned)); ++i) {
        for (j = 0; j < (sizeof(temp_files) / sizeof(unsigned)); ++j) {
            fprintf(stderr,
                    "Testing file sort (%lu records) with buffer size of %u "
                    "bytes"
                    " and %u temporary files\n",
                    nrecords,
                    buffer_sizes[i],
                    temp_files[j]);
            test_file_sort(buffer_sizes[i], temp_files[j], nullptr, 0);
        }
    }

    fprintf(stderr,
            "Testing file sort callback (%lu records) with buffer size of %lu "
            "bytes"
            " and %u temporary files\n",
            nrecords,
            sizeof(int) * 501,
            3);
    test_file_sort(sizeof(int) * 501, 3, check_sorted_callback, 0);

    fprintf(stderr,
            "Testing file sort callback (%lu records) with buffer size of %lu "
            "bytes"
            " and %u temporary files\n",
            nrecords,
            sizeof(int) * 50,
            10);
    test_file_sort(sizeof(int) * 50, 10, check_sorted_callback, 0);

    fprintf(stderr,
            "Testing file sort callback with skip writeback (%lu records)"
            "with buffer size of %lu bytes and %u temporary files\n",
            nrecords,
            sizeof(int) * 501,
            3);
    test_file_sort(sizeof(int) * 501, 3, check_sorted_callback, 1);

    fprintf(stderr,
            "Testing file sort callback with skip writeback (%lu records)"
            "with buffer size of %lu bytes and %u temporary files\n",
            nrecords,
            sizeof(int) * 50,
            10);
    test_file_sort(sizeof(int) * 50, 10, check_sorted_callback, 1);

    fprintf(stderr, "File sorter tests passed\n\n");
    return 0;
}
