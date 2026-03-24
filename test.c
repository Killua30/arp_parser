#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "arp.h"

#define ck_assert_strstr(haystack, needle) \
    do { \
        const char *__hay = (haystack); \
        const char *__nee = (needle); \
        ck_assert_ptr_nonnull(__hay); \
        ck_assert_msg(strstr(__hay, __nee) != NULL, \
                     "Assertion '%s' contains '%s' failed: '%s'", \
                     #haystack, #needle, __hay); \
    } while(0)

static const uint8_t test_arp_packet[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x08, 0x00, 0x27, 0x12, 0x34, 0x56, 0xC0, 0xA8,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x02
};

static char *capture_stdout(void (*func)(const struct arp_packet *), 
                           const struct arp_packet *packet) {
    int pipefd[2];
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    if (pipe(pipefd) == -1) {
        free(buffer);
        return NULL;
    }
    int stdout_fd = dup(STDOUT_FILENO);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    func(packet);
    fflush(stdout);
    dup2(stdout_fd, STDOUT_FILENO);
    close(stdout_fd);
    ssize_t n = read(pipefd[0], buffer, 4095);
    if (n < 0) n = 0;
    buffer[n] = '\0';
    close(pipefd[0]);
    
    return buffer;
}

// ==================== parse_arp tests ====================

START_TEST(test_parse_arp_valid_packet) {
    uint8_t test_data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xC0, 0xA8, 0x01, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xC0, 0xA8, 0x01, 0x02,
    };
    
    struct arp_packet packet;
    int result = parse_arp(test_data, sizeof(test_data), &packet);
    
    ck_assert_int_eq(result, 0);

    printf("\n--- %s: Parsed packet ---\n", __func__);
    print_arp(&packet);
    printf("--- End of packet ---\n\n");
    
    ck_assert_int_eq(packet.htype, 0x0001);
    ck_assert_int_eq(packet.ptype, 0x0800);
    ck_assert_int_eq(packet.hsize, 6);
    ck_assert_int_eq(packet.psize, 4);
    ck_assert_int_eq(packet.op, 0x0001);
    
    ck_assert_int_eq(packet.sha[0], 0xAA);
    ck_assert_int_eq(packet.sha[1], 0xBB);
    ck_assert_int_eq(packet.sha[2], 0xCC);
    ck_assert_int_eq(packet.sha[3], 0xDD);
    ck_assert_int_eq(packet.sha[4], 0xEE);
    ck_assert_int_eq(packet.sha[5], 0xFF);
    
    ck_assert_int_eq(packet.spa[0], 0xC0);
    ck_assert_int_eq(packet.spa[1], 0xA8);
    ck_assert_int_eq(packet.spa[2], 0x01);
    ck_assert_int_eq(packet.spa[3], 0x01);
    
    ck_assert_int_eq(packet.tha[0], 0x11);
    ck_assert_int_eq(packet.tha[1], 0x22);
    ck_assert_int_eq(packet.tha[2], 0x33);
    ck_assert_int_eq(packet.tha[3], 0x44);
    ck_assert_int_eq(packet.tha[4], 0x55);
    ck_assert_int_eq(packet.tha[5], 0x66);
    
    ck_assert_int_eq(packet.tpa[0], 0xC0);
    ck_assert_int_eq(packet.tpa[1], 0xA8);
    ck_assert_int_eq(packet.tpa[2], 0x01);
    ck_assert_int_eq(packet.tpa[3], 0x02);
}
END_TEST

START_TEST(test_parse_arp_reply_packet) {
    uint8_t test_data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xC0, 0xA8, 0x01, 0x02,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xC0, 0xA8, 0x01, 0x01,
    };
    
    struct arp_packet packet;
    int result = parse_arp(test_data, sizeof(test_data), &packet);
    
    ck_assert_int_eq(result, 0);
    
    printf("\n--- %s: Parsed packet ---\n", __func__);
    print_arp(&packet);
    printf("--- End of packet ---\n\n");
    
    ck_assert_int_eq(packet.op, 0x0002);
}
END_TEST

START_TEST(test_parse_arp_null_pointer) {
    uint8_t test_data[28] = {0};
    struct arp_packet packet;
    
    ck_assert_int_eq(parse_arp(NULL, sizeof(test_data), &packet), -1);
    ck_assert_int_eq(parse_arp(test_data, sizeof(test_data), NULL), -1);
    
    printf("\n--- %s: NULL pointer test passed ---\n\n", __func__);
}
END_TEST

START_TEST(test_parse_arp_insufficient_length) {
    uint8_t test_data[20] = {0};
    struct arp_packet packet;
    
    ck_assert_int_eq(parse_arp(test_data, 10, &packet), -1);
    ck_assert_int_eq(parse_arp(test_data, 27, &packet), -1);
    
    printf("\n--- %s: Insufficient length test passed ---\n\n", __func__);
}
END_TEST

START_TEST(test_parse_arp_exact_minimum_length) {
    uint8_t test_data[28] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    struct arp_packet packet;
    int result = parse_arp(test_data, sizeof(test_data), &packet);
    
    ck_assert_int_eq(result, 0);
    
    printf("\n--- %s: Parsed packet (minimum length) ---\n", __func__);
    print_arp(&packet);
    printf("--- End of packet ---\n\n");
    
    ck_assert_int_eq(packet.htype, 0x0001);
    ck_assert_int_eq(packet.ptype, 0x0800);
}
END_TEST

START_TEST(test_parse_arp_max_values) {
    uint8_t test_data[28];
    
    for (int i = 0; i < 28; i++) {
        test_data[i] = 0xFF;
    }
    
    struct arp_packet packet;
    int result = parse_arp(test_data, 28, &packet);
    
    ck_assert_int_eq(result, 0);
    
    printf("\n--- %s: Parsed packet (max values) ---\n", __func__);
    print_arp(&packet);
    printf("--- End of packet ---\n\n");
    
    ck_assert_int_eq(packet.htype, 0xFFFF);
    ck_assert_int_eq(packet.ptype, 0xFFFF);
    ck_assert_int_eq(packet.hsize, 0xFF);
    ck_assert_int_eq(packet.psize, 0xFF);
    ck_assert_int_eq(packet.op, 0xFFFF);
    
    for (int i = 0; i < 6; i++) {
        ck_assert_int_eq(packet.sha[i], 0xFF);
        ck_assert_int_eq(packet.tha[i], 0xFF);
    }
    for (int i = 0; i < 4; i++) {
        ck_assert_int_eq(packet.spa[i], 0xFF);
        ck_assert_int_eq(packet.tpa[i], 0xFF);
    }
}
END_TEST

// ==================== print_arp tests ====================

START_TEST(test_print_arp_valid_packet) {
    struct arp_packet packet = {
        .htype = 0x0001,
        .ptype = 0x0800,
        .hsize = 6,
        .psize = 4,
        .op = 0x0001,
        .sha = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .spa = {192, 168, 1, 1},
        .tha = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
        .tpa = {192, 168, 1, 2}
    };
    
    printf("\n--- %s: Original packet ---\n", __func__);
    print_arp(&packet);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "ARP Packet:");
    ck_assert_strstr(output, "Hardware type:");
    ck_assert_strstr(output, "Hardware size: 6");
    ck_assert_strstr(output, "Protocol size: 4");
    ck_assert_strstr(output, "Sender MAC address: aa:bb:cc:dd:ee:ff");
    ck_assert_strstr(output, "Sender IP address: 192.168.1.1");
    ck_assert_strstr(output, "Target MAC address: 11:22:33:44:55:66");
    ck_assert_strstr(output, "Target IP address: 192.168.1.2");
    
    free(output);
}
END_TEST

START_TEST(test_print_arp_reply_packet) {
    struct arp_packet packet = {
        .htype = 0x0001,
        .ptype = 0x0800,
        .hsize = 6,
        .psize = 4,
        .op = 0x0002,
        .sha = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
        .spa = {192, 168, 1, 2},
        .tha = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .tpa = {192, 168, 1, 1}
    };
    
    printf("\n--- %s: Original packet ---\n", __func__);
    print_arp(&packet);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "Operation:");
    ck_assert_strstr(output, "Sender MAC address: 11:22:33:44:55:66");
    ck_assert_strstr(output, "Target MAC address: aa:bb:cc:dd:ee:ff");
    
    free(output);
}
END_TEST

START_TEST(test_print_arp_zero_values) {
    struct arp_packet packet = {0};
    
    printf("\n--- %s: Original packet ---\n", __func__);
    print_arp(&packet);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "Hardware type:");
    ck_assert_strstr(output, "Hardware size: 0");
    ck_assert_strstr(output, "Protocol size: 0");
    ck_assert_strstr(output, "Sender MAC address: 00:00:00:00:00:00");
    ck_assert_strstr(output, "Sender IP address: 0.0.0.0");
    
    free(output);
}
END_TEST

START_TEST(test_print_arp_max_values) {
    struct arp_packet packet;
    
    packet.htype = 0xFFFF;
    packet.ptype = 0xFFFF;
    packet.hsize = 0xFF;
    packet.psize = 0xFF;
    packet.op = 0xFFFF;
    
    for (int i = 0; i < 6; i++) {
        packet.sha[i] = 0xFF;
        packet.tha[i] = 0xFF;
    }
    for (int i = 0; i < 4; i++) {
        packet.spa[i] = 0xFF;
        packet.tpa[i] = 0xFF;
    }
    
    printf("\n--- %s: Original packet ---\n", __func__);
    print_arp(&packet);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "Hardware type:");
    ck_assert_strstr(output, "Hardware size: 255");
    ck_assert_strstr(output, "Sender MAC address: ff:ff:ff:ff:ff:ff");
    ck_assert_strstr(output, "Sender IP address: 255.255.255.255");
    
    free(output);
}
END_TEST

START_TEST(test_print_arp_null_packet) {
    printf("\n--- %s: Testing NULL packet ---\n", __func__);
    
    char *output = capture_stdout(print_arp, NULL);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    free(output);
}
END_TEST

START_TEST(test_print_arp_special_addresses) {
    struct arp_packet packet = {
        .htype = 0x0001,
        .ptype = 0x0800,
        .hsize = 6,
        .psize = 4,
        .op = 0x0001,
        .sha = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .spa = {0, 0, 0, 0},
        .tha = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01},
        .tpa = {127, 0, 0, 1}
    };
    
    printf("\n--- %s: Original packet ---\n", __func__);
    print_arp(&packet);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Captured output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "Sender MAC address: ff:ff:ff:ff:ff:ff");
    ck_assert_strstr(output, "Sender IP address: 0.0.0.0");
    ck_assert_strstr(output, "Target MAC address: 01:00:5e:00:00:01");
    ck_assert_strstr(output, "Target IP address: 127.0.0.1");
    
    free(output);
}
END_TEST

// ==================== Integration tests ====================

START_TEST(test_parse_and_print_integration) {
    struct arp_packet packet;
    int result = parse_arp(test_arp_packet, sizeof(test_arp_packet), &packet);
    
    ck_assert_int_eq(result, 0);
    
    printf("\n--- %s: Parsed packet from test_arp_packet ---\n", __func__);
    print_arp(&packet);
    
    ck_assert_int_eq(packet.htype, 0x0001);
    ck_assert_int_eq(packet.ptype, 0x0800);
    ck_assert_int_eq(packet.hsize, 6);
    ck_assert_int_eq(packet.psize, 4);
    ck_assert_int_eq(packet.op, 0x0001);
    
    ck_assert_int_eq(packet.sha[0], 0x08);
    ck_assert_int_eq(packet.sha[1], 0x00);
    ck_assert_int_eq(packet.sha[2], 0x27);
    ck_assert_int_eq(packet.sha[3], 0x12);
    ck_assert_int_eq(packet.sha[4], 0x34);
    ck_assert_int_eq(packet.sha[5], 0x56);
    
    ck_assert_int_eq(packet.spa[0], 0xC0);
    ck_assert_int_eq(packet.spa[1], 0xA8);
    ck_assert_int_eq(packet.spa[2], 0x01);
    ck_assert_int_eq(packet.spa[3], 0x01);
    
    ck_assert_int_eq(packet.tpa[0], 0xC0);
    ck_assert_int_eq(packet.tpa[1], 0xA8);
    ck_assert_int_eq(packet.tpa[2], 0x01);
    ck_assert_int_eq(packet.tpa[3], 0x02);
    
    char *output = capture_stdout(print_arp, &packet);
    ck_assert_ptr_nonnull(output);
    
    printf("--- %s: Printed output ---\n%s\n", __func__, output);
    
    ck_assert_strstr(output, "Sender MAC address: 08:00:27:12:34:56");
    ck_assert_strstr(output, "Sender IP address: 192.168.1.1");
    ck_assert_strstr(output, "Target IP address: 192.168.1.2");
    
    free(output);
}
END_TEST

// ==================== Suite creation ====================

Suite *arp_suite(void) {
    Suite *s;
    TCase *tc_core;
    TCase *tc_parse;
    TCase *tc_print;
    TCase *tc_integration;
    
    s = suite_create("ARP");
    
    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_parse_arp_null_pointer);
    tcase_add_test(tc_core, test_parse_arp_insufficient_length);
    tcase_add_test(tc_core, test_parse_arp_exact_minimum_length);
    suite_add_tcase(s, tc_core);
    
    tc_parse = tcase_create("Parse");
    tcase_add_test(tc_parse, test_parse_arp_valid_packet);
    tcase_add_test(tc_parse, test_parse_arp_reply_packet);
    tcase_add_test(tc_parse, test_parse_arp_max_values);
    suite_add_tcase(s, tc_parse);
    
    tc_print = tcase_create("Print");
    tcase_add_test(tc_print, test_print_arp_valid_packet);
    tcase_add_test(tc_print, test_print_arp_reply_packet);
    tcase_add_test(tc_print, test_print_arp_zero_values);
    tcase_add_test(tc_print, test_print_arp_max_values);
    tcase_add_test(tc_print, test_print_arp_null_packet);
    tcase_add_test(tc_print, test_print_arp_special_addresses);
    suite_add_tcase(s, tc_print);
    
    tc_integration = tcase_create("Integration");
    tcase_add_test(tc_integration, test_parse_and_print_integration);
    suite_add_tcase(s, tc_integration);
    
    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;
    
    s = arp_suite();
    sr = srunner_create(s);
    
    printf("\n=== Starting ARP tests ===\n");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    printf("\n=== Tests finished: %d failed ===\n", number_failed);
    
    return (number_failed == 0) ? 0 : 1;
}