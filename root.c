#include "client.h"
#include "data.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <string.h>

int main() {
    // 初始化地址
    struct sockaddr_in local_server_addr;
    struct sockaddr_in root_addr;
    init_receiver_addr(&root_addr, ROOT_SERVER_IP);

    int sock = tcp_socket();
    server_bind(sock, &root_addr);
    // 设置成监听**模式**
    tcp_listen(sock);

    // 读取所有RR, 存到records这个数组里
    dns_rr *records;
    int count = get_records(&records, "./data/root.txt");

    while (1) {
        // 同意connect的配对
        int client_sock = tcp_accept(sock, &local_server_addr);
        // 缓冲区, 全初始化成0. 存别人发的东西.
        uint8_t buffer[BUFSIZE] = {0};

        // 初始化俩结构体, malloc: 分配内存
        dns_header *header = (dns_header *)malloc(sizeof(dns_header));
        dns_query *query = (dns_query *)malloc(sizeof(dns_query));

        int receive_len = 0;
        // 1. tcp_receive的返回值赋值给receive_len
        // 2. 判断receive_len. 相当于 while(receive_len) {...}
        while (receive_len = tcp_receive(client_sock, buffer)) {
            // 因为TCP下, DNS包的头2byte是长度, 所以解析从buffer + 2开始.
            int header_len = parse_header(buffer + 2, header);
            parse_query(query, buffer + 2 + header_len);
            // 把buffer置0
            memset(buffer, 0, BUFSIZE);

            unsigned short length = 0;
            // 从records数组里, 找到匹配query的RR. 返回这个RR的下标.
            int ns_idx = find_ns(records, count, query);
            // -1表示匹配失败. 若成功返回>=0的数（数组的下标）.
            if (ns_idx != -1) {
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_STD, 1, R_FINE),
                            header->num_query, 0, 1, 1);
                int a_idx = find_a_for_ns(records, count, records[ns_idx].data);
                if (a_idx == -1) {
                    perror("Database error!");
                    exit(EXIT_FAILURE);
                }
                // 装填
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                length += add_domain_rr(buffer + 2 + length, records + ns_idx);
                length += add_ip_rr(buffer + 2 + length, records + a_idx);
                *((unsigned short *)buffer) = htons(length);
            } else {
                init_header(
                    header, header->id,
                    generate_flags(QR_RESPONSE, OP_STD, 1, R_NAME_ERROR),
                    header->num_query, 0, 0, 0);
                // 装填
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((unsigned short *)buffer) = htons(length);
            }
            // 装填完了, free释放内存. malloc分配完之后必须free, 省内存.
            free(header);
            free_query(query);
            // 发
            tcp_send(client_sock, buffer, length + 2);
            // 循环跳出
            break;
        }
        // 聊完了, 关聊天socket
        close(client_sock);
    }
    // 谁都不想聊了
    close(sock);
}