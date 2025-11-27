#include <sys/socket.h>
#include <string.h>

void process_network_data(char *data) {
    char buf[50];
    strcpy(buf, data);  // VULNERABLE!
}

int main() {
    char network_buffer[200];
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    recv(sock, network_buffer, 200, 0);  
    process_network_data(network_buffer);  
    return 0;
}
