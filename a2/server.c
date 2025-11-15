// CS112 Networks Homework2 - Final Delivery 
// Author: Pang Liu

// *** Reference of the Codes ***
// I referred to some of the design ideas of this program: (This cite is based on C++)
// Socket Programming in C/C++: Handling multiple clients on server without multi threading
// https://www.geeksforgeeks.org/cpp/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/

#include <stdio.h> // printf
#include <stdlib.h> // malloc, free, atoi
#include <string.h> // strcpy, strcmp, strlen, memset
#include <unistd.h> // read, write, close
#include <arpa/inet.h> // htons, htonl, ntohs, ntohl
#include <sys/socket.h> // socket
#include <sys/select.h> // select
#include <time.h>
#include <errno.h>

#define MAX_CLIENTS 200

// homework's head structure
struct __attribute__((__packed__)) head {
    unsigned short type;
    char           source[20];
    char           destination[20];
    unsigned int   length;
    unsigned int   message_id;
};

// client structure
typedef struct {
    int socket_fd; // socket file description
    char client_id[20];
    int slot; // 0 is not used, 1 is in use, 2 is used and will not be used again
    int is_authenticated; // 0 is not auth, 1 is auth
    unsigned char partial_message_buffer[sizeof(struct head) + 401]; // about 15-30 clients, corresponding to the name length
    int bytes_in_buffer;
    time_t last_activity_time;
} client_info;

client_info clients[MAX_CLIENTS];
int serverfd;
fd_set master_fds;

// message structure
struct message {
    struct head header;
    unsigned char data[400];
};

void manipulate_message(int client_index, struct message* msg);
void add_client_to_list(int socket_fd);
void del_client_from_list(int client_index);
void send_client_list(int client_index);
int find_client_by_id(const char* client_id);

// CORE MESSAGE MANIPULATING FUNCTION
void manipulate_message(int client_index, struct message* msg) {
    // 1. Check if a client is auth, if not, it cannot send message other than HELLO
    if (!clients[client_index].is_authenticated && msg->header.type != 1) {
        printf("Warning: Un-authenticated client fd=%d sent a non-HELLO message. Disconnecting.\n", clients[client_index].socket_fd);
        del_client_from_list(client_index);
        return;
    }

    // 2. MAIN MESSAGE TYPES
    switch (msg->header.type) {
        case 1: { // HELLO
            printf("RECEIVE CLIENT fd=%d MESSAGE HELLO, ClientID: %s\n", clients[client_index].socket_fd, msg->header.source);
            
            // check if client id exist
            if (find_client_by_id(msg->header.source) != -1) {
                printf("Warning: ClientID '%s' already exists.\n", msg->header.source);
                struct head err_header = {7, "Server", "", 0, 0};
                strcpy(err_header.destination, msg->header.source);
                err_header.type = htons(err_header.type);
                write(clients[client_index].socket_fd, &err_header, sizeof(struct head));
                del_client_from_list(client_index);
                return;
            }
            
            // register a new client
            strcpy(clients[client_index].client_id, msg->header.source);
            clients[client_index].is_authenticated = 1;
            
            // ACK
            struct head ack_header = {2, "Server", "", 0, 0};
            strcpy(ack_header.destination, clients[client_index].client_id);
            ack_header.type = htons(ack_header.type);
            write(clients[client_index].socket_fd, &ack_header, sizeof(struct head));
            
            // Only send to this client, otherwise the test will breakdown
            send_client_list(client_index);
            break;
        }
        case 3: { // LIST_REQUEST
            printf("Receive client %s (fd=%d) LIST_REQUEST MESSAGE.\n", clients[client_index].client_id, clients[client_index].socket_fd);
            send_client_list(client_index);
            break;
        }
        case 5: { // CHAT
            // destination must exist and not self
            if (strlen(msg->header.destination) == 0 || strcmp(msg->header.source, msg->header.destination) == 0) {
                printf("Warning: client fd=%d sent chat with invalid destination. Disconnecting.\n", clients[client_index].socket_fd);
                del_client_from_list(client_index);
                return;
            }

            // find destination
            int dest_index = find_client_by_id(msg->header.destination);
            if (dest_index != -1) {
                // htons/htonl
                struct head net_header = msg->header;
                net_header.type = htons(net_header.type);
                net_header.length = htonl(net_header.length);
                net_header.message_id = htonl(net_header.message_id);
                
                // send data
                write(clients[dest_index].socket_fd, &net_header, sizeof(struct head));
                if (msg->header.length > 0) {
                    write(clients[dest_index].socket_fd, msg->data, msg->header.length);
                }
            } else {
                // not find the receiver, ERROR(CANNOT_DELIEVER)
                struct head err_header = {8, "Server", "", 0, msg->header.message_id};
                strcpy(err_header.destination, msg->header.source);
                err_header.type = htons(err_header.type);
                err_header.message_id = htonl(err_header.message_id);
                write(clients[client_index].socket_fd, &err_header, sizeof(struct head));
            }
            break;
        }
        case 6: { // EXIT (graceful exit)
            printf("Client '%s' (fd=%d) is now off.\n", clients[client_index].client_id, clients[client_index].socket_fd);
            del_client_from_list(client_index);
            break;
        }
        default:
            // unkown messages
            printf("Warning: client fd=%d has sent an unknown message type %d. Disconnecting.\n", clients[client_index].socket_fd, msg->header.type);
            del_client_from_list(client_index);
            break;
    }
}

void send_client_list(int client_index) {
    // buffer limitation is 400 bytes
    char list_buffer[401] = {0};
    int current_len = 0;
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        // add valid clients into list
        if (clients[i].slot == 1 && clients[i].is_authenticated) {
            int id_len = strlen(clients[i].client_id);
            // check if the list can add new client and not exceed byte limitations
            if (current_len + id_len + 1 <= 400) {
                strcpy(list_buffer + current_len, clients[i].client_id);
                current_len += id_len + 1;
            } else {
                // if buffer is full, stop
                break; 
            }
        }
    }

    // CLIENT_LIST head message
    struct head list_header = {4, "Server", "", current_len, 0};
    strcpy(list_header.destination, clients[client_index].client_id);
    list_header.type = htons(list_header.type);
    list_header.length = htonl(list_header.length);

    // send head
    write(clients[client_index].socket_fd, &list_header, sizeof(struct head));
    
    // send message
    if (current_len > 0) {
        write(clients[client_index].socket_fd, list_buffer, current_len);
    }
}

// ADD NEW CLIENT INTO LIST FUNCTION
void add_client_to_list(int socket_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        // ONLY ADD INTO 0 SLOT, TO KEEP ORDER
        // 0: not used
        // 1: now is using
        // 2: used, and will not be used agian
        if (clients[i].slot == 0) { 
            clients[i] = (client_info){
                .socket_fd = socket_fd, 
                .slot = 1,
                .is_authenticated = 0, 
                .bytes_in_buffer = 0, 
                .last_activity_time = time(NULL)
            };

            // clear
            memset(clients[i].client_id, 0, 20);
            memset(clients[i].partial_message_buffer, 0, sizeof(clients[i].partial_message_buffer));
            
            // add socket to select
            FD_SET(socket_fd, &master_fds);
            return;
        }
    }
    // if not slot available, the server is full
    printf("MAXIMUM CLIENTS REACHED. CONNECTION REJECTED.\n");
    close(socket_fd);
}

// REMOVE A CLIENT FROM THE LIST
void del_client_from_list(int client_index) {
    if (client_index < 0 || client_index >= MAX_CLIENTS || clients[client_index].slot != 1) {
        return;
    }
    // remove from select
    FD_CLR(clients[client_index].socket_fd, &master_fds);
    // clear
    close(clients[client_index].socket_fd);
    // set as 2, will not be used to keep order
    clients[client_index].slot = 2; 
}

// FUNCTION: FIND WITH ClientID
int find_client_by_id(const char* client_id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].slot == 1 && clients[i].is_authenticated && strcmp(clients[i].client_id, client_id) == 0) {
            return i;
        }
    }
    return -1; 
}

// MAIN FUNCTION
int main(int argc, char* argv[]) {
    // start with arg
    if (argc != 2) {
        char error_msg[128];
        strcpy(error_msg, "USAGE: ");
        strcat(error_msg, argv[0]);
        strcat(error_msg, " <PORT>\n");
        write(2, error_msg, strlen(error_msg));
        exit(EXIT_FAILURE);
    }
    char* port_str = argv[1];

    // INIT client list
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].slot = 0;
    }

    // socket
    struct sockaddr_in server_addr;
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // all
    server_addr.sin_port = htons(atoi(port_str)); // certain.

    if (bind(serverfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(serverfd, 10) < 0) { // 10 is max len
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server started on port %s\n", port_str);
    
    // INIT select()
    fd_set read_fds;
    int max_fd;
    FD_ZERO(&master_fds); 
    FD_SET(serverfd, &master_fds);
    
    // MAIN LOOP
    while (1) {
        read_fds = master_fds;

        max_fd = serverfd;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].slot == 1 && clients[i].socket_fd > max_fd) {
                max_fd = clients[i].socket_fd;
            }
        }

        // time
        struct timeval tv = {1, 0};
        
        // select socket
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }

        // 
        time_t current_time = time(NULL);
        for(int i = 0; i < MAX_CLIENTS; i++) {
            if(clients[i].slot == 1 && clients[i].bytes_in_buffer > 0 && difftime(current_time, clients[i].last_activity_time) > 60) {
                printf("Warning: client (fd=%d) disconnected due to partial message timeout.\n", clients[i].socket_fd);
                del_client_from_list(i);
            }
        }

        // CHECK: new connection
        if (FD_ISSET(serverfd, &read_fds)) {
            int new_socket = accept(serverfd, NULL, NULL);
            if (new_socket > 0) {
                add_client_to_list(new_socket);
            }
        }

        // CHECK: current clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].slot == 1 && FD_ISSET(clients[i].socket_fd, &read_fds)) {
                // read data from socket
                int valread = read(clients[i].socket_fd,
                                   clients[i].partial_message_buffer + clients[i].bytes_in_buffer,
                                   sizeof(clients[i].partial_message_buffer) - 1 - clients[i].bytes_in_buffer);
                
                // data read
                if (valread > 0) {
                    clients[i].bytes_in_buffer += valread;
                    clients[i].last_activity_time = time(NULL);
                    
                    // manipulate buffer data
                    while (clients[i].bytes_in_buffer >= sizeof(struct head)) {
                        struct message current_msg;
                        memcpy(&current_msg.header, clients[i].partial_message_buffer, sizeof(struct head));
                        
                        // ntohl
                        current_msg.header.type = ntohs(current_msg.header.type);
                        current_msg.header.length = ntohl(current_msg.header.length);
                        current_msg.header.message_id = ntohl(current_msg.header.message_id);
                        
                        // len check
                        if(current_msg.header.length > 400) {
                            del_client_from_list(i);
                            break;
                        }

                        // validate message
                        if (clients[i].bytes_in_buffer >= sizeof(struct head) + current_msg.header.length) {
                            memcpy(current_msg.data, clients[i].partial_message_buffer + sizeof(struct head), current_msg.header.length);
                            manipulate_message(i, &current_msg);
                            
                            // break situation
                            if(clients[i].slot != 1) break;

                            // finish remain
                            int msg_total_size = sizeof(struct head) + current_msg.header.length;
                            memmove(clients[i].partial_message_buffer,
                                    clients[i].partial_message_buffer + msg_total_size,
                                    clients[i].bytes_in_buffer - msg_total_size);
                            clients[i].bytes_in_buffer -= msg_total_size;
                        } else {
                            // wait for next read to get a whole message
                            break;
                        }
                    }
                } else {
                    // disconnect
                    del_client_from_list(i);
                }
            }
        }
    }
    close(serverfd);
    return 0;
}