/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */ 

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <map>
#include <cstdlib>
#include <cmath>
namespace E {
using namespace std;
int num_packet=0;
typedef pair<int, int>  pid_fd;
typedef pair<int, int>  max_socket;
typedef pair<uint32_t, uint16_t>  address_port;
#define seconds pow(10,9)

map<pid_fd , address_port > src_m;
map<pid_fd , address_port > dest_m;
//map<pid_fd , max_socket > listen_m;
map<address_port , int > accepted_que;
map<address_port , max_socket > for_listen;


TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2, int param3)
{
  int sock_fd;
  sock_fd = createFileDescriptor(pid);
  return returnSystemCall(syscallUUID, sock_fd);
}
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1)
{
  pid_fd pf1=make_pair(pid,param1);
  accepted_que.erase(src_m[pf1]); //added
  for_listen.erase(src_m[pf1]);
  src_m.erase(pf1);
  dest_m.erase(pf1); //added
  removeFileDescriptor(pid,param1);
  return returnSystemCall(syscallUUID, 0); //두 번째 미정
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, sockaddr * param2_ptr, socklen_t param3_int){

  struct sockaddr_in* socksock = (sockaddr_in *)param2_ptr;
  
  pid_fd pf1=make_pair(pid,param1_int);
  address_port ap1=make_pair(socksock->sin_addr.s_addr,socksock->sin_port);
  address_port INADDR_ANY_port=make_pair(htonl(INADDR_ANY),socksock->sin_port);
  
  for (auto iter = src_m.begin() ; iter != src_m.end(); iter++) {
      if(iter->second.first==ap1.first &&
       iter->second.second==ap1.second){ //(bind: Address already in use ) //same IP=INADDR_ANY, same port일때도 포함
        return returnSystemCall(syscallUUID, -1);
      }
      if(iter->second.first==INADDR_ANY_port.first &&
       iter->second.second==INADDR_ANY_port.second){ //inaddr_any 9999,  "192.168.0.7", 9999 
        return returnSystemCall(syscallUUID, -2);
      }
  }
  if(socksock->sin_addr.s_addr==0){  //inaddr_any 9999, inaddr_any 10000
    for (auto iter = src_m.begin() ; iter != src_m.end(); iter++) {
        if(iter->second.first==0){ 
          return returnSystemCall(syscallUUID, -3);
        }
    } 
  }
  src_m.insert(pair<pid_fd, address_port>(pf1, ap1));

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1,
    sockaddr * param2_ptr, socklen_t* param3_ptr){

  pid_fd pf1=make_pair(pid,param1);
  if (src_m.find(pf1) == src_m.end()) {
     return returnSystemCall(syscallUUID, -1); 
  }
  
  address_port ap1 = src_m[pf1];
  struct sockaddr_in* socksock = (sockaddr_in*) param2_ptr;
  //memset(&socksock, 0, sizeof(socksock));
  socksock->sin_family = AF_INET;
  socksock->sin_addr.s_addr =ap1.first;
  socksock->sin_port =ap1.second;
  *param3_ptr = sizeof(param2_ptr);

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1, 
   sockaddr*param2_ptr,socklen_t param3){
  
  printf("in connect!!!\n");
  /*
  struct sockaddr_in* socksock = (sockaddr_in *)param2_ptr;
  ipv4_t dest_ip ;  
  for(int i=0;i<4;i++){
    dest_ip[i]= socksock->sin_addr.s_addr >> (8*(3-i)); 
  }
  int port = getRoutingTable(dest_ip); 
  std::optional<ipv4_t> ip = getIPAddr(port); // retrieve the source IP address
  ipv4_t ip_real = ip.value();
  uint32_t ip_32 = ip_real[3] | (ip_real[2] << 8) | (ip_real[1] << 16) | (ip_real[0] << 24);
  uint16_t port_16 = (in_port_t) port;
  //std::optional<mac_t> mac = getMACAddr(port); // retrieve the source MAC address; used only in the IP layer

  size_t packet_size = 54;
  Packet pkt (packet_size);

  int ip_start= 14;
  int tcp_start = 34;

  uint32_t src_ip_32 = ip_32;
  uint32_t dest_ip_32 = socksock->sin_addr.s_addr;
  
  std::srand(5323);
  uint16_t source_port = std::rand(); //있는 거 생성하면 안됨 나중에 생각
  uint16_t dest_port = socksock->sin_port;

  src_ip_32 = htonl(src_ip_32);
  dest_ip_32 = htonl(dest_ip_32);
  source_port = htons(source_port);
  dest_port = htons(dest_port);

  pkt.writeData(ip_start+12, (uint8_t *)&src_ip_32, 4);
  pkt.writeData(ip_start+16, (uint8_t *)&dest_ip_32, 4);
  pkt.writeData(tcp_start, (uint8_t *)&source_port, 2);
  pkt.writeData(tcp_start+2, (uint8_t *)&dest_port, 2);

  uint32_t seq_num =1;
  uint32_t ack_num =0;
  uint16_t flag = 0b10; 
  uint16_t urg = 0; 

  seq_num = htonl(seq_num);
  ack_num = htonl(ack_num);
  flag = htons(flag);
  urg = htons(urg);

  pkt.writeData(tcp_start+4, (uint8_t *)&dest_port, 4);
  pkt.writeData(tcp_start+8, (uint8_t *)&dest_port, 4);
  pkt.writeData(tcp_start+12, (uint8_t *)&dest_port, 2);
  pkt.writeData(tcp_start+18, (uint8_t *)&dest_port, 2);

  uint8_t temp[20];
  pkt.readData(tcp_start, &temp, 20);

  uint16_t checksum = NetworkUtil::tcp_sum(ntohl(src_ip_32),ntohl(dest_ip_32),temp,20); //
  checksum = ~checksum;
  checksum = htons(checksum);
  pkt.writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

  sendPacket("IPv4", std::move(pkt));

  address_port ap1=make_pair(ip_32,port_16);
  address_port ap2=make_pair(ntohl(dest_ip_32),ntohs(dest_port));

  pid_fd pf1=make_pair(pid,param1);
  src_m.insert(pair<pid_fd, address_port>(pf1, ap1));
  dest_m.insert(pair<pid_fd, address_port>(pf1, ap2));
  printf("in connect!!!\n");
  */
  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID,int pid, int param1, 
  int param2){
  pid_fd pid_fd1=make_pair(pid,param1);
  
  address_port address_port1=src_m[pid_fd1];
  max_socket max_socket1=make_pair(param2,0);

  accepted_que.insert(pair<address_port,int>(address_port1, 0));
  for_listen.insert(pair<address_port,max_socket>(address_port1, max_socket1));

  printf("listen is %d\n",param2);
  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID,int pid, int param1,
    		sockaddr* param2_ptr, socklen_t* param3_ptr){
  
  pid_fd server_pf=make_pair(pid,param1);
  
  if (src_m.find(server_pf) == src_m.end()) {
     return returnSystemCall(syscallUUID, -1); 
  }
  
  address_port server_adress_port = src_m[server_pf];
  
  if(for_listen[server_adress_port].second==0){
    printf("wait\n");
    //TimerModule::addTimer(syscallUUID ,100*seconds);
    return returnSystemCall(syscallUUID, -1); 
  }
  for_listen[server_adress_port].second-=1;
  if (accepted_que[server_adress_port]>0){
    accepted_que[server_adress_port]-=1;
    for_listen[server_adress_port].second+=1;
  }
  
  int sock_fd;
  sock_fd = createFileDescriptor(pid);
  printf("sock_fd is %d\n",sock_fd);

  pid_fd pf1 = make_pair(pid,sock_fd);
  src_m.insert(pair<pid_fd, address_port>(pf1, server_adress_port));

  address_port ap1 = src_m[pf1];
  struct sockaddr_in* socksock = (sockaddr_in*) param2_ptr;
  //memset(&socksock, 0, sizeof(socksock));
  socksock->sin_family = AF_INET;
  //socksock->sin_addr.s_addr =ap1.first;
  socksock->sin_port =ap1.second;
  *param3_ptr = sizeof(*socksock);

  return returnSystemCall(syscallUUID, sock_fd);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int param1,
    	sockaddr * param2_ptr, socklen_t*param3_ptr){


  pid_fd pf1=make_pair(pid,param1);
  if (dest_m.find(pf1) == dest_m.end()) {
     return returnSystemCall(syscallUUID, -1); 
  }
  
  address_port ap1 = dest_m[pf1];
  struct sockaddr_in* socksock = (sockaddr_in*) param2_ptr;
  //memset(&socksock, 0, sizeof(socksock));
  socksock->sin_family = AF_INET;
  socksock->sin_addr.s_addr =ap1.first;
  socksock->sin_port =ap1.second;
  *param3_ptr = sizeof(param2_ptr);

  return returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,param.param2_int,param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    //this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,param.param3_int);
    break;
  case WRITE:
    //this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr),
    (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
     this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  int ip_start= 14;
  int tcp_start = 34;

  uint32_t src_ip;
  uint32_t dest_ip;
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint16_t flag;
  uint16_t window;
  uint16_t checksum;
  //uint16_t urg;

  packet.readData(tcp_start-8, &src_ip, 4);
  packet.readData(tcp_start-4, &dest_ip, 4);
  packet.readData(tcp_start, &src_port, 2);
  packet.readData(tcp_start+2, &dest_port, 2);
  packet.readData(tcp_start+4, &seq_num, 4);
  packet.readData(tcp_start+8, &ack_num, 4);
  packet.readData(tcp_start+12, &flag, 2);
  packet.readData(tcp_start+14, &window, 2);
  packet.readData(tcp_start+16, &checksum, 2);
  uint8_t test[20];
  packet.readData(tcp_start, &test, 20);
  uint16_t test_checksum;
  test_checksum = NetworkUtil::tcp_sum(src_ip,dest_ip,test,20);
  //uint16_t test_checksum = NetworkUtil::tcp_sum(src_ip),ntohl(dest_ip),test,20);
  test_checksum = ~test_checksum;
  test_checksum = htons(test_checksum);
  //std::cout << std::hex << checksum << " checksum " << std::endl;
  //std::cout << std::hex << test_checksum << " test_checksum " << std::endl;
  
  
  //std::cout << std::hex << ntohl(src_ip) << " Src ip " <<  std::hex << ntohl(dest_ip) <<" dest_ip"<< std::endl;
  //std::cout << std::hex << ntohs(src_port) << " src_port " <<  std::hex << ntohs(dest_port) << " dest_port " << std::endl;
  /*
  std::cout << std::hex << seq_num << " seq_num " << std::endl;
  std::cout << std::hex << ack_num << " ack_num " << std::endl;
  std::cout << std::hex << ntohs(flag) << " flag " << std::endl;
  std::cout << std::hex << window << " window " << std::endl;
  std::cout << std::hex << checksum << " checksum " << std::endl;
  */
  uint8_t real_flag = ntohs(flag) & 0xff;

  size_t pkt_size = 54;
  Packet pkt (pkt_size);

  pkt.writeData(ip_start+12, (uint8_t *)&dest_ip, 4);
  pkt.writeData(ip_start+16, (uint8_t *)&src_ip, 4);
  pkt.writeData(tcp_start, (uint8_t *)&dest_port, 2);
  pkt.writeData(tcp_start+2, (uint8_t *)&src_port, 2);

  std::srand(5000);  
  uint32_t new_seq_num;
  uint32_t new_ack_num=htonl(ntohl(seq_num)+1); //o
  //uint32_t new_ack_num=seq_num+1;

  //
  pkt.writeData(tcp_start+8, (uint8_t *)&new_ack_num, 4); //ack_num
  pkt.writeData(tcp_start+14, (uint8_t *)&window, 2); //window

  uint16_t new_flag;
  uint16_t new_checksum;
  printf("flag is %x\n",real_flag);
  switch(real_flag){
    case 0b00000010:{ //connect, syn
        TimerModule::addTimer(NULL ,100*seconds);
        address_port server_address_port = make_pair(htonl(INADDR_ANY),dest_port);  
        if(for_listen[server_address_port].first==for_listen[server_address_port].second){
          accepted_que[server_address_port]+=1;
          for_listen[server_address_port].second-=1;
          //return;
        }
        for_listen[server_address_port].second+=1;
        new_flag = htons(0x5012);
        new_seq_num = std::rand();//
        pkt.writeData(tcp_start+4, (uint8_t *)&new_seq_num, 4); //seq_num
        pkt.writeData(tcp_start+12, (uint8_t *)&new_flag, 2); //flag
      break;
    }
    case 0b00010010:
        new_flag = htons(0x5010);
        new_seq_num = ack_num;
        pkt.writeData(tcp_start+4, (uint8_t *)&new_seq_num, 4); //seq_num
        pkt.writeData(tcp_start+12, (uint8_t *)&new_flag, 2); //flag
      break;
    case 0b00010000:{
        //address_port server_address_port = make_pair(htonl(INADDR_ANY),dest_port); 
        //accepted_que[server_address_port]+=1;
        new_flag = htons(0x5010);
        new_seq_num = ack_num;
        pkt.writeData(tcp_start+4, (uint8_t *)&new_seq_num, 4); //seq_num
        pkt.writeData(tcp_start+12, (uint8_t *)&new_flag, 2); //flag
      break;
  }
    case 0b00010001:
      break;
    default :    
      //printf("%x\n",real_flag);
      //printf("not yet\n");
      return;
      //perror("not yet\n");
      break;
  }

  uint8_t temp[20];
  pkt.readData(tcp_start, &temp, 20);
  //new_checksum = NetworkUtil::tcp_sum(dest_ip,src_ip,temp,20); //ntoh?
  new_checksum = NetworkUtil::tcp_sum(src_ip,dest_ip,temp,20); //ntoh?
  new_checksum = ~new_checksum;
  new_checksum = htons(new_checksum);
  //std::cout << std::hex << new_checksum << " new_checksum " << std::endl;
  pkt.writeData(tcp_start + 16, (uint8_t *)&new_checksum, 2);
  num_packet+=1;
  sendPacket("IPv4", std::move(pkt));
  
} 

void TCPAssignment::timerCallback(std::any payload) {
  //int a =std::any_cast<int>(payload);
  //std::cout << "a is !!!!!!!!" << a << std::endl;

}


} // namespace E

//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
