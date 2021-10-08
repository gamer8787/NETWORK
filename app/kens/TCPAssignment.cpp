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
namespace E {
using namespace std;

typedef pair<int, int>  pid_fd;
typedef pair<long, short>  addrest_port;
map<pid_fd , addrest_port > m;

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
  m.erase(pf1);
  removeFileDescriptor(pid,param1);
  return returnSystemCall(syscallUUID, 0); //두 번째 미정
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, sockaddr * param2_ptr, socklen_t param3_int){
  struct sockaddr_in* socksock = (sockaddr_in *)param2_ptr;
  
  pid_fd pf1=make_pair(pid,param1_int);
  addrest_port ap1=make_pair(socksock->sin_addr.s_addr,socksock->sin_port);
  addrest_port INADDR_ANY_port=make_pair(htonl(INADDR_ANY),socksock->sin_port);
  
  for (auto iter = m.begin() ; iter != m.end(); iter++) {
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
    for (auto iter = m.begin() ; iter != m.end(); iter++) {
        if(iter->second.first==0){ 
          return returnSystemCall(syscallUUID, -3);
        }
    } 
  }
  m.insert(pair<pid_fd, addrest_port>(pf1, ap1));

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1,
    sockaddr * param2_ptr, socklen_t* param3_ptr){

  pid_fd pf1=make_pair(pid,param1);
  if (m.find(pf1) == m.end()) {
     return returnSystemCall(syscallUUID, -1); 
  }
  
  addrest_port ap1 = m[pf1];
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
    
  size_t packet_size = 100;
  Packet pkt (packet_size);
  pkt.writeData(0, data, 20); 

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID,int pid, int param1, 
  int param2_int){

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID,int pid, int param1,
    		sockaddr* param2_ptr, socklen_t* param3_ptr){
          
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
    this->syscall_connect(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
     this->syscall_listen(syscallUUID, pid, param.param1_int,
     param.param2_int);
    break;
  case ACCEPT:
     this->syscall_accept(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
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
     //this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    		//static_cast<struct sockaddr *>(param.param2_ptr),
    		//static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below

}

void TCPAssignment::timerCallback(std::any payload) {


}

} // namespace E

//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
