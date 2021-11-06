/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
  virtual void syscall_socket(UUID syscallUUID, int pid, int param1, int param2, int param3);
  virtual void syscall_close(UUID syscallUUID, int pid, int param1);
  virtual void syscall_read(UUID syscallUUID, int pid, int param1, void *ptr,int param3);
  virtual void syscall_write(UUID syscallUUID, int pid, int param1, void *ptr,int param3);
  virtual void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t param3_int);
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1,
    		sockaddr * param2_ptr, socklen_t* param3_ptr);
  virtual void syscall_connect(UUID syscallUUID, int pid, int param1, sockaddr*param2_ptr,socklen_t param3);
  virtual void syscall_listen(UUID syscallUUID,int pid, int param1, 
  int param2_int);
  virtual void syscall_accept(UUID syscallUUID,int pid, int param1,
    		sockaddr* param2_ptr, socklen_t* param3_ptr);
  virtual void syscall_getpeername(UUID syscallUUID, int pid, int param1,
    	sockaddr * param2_ptr, socklen_t*param3_ptr);
protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual void Write_and_Send_pkt(std::any pkt) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
