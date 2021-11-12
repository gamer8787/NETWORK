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
#include <list>
namespace E {
using namespace std;
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

typedef pair<int, int>  pid_fd;
typedef pair<uint32_t, uint16_t>  address_port;

typedef list<uint16_t> ready_listen_que ;
typedef list<uint16_t> complete_listen_que ;
typedef pair<ready_listen_que,complete_listen_que> listen_que;
typedef tuple<uint32_t, uint16_t, uint32_t,uint16_t> Four_tuple;

#define seconds pow(10,9)
#define tcp_start 34
#define packet_size 54

map<pid_fd , address_port > bind_map;
map<address_port , listen_que > listen_que_map;
map<address_port , int > listen_room_size_map;
map<address_port , int > listen_is_connected_map;
map<pid_fd , Four_tuple > connect_map;


/////unreliable variable
typedef pair<uint64_t, uint64_t> send_receive_time;
typedef map<uint32_t, send_receive_time> timer_map; //ack num

#define ALPHA 0.125
#define BETA 0.25
struct Four_tuple_struct 
{ 
  Time time=0;
  Time EstimatedRTT = 0.1 * seconds;
  Time SampleRTT = 0 * seconds;
  Time DevRTT = 0.1 * seconds;
  Time TimeoutInterval = 0.1 * seconds;
  timer_map Timer;
  vector<uint32_t> ack_vector;
};

map<Four_tuple , Four_tuple_struct > Four_tuple_map;
vector<any> retransmit_pkt;



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
  listen_que_map.erase(bind_map[pf1]); //FIN에서 진행
  //listen_room_size_map.erase(bind_map[pf1]);   //FIN에서 진행 ? 적절한 곳에서 해야됨 
  //listen_is_connected_map.erase(bind_map[pf1]);
  bind_map.erase(pf1); 
  connect_map.erase(pf1);
  removeFileDescriptor(pid,param1);
  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, sockaddr * param2_ptr, socklen_t param3_int){

  struct sockaddr_in* socksock = (sockaddr_in *)param2_ptr;
  
  pid_fd pf1=make_pair(pid,param1_int);
  address_port ap1=make_pair(socksock->sin_addr.s_addr,socksock->sin_port);
  address_port INADDR_ANY_port=make_pair(htonl(INADDR_ANY),socksock->sin_port);
  
  for (auto iter = bind_map.begin() ; iter != bind_map.end(); iter++) {
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
    for (auto iter = bind_map.begin() ; iter != bind_map.end(); iter++) {
        if(iter->second.first==0){ 
          return returnSystemCall(syscallUUID, -3);
        }
    } 
  }
  bind_map.insert(pair<pid_fd, address_port>(pf1, ap1));

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1,
    sockaddr * param2_ptr, socklen_t* param3_ptr){
  pid_fd pf1=make_pair(pid,param1);
  address_port ap1;
  if ( (bind_map.find(pf1) == bind_map.end()) && (connect_map.find(pf1) == connect_map.end()) ) {
     return returnSystemCall(syscallUUID, -1); 
  }
  else if ( (bind_map.find(pf1) != bind_map.end()) && (connect_map.find(pf1) == connect_map.end()) ) {
     ap1 = bind_map[pf1];
  }
  else if( (bind_map.find(pf1) == bind_map.end()) && (connect_map.find(pf1) != connect_map.end()) ) {
    Four_tuple ssdd = connect_map[pf1];
    ap1 = make_pair(get<0>(ssdd),get<1>(ssdd));
  }
  else{
    ap1 = bind_map[pf1];
  }
  struct sockaddr_in* socksock = (sockaddr_in*) param2_ptr;
  socksock->sin_family = AF_INET;
  socksock->sin_addr.s_addr =ap1.first;
  socksock->sin_port =ap1.second;
  *param3_ptr = sizeof(param2_ptr);

  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1, 
   sockaddr*param2_ptr,socklen_t param3){
  cout << "connect!!\n" << endl;
  struct sockaddr_in* socksock = (sockaddr_in *)param2_ptr;
  ipv4_t dest_ip ;  
  for(int i=0;i<4;i++){
    dest_ip[i]= socksock->sin_addr.s_addr >> (8*(3-i)); 
  }
  int port = getRoutingTable(dest_ip); 
  std::optional<ipv4_t> ip = getIPAddr(port); // retrieve the source IP address
  ipv4_t ip_real = ip.value();
  uint32_t ip_32 = NetworkUtil::arrayToUINT64<4>(ip_real);

  ////////////////////////////////////////////////////////

  uint32_t src_ip_32 = ip_32;
  uint32_t dest_ip_32 = socksock->sin_addr.s_addr;
  std::srand(5323);
  uint16_t source_port = std::rand(); //사용 되는 port 생성하면 안됨 나중에 생각
  uint16_t dest_port = socksock->sin_port;
  uint32_t seq_num =1;
  uint32_t ack_num =0;
  uint16_t flag = 0x5002; 
  uint16_t window = 0x0000; 
  seq_num = htonl(seq_num);
  ack_num = htonl(ack_num);
  flag = htons(flag);
  
  uint32_t expected_ack = ntohl(seq_num)+1;
  std::array<any, 9> pkt_variable = {&src_ip_32, &dest_ip_32, &source_port, &dest_port
  ,&seq_num, &ack_num, &flag, &window, &expected_ack};
  
  
  pid_fd pf1 = make_pair(pid, param1);

  Four_tuple ssdd= make_tuple(src_ip_32, source_port, dest_ip_32, dest_port);
  connect_map.insert(pair<pid_fd, Four_tuple>(pf1, ssdd));

  Four_tuple_struct Four_tuple_struct1; //초기화
  Four_tuple_map[ssdd] = Four_tuple_struct1;
  Write_and_Send_pkt(pkt_variable);


  returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID,int pid, int param1, 
  int param2){
  pid_fd pid_fd1=make_pair(pid,param1);
  
  address_port address_port1=bind_map[pid_fd1];

  ready_listen_que rlq;
  complete_listen_que clq;
  listen_que lq = make_pair(rlq,clq);
  //listen_que_map.erase(address_port1);
  listen_que_map.insert(pair<address_port,listen_que>(address_port1, lq));
  listen_room_size_map.erase(address_port1);
  listen_room_size_map.insert(pair<address_port, int >(address_port1, param2));
  listen_is_connected_map.erase(address_port1);
  listen_is_connected_map.insert(pair<address_port, int >(address_port1, 0));
  printf("listen is %d\n",param2);
  return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID,int pid, int param1,
    		sockaddr* param2_ptr, socklen_t* param3_ptr){
  cout << "accept!!" << endl; 
  pid_fd server_pf=make_pair(pid,param1);
  
  if (bind_map.find(server_pf) == bind_map.end()) {
      printf("bind_map not find!\n");
     return returnSystemCall(syscallUUID, -1); 
  }
  
  address_port server_address_port = bind_map[server_pf];
  if(listen_que_map[server_address_port].second.size()!=0){ //complete_listen_que에 있는 것 다 빼줌 대기열 크기 상관없이
    listen_que_map[server_address_port].second.pop_front();
  }
  else if(listen_que_map[server_address_port].first.size()!=0){ //ready_listen_que에 있는 것 다 빼줌 최대 대기열 크기
    listen_que_map[server_address_port].first.pop_front();
  }
  else{
    if(listen_is_connected_map[server_address_port]==0){ //만약 connect 시도한 클라가 없으면 대기(이 함수를 몇 0.5초 뒤에 실행함)
      vector<any> all_information;
      all_information.push_back(0);
      all_information.push_back(syscallUUID);
      all_information.push_back(pid);
      all_information.push_back(param1);
      all_information.push_back(param2_ptr);
      all_information.push_back(param3_ptr);
      TimerModule::addTimer(all_information ,0.5*seconds); //시간 바꿔봄
      return;
    }
    else {
      return returnSystemCall(syscallUUID, -1);
    }
  }

  //if문 끝난후 각각 socket 생성해줌
  int sock_fd;
  sock_fd = createFileDescriptor(pid);

  pid_fd pf1 = make_pair(pid,sock_fd);
  bind_map.insert(pair<pid_fd, address_port>(pf1, server_address_port));

  address_port ap1 = bind_map[pf1];
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
  if (connect_map.find(pf1) == connect_map.end()) {
     return returnSystemCall(syscallUUID, -1); 
  }
  Four_tuple ssdd = connect_map[pf1];
  address_port ap1 = make_pair(get<2>(ssdd),get<3>(ssdd));
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
  printf("arrived\n");
  uint32_t src_ip;
  uint32_t dest_ip;
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint16_t flag;
  uint16_t window;
  uint16_t checksum;
  uint32_t expected_ack;

  packet.readData(tcp_start-8, &src_ip, 4);
  packet.readData(tcp_start-4, &dest_ip, 4);
  packet.readData(tcp_start, &src_port, 2);
  packet.readData(tcp_start+2, &dest_port, 2);
  packet.readData(tcp_start+4, &seq_num, 4);
  packet.readData(tcp_start+8, &ack_num, 4);
  packet.readData(tcp_start+12, &flag, 2);
  packet.readData(tcp_start+14, &window, 2);
  packet.readData(tcp_start+16, &checksum, 2);
  cout << "seq is "<< ntohl(seq_num) << endl;
  cout << "ack is "<< ntohl(ack_num) << endl;
  Four_tuple ssdd= make_tuple(dest_ip, dest_port, src_ip, src_port);

  uint8_t real_flag = ntohs(flag) & 0xff;
  std::srand(5000);  
  uint32_t new_seq_num;
  uint32_t new_ack_num=htonl(ntohl(seq_num)+1); 
  if(real_flag == 0b00010000){ //ack일때는 그대로
    new_ack_num =seq_num;
  }
  uint16_t new_flag;
  //printf("flag is %x src_port is %x\n",real_flag, src_port);
  //printf("flag is %x \n",real_flag);
  switch(real_flag){
    case 0b00000010:{ //SYN, HANDSHAKE 첫 단계 (서버)
        Four_tuple_struct Four_tuple_struct1; //초기화
        Four_tuple_map[ssdd] = Four_tuple_struct1;
        
        address_port server_address_port;
        address_port INADDR_address_port = make_pair(htonl(INADDR_ANY),dest_port); //서버가 bind를 inaddr로 만들었을때의 pair
        address_port dest_address_port = make_pair(dest_ip,dest_port);             //서버가 bind를 특정ip로 만들었을때의 pair
        for (auto iter = bind_map.begin() ; iter != bind_map.end(); iter++) {       
          if(iter->second.first==INADDR_address_port.first && iter->second.second==INADDR_address_port.second){
            server_address_port = INADDR_address_port;  //서버가 bind를 inaddr로 만들었을 경우 (inaddr ip/port) 에 listen que를 만듬
            //get<0>(ssdd) = htonl(INADDR_ANY); //맞는지 모름
          }
          else{
            server_address_port = dest_address_port;   //아닐 경우 (특정 ip/port) 에 listen que를 만듬
          }
        }
        listen_is_connected_map[server_address_port]=1; //클라로부터 커넥트가 왔으므로 1로 설정
        new_flag = htons(0x5012);
        new_seq_num = std::rand();//
        //cout << "listen size is " << listen_room_size_map[server_address_port] << endl;
        if(listen_room_size_map[server_address_port]==listen_que_map[server_address_port].first.size()){ //ready_listen_que의 크기가 대기열 크기랑 같을 때 full
          if(listen_room_size_map[server_address_port]==0){ //대기열 크기가 0일 때 <= listen을 안 하고 연결하는 경우(handshake 마지막 case)
            break;
          }
          else{ //대기열 크기가 다 찼으므로 더이상 안 받고 버림 클라이언트한테 아무것도 안 보냄
            return; 
          }
        } //대기열이 넉넉하면 ready_listen_que 하나 넣어줌
        else{
          listen_que_map[server_address_port].first.push_back(src_port);
        }
        expected_ack = ntohl(seq_num)+1;
      break;
    }
    case 0b00010010:  //SYN + ACK, HANDSHAKE 두 단계 (클라)
        new_flag = htons(0x5010);
        new_seq_num = ack_num;
        expected_ack = ntohl(seq_num);
      break;
    case 0b00010000:{  //ACK, HANDSHAKE 세 단계 (서버)
        address_port server_address_port;
        address_port INADDR_address_port = make_pair(htonl(INADDR_ANY),dest_port); //서버가 bind를 inaddr로 만들었을때의 pair
        address_port dest_address_port = make_pair(dest_ip,dest_port);             //서버가 bind를 특정ip로 만들었을때의 pair
        for (auto iter = bind_map.begin() ; iter != bind_map.end(); iter++) {
          if(iter->second.first==INADDR_address_port.first && iter->second.second==INADDR_address_port.second){
            server_address_port = INADDR_address_port; 
          }
          else{
            server_address_port = dest_address_port; 
          }
        }
        if(listen_que_map[server_address_port].first.size()!=0){ //ready_listen_que 에 있는 것들을 complete_listen_que 옮겨줌
          for(auto iter = listen_que_map[server_address_port].first.begin(); iter!= listen_que_map[server_address_port].first.end(); iter++){
            if (*iter==src_port){
              listen_que_map[server_address_port].first.erase(iter);
              listen_que_map[server_address_port].second.push_back(src_port);
              break;
            }
          }  
        }

        new_flag = htons(0x5010);
        new_seq_num = ack_num;
        expected_ack = ntohl(seq_num);
      break;
  }
    case 0b00010001: //FIN + ACK
        new_flag = htons(0x5010);
        new_seq_num = std::rand();//
        expected_ack = ntohl(seq_num)+1;
        //return;
      break;
    default :    
      printf("flag is !! %x\n",real_flag);
      printf("not yet\n");
      
      //perror("not yet\n");
      break;
  }

  Time time = HostModule::getCurrentTime();
  
  Four_tuple_map[ssdd].Timer[ntohl(ack_num)].second = time; //map 2개
  if(real_flag != 0b00000010){ //처음아닐때만
    Four_tuple_map[ssdd].SampleRTT = time - Four_tuple_map[ssdd].Timer[ntohl(ack_num)].first;
  }
  Four_tuple_map[ssdd].EstimatedRTT = (1-ALPHA) * Four_tuple_map[ssdd].EstimatedRTT + ALPHA * Four_tuple_map[ssdd].SampleRTT;
  Time t = (Four_tuple_map[ssdd].SampleRTT > Four_tuple_map[ssdd].EstimatedRTT) ? (Four_tuple_map[ssdd].SampleRTT-Four_tuple_map[ssdd].EstimatedRTT) : (Four_tuple_map[ssdd].EstimatedRTT-Four_tuple_map[ssdd].SampleRTT);
  Four_tuple_map[ssdd].DevRTT = (1-BETA) * Four_tuple_map[ssdd].DevRTT + BETA * t;
  Four_tuple_map[ssdd].TimeoutInterval = Four_tuple_map[ssdd].EstimatedRTT + 4*Four_tuple_map[ssdd].DevRTT;
  Four_tuple_map[ssdd].ack_vector.push_back(ntohl(ack_num));   //받은 ack을 기록
  cout << "new seq is "<< ntohl(new_seq_num) << endl;
  cout << "new ack is "<< ntohl(new_ack_num) << endl;
  array<any, 9> pkt_variable = {&dest_ip, &src_ip, &dest_port, &src_port
  ,&new_seq_num, &new_ack_num, &new_flag, &window, &expected_ack};
  Write_and_Send_pkt(pkt_variable);
} 

void TCPAssignment::timerCallback(std::any payload) {
  vector<any> all_information = any_cast<vector<any>>(payload);
  switch (any_cast<int>(all_information[0])) {
    case -1:{
      uint32_t src_ip = (any_cast<uint32_t >(all_information[1]));
      uint32_t dest_ip = (any_cast<uint32_t >(all_information[2]));
      uint16_t source_port = (any_cast<uint16_t >(all_information[3]));
      uint16_t dest_port = (any_cast<uint16_t >(all_information[4]));
      uint32_t seq_num =(any_cast<uint32_t >(all_information[5]));
      uint32_t ack_num =(any_cast<uint32_t >(all_information[6]));
      uint16_t flag = (any_cast<uint16_t >(all_information[7]));
      uint16_t window = (any_cast<uint16_t >(all_information[8]));
      uint32_t expected_ack = (any_cast<uint32_t >(all_information[9]));
      
      std::array<any, 9> pkt_variable = {&src_ip, &dest_ip, &source_port, &dest_port
        ,&seq_num, &ack_num, &flag, &window, &expected_ack};
      Four_tuple ssdd= make_tuple(src_ip, source_port, dest_ip, dest_port);

      if(find(Four_tuple_map[ssdd].ack_vector.begin(),Four_tuple_map[ssdd].ack_vector.end(), expected_ack)==Four_tuple_map[ssdd].ack_vector.end()){ //원하는 ack이 없으면
        Write_and_Send_pkt(pkt_variable);
      }
      break;
    }
    case 0:
      syscall_accept(any_cast<UUID>(all_information[1]), any_cast<int>(all_information[2])
      , any_cast<int>(all_information[3]), any_cast<sockaddr*>(all_information[4]), any_cast<socklen_t*>(all_information[5]));
      break;
    case 1:{
      sendPacket("IPv4", std::move(any_cast<Packet>(all_information[1])));
      break;
    }
    default:
      printf("error\n");
      assert(0);
      break;
  }
}

void TCPAssignment::Write_and_Send_pkt(std::any pkt_variable){
  //cout << "send_pkt " <<endl;
  Packet pkt (packet_size);
  array<any,9> pkt_vector = any_cast<array<any,9>>(pkt_variable);

  uint32_t src_ip = *(any_cast<uint32_t *>(pkt_vector[0]));
  uint32_t dest_ip = *(any_cast<uint32_t *>(pkt_vector[1]));
  uint16_t source_port = *(any_cast<uint16_t *>(pkt_vector[2]));
  uint16_t dest_port = *(any_cast<uint16_t *>(pkt_vector[3]));
  uint32_t seq_num =*(any_cast<uint32_t *>(pkt_vector[4]));
  uint32_t ack_num =*(any_cast<uint32_t *>(pkt_vector[5]));
  uint16_t flag = *(any_cast<uint16_t *>(pkt_vector[6]));
  uint16_t window = *(any_cast<uint16_t *>(pkt_vector[7]));
  uint32_t expected_ack = *(any_cast<uint32_t *>(pkt_vector[8]));

  pkt.writeData(tcp_start-8, &src_ip, 4);
  pkt.writeData(tcp_start-4, &dest_ip, 4);
  pkt.writeData(tcp_start,   &source_port, 2);
  pkt.writeData(tcp_start+2, &dest_port, 2);
  pkt.writeData(tcp_start+4, &seq_num, 4);
  pkt.writeData(tcp_start+8, &ack_num, 4);
  pkt.writeData(tcp_start+12, &flag, 2);
  pkt.writeData(tcp_start+14, &window, 2); //window

  //checksum
  uint8_t temp[20];
  pkt.readData(tcp_start, &temp, 20);
  uint16_t checksum = NetworkUtil::tcp_sum(src_ip, dest_ip,temp,20); //
  checksum = ~checksum;
  checksum = htons(checksum);
  pkt.writeData(tcp_start + 16, (uint8_t *)&checksum, 2);
  //

  Four_tuple ssdd= make_tuple(src_ip, source_port, dest_ip, dest_port);
  Time time = HostModule::getCurrentTime();
  Four_tuple_map[ssdd].Timer[ntohl(seq_num)+1].first = time; //hand shake이므로 받을 ack은 seq+1이고 거기에 저장
  sendPacket("IPv4", std::move(pkt));

  if(find(Four_tuple_map[ssdd].ack_vector.begin(),Four_tuple_map[ssdd].ack_vector.end(), expected_ack)==Four_tuple_map[ssdd].ack_vector.end()){ //원하는 ack이 없으면
    vector<any> retransmit_pkt2;
    retransmit_pkt = retransmit_pkt2;
    retransmit_pkt.push_back(-1);
    retransmit_pkt.push_back(src_ip);
    retransmit_pkt.push_back(dest_ip);
    retransmit_pkt.push_back(source_port);
    retransmit_pkt.push_back(dest_port);
    retransmit_pkt.push_back(seq_num);
    retransmit_pkt.push_back(ack_num);
    retransmit_pkt.push_back(flag);
    retransmit_pkt.push_back(window);
    retransmit_pkt.push_back(expected_ack);
    TimerModule::addTimer(retransmit_pkt ,Four_tuple_map[ssdd].TimeoutInterval);
  }
}




} // namespace E

//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