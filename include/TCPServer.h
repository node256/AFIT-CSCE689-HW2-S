#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <list>
#include <memory>
#include <fstream>
#include "Server.h"
#include "FileDesc.h"
#include "TCPConn.h"

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   bool authIP(std::string &ipAddr);
   void bindSvr(const char *ip_addr, unsigned short port);
   void writeLog(std::string log_input);
   void listenSvr();
   void shutdown();

private:
   // Class to manage the server socket
   SocketFD _sockfd;
 
   // List of TCPConn objects to manage connections
   std::list<std::unique_ptr<TCPConn>> _connlist;

   std::ofstream _server_log;
};


#endif
