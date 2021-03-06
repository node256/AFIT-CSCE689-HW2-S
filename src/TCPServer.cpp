#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <strings.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <ctime>
#include <chrono>
#include "strfuncts.h"
#include "TCPServer.h"

TCPServer::TCPServer(){ // :_server_log("server.log", 0) {
   _server_log.open("server.log", std::ios::app);
}

TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   // _server_log.writeLog("Server started.");
   writeLog("Server started.");


   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);

    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         TCPConn *new_conn = new TCPConn();
         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }
         std::cout << "***Got a connection***\n";

         // Add connection to list and send banner msg
         _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));
         

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);

         // check if IP is authorized to connect
         if (!authIP(ipaddr_str)) {
            new_conn->sendText("Connection failed!\n");
            new_conn->disconnect();
            writeLog( "Unauthorized connection attempt from " + ipaddr_str );
         }
         else {         
            new_conn->sendText("Welcome to the CSCE 689 Server!\n");
            writeLog( "Authorized connection from " + ipaddr_str );
            // Change this later
            new_conn->startAuthentication();
            if ( !new_conn->auth()){
               if ( new_conn->pwd_attempts()  ){
                  writeLog("Password authorization failed for user @" + ipaddr_str );
               }
               else {
                  writeLog("Unauthorized user @" + ipaddr_str );
               }
            }
            else{
               writeLog("User @ "  + ipaddr_str + " login successful" );
            }
         }  
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {
            // Log it
            std::string ipaddr_str;
            (*tptr)->getIPAddrStr(ipaddr_str);
            writeLog("User @ " + ipaddr_str + " disconnected");

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 
}

/**********************************************************************************************
 * AuthIP - compares client IP address with system whitelist
 * 
 *    Returns: true if authorize, false if not
 **********************************************************************************************/

bool TCPServer::authIP(std::string &ipAddr){
   std::fstream infile("whitelist");
   std::string evalIP;
   bool auth = false;
   while (std::getline(infile, evalIP)){
      if ( ipAddr.compare(evalIP) == 0 ){
         auth = true;
         break;
      }
   }
   infile.close();
   return auth;
}

void TCPServer::writeLog(std::string log_input){

   time_t sys_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); 
   std::string event_time = ctime(&sys_time);
   clrNewlines(event_time);
   _server_log << event_time << " " << log_input << "\n";
   _server_log.flush();
}

/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {

   _sockfd.closeFD();
}


