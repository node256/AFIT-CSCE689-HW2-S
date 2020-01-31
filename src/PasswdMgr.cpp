#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <list>
#include <vector>
#include <iterator>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"
#include "exceptions.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   return result;
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   // Insert your insane code here

   // temp variables
   std::vector<uint8_t> hash, salt;
   std::string input;

   // open password file for binary read/write
   std::fstream pass_file;
   pass_file.open(_pwd_file, std::ios::in | std::ios::out | std::ios::binary);

   // read strings until username matches
   while ( std::getline(pass_file, input) ){    
      if ( name == input ){

         // write new hash & salt to user entry
         hashArgon2(hash,salt,passwd);
         // would not have finished without Staricus http://www.cplusplus.com/forum/beginner/197490/
         pass_file.write(reinterpret_cast<char*>(&hash[0]), hashlen);
         pass_file.write(reinterpret_cast<char*>(&salt[0]), saltlen);
         break;
      }
   }

   pass_file.close();

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *

 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!

   // tmp char to hold excess newlines
   unsigned char tmp;

 
   // read name, hash, and salt
   // return false if eof(zero bytes read)
   if (pwfile.readStr(name) == 0){ 
      return false;
   }
   if (pwfile.readBytes(hash, hashlen) == 0){
      return false;
   }
   if (pwfile.readBytes(salt, saltlen) == 0 ){
      return false;
   }
   if (pwfile.readByte(tmp) == 0){
      return false;
   }   

   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // Insert your wild code here!

   // open password file for write
   if (!pwfile.openFile(FileFD::appendfd)){
      throw pwfile_error("Could not open passwd file for append");
   }

   if ( pwfile.writeFD(name) < 0 ){
      throw pwfile_error("User write failed");
   }
   if ( pwfile.writeFD("\n") < 0 ){
      throw pwfile_error("User delim write failed");
   }
   if ( pwfile.writeBytes(hash) < 0 ){
      throw pwfile_error("hash write failed");
   }
   if ( pwfile.writeBytes(salt) < 0){
      throw pwfile_error("salt write failed");
   }
   if ( pwfile.writeFD("\n") < 0 ){
      throw pwfile_error("salt delim write failed");
   }

   // bytes written
   results = sizeof(name) + sizeof(hash) + sizeof(salt) + 2;

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
   
   // create hashing parameters
   uint8_t hash[hashlen];
   uint8_t salt[saltlen];
   uint32_t pwdlen = strlen(in_passwd);
   uint32_t t_cost = 2;
   uint32_t m_cost = (1<<16);
   uint32_t parallelism = 1;
   
   // populate salt
   // gen random salt if none passed
   if ( in_salt == NULL) {
      srand((unsigned)time(NULL));
      for ( int i = 0; i < saltlen; i++){
         salt[i] = rand() % 255;
      }
   }
   // copy salt if proper length
   else if ( in_salt->capacity() == saltlen ){
      std::copy(in_salt->begin(), in_salt->end(), salt);
   }
   // error if salt is the wrong size
   else {
      throw std::runtime_error("Invalid salt length\n");
   }
 
   // populate hash
   argon2i_hash_raw(t_cost, m_cost, parallelism, in_passwd, pwdlen, salt, saltlen, hash, hashlen);

   // copy hash & salt to ret hash & salt
   ret_hash.clear();
   ret_hash.insert(ret_hash.end(), &hash[0], &hash[hashlen]);
   ret_salt.clear();
   ret_salt.insert(ret_salt.end(), &salt[0], &salt[saltlen]);
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!

   // if user doesn't exist, add to passwd file
   if (!checkUser(name)){

      // set up variables
      std::string uname = name;
      std::vector<uint8_t> hash, salt;

      // create the passwd hash
      hashArgon2(hash,salt,passwd, NULL);

      // write username\nhashsalt\n to passwd file
      FileFD pwfile(_pwd_file.c_str());
      writeUser(pwfile, uname, hash, salt);
   }
}

