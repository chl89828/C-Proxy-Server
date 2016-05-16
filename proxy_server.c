#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>

#define BUFFSIZE 2048	//define buffer size - 2048

//SET PORT NUMBER!
#define PORTNO 40058	//port number - 40058

char* sha1_hash(char *input_url, char *hashed_url);	//converting url into SHA1_hash function
char *getHomeDir(char *home);				//function getting home directory

int initialize_sem();					//function to set semaphore init state
void P(int semid);					//P of semaphore
void V(int semid);					//V of semaphore

void print_logfile(int hit, int semid, char* contents); //print logfile function

char *getURL(char* req_message, char* URL);		//function to get URL
int getHostname_AND_portnum(char* req_message, char* hostname);//function to get hostname and port number
char *getIPAddr(char *addr);				//get IP address function

char* proxy_cache(char* input_url, char *h_path, int semid);//function checking Hit or miss
void connect_webserver(char *IPAddr, int portnum, char *buf, char *URL, int semid);	//function to connect to web-server

void sig_handler(int signo);				//signal handler function

char hash_path[200];						//path of cache of hashed URL in which response message is stored

int main(){
	int opt;						//for setsockopt
	struct sockaddr_in server_addr, client_addr;		//declare structure sockaddr_in of server, client 	
	int socket_fd, client_fd;				//declare socket descripter
	int len;						//message length 
	char req_buf[BUFFSIZE], res_buf[BUFFSIZE];		//message buffer				
	int portnum=80;						//port number

	char* IPAddr;						//IPaddress
	char host[100];
	char URL[500];						//URL

	pid_t pid;						//pid varialbe for fork		
	int hash_fd;						//file descriptor of hashed file
	int semid;
	
	semid=initialize_sem();					//set semaphore initializial state
	
	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) <0){	//create socket about server part
		printf("Server : Can't open stream socket.");	//if can't create, print error message
		return 0;
	}		  
	
	bzero((char *)&server_addr, sizeof(server_addr));	//initialize s_server_addr
	server_addr.sin_family=AF_INET;				//set variables of s_server_addr
	
	
	

	///////SET SERVER ADDRESS!!
	server_addr.sin_addr.s_addr=inet_addr("128.134.52.60");	
	//set address of proxy_server




	server_addr.sin_port=htons(PORTNO);			//set portnumber of my process
	
	opt=1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));//set socket option
	
	//bind s_server_addr and s_socket
	if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))<0){
		printf("Server : Can't bind local address.\n");		//if bind error , print message
		return 0;
	}
	
	listen(socket_fd, 5);						//change proxy_server state to wait connection
		
	if(signal(SIGCHLD, sig_handler)==SIG_ERR)					//**signal for SIGCHLD	
		printf("SIGNAL ERROR\n");
	if(signal(SIGALRM, sig_handler)==SIG_ERR)					//**signal for SIGALRM
		printf("SIGNAL ERROR\n");

	while(1){	
		
		//length of client_addr
		len=sizeof(client_addr);	
		
		//accept connection request of client(WEB-BROWSER)
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);	
		if(client_fd<0) {					//if connection fails, print error meesage
			printf("Server : accept failed.\n");
		}
		
		//**create child process
		pid=fork();		
	
		if(pid<0)		//if fork error
			fprintf(stderr, "fork error\n");
	
		else if(pid==0)		//Child process
		{	
			bzero(res_buf, BUFFSIZE);		//initialize buffer
			bzero(req_buf, BUFFSIZE);
			printf("===========================================\n");
			printf("PID : %d\n",getpid());			//print child process id 
			read(client_fd, req_buf, BUFFSIZE);		//read request message of client
			
			getURL(req_buf, URL);
			portnum=getHostname_AND_portnum(req_buf, host);
			IPAddr=getIPAddr(host);				//hostname swap into IPaddress
			
			printf("* request :\n%s\n",req_buf); 		//print request message 
			printf("* host name(%d) : %s\n",getpid(),host);	//print host name
			printf("* IP address : %s\n", IPAddr);		//print IPaddress

			//hash_path is hashed file of URL
			proxy_cache(URL, hash_path, semid);		//check whether HIT or MISS AND get hash_path

			
			hash_fd=open(hash_path, O_RDWR);		//open file of hash_path
			
			if(hash_fd==-1)					//if file descriptor of hash_path is -1, that file doesn't exist
				printf("* ProxyCache(%d) : MISS\n",getpid());		//Thus MISS
			else{						//else that file exist	
				printf("* ProxyCache(%d) : HIT\n",getpid());		//Thus HIT
				close(hash_fd);				//close file descriptor of hash_path
			}


			if(hash_fd==-1)					//MISS
				connect_webserver(IPAddr, portnum, req_buf, URL, semid);
				//proxy server as clinet is connected to web-server

			hash_fd=open(hash_path, O_RDONLY);		//hasehd file open in proxy_cache

                        while((len=read(hash_fd, res_buf, BUFFSIZE))>0)	//read Response message from file
                        {
                                write(client_fd, res_buf, len);		//write response message to client
                        	bzero(res_buf, BUFFSIZE);		//initialize
                        }  
			close(client_fd);				//close descriptor
			close(hash_fd);
			return 0;
		}	
	
	
	}
					

	return 0;
}


void connect_webserver(char *IPAddr, int portnum, char *buf, char *URL, int semid){
	int hash_fd;			//hash file descriptor
	int socket_fd;			//socket descriptor
	struct sockaddr_in server_addr; 
	int len;
	char res_buf[BUFFSIZE];
	
	creat(hash_path, 0777);		
	hash_fd=open(hash_path, O_WRONLY);
	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0))<0){	//create socket of client
		printf("Proxy Server : can't create socket.\n");//if it fails, print error message
		exit(0);
	}	
	bzero((char*)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;                       //set information of c_server_addr 
	server_addr.sin_addr.s_addr=inet_addr(IPAddr);          //set address. s_req_IPAddr is ip address in request message
	server_addr.sin_port=htons(portnum);                          //set port number. HTTP port number is 80

	//request connection to web server
	if(connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr))<0){
		printf("Proxy Server : can't connect to web server.\n");//if it fails, print error message
	}
	write(socket_fd, buf, strlen(buf)+1);               //write request meesage to web server

	bzero(res_buf, BUFFSIZE);
	
	//print logfile
	print_logfile(0, semid, URL);
	
	//set alarm by 10 second
	alarm(10);	

	while((len=read(socket_fd, res_buf, BUFFSIZE))>0){//read response message from web server, until message finish.
		
		write(hash_fd, res_buf, len);
		bzero(res_buf, BUFFSIZE);
	}
	alarm(0);
	close(hash_fd);
	close(socket_fd);                     //close socket descriptors
}



//signal handler function
//it can cover SIGCHLD, SIGALRM
void sig_handler(int signo)
{
	pid_t c_pid;
	
	switch(signo){		
	case SIGCHLD : 
		c_pid=wait(0);		//case signo - SIGCHLD
		printf("PID : %d Child End!\n", c_pid); //Print exit message
	break;
	
	case SIGALRM :
		printf("Not response\n");	//case signo - SIGALRM
		c_pid = getpid();		//get this process's process id
		remove(hash_path);		//hashed_file delete 
		exit(0);
	break;

	default :
	break;
	}
}


char* proxy_cache(char* input_url, char* h_path, int semid)
{
        umask(000);             //set permission umask(000)
        char homedir[30];
	char hash_url[41];      //hashed URL
        int check = 0;          //check variable

        struct dirent *pFile;   //declare dirent
        DIR *pDir;              //declare DIR 
	
	strcpy(h_path, getHomeDir(homedir));
        strcat(h_path, "/proxy_cache");                 //attach "/proxy_cache" after home directory
        mkdir(h_path, S_IRWXU | S_IRWXG | S_IRWXO);     //make proxy_cache directory

        sha1_hash(input_url, hash_url);                 //convert input_url to hashed URL
        strncat(h_path, "/",1);                         //attach "/" to h_path
        strncat(h_path, hash_url,1);                    //attach hash_url[0] to h_path
        //current h_path = "home directory/proxy_cache/hash_url[0]"

        mkdir(h_path, S_IRWXU | S_IRWXG | S_IRWXO);     //make h_path directory
	
        strncat(h_path, "/",1);                         //attach "/' to h_path
        strncat(h_path,&hash_url[1], 1);                //attach hash_url[1] to h_path
        //current h_path = "home directory/proxy_cache/hash_url[0]/hash_url[1]"
        check=mkdir(h_path, S_IRWXU | S_IRWXG | S_IRWXO);       //make h_path directory
        if(check==-1){                                          //only in case h_path aleady exist, to read file is executed.   
                pDir=opendir(h_path);                           //pDir = h_path directory

                for(pFile=readdir(pDir); pFile; pFile=readdir(pDir)){           //check same name file to already exist(
                        if(strcmp(pFile->d_name, &hash_url[2])==0){             //compare files in h_pat with hash_url[2]~end
                                //!HIT!
                                //print hash_url, local time in "logfile"
				print_logfile(1, semid, hash_url);			
                                check=1;        //if same check ==1? HIT
                                break;
                        }
                }
                closedir(pDir);                 //close directory
        }


        strncat(h_path, "/",1);                 //attach "/" to h_path
        strcat(h_path, &hash_url[2]);                        //current h_path="home directory/proxy_cache/hash_url[0]/hash_url[1]/hash_url[2]~end"
	
        return h_path;
}



char* sha1_hash(char *input_url, char *hashed_url){             //sha1 function
        unsigned char hashed_160bits[20];                       //declare variables
   char hashed_hex[41];
   int i;

   SHA1(input_url,strlen(input_url), hashed_160bits);           //convert input_url to 160-bits hash data

   for(i=0; i<sizeof(hashed_160bits); i++)                      //convert hash data to hexadecimal data
        sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

      strcpy(hashed_url, hashed_hex);                           //copy hashed_hex to hashed_url

      return hashed_url;                                        //return
}


char *getHomeDir(char *home){                       		//get Homedirectory path function
        struct passwd *usr_info = getpwuid(getuid());		//get user id
        strcpy(home, usr_info -> pw_dir);                       //copy directory name

        return home;                                            //return
}


///////////////ANALYSIS REQUEST MESSAGE////////////////////////////////////////////
char *getURL(char *req_message, char *URL){
	int i=0;
	char temp[BUFFSIZE];		//temp array
	char *temp_URL;			

	strcpy(temp, req_message);	//copy request message
	temp_URL=&temp[4];		//move pointer next "GET"
	i=0;
	
	while(temp_URL[i]!=' ')		//extract URL
		i++;
	temp_URL[i]='\0';
	strcpy(URL, temp_URL);		
	
	return URL;
}

int getHostname_AND_portnum(char* req_message, char* hostname){
	char temp[BUFFSIZE];
	char *token;
	int portnumber=80;				
	int i=0;
	
	strcpy(temp, req_message);
	token=strtok(temp, " \n");				//token request message delim : space , \n
	while(token!=NULL){
		token=strtok(NULL, " \n");
		if(strcmp(token, "Host:")==0){			//find "Host:" string 
			token=strtok(NULL, " \n");		//if it is found, one more token
			break;
		}
	}

	if(token==NULL){                              		//if token is NULL, "Host:" doesn't exist. thus that request message is error
		printf("Server : request message error\n");
		exit(0);
	}

	token[strlen(token)-1]='\0';				//delete carrige return character
	strcpy(hostname, token);
	
	i=strlen(hostname)-1;					//if other port number exist, extract it
	if(hostname[i]==':'){
		portnumber=atoi(&hostname[i+1]);
		hostname[i]='\0';
	}	
	
	return portnumber;
}

char *getIPAddr(char *addr)             //function to swap host name into IP address
{
        struct hostent* hent;           //hostent structure
        char * haddr;                   //IPaddress
        int len = strlen(addr);         //length

        if ( (hent = (struct hostent*)gethostbyname(addr)) != NULL)             //swap hostname into binary IPaddress
        {
                haddr=inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));      //swap binary IPaddress into dotted IP address
        }
        return haddr;
}
//////////////////////////////////////////////////////////////////////////////////


////////////////LOGFILE///////////////////////////////////////////////////////////
void print_logfile(int hit, int semid, char *contents){
	time_t now;	
	struct tm *ltp;	
	FILE * pF;
	P(semid);				//semaphore lock
	pF=fopen("logfile", "a");
	chmod("logfile", 0777);
	
	fprintf(pF, "*pid : %d lock -- ",getpid());	//print locked pid 	
	time(&now);				//get current time
	ltp=localtime(&now);			
	if(hit==0)
		fprintf(pF, "%s-[%d/%d/%d, %d:%d:%d]", contents , (ltp->tm_year)+1900, (ltp->tm_mon)+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
	
	else
		fprintf(pF, "%c/%c/%s-[%d/%d/%d, %d:%d:%d]", contents[0], contents[1], &contents[2], (ltp->tm_year)+1900, (ltp->tm_mon)+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

	fprintf(pF, "-- %d unlock\n", getpid());	//print locked pid

	fclose(pF);
	V(semid);				//semaphore unlock
}
///////////////////////////////////////////////////////////////////////////////////


/////////////////SEMAPHORE/////////////////////////////////////////////////////////
int initialize_sem(){				//create semaphore
	int semid, i;

	union semun{				//define union semun
		int val;			
		struct semid_ds *buf;
		unsigned short int *array;
	} arg;
	
	//create semaphore key : 40058(portnum) 
	if((semid = semget((key_t)40058, 1, IPC_CREAT|0666))==-1){	
		perror("semget failed");
		exit(1);
	}
	
	arg.val=1;

	//control semaphore
	if((semctl(semid, 0, SETVAL, arg)) ==-1){
		perror("semctl failed");
		exit(1);
	}
	return semid;
}

void P(int semid){			//P operation of semaphore
	struct sembuf pbuf;
	pbuf.sem_num=0;			
	pbuf.sem_op=-1;			//operation is -1, than whenever P execute, semaphore-=1
	pbuf.sem_flg = SEM_UNDO;
	if((semop(semid, &pbuf,1)) == -1){	//operate 
		perror("p : semop failed");
		exit(1);
	}

}
void V(int semid){			//V operation of semaphore
	struct sembuf vbuf;
	vbuf.sem_num=0;
	vbuf.sem_op=1;			//operation is 1, than whenever V execute, semaphore +=1
	vbuf.sem_flg=SEM_UNDO;
	if((semop(semid, &vbuf, 1)) == -1){	//operate
		perror("v : semop failed");
		exit(1);
	}
}
///////////////////////////////////////////////////////////////////////////////
