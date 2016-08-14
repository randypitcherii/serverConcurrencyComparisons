const char * usage = 	"                               \n"
						"myhttp-server:                 \n"
						"                              	\n"
						"To use it in one window type:  \n"
						"                               \n"
						"   myhttpd [-f|-t|-p] <port>              \n"
						"                               \n"
						"Where 1024 < port < 65536. 	\n"
						"\t-f triggers child process concurrency\n"
						"\t-t triggers new thread concurrency\n"
						"\t-p triggers thread pool concurrency\n\n";

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <pthread.h>

int QueueLength = 5;
char * currentHTTPDirectory;//string containing the absolute path to the http root directory
pthread_mutex_t poolMutex;//mutex object for thread synchronization

/**
 * This method expands the default document path and makes sure
 * that no '..' or other illegal components are present in documentPath.
 *
 * @param char ** documentPath - pointer to string that initially contains unexpanded path but
 *								will point to the fully expanded path at the end of the function.
 */
void parseDocumentPath(char ** documentPath) {
	char * path = (char *) malloc((strlen(*documentPath) + 2)*sizeof(char));
	strcpy(path, ".\0");
	strcat(path, *documentPath);
	free(*documentPath);//done with this. Don't want to forget to free it
	
	//check if the request is for the default doc
	if (!strcmp(path,"./" )) {
		free(path);
		path = strdup("./http-root-dir/htdocs/index.html");//default file
	}
	
	//do custom path expansion below
	char * tmp;//used to build modified document paths below.
	char * httpRootPath = strdup("./http-root-dir/");//prepended to path if necessary
	
	//check for the /icons and the /htdocs cases
	if (!strncmp(path, "./icons", strlen("./icons")) || 
					!strncmp(path, "./htdocs", strlen("./htdocs"))) {
		//use tmp to build the modified document path string
		tmp = (char *) realloc(httpRootPath,
					sizeof(char) * (strlen(httpRootPath) + strlen(path) - 1));
		strcat(tmp, path + 2);//path+2 to skip the existing "./" in path
		free(path);//done with this memory
		path = tmp;

	//for all other paths, make sure it starts with ./http-root-dir/htdocs if it doesn't
	} else if (strncmp(path, "./http-root-dir/htdocs", strlen("./http-root-dir/htdocs"))){
		//use tmp to build the modified document path string
		tmp = strdup("htdocs/");
		httpRootPath = (char *) realloc(httpRootPath,
			sizeof(char) * (strlen(tmp) + strlen(httpRootPath) + strlen(path) - 1));
		strcat(httpRootPath, tmp);//build in htdocs to the new path
		strcat(httpRootPath, path + 2);//path+2 to skip the existing "./" in path
		free(path);//done with this memory
		free(tmp);//done with this memory
		path = httpRootPath;
	}

	//now expand any '.' or '..' in the path
	char * expandedPathBuffer = (char *) malloc(sizeof(char)*1024);
	realpath(path, expandedPathBuffer);//expand path into the buffer
	free(path);//done with this memory.
	
	//let's trim down the memory space from buffer to just what's taken up
	//by the expanded path. Realloc will free the rest for us.
	path = (char *) realloc(expandedPathBuffer, 
				sizeof(char) * (strlen(expandedPathBuffer) + 1));
				
	*documentPath = path;
	
	printf("fully processed path request:\n%s\n\n", path);
}
	
/**
 * This method sends a general file not found message to the client.
 *
 * @param int fd - file descriptor for writing to the client socket.
 */
void documentNotFound(int fd) {
	const char * response = 
		"HTTP/1.0 404 File Not Found\r\nServer: CS 252 lab5\nContent-type: text/plain\r\n\r\nNo matching file found.";
		
		write(fd, response, strlen(response));
}

/**
 * This method extracts the file extension from docPath and returns the appopriate
 * string for sending content type header information to the client.
 *
 * @param char * docPath - full path to the document requested by the client
 * @return char * - string containing content type information for the client response header
 */
char * getFileType(char * docPath) {
	//get file extension
	char * extension = docPath;
	while (strchr(extension, '.') != NULL) {
		extension = strchr(extension, '.') + 1;
	}
	
	//remove the final '/' from extension if it exists
	//This simplifies the identification of the filetype
	if (extension[strlen(extension) - 1] == '/') {
		extension[strlen(extension) - 1] = '\0';
	}
	
	//use extension to determine the file type
	if (!strcmp(extension, "html")) {
		return strdup("text/html\r\n\r\n");
	} 
	
	if (!strcmp(extension, "gif")) {
		return strdup("image/gif\r\n\r\n");
	} 
	
	if (!strcmp(extension, "jpeg") || !strcmp(extension, "jpg")) {
		return strdup("image/jpeg\r\n\r\n");
	}  
	
	//if none of the above filetypes are match, assume plain text
	return strdup("text/plain\r\n\r\n");
}

/**
 * This function sends the document located at docPath to the client.
 *
 * @param char * docPath - path to requested document
 * @param int client_fd - file descriptor for writing content to client socket
 * @param int content_fd - file descriptor for reading content from the requested document.
 */
void sendDocument(char * docPath, int client_fd, int content_fd) {
	char * response = strdup(
			"HTTP/1.0 200 Document follows\r\nServer: CS 252 lab5\nContent-type: ");
	write(client_fd, response, strlen(response));
	free(response);
	
	response = getFileType(docPath);
	write(client_fd, response, strlen(response));
	free(response);
	
	//now write the actual content
	char buffer;
	int bufferSize = sizeof(buffer);
	
	while (read(content_fd, &buffer, bufferSize) > 0) {
		write(client_fd, &buffer, bufferSize);
	}
}

/**
 * determine if the requested document exists and return a fileDescriptor 
 * to the opened file if it does exist and return 0 if it does not.
 *
 * @param char * absPath - absolute path to the requested document
 * @return int - file descriptor for reading from the opened document. 
 *					This is 0 if the document is not found.
 */
int findDocument(char * absPath) {
	//check that absPath is within the http-root-dir directory
	if (strncmp(absPath, currentHTTPDirectory, strlen(currentHTTPDirectory))) {
		return 0;//the request is outside of the allowable search area.
	}
	
	//try to open the file. An error here is handled by calling documentNotFound.
	//use write permission to throw error when path points to a directory
	return open(absPath, O_RDWR);
}

/**
 * This function will dispose of the remaining input from the current client.
 *
 * @param int fd - file descriptor for reading from the client socket.
 */
void flushRemainingClientMessage(int fd) {
	//read until we find the \r\n\r\n sequence that
	//tells us the input from the client is done.
	char last3, last2, last1, last;//the previous 3 chars, 3 being oldest
	char nextChar;//used to get next char from client.
	int charsRead = 0;	
	//dispose of the rest of the request.
	while (read(fd, &nextChar, sizeof(nextChar)) > 0) {
		last3 = last2;
		last2 = last1;
		last1 = last;
		last = nextChar;
		charsRead++;
		
		if (last3 == '\r' && last2 == '\n' && last1 == '\r' && last == '\n') {
			//found a match for \r\n\r\n. Time to stop reading and start processing
			break;//break the loop and move on.
		}
	}
}

/**
 * This function processes a received request from a client.
 *
 * @param int fd - file descriptor for reading from and writing to the current client socket.
 */
void processRequest( int fd ) {
	//create variables for parsing client request
	char nextChar = 0;
	int bufferSize = 1024;
	char * buffer = (char *) malloc(bufferSize * sizeof(char));
	int currentLength = 0;
	char * documentPath;
	
	//get each section of the request from the client request header
	
	//get request type
	while (read(fd, &nextChar, sizeof(nextChar)) > 0) {
		if (nextChar == ' ') {
			break;
		}		
	}
	
	//get the document path
	while (read(fd, &nextChar, sizeof(nextChar)) > 0) {
		if (nextChar == ' ') {
			break;
		} 
		
		//check for buffer overflow
		if (currentLength == bufferSize) {
			bufferSize = bufferSize * 2;
			buffer = (char *) realloc(buffer, bufferSize * sizeof(char));
		}
		
		buffer[currentLength] = nextChar;
		currentLength++;
	}
	//copy buffer to documentPath string and dispose of the buffer
	buffer[currentLength] = '\0';
	documentPath = strdup(buffer);
	free(buffer);
	
	//dispose of the remaining 
	flushRemainingClientMessage(fd);
	
	//check for an empty request
	if (!strcmp(documentPath, "")) {
		//if an empty request, send documentNotFound and return
		documentNotFound(fd);
		return;
	}
	
	//get the absolutePath requested
	parseDocumentPath(&documentPath);
	int content_fd = 0;//file descriptor for an opened document
	
	//find the document, if it exists. This returns true if it is found, false if not
	if ((content_fd = findDocument(documentPath)) > 0) {
		//send the document to the client.
		sendDocument(documentPath, fd, content_fd);
		close(content_fd);
	} else {
		documentNotFound(fd);//inform the client that the requested doc was not found.
	}
	
	// Close socket
	close(fd);
}

/**
 * This function runs the standard iterative server.
 *
 * @param int masterSocket - file descriptor for the master socket. Used to accept client requests
 */
void startIterativeServer(int masterSocket) {
	while ( 1 ) {
		// Accept incoming connections
		struct sockaddr_in clientIPAddress;
		int alen = sizeof( clientIPAddress );
		int slaveSocket = accept( masterSocket,
					  (struct sockaddr *)&clientIPAddress,
					  (socklen_t*)&alen);

		if ( slaveSocket < 0 ) {
		  perror( "accept" );
		  exit( -1 );
		}

		// Process request. This also closes the client socket
		processRequest( slaveSocket );
  	}
}

/**
 * This function runs the concurrent server that 
 * uses new child processes for each request.
 *
 * @param int masterSocket - file descriptor for the master socket. Used to accept client requests
 */
void startForkServer(int masterSocket) {
	while ( 1 ) {
		// Accept incoming connections
		struct sockaddr_in clientIPAddress;
		int alen = sizeof( clientIPAddress );
		int slaveSocket = accept( masterSocket,
					  (struct sockaddr *)&clientIPAddress,
					  (socklen_t*)&alen);

		if ( slaveSocket < 0 ) {
		  perror( "accept" );
		  exit( -1 );
		}

		int ret = fork();
		if (ret == 0) {
			//double child to detach from parent process
			if (fork() == 0) {
				// Process request.This also closes the client socket
				processRequest(slaveSocket);
				exit(0);
			}
			exit(0);
		}
		
		//Continue parent process
		waitpid(ret, NULL, 0);//kill zombies
		close( slaveSocket );//close parent copy of the client file descriptor
  }
}

/**
 * This function runs the concurrent server that uses new threads for each request
 *
 * @param int masterSocket - file descriptor for the master socket. Used to accept client requests
 */
void startThreadServer(int masterSocket) {
	while ( 1 ) {
		// Accept incoming connections
		struct sockaddr_in clientIPAddress;
		int alen = sizeof( clientIPAddress );
		int slaveSocket = accept( masterSocket,
					  (struct sockaddr *)&clientIPAddress,
					  (socklen_t*)&alen);

		if ( slaveSocket < 0 ) {
		  perror( "accept" );
		  exit( -1 );
		}
		
		pthread_t thread;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&thread, &attr, 
			(void * (*)(void *)) processRequest, (void *) slaveSocket);
  }
}

/**
 * This is the listener loop for the pool of threads server
 *
 * @param int masterSocket - file descriptor for the master socket. Used to accept client requests
 */
void poolOfThreadsLoop(int masterSocket) {
	while ( 1 ) {
		pthread_mutex_lock(&poolMutex);//begin atomic section
		// Accept incoming connections
		struct sockaddr_in clientIPAddress;
		int alen = sizeof( clientIPAddress );
		int slaveSocket = accept( masterSocket,
					  (struct sockaddr *)&clientIPAddress,
					  (socklen_t*)&alen);

		if ( slaveSocket < 0 ) {
		  perror( "accept" );
		  exit( -1 );
		}
		pthread_mutex_unlock(&poolMutex);//end atomic section

		// Process request. This also closes the client socket
		processRequest( slaveSocket );
  	}
}

/**
 * This function runs the concurrent server that uses the pool of threads concurrency strategy
 *
 * @param int masterSocket - file descriptor for the master socket. Used to accept client requests
 */
void startPoolOfThreadsServer(int masterSocket) {
	//initialize mutex
	pthread_mutex_init(&poolMutex, NULL);
	
	//create threads and thread_attr
	pthread_t tid[5];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	
	//put those threads to work listening for client connections
	for(int i = 0; i < 5; i++) {
		pthread_create(&tid[i], &attr, 
			(void * (*)(void *)) poolOfThreadsLoop, (void *) masterSocket);
	}
	
	//send the main thread to do some work in poolOfThreadsLoop too. Slacker.
	poolOfThreadsLoop(masterSocket);
}

int main( int argc, char ** argv ) {
	// Print usage if not enough arguments
	if ( argc > 3 ) {
		fprintf( stderr, "%s", usage );
		exit( -1 );
	}
  
	//used to record user preferred concurrency strategy
	//0 = iterative, 1 = newProcess, 2 = newThread, 3 = poolOfThreads
	int concurrencyType = 0;//default concurrency strategy
	int port = 8060;//default port
	if (argc == 3) {
		if (!strcmp(argv[1], "-f")) {
			concurrencyType = 1;
		} else if (!strcmp(argv[1], "-t")) {
			concurrencyType = 2;
		} else if (!strcmp(argv[1], "-p")) {
			concurrencyType = 3;
		} else {
			fprintf( stderr, "%s", usage );
			exit( -1 );
		}
		port = atoi(argv[2]);
	} else if (argc == 2) {
		if (!strcmp(argv[1], "-f")) {
			concurrencyType = 1;
		} else if (!strcmp(argv[1], "-t")) {
			concurrencyType = 2;
		} else if (!strcmp(argv[1], "-p")) {
			concurrencyType = 3;
		} else {
			port = atoi( argv[1] );
		}
	}
  
	//inform the user of the current server settings.
	printf("Listening on port %d and using concurrency strategy %d\n", 
  			port, concurrencyType);
  
	// Set the IP address and port for this server
	struct sockaddr_in serverIPAddress; 
	memset( &serverIPAddress, 0, sizeof(serverIPAddress) );
	serverIPAddress.sin_family = AF_INET;
	serverIPAddress.sin_addr.s_addr = INADDR_ANY;
	serverIPAddress.sin_port = htons((u_short) port);
  
	// Allocate a socket
	int masterSocket =  socket(PF_INET, SOCK_STREAM, 0);
	if ( masterSocket < 0) {
		perror("socket");
		exit( -1 );
	}

	// Set socket options to reuse port. Otherwise we will
	// have to wait about 2 minutes before reusing the sae port number
	int optval = 1; 
	int err = setsockopt(masterSocket, SOL_SOCKET, SO_REUSEADDR, 
		   (char *) &optval, sizeof( int ) );

	// Bind the socket to the IP address and port
	int error = bind( masterSocket,
			(struct sockaddr *)&serverIPAddress,
				sizeof(serverIPAddress) );
	if ( error ) {
		perror("bind");
		exit( -1 );
	}

	// Put socket in listening mode and set the 
	// size of the queue of unprocessed connections
	error = listen( masterSocket, QueueLength);
	if ( error ) {
		perror("listen");
		exit( -1 );
	}

	//go ahead and get the currentHTTPDirectory for path request validation
	currentHTTPDirectory = (char*) malloc(1024 * sizeof(char));
	realpath("./http-root-dir", currentHTTPDirectory);//expand to absolute path
  
	//trim the memory of currentHTTPDirectory down to just the size of the absolute path
	currentHTTPDirectory = (char *) realloc(currentHTTPDirectory, 
  								(strlen(currentHTTPDirectory) + 1) * sizeof(char));
  
	//determine which process loop to enter from the current concurrencyType
	if (concurrencyType == 1) {
		startForkServer(masterSocket);
	} else if (concurrencyType == 2) {
		startThreadServer(masterSocket);
	} else if (concurrencyType == 3) {
		startPoolOfThreadsServer(masterSocket);
	} else {
		//default case
		startIterativeServer(masterSocket);
	}
}
