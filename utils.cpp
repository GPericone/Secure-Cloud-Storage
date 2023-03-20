#include "utils.h"

int cl_index_free_buf = 0;
unsigned char *cl_free_buf[65536] = {0};
int sv_index_free_buf = 0;
unsigned char *sv_free_buf[65536] = {0};

void free_var(int side){	// Buffer allocated with malloc() pointers, multiple free()
	int counter = 0;
	if(side == 1){
		counter = cl_index_free_buf;
		for(int i = 0; i < counter - 1; i++){
			if(cl_free_buf[i]){
				free((void*)cl_free_buf[i]);
				cl_free_buf[i] = NULL;
			}
		}
		cl_index_free_buf = 0;
	}
	else if(side == 0){
		counter = sv_index_free_buf;
		for(int i = 0; i < counter - 1; i++){
			if(sv_free_buf[i]){
				free((void*)sv_free_buf[i]);
				sv_free_buf[i] = NULL;
			}
		}
		sv_index_free_buf = 0;
	}
	else{
		cerr << "Panic! Critical error, shutting down program..." << endl;
		exit(0);
	}	
}

void memory_handler(int side, int socket, int new_size, unsigned char **new_buf){
	*new_buf = (unsigned char*)calloc(new_size+1, sizeof(unsigned char));	
	if(!*new_buf){
		free_var(side);
		if(socket)
			close(socket);

		cerr << "Critical error: malloc() failed allocating " << new_size << " new bytes" << endl << "Exit program" << endl;
		exit(0);
	}

	if(side == 1){
		cl_free_buf[cl_index_free_buf] = *new_buf;
		cl_index_free_buf++;
	}
	else if(side == 0){
		sv_free_buf[sv_index_free_buf] = *new_buf;
		sv_index_free_buf++;
	}
	else{
		cerr << "Panic! Critical error, shutting down program..." << endl;
		if(socket)
			close(socket);
		free_var(0);
		free_var(1);
		exit(0);
	}	
}

void serialize_int(int val, unsigned char *c){
	c[0] =  val & 0xFF;
	c[1] = (val>>8) & 0xFF;
	c[2] = (val>>16) & 0xFF;
	c[3] = (val>>24) & 0xFF;
}

void serialize_longint(long int val, unsigned char *c){
	c[0] =  val & 0xFF;
	c[1] = (val>>8) & 0xFF;
	c[2] = (val>>16) & 0xFF;
	c[3] = (val>>24) & 0xFF;
	c[4] = (val>>32) & 0xFF;
	c[5] = (val>>40) & 0xFF;
	c[6] = (val>>48) & 0xFF;
	c[7] = (val>>56) & 0xFF;
}