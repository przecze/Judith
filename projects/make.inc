# the following definitions you need to adjust for your computer

# define which C++-compiler to use
CXX = g++

# flags for compilation
# INST main installation directory
INST = ../..

# in which directories to look for library files
LIBS = -L$(INST)/lib

# in which directories to look for .h files 
INCS = -I$(INST)/inc

# Output all warnings
#CFLAGS+= -Wall
