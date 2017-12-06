include ../make.inc


# Compile a cpp file
%.o: %.cpp
	$(CXX) $(INCS) -c $< -o $@ $(CFLAGS)

main: main.o $(OBJS)
	$(CXX) -o main main.o $(OBJS) $(LIBS)



# Remove all generated files
clean:
	rm -f *.o main
