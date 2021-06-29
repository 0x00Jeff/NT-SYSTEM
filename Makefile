CC	= x86_64-w64-mingw32-g++
FILE 	= nt-system.exe
SRC	= $(FILE:.exe=.c)
OBJ	= $(FILE:.exe=.o)

$(FILE): $(OBJ)
	$(CC) $< -o $@

$(OBJ):

clean:
	rm -- $(OBJ) $(FILE)
