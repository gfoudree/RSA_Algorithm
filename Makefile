CXX = g++
LIBS = -lgmp -lpthread -lgmpxx
CXXFLAGS = -std=gnu++11 -g
TARGET = rsa
SOURCES = rsa.cpp main.cpp

all : $(SOURCES)
	$(CXX) $(SOURCES) -o $(TARGET) $(LIBS) $(CXXFLAGS)

clean :
	rm $(TARGET)
