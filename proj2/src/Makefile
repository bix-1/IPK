CXX = g++
CXX_FLAGS = -Wall -Wextra -std=c++17 -g # -Werror
EXEC = ipk-sniffer

all: $(EXEC)

run: $(EXEC)
	sudo ./$(EXEC) -i wlp3s0 -n -1

$(EXEC): $(EXEC).cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@ -lpcap

clean:
	rm -f $(EXEC)
