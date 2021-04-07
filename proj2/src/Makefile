CXX = g++
CXX_FLAGS = -Wall -Wextra -std=c++17 -g # -Werror
EXEC = ipk-sniffer

all: $(EXEC)

run: $(EXEC)
	./$(EXEC)

$(EXEC): $(EXEC).cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@

clean:
	rm -f $(EXEC)
