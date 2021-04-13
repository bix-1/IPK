CXX = g++
CXX_FLAGS = -Wall -Wextra -std=c++17 -g # -Werror
EXEC = ipk-sniffer

all: $(EXEC)

run: $(EXEC)
	sudo ./$(EXEC) -i wlp3s0 -n -1

$(EXEC): $(EXEC).cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@ -lpcap

doc:
	cd ../doc/ && pdflatex manual.tex
	cd ../doc/ && bibtex manual.aux
	cd ../doc/ && pdflatex manual.tex
	cd ../doc/ && pdflatex manual.tex	
	cd ../doc/ && rm -f *.aux *.log *.bbl *.blg *.out *.toc

clean:
	rm -f $(EXEC) && cd ../doc/ && rm -f *.aux *.log *.bbl *.blg *.out *.toc manual.pdf
