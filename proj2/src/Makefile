CXX = g++
CXX_FLAGS = -Wall -Wextra -std=c++17 -g # -Werror
EXEC = ipk-sniffer
LOGIN = xbartk07

all: $(EXEC)

run: $(EXEC)
	sudo ./$(EXEC) -i wlp3s0 -n -1

$(EXEC): $(EXEC).cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@ -lpcap

doc: ../doc/manual.pdf

../doc/manual.pdf: ../doc/manual.tex ../doc/citations.bib
	cd ../doc/ && pdflatex manual.tex
	cd ../doc/ && bibtex manual.aux
	cd ../doc/ && pdflatex manual.tex
	cd ../doc/ && pdflatex manual.tex	
	cd ../doc/ && rm -f *.aux *.log *.bbl *.blg *.out *.toc

pack: ../doc/manual.pdf ipk-sniffer.cpp ipk-sniffer.h Makefile README
	tar -cvf $(LOGIN).tar ipk-sniffer.cpp ipk-sniffer.h Makefile README
	cd ../doc/ && tar -rvf ../src/$(LOGIN).tar manual.pdf

clean:
	rm -f $(EXEC) *.tar && cd ../doc/ && rm -f *.aux *.log *.bbl *.blg *.out *.toc manual.pdf
