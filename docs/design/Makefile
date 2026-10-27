PAPER := ziren-b3-design
LATEX := pdflatex
BIBTEX := bibtex
LATEX_FLAGS := -interaction=nonstopmode -halt-on-error

.PHONY: all clean

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex sections/*.tex references.bib
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex
	$(BIBTEX) $(PAPER)
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).log $(PAPER).bbl $(PAPER).blg $(PAPER).out $(PAPER).toc
	rm -f sections/*.aux
	rm -f $(PAPER).pdf
