PAPER := main
LATEX := pdflatex
BIBTEX := bibtex
LATEX_FLAGS := -interaction=nonstopmode -halt-on-error

.PHONY: all clean view chk figures

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex sections/*.tex figures/*.tex references.bib
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex
	$(BIBTEX) $(PAPER)
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex
	$(LATEX) $(LATEX_FLAGS) $(PAPER).tex

figures:
	./figures/build_figs.sh

chk:
	@which chktex >/dev/null && chktex -q $(PAPER).tex sections/*.tex || echo "chktex not installed"

view: $(PAPER).pdf
	@xdg-open $(PAPER).pdf 2>/dev/null || open $(PAPER).pdf 2>/dev/null || echo "No PDF viewer configured."

clean:
	rm -f $(PAPER).aux $(PAPER).log $(PAPER).bbl $(PAPER).blg $(PAPER).out $(PAPER).toc
	rm -f sections/*.aux figures/*.aux
	rm -f $(PAPER).pdf
	rm -rf figures/out
