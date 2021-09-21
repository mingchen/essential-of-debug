.PHONY: all pdf shell clean

all: pdf

pdf:
	# Run xelatex multiple times to generate cross-references like cite, book of content etc.
	docker run --rm -i \
		-v `pwd`:/data \
		-v `pwd`/.fonts:/root/.fonts \
		mingc/latex ./build.sh

pdf1:
	# Only run xelatex one time.
	docker run --rm -i \
		-v `pwd`:/data \
		-v `pwd`/.fonts:/root/.fonts \
		mingc/latex	xelatex essential-of-debug.tex

shell:
	docker run --rm -it -v `pwd`:/data -v `pwd`/.fonts:/root/.fonts mingc/latex bash

clean:
	rm -f *log  *.out *.dvi *.toc *.aux *~ core.* *.pdf *.idx *.ind *.lot *.lof *.ilg *.bbl *.blg
