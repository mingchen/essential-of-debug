#!/bin/sh

xelatex essential-of-debug.tex

makeindex essential-of-debug.idx
bibtex essential-of-debug
xelatex essential-of-debug.tex

xelatex essential-of-debug.tex
