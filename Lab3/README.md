#To compile
Working for the full install of `latex` in MacOS X, not controlled in other 
operating systems.

Go in to folder latex then

```
$ pdflatex report
$ biber report
$ pdflatex report
$ pdflatex report
```

The double last command is needed for the references in the toc and hyperref 
to function properly.

***