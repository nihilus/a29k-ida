IDADIR?=/opt/ida-6.8

install: 
	install a29k-coff.py ${IDADIR}/loaders/
	install amd29k.py ${IDADIR}/procs/



link:
	ln -f -s -t ${IDADIR}/loaders $(abspath a29k-coff.py)
	ln -f -s -t ${IDADIR}/procs $(abspath amd29k.py)

