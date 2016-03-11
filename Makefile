IDADIR?=/opt/ida-6.8

install: 
	install a29k-coff.py ${IDADIR}/loaders/
	install amd29k.py ${IDADIR}/procs/
