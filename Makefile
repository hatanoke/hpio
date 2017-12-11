

subdirs = kmod tools

all:
	for i in $(subdirs); do \
		echo; echo $i;	\
		make -C $$i;	\
	done

clean:
	for i in $(subdirs); do \
		echo; echo $i;	\
		make -C $$i clean;	\
	done
