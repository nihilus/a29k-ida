void sbrk() { }

int main(int c, char**v) {
	void * labarr[]= {&&l1, &&l2, &&l3, &&l4, &&l5, &&l6};
	goto *labarr[c];
l1:	return 0;
l2:	return 1;
l3:	return 2;
l4:	return 3;
l5:	return 4;
l6:	return 5;
}
