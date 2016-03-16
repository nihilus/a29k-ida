void sbrk() { }

send(to, from, count)
register char *to, *from;
register count;
{
    register n = (count+7)/8;
    switch (count%8) {
        case 0:	do {    *to++ = *from++;
        case 7:         *to++ = *from++;
        case 6:         *to++ = *from++;
        case 5:         *to++ = *from++;
        case 4:         *to++ = *from++;
        case 3:         *to++ = *from++;
        case 2:         *to++ = *from++;
        case 1:         *to++ = *from++;
        } while (--n>0);
    }
}

int main(int c, char**v) {
	send(v[0],v[1],strlen(v[1]));
	return 0;
}
