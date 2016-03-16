void sbrk() { }

void dings(char c) { }

void sw(int i) {
	switch(i) {
		case 0:
			dings(i+123);
			break;
		case 1:
			dings(i+12);
			break;
		case 2:
			dings(i+13);
			break;
		case 3:
			dings(i+23);
			break;
		case 4:
		case 5:
			dings(i+1);
			break;
		case 6:
		case 7:
			dings(i+2);
			break;
		case 8:
			dings(i+3);
			break;
		case 9:
			dings(i+127);
		case 20:
			dings(i+127);
			break;
		case 21:
			dings(i+127);
			break;
		case 22:
			dings(i+123);
		case 23:
			dings(i+127);
		case 24:
			dings(i+129);
		case 25:
			dings(i+127);
			break;
		case 26:
		case 27:
			dings(i+123);
			break;
		case 28:
		case 29:
	}

}

int main(int c, char**v) {
	sw(c);
	return 0;
}
