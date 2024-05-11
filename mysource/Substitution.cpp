struct test{
	int a;
	int b;
	int c;
};

auto f(){
	return test{1,2,3};
}

int main(int argc,char*argv[]) {
	int a = 0;
	volatile int b= a+1;
	test t;
	t.b=b;
	t.a=a;
	t.c=0;
	auto r = f();
	return t.b;
}