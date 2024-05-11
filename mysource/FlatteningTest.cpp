// 递归实现斐波那契数列
int fibonacci_recursive(int n) {
    if (n <= 1)
        return n;
    else
        return fibonacci_recursive(n - 1) + fibonacci_recursive(n - 2);
}

// 循环实现斐波那契数列
int fibonacci_iterative(int n) {
    if (n <= 1)
        return n;

    int a = 0, b = 1;
    for (int i = 2; i <= n; ++i) {
        int temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

int main() {
    int n = 10; // 生成斐波那契数列的前n项
    for (int i = 0; i < n; ++i) {
        fibonacci_recursive(i);
    }
    for (int i = 0; i < n; ++i) {
        fibonacci_iterative(i);
    }
    return 0;
}