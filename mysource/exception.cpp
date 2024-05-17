#include <Windows.h>
#pragma comment(lib,"Bcrypt.lib")
int main() {
    int i = 0;

    try 
{
        i = BCryptGenRandom(0, 0, 0, 0);
        i = i + 1;
    }
    catch (...)
    {
        return 1;
    }
    return 0;
}