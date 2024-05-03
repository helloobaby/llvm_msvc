// ClangBuildTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
//  C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe

// 自定义LLVM设置
//https://learn.microsoft.com/en-us/cpp/build/clang-support-msbuild?view=msvc-170#custom_llvm_location

/*
<Project>
  <PropertyGroup>
    <LLVMInstallDir>D:\workspace\llvm-msvc\build\Release\</LLVMInstallDir>
    <LLVMToolsVersion>777</LLVMToolsVersion>
  </PropertyGroup>
</Project>
*/

__attribute((__annotate__(("Hello"))));
extern "C"{
void test();
}
int main(int argc,char*argv[])  __attribute((__annotate__(("Hello"))));

//#include <iostream>
//#include <vector>

int main(int argc,char*argv[]) {
//#ifdef _MSC_VER
//  std::cout << "I'm msvc" << std::endl;
//#elif __clang__
//  std::cout << "I'm clang" << std::endl;
//#else
//  std::cout << "I'm unknow" << std::endl;
//#endif
//
//  #ifdef __clang__
//  std::cout << "I'm clang" << std::endl;
//  #endif
//
//#ifdef __llvmmsvc__
//  std::cout << "I'm clang" << std::endl;
//#endif

  if(argc >= 1)
	  return 1;
  else if(argc >=2)
	  return 2;
  else if(argc >=3)
	  return 3;

  test();
  return 0;
}

void test(){
	int __attribute__((annotate("Hello"))) var = 0;
	return;
}