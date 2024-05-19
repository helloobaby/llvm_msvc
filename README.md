## LLVM(Clang) For Windows Native Compile and integrated to VisualStudio   


### MyBuildConfig

```

X86+ARM64：clang+lld+lldb+RelWithDebInfo
mkdir build2
pushd build2
cmake .. -G "Visual Studio 16 2019" -A X64 -DLLVM_ENABLE_PACK_PDB=ON -DLLDB_ENABLE_PYTHON=OFF -DLLVM_ENABLE_PROJECTS="clang;lld;lldb" -DCMAKE_INSTALL_PREFIX=E:\llvm\install-RelWithDebInfo-64 -DLLVM_ENABLE_LIBXML2=OFF -DLLVM_ENABLE_ZLIB=OFF -DLLVM_TARGETS_TO_BUILD="X86;AArch64" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLLVM_USE_CRT_RELEASE=MT ../llvm
msbuild /m:1 -p:Configuration=RelWithDebInfo INSTALL.vcxproj 

```

大内存的电脑可以多处理器编译

```
msbuild /m -p:Configuration=RelWithDebInfo INSTALL.vcxproj 

```



如果要调试的话还需要一个插件

 [Microsoft Child Process Debugging Power Tool](https://cloud.tencent.com/developer/tools/blog-entry?target=https%3A%2F%2Fmarketplace.visualstudio.com%2Fitems%3FitemName%3Dvsdbgplat.MicrosoftChildProcessDebuggingPowerTool&source=article&objectId=1580580) 

参考

https://cloud.tencent.com/developer/article/1580580



因为clang他是中途fork出子进程然后在子进程里做编译工作的，没插件的话调试的话不好调的



##### Credits to @gmh5225



RelaseWithDbg跟DEBUG还是差不少，建议还是DEBUG编译。





比较好的文章

https://maskray.me/blog/2023-09-24-a-deep-dive-into-clang-source-file-compilation



非常好的工具网站

https://llvm.godbolt.org/



工具链命令行的基本操作

https://github.com/helloobaby/llvm_tools_examples





### How to Use:

(1)Download Release to C:\RelWithDebInfo

(2)VisualStudio Install Standard clang tool chain

https://learn.microsoft.com/en-us/cpp/build/clang-support-msbuild?view=msvc-170

(3)Directory.build.props

```
<Project>
  <PropertyGroup>
    <LLVMInstallDir>C:\RelWithDebInfo</LLVMInstallDir>
    <LLVMToolsVersion>18</LLVMToolsVersion>
  </PropertyGroup>
</Project>
```


### Demo 
![Image text]("./Demo.png")