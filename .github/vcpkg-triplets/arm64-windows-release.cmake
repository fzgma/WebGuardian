# Windows ARM64 原生编译配置

# 目标架构为 ARM64
set(VCPKG_TARGET_ARCHITECTURE arm64)

# 使用动态链接的 MSVC 运行库
set(VCPKG_CRT_LINKAGE dynamic)

# 优先使用动态链接库
set(VCPKG_LIBRARY_LINKAGE dynamic)

# 仅构建 Release 版本，不构建 Debug 版本
set(VCPKG_BUILD_TYPE release)