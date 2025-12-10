#!/bin/bash

# Python 虚拟环境设置脚本
# 创建和配置 Python 虚拟环境

set -e

VENV_DIR="venv"

echo "正在设置 Python 虚拟环境..."

# 检查 Python
if command -v python3.12 &> /dev/null; then
    PYTHON_CMD=python3.12
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
else
    echo "错误: 未找到 Python 3"
    exit 1
fi

echo "使用 Python: $PYTHON_CMD"
$PYTHON_CMD --version

# 创建虚拟环境
if [ -d "$VENV_DIR" ]; then
    echo "虚拟环境已存在，正在删除..."
    rm -rf "$VENV_DIR"
fi

echo "正在创建虚拟环境: $VENV_DIR"
$PYTHON_CMD -m venv "$VENV_DIR"

# 激活虚拟环境
source "$VENV_DIR/bin/activate"

# 升级 pip
echo "正在升级 pip..."
pip install --upgrade pip

# 安装 parent 依赖
if [ -f "parent/requirements.txt" ]; then
    echo "正在安装 parent 依赖..."
    pip install -r parent/requirements.txt
fi

deactivate

echo ""
echo "==================================="
echo "Python 虚拟环境设置完成"
echo "==================================="
echo ""
echo "激活虚拟环境:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "退出虚拟环境:"
echo "  deactivate"
