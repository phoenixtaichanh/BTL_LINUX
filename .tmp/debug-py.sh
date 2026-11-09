#!/usr/bin/env bash
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
cd /d/BTL_Linux || exit 1

echo "=== which python ==="
which python python3 2>&1
echo "=== python version ==="
python --version 2>&1
echo "=== module import ==="
python -c "import btl.cli; print('btl.cli OK')" 2>&1 | tail -5
echo "=== module run ==="
python -m btl.cli --version 2>&1 | tail -5
