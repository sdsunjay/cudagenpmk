nvcc -O2 -Xptxas="-v" -gencode arch=compute_20,code=sm_20 genpmk.cu -o cudagenpmk
