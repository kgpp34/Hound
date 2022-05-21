# Hound
Hound is a network monitor tool by using eBPF, and it is dedicated to probe kernel network event and visualization

## env
- linux kernel version: 5.15.0-30-generic
- golang version: 1.18
- clang version: 14.0.0

## description
Recently, Hound kernel code used BPF_HASH_MAP to record tcp active connection session，

then，we used BPF_RINGBUF to collect and print tcp connection estabished event from kernel
