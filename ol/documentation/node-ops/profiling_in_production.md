
# Non-intrusive stack sampling profiling with `prof`

https://rust-lang.github.io/packed_simd/perf-guide/prof/linux.html

## Install

With sudo permissions, install:

```

sudo apt install linux-oem-5.6-tools-common
sudo apt install linux-tools-5.4.0-81-generic

#for call hierarchy report
sudo apt instsall binutils 

```

Your cloud vendor may have a different version of this. On google cloud it would be:
```
linux-tools-5.11.0-1021-gcp
linux-tools-gcp
```

## Profile

get the PID of the diem-node process:

```
ps -a
```

Run the profiler for 30 seconds
``` 
sudo perf record -F 99 -p <pid> -g sleep 30
```

Reporter:
```
sudo perf report -n --stdio
```