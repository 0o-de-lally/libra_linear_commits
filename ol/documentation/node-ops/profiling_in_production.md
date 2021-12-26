
# Non-intrusive stack sampling profiling with `prof`
## Install

With sudo permissions, install:

```
sudo apt install linux-oem-5.6-tools-common
sudo apt install linux-tools-5.4.0-81-generic

```

## Profile

get the PID of the diem-node process:

```
ps -a
```

Run the profiler
```
sudo perf record -F 99 -p <pid>  sleep 300
```

Reporter:
```
sudo perf report
```