<div align="center">
  <h1> Netsniff </h1>
</div>

## 介绍

Netsniff 是一个使用 **eBPF** 技术对网络数据包进行嗅探的工具，基于 `aya` 框架进行构建的 `BPF_PROG_TYPE_SCHED_CLS` eBPF 类型项目，并挂载到 `tc` 子系统中。

目前 Netsniff 有两种使用方式:
1. 作为命令行工具对指定条件的网络数据包进行探测
2. 作为 server 抓取网络数据包后转为 metrics 并向外暴露

```bash
$ ./netsniff
Usage: sniff [OPTIONS] <COMMAND>

Commands:
  all    Detect all types of (TCP/UDP) traffic
  tcp    Detect TCP type traffic
  udp    Detect UDP type traffic
  check  Check whether the sniff ebpf program can be mounted correctly
  run    Running sniff ebpf program as server

Options:
  -v <verbose>      Set the log verbose [default: info] [possible values: trace, debug, info, warn, error]
  -d [<FLOW>]       Detected traffic direction [default: all] [possible values: ingress, egress, all]
  -i <iface,>       One or more ifaces to attach. (e.g. --iface lo,eth0...)
  -c <cidr,>        Detect traffic matching the given cidr. If not set, all traffic will be matched
  -h, --help        Print help (see more with '--help')
```

## 演示

使用 server 模式探测 `1.1.1.1` 的 Ingress/Egress 数据包大小和 `8.8.8.8` 的 Egress 数据包大小，并获取其导出的指标信息

> NOTE: server 模式下需要提供配置文件

1.准备 `config.yaml` 配置文件:
```yaml
# 附加到 metrics 上的 labels
constLabels:
  - appName
# 设置 15s 收集并记录一次 metrics 
exportInterval: 15s
rules:
  - name: rule1
    protocol: tcp
    cidrs: ["1.1.1.0/24"]
    inPorts: []
    # 仅在 in/outIface 中配置了网卡时才会探测该网卡上的数据包
    inIface: [enp1s0]
    outIface: [enp1s0]
    constValues:
      appName: cf
```
2.启动 Netsniff:
```bash
# 打印 trace 级别的日志
$ ./netsniff run config.yaml -v trace
```
3.结果
```shell
# terminal netsniff
......
[2025-03-04T03:04:01Z INFO  netsniff::ebpf] success to attach the ingress eBPF program(TC) to the 'enp1s0' network interface!
[2025-03-04T03:04:01Z INFO  netsniff::ebpf] success to attach the egress eBPF program(TC) to the 'enp1s0' network interface!
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=60   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Ingress   1.1.1.1:80              ->    10.199.0.20:60426       Tcp    length=60   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=52   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=124  
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Ingress   1.1.1.1:80              ->    10.199.0.20:60426       Tcp    length=52   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=52   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Ingress   1.1.1.1:80              ->    10.199.0.20:60426       Tcp    length=271  
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=52   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Egress    10.199.0.20:60426       ->    1.1.1.1:80              Tcp    length=52   
[2025-03-04T03:04:06Z TRACE netsniff::app] * [2025-03-04 03:04:06] Ingress   1.1.1.1:80              ->    10.199.0.20:60426       Tcp    length=52


# terminal curl
$ curl localhost:10010/metrics  # 10010是 netsniff metrics server 默认端口
network_packet_tolal{appName="cf",network_iface="enp1s0",port="undefine",protocol="tcp",rule_name="rule1",traffic="ingress"} 435
network_packet_tolal{appName="cf",network_iface="enp1s0",port="unsupport",protocol="tcp",rule_name="rule1",traffic="egress"} 392
```

> NOTE: 当前仅导出四层数据包大小指标, 后续将支持更多特性数据包指标导出

## 命令行参数

### netsniff run

将 netsniff 作为服务的方式运行, 需要指定配置文件

可选参数:
* -v: 设置日志格式。 trace 级别将打印探测的每一个数据包

```shell
Running sniff ebpf program as server

Usage: netsniff run [OPTIONS] <CONFIG>

Arguments:
  <CONFIG>  Specify the configuration file to be loaded by sniff

Options:
  -v <verbose>      Set the log verbose [default: info] [possible values: trace, debug, info, warn, error]
  -h, --help        Print help (see more with '--help')
```

### netsniff tcp/udp

将 netsniff 作为命令行工具的方式运行, 需要指定网口

可选参数:
* -v: 设置日志格式。 trace 级别将打印探测的每一个数据包
* -i(Required): 指定要附加到的网口
* -d: 指定探测的网络数据包流量方向
* -c: 指定探测匹配的 cidr 的网络流量

```shell
Detect TCP/UDP type traffic

Usage: netsniff tcp/udp [OPTIONS]

Options:
  -v <verbose>      Set the log verbose [default: info] [possible values: trace, debug, info, warn, error]
  -d [<FLOW>]       Detected traffic direction [default: all] [possible values: ingress, egress, all]
  -i <iface,>       One or more ifaces to attach. (e.g. --iface lo,eth0...)
  -c <cidr,>        Detect traffic matching the given cidr. If not set, all traffic will be matched
  -h, --help        Print help (see more with '--help')
```

### netsniff check

netsniff 尝试在当前操作系统挂载 eBPF 程序, 并执行检查

可选参数:
* -v: 设置日志格式。 trace 级别将打印探测的每一个数据包
* -i(Required): 指定要附加到的网口
* -d: 指定探测的网络数据包流量方向
* -c: 指定探测匹配的 cidr 的网络流量

```shell
Check whether the sniff ebpf program can be mounted correctly

Usage: netsniff check [OPTIONS]

Options:
  -v <verbose>      Set the log verbose [default: info] [possible values: trace, debug, info, warn, error]
  -d [<FLOW>]       Detected traffic direction [default: all] [possible values: ingress, egress, all]
  -i <iface,>       One or more ifaces to attach. (e.g. --iface lo,eth0...)
  -c <cidr,>        Detect traffic matching the given cidr. If not set, all traffic will be matched
  -h, --help        Print help (see more with '--help')
```

## 配置文件

Netsniff 作为 server 模式启动时，需要提供配置文件。配置文件的结构如下:

```yaml
# 附加到导出指标的 labels
constLabels:
  - <string>
# 设置 netsniff 收集指标周期
exportInterval: <s/m/h/d/w>
rules:
  - name: <string>  # 规则名称, 必须是唯一的
    protocol: tcp   # 探测的协议, 目前可选值: all,tcp,udp
    cidrs: ["1.1.1.0/24"] # 探测匹配 cidr 的流量
    inPorts: [] # ingress 流量的端口
    inIface: [enp1s0] # 指定探测 ingress 流量的网卡
    outIface: [enp1s0]  # 指定探测  egress 流量的网卡
    constValues:  # 设置附加到导出指标的 values
      appName: cf
```

> NOTE: Netsniff 内部使用 `prometheus` crate 导出指标。在构建指标时需要确认 label_values, 故配置文件中 constValues 的 label key 需要存在于 constLabels 中。如果未提供将被设置为 `unset`
>
> * constLabel 的 label key 与 constValues label key 对应:
> ```shell
> $ cat config.yaml
> constLabels:
>   - appName
> exportInterval: 15s
> rules:
>   - name: rule1
>     protocol: tcp
>     cidrs: ["1.1.1.0/24"]
>     inPorts: []
>     inIface: [enp1s0]
>     outIface: [enp1s0]
>     constValues:
>       appName: cf
>
> $ curl localhost:10010/metrics
> network_packet_tolal{appName="cf",network_iface="enp1s0",port="unsupport",protocol="tcp",rule_name="rule1",traffic="egress"} 392
> ```
>
> * constValues 未配置 constLabel 的 label key:
> ```shell
> $ cat config.yaml
> constLabels:
>   - appName
> exportInterval: 15s
> rules:
>   - name: rule1
>     protocol: tcp
>     cidrs: ["1.1.1.0/24"]
>     inPorts: []
>     inIface: [enp1s0]
>     outIface: [enp1s0]
>
> $ curl localhost:10010/metrics
> network_packet_tolal{appName="unset",network_iface="enp1s0",port="unsupport",protocol="tcp",rule_name="rule1",traffic="egress"} 392
> ```
>
> * constValues 存在 constLabel 不存在的 label key:
> ```shell
> $ cat config.yaml
> constLabels:
>   - appName
> exportInterval: 15s
> rules:
>   - name: rule1
>     protocol: tcp
>     cidrs: ["1.1.1.0/24"]
>     inPorts: []
>     inIface: [enp1s0]
>     outIface: [enp1s0]
>     constValues: 
>       foo: bar
>
> $ ./netsniff run config.yaml
> [2025-03-04T03:51:23Z INFO  netsniff] read configuration from a config file
> [2025-03-04T03:51:23Z ERROR netsniff] failed to load config 'sniff.yaml' by err label=foo in the rule1 rule does not match that in constLabels or constLabels is empty
> ```
>