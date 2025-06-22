#!/bin/sh
# 99-custom.sh 就是immortalwrt固件首次启动时运行的脚本 位于固件内的/etc/uci-defaults/99-custom.sh
# Log file for debugging
LOGFILE="/tmp/uci-defaults-log.txt"
echo "Starting 99-custom.sh at $(date)" >> $LOGFILE
# 读取当前WAN协议
current_wan_proto=$(uci get network.wan.proto 2>/dev/null || echo "none")
echo "Current WAN proto: $current_wan_proto" >> $LOGFILE

# 如果WAN已经是pppoe，就不重复配置
if [ "$current_wan_proto" = "pppoe" ]; then
  echo "WAN is already PPPoE, skipping WAN config" >> $LOGFILE

# 追加写入并加载 TCP 内核参数
cat <<EOF >> /etc/sysctl.conf
# 自定义 TCP 参数（接收/发送窗口最大值，动态窗口缩放，BBR）
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = cubic
EOF
sysctl -p /etc/sysctl.conf
echo "TCP sysctl parameters loaded at $(date)" >> $LOGFILE

# 设置默认防火墙规则，方便虚拟机首次访问 WebUI
uci set firewall.@zone[1].input='ACCEPT'

# 设置主机名映射，解决安卓原生 TV 无法联网的问题
uci add dhcp domain
uci set "dhcp.@domain[-1].name=time.android.com"
uci set "dhcp.@domain[-1].ip=203.107.6.88"

# 检查配置文件pppoe-settings是否存在 该文件由build.sh动态生成
SETTINGS_FILE="/etc/config/pppoe-settings"
if [ ! -f "$SETTINGS_FILE" ]; then
    echo "PPPoE settings file not found. Skipping." >> $LOGFILE
else
   # 读取pppoe信息($enable_pppoe、$pppoe_account、$pppoe_password)
   . "$SETTINGS_FILE"
fi

# 计算网卡数量
count=0
ifnames=""
for iface in /sys/class/net/*; do
  iface_name=$(basename "$iface")
  # 检查是否为物理网卡（排除回环设备和无线设备）
  if [ -e "$iface/device" ] && echo "$iface_name" | grep -Eq '^eth|^en'; then
    count=$((count + 1))
    ifnames="$ifnames $iface_name"
  fi
done
# 删除多余空格
ifnames=$(echo "$ifnames" | awk '{$1=$1};1')

# 获取网卡列表
ifnames=$(ls /sys/class/net | grep -E '^eth[0-9]+$' | sort)

# 判断网口数量
count=$(echo "$ifnames" | wc -l)

# 仅继续处理多网口设备
if [ "$count" -ge 2 ]; then
   lan_ifname=$(echo "$ifnames" | awk 'NR==1')  # 第一个接口为 LAN（eth0）
   wan_ifname=$(echo "$ifnames" | awk 'NR==2')  # 第二个接口为 WAN（eth1）

   # 设置LAN
   uci set network.lan=interface
   uci set network.lan.device="$lan_ifname"
   uci set network.lan.proto='static'
   uci set network.lan.ipaddr='192.168.100.1'
   uci set network.lan.netmask='255.255.255.0'

   # 设置WAN
   uci set network.wan=interface
   uci set network.wan.device="$wan_ifname"
   uci set network.wan.proto='dhcp'

   # 设置WAN6
   uci set network.wan6=interface
   uci set network.wan6.device="$wan_ifname"
   uci set network.wan6.proto='dhcpv6'

   # 绑定LAN网口到 br-lan 的 bridge ports
   section=$(uci show network | awk -F '[.=]' '/\.@?device\[\d+\]\.name=.br-lan.$/ {print $2; exit}')
   if [ -n "$section" ]; then
      uci -q delete "network.$section.ports"
      uci add_list "network.$section.ports"="$lan_ifname"
      echo "LAN port $lan_ifname 已绑定到 br-lan" >> $LOGFILE
   else
      echo "❌ 找不到 br-lan 接口 section" >> $LOGFILE
   fi
   uci commit network
   echo "✅ 接口已重新配置为 LAN=$lan_ifname, WAN=$wan_ifname" >> $LOGFILE
fi

   # LAN口设置静态IP
   uci set network.lan.proto='static'
   # 多网口设备 支持修改为别的ip地址,别的地址应该是网关地址，形如192.168.xx.1 项目说明里都强调过。
   # 大家不能胡乱修改哦 比如有人修改为192.168.100.55 这是错误的理解 这个项目不能提前设置旁路地址
   # 旁路的设置分2类情况,情况一是单网口的设备,默认是DHCP模式，ip应该在上一级路由器里查看。之后进入web页在设置旁路。
   # 情况二旁路由如果是多网口设备，也应当用网关访问网页后，在自行在web网页里设置。总之大家不能直接在代码里修改旁路网关。千万不要徒增bug啦。
   uci set network.lan.ipaddr='192.168.100.1'
   uci set network.lan.netmask='255.255.255.0'
   echo "set 192.168.100.1 at $(date)" >> $LOGFILE
   # 判断是否启用 PPPoE
   echo "print enable_pppoe value=== $enable_pppoe" >> $LOGFILE
   if [ "$enable_pppoe" = "yes" ]; then
      echo "PPPoE is enabled at $(date)" >> $LOGFILE
      # 设置ipv4宽带拨号信息
      uci set network.wan.proto='pppoe'
      uci set network.wan.username=$pppoe_account
      uci set network.wan.password=$pppoe_password
      uci set network.wan.peerdns='1'
      uci set network.wan.auto='1'
      # 设置ipv6 默认不配置协议
      uci set network.wan6.proto='none'
      echo "PPPoE configuration completed successfully." >> $LOGFILE
   else
      echo "PPPoE is not enabled. Skipping configuration." >> $LOGFILE
   fi
fi

# 添加docker zone
uci add firewall zone
uci set firewall.@zone[-1].name='docker'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].device='docker0'

# 添加 forwarding docker -> lan
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='docker'
uci set firewall.@forwarding[-1].dest='lan'

# 添加 forwarding docker -> wan
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='docker'
uci set firewall.@forwarding[-1].dest='wan'

# 添加 forwarding lan -> docker
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='docker'

# 设置所有网口可访问网页终端
uci delete ttyd.@ttyd[0].interface

# 设置所有网口可连接 SSH
uci set dropbear.@dropbear[0].Interface=''
uci commit

# 设置编译作者信息
FILE_PATH="/etc/openwrt_release"
NEW_DESCRIPTION="Compiled by wukongdaily"
sed -i "s/DISTRIB_DESCRIPTION='[^']*'/DISTRIB_DESCRIPTION='$NEW_DESCRIPTION'/" "$FILE_PATH"
# 确保脚本有执行权限
chmod +x /etc/uci-defaults/99-custom.sh

# 脚本执行完毕后删除自己，防止重复执行
rm -f /etc/uci-defaults/99-custom.sh

exit 0
