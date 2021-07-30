# xray纯净安装，基于手动纯净部署命令的整理，内容一目了然。你可以理解为你手动执行时的每一个复制粘贴和修改文件的命令的合集，批处理而已
# 一分钟xray：vless+tcp+xtls+nginx
# xray 一键安装，只需30s

解析好域名

xray安装：

执行curl -s https://raw.githubusercontent.com/HappyLife-page/xray/main/xray_installation_vless_xtls.sh | bash -s "你的解析好的域名"
# EG： 
curl -s https://raw.githubusercontent.com/HappyLife-page/xray/main/xray_installation_vless_xtls.sh | bash -s kty.v2ray.one


vultr 5美元机器只需要不到30s部署完成 【https://www.vultr.com/?ref=8773909】

你完全不需要任何干预，一键执行脚本稍等片刻就好

######################################### 详细配置说明如下 #########################################

xray安装： nginx+tcp+xtls+vless
nginx做前端代理，分发443端口到xray，回落到nginx默认站点目录/usr/share/nginx/html，但需要你了解nginx端口复用才能灵活配置你自己其他的站点（不建议使用回落方式作为你的其他站点）

该方案不影响nginx作为前端代理和web服务的性能，xray只是其一个后端服务，类似PHP或Java

你可以很愉快的玩耍你自己的站点，如wordpress

---------------------- xray配置文件一览： ----------------------

xray配置文件路径： /usr/local/etc/xray/config.json

nginx配置文件路径： /etc/nginx/conf.d/xray.conf /etc/nginx/modules-enabled/stream.conf
