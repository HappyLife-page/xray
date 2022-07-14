#!/bin/bash
# Author: happylife
# OS: Ubuntu 18.0+
# Desc: x-ui install
# Eg: bash x-ui_install.sh "你的解析好的域名"


# 检测域名和用户权限
if [ -z "$1" ];then echo "域名不能为空";exit;fi
if [ `id -u` -ne 0 ];then echo "需要root用户";exit;fi

# 配置系统时区为东八区,并设置时间为24H制
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
if ! grep -q 'LC_TIME' /etc/default/locale;then echo 'LC_TIME=en_DK.UTF-8' >> /etc/default/locale;fi

# 更新Ubuntu官方源,安装curl等,关闭防火墙
dpkg --configure -a
apt clean all && apt update
apt install curl tar nginx cron pwgen -y
ufw disable

# 检测域名解析是否正确
domainName="$1"
local_ip="$(curl ifconfig.me 2>/dev/null;echo)"
resolve_ip="$(host "$domainName" | awk '{print $NF}')"
if [ "$local_ip" != "$resolve_ip" ];then echo "域名解析不正确";exit 9;fi

# 随机生成x-ui面板管理用户名,密码,和服务端口;证书目录,nginx配置目录
xui_account_name="$(pwgen -0 15 1)"
xui_account_password="$(pwgen -cny -r "\"\\;'\`" 26 1)"
xui_panel_port="$(shuf -i 20000-65000 -n 1)"
xui_latest_version="$(curl -Ls "https://api.github.com/repos/vaxilu/x-ui/releases/latest" | grep -Po '(?<=tag_name": ")[^\"]+')"
nginxConfig="/etc/nginx/conf.d/x-ui.conf"
ssl_dir="$(mkdir -pv "/etc/nginx/ssl/`date +"%F-%H-%M-%S"`" |awk -F"'" END'{print $2}')"


# 安装acme,并申请加密证书
if nc -z localhost 443;then /etc/init.d/nginx stop;fi
if nc -z localhost 443;then lsof -i :443 | awk 'NR==2{print $1}' | xargs -i killall {};sleep 1;fi
if ! [ -d /root/.acme.sh ];then curl https://get.acme.sh | sh;fi
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$domainName" -k ec-256 --alpn
~/.acme.sh/acme.sh --installcert -d "$domainName" --fullchainpath $ssl_dir/x-ui.crt --keypath $ssl_dir/x-ui.key --ecc
chown www-data.www-data $ssl_dir/x-ui.*

# 把续签证书命令添加到计划任务
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root;then (crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab;fi

# 下载x-ui并设置服务
[ -d /usr/local/x-ui ] && rm -rf /usr/local/x-ui
curl -L https://github.com/vaxilu/x-ui/releases/download/${xui_latest_version}/x-ui-linux-amd64.tar.gz | tar xz -C /usr/local/
if cd /usr/local/x-ui;then
	chmod +x x-ui bin/xray-linux-* x-ui.sh
	cp -f x-ui.sh /usr/bin/x-ui
	sed -i '/\[Service\]/aUser=www-data' x-ui.service
	cp -f x-ui.service /etc/systemd/system/
else
	echo "x-ui not found"
	exit 3
fi

# 配置x-ui用户名,密码和服务端口
/usr/local/x-ui/x-ui setting -username ${xui_account_name} -password ${xui_account_password}
/usr/local/x-ui/x-ui setting -port ${xui_panel_port}

# 添加nginx代理配置
echo "
server {
	listen 80;
	server_name "$domainName";
	return 301 https://"'$host'""'$request_uri'";
}
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2 default_server;
	server_name "$domainName";
	ssl_certificate $ssl_dir/x-ui.crt;
	ssl_certificate_key $ssl_dir/x-ui.key;
	ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
	ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
	root /usr/share/nginx/html;
	
	location / {
		proxy_redirect off;
		proxy_pass http://127.0.0.1:"$xui_panel_port";
		proxy_http_version 1.1;
            	proxy_set_header Host "'"$host"'";
            	proxy_set_header X-Real-IP "'"$remote_addr"'";
            	proxy_set_header X-Forwarded-For "'"$proxy_add_x_forwarded_for"'";
	}
}
" > $nginxConfig

# 添加x-ui开机启动并启动x-ui服务
systemctl daemon-reload
systemctl enable x-ui
systemctl restart x-ui
echo; nginx -t && /etc/init.d/nginx start || exit 9

# 输出x-ui管理账号和密码
echo "
x-ui账号: $xui_account_name
x-ui密码: $xui_account_password
" | tee x-ui_info.txt
