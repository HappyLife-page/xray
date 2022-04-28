#!/bin/bash
# Auth: happylife
# Desc: xray installation script
# Plat: ubuntu 18.04+
# Eg  : bash xray_installation_grpc_ws.sh "你的域名"

if [ -z "$1" ];then
	echo "域名不能为空"
	exit
fi

# 配置系统时区为东八区,并设置时间为24H制
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
if ! grep -q 'LC_TIME' /etc/default/locale;then echo 'LC_TIME=en_DK.UTF-8' >> /etc/default/locale;fi


# 使用ubuntu官方源安装nginx和依赖包并设置开机启动，关闭防火墙ufw
apt update
apt install nginx curl pwgen openssl netcat cron -y
systemctl enable nginx
ufw disable


# 开始部署之前，我们先配置一下需要用到的参数，如下：
# "域名，uuid，ws和grpc路径，ws和grpc sock位置，ssl证书目录"
# 1.设置你的解析好的域名
domainName="$1"
# 2.随机生成一个uuid
uuid="`uuidgen`"
# 3.随机生成一个ws需要使用的path
ws_path="/`pwgen -A0 6 8 | xargs |sed 's/ /\//g'`"
# 4.随机生成一个grpc需要使用的path
grpc_path="/`pwgen -A0 8 3 | xargs |sed 's/ /\//g'`"
# 5.创建ws和grpc需要用的sock目录,并授权nginx用户权限
sock_dir="/run/xray";! [ -d $sock_dir ] && mkdir -pv $sock_dir && chown www-data.www-data $sock_dir
# 5.定义ws sock位置
ws_sock="$sock_dir/xray_ws.sock"
# 6.定义grpc sock位置
grpc_sock="$sock_dir/xray_grpc.sock"
# 7.以时间为基准随机创建一个存放ssl证书的目录
ssl_dir="$(mkdir -pv "/etc/nginx/ssl/`date +"%F-%H-%M-%S"`" |awk -F"'" END'{print $2}')"


# 使用xray官方命令安装xray并指定用户为和nginx同一用户
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data

##安装acme,并申请加密证书
source ~/.bashrc
if nc -z localhost 443;then /etc/init.d/nginx stop;fi
if ! [ -d /root/.acme.sh ];then curl https://get.acme.sh | sh;fi
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$domainName" -k ec-256 --alpn
~/.acme.sh/acme.sh --installcert -d "$domainName" --fullchainpath $ssl_dir/xray.crt --keypath $ssl_dir/xray.key --ecc
chown www-data.www-data $ssl_dir/xray.*

## 把申请证书命令添加到计划任务
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
(crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab


# 配置nginx,执行如下命令即可添加nginx配置文件
echo "
server {
	listen 80;
	listen [::]:80;
	server_name "$domainName";
	return 301 https://"'$host'""'$request_uri'";
}
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name "$domainName";
	ssl_certificate $ssl_dir/xray.crt;
	ssl_certificate_key $ssl_dir/xray.key;
	ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
	ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
	access_log /var/log/nginx/xray_access.log;
	error_log /var/log/nginx/xray_error.log;
	root /usr/share/nginx/html;
	
	location "$ws_path" {
		proxy_redirect off;
		proxy_pass http://unix:"$ws_sock";
		proxy_http_version 1.1;
		proxy_set_header Upgrade "'"$http_upgrade"'";
		proxy_set_header Connection '"'upgrade'"';
   	     	proxy_set_header Host "'"$host"'";
       	 	proxy_set_header X-Real-IP "'"$remote_addr"'";
        	proxy_set_header X-Forwarded-For "'"$proxy_add_x_forwarded_for"'";
	}
	location "$grpc_path" {
		proxy_redirect off;
		client_max_body_size 0;
		client_body_timeout 1h;
		grpc_read_timeout 1h;
		grpc_set_header X-Real-IP "'"$remote_addr"'";
		grpc_pass grpc://unix:"$grpc_sock";
	}
}
" > /etc/nginx/conf.d/xray.conf

# 配置xray，执行如下命令即可添加xray配置文件
echo '
{
  "log" : {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
    "listen": '"\"$ws_sock\""',	
      "protocol": "vless",
      "settings": {
        "decryption":"none",
        "clients": [
          {
          "id": '"\"$uuid\""',
          "level": 1
          }
        ]
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": '"\"$ws_path\""'
        }
      }
    },
    {
    "listen": '"\"$grpc_sock\""',
      "protocol": "vless",
      "settings": {
        "decryption":"none",
        "clients": [
          {
            "id": '"\"$uuid\""',
            "level": 1
          }
        ]
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
             "serviceName": '"\"$grpc_path\""'
        }
      }
    }
  ],
  "outbound": {
    "protocol": "freedom",
    "settings": {
      "decryption":"none"
    }
  },
  "outboundDetour": [
    {
      "protocol": "blackhole",
      "settings": {
        "decryption":"none"
      },
      "tag": "blocked"
    }
  ],
  "routing": {
      "domainStrategy": "IPIfNonMatch",
      "rules": [
        {
            "ip": [
                "geoip:cn"
            ],
            "outboundTag": "blocked",
            "type": "field"
        }
      ]
  },
  "routing": {
    "strategy": "rules",
    "settings": {
      "decryption":"none",
      "rules": [
        {
          "type": "field",
          "ip": [ "geoip:private" ],
          "outboundTag": "blocked"
        }
      ]
    }
  }
}

' > /usr/local/etc/xray/config.json

# 重启xray和nginx
systemctl restart xray
systemctl status xray
/usr/sbin/nginx -t && systemctl restart nginx

##输出配置信息
xray_config_info="/root/xray_config.info"
echo "
域名	: $domainName
端口	: 443
协议	: vless
UUID	: $uuid
WS路径	: $ws_path
grpc路径: $ws_path
" | tee $xray_config_info
