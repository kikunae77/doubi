#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR server
#	Version: 2.0.38
#	Author: Toyo
#	Blog: https://doub.io/ss-jc42/
#	Translation : kikunae
#	Blog: https://blog.szkorean.net
#=================================================

sh_ver="2.0.38"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
ssr_ss_file="${ssr_folder}/shadowsocks"
config_file="${ssr_folder}/config.json"
config_folder="/etc/shadowsocksr"
config_user_file="${config_folder}/user-config.json"
ssr_log_file="${ssr_ss_file}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.13"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[정보]${Font_color_suffix}"
Error="${Red_font_prefix}[오류]${Font_color_suffix}"
Tip="${Green_font_prefix}[주의]${Font_color_suffix}"
Separator_1="——————————————————————————————"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 현재 사용자는 ROOT계정(또는ROOT권한을 가진 계정)이 아니어서，계속 진행할 수 없습니다.${Green_background_prefix} sudo su ${Font_color_suffix}명령어로 ROOT 권한을 임시로 획득한 후 다시 스크립트를 시작하세요." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
SSR_installation_status(){
	[[ ! -e ${config_user_file} ]] && echo -e "${Error} ShadowsocksR 설정 문서를 찾을 수 없습니다. 설정 문서 유무를 확인해 주세요." && exit 1
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR 디렉토리를 찾을 수 없습니다，디렉토리 유무를 확인해 주세요." && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} 서버 가속기(Server Speeder)가 설치되어 있지 않습니다. 설치 여부를 확인해 주세요." && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} LotServer가 설치되어 있지 않습니다. 설치 여부를 확인해 주세요." && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} BBR 스크립트를 찾지 못하였습니다. 다운로드를 시작합니다..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/kikunae77/doubi/master/bbr.sh; then
			echo -e "${Error} BBR 스크립트 다운로드 실패 !" && exit 1
		else
			echo -e "${Info} BBR 스크립트 다운로드 완료 !"
			chmod +x bbr.sh
		fi
	fi
}
# 设置 防火墙规则
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# 설정 정보 취득
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User(){
	[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ해석기가 존재하지 않습니다. 확인해 주세요." && exit 1
	port=`${jq_file} '.server_port' ${config_user_file}`
	password=`${jq_file} '.password' ${config_user_file} | sed 's/^.//;s/.$//'`
	method=`${jq_file} '.method' ${config_user_file} | sed 's/^.//;s/.$//'`
	protocol=`${jq_file} '.protocol' ${config_user_file} | sed 's/^.//;s/.$//'`
	obfs=`${jq_file} '.obfs' ${config_user_file} | sed 's/^.//;s/.$//'`
	protocol_param=`${jq_file} '.protocol_param' ${config_user_file} | sed 's/^.//;s/.$//'`
	speed_limit_per_con=`${jq_file} '.speed_limit_per_con' ${config_user_file}`
	speed_limit_per_user=`${jq_file} '.speed_limit_per_user' ${config_user_file}`
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="http://mqr.kr/qr/?t=${SSurl}"
	ss_link=" SS    링크     : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS  QR코드     : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="http://mqr.kr/qr/?t=${SSRurl}"
	ssr_link=" SSR   링크     : ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR코드     : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# 설정 정보 표시
View_User(){
	SSR_installation_status
	Get_IP
	Get_User
	now_mode=$(cat "${config_user_file}"|grep '"port_password"')
	[[ -z ${protocol_param} ]] && protocol_param="0(무제한)"
	if [[ -z "${now_mode}" ]]; then
		ss_ssr_determine
		clear && echo "===================================================" && echo
		echo -e " ShadowsocksR계정 설정 정보：" && echo
		echo -e " I  P           : ${Green_font_prefix}${ip}${Font_color_suffix}"
		echo -e " 포트           : ${Green_font_prefix}${port}${Font_color_suffix}"
		echo -e " 비번           : ${Green_font_prefix}${password}${Font_color_suffix}"
		echo -e " 암호화         : ${Green_font_prefix}${method}${Font_color_suffix}"
		echo -e " 프로토콜       : ${Red_font_prefix}${protocol}${Font_color_suffix}"
		echo -e " 난독화         : ${Red_font_prefix}${obfs}${Font_color_suffix}"
		echo -e " 기기수제한     : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
		echo -e " 기기별속도제한 : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
		echo -e " 포트총속도제한 : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
		echo -e "${ss_link}"
		echo -e "${ssr_link}"
		echo -e " ${Green_font_prefix} 참고: ${Font_color_suffix}
 브라우저에서 QR코드 링크에 접속하면 QR코드 이미지가 표시됩니다.
 프로토콜 및 난독화 명칭 뒤의 [ _compatible ]은 원본 프로토콜/난독화의 겸용 버전임을 표시합니다."
		echo && echo "==================================================="
	else
		user_total=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | wc -l`
		[[ ${user_total} = "0" ]] && echo -e "${Error} 다중포트 사용자를 발견하지 못했습니다. 확인해 주세요." && exit 1
		clear && echo "===================================================" && echo
		echo -e " ShadowsocksR계정 설정 정보：" && echo
		echo -e " I  P           : ${Green_font_prefix}${ip}${Font_color_suffix}"
		echo -e " 암호화         : ${Green_font_prefix}${method}${Font_color_suffix}"
		echo -e " 프로토콜       : ${Red_font_prefix}${protocol}${Font_color_suffix}"
		echo -e " 난독화         : ${Red_font_prefix}${obfs}${Font_color_suffix}"
		echo -e " 기기수제한     : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
		echo -e " 기기별속도제한 : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
		echo -e " 포트총속도제한 : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}" && echo
		for((integer = ${user_total}; integer >= 1; integer--))
		do
			port=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $1}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
			password=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $2}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
			ss_ssr_determine
			echo -e ${Separator_1}
			echo -e " 포트           : ${Green_font_prefix}${port}${Font_color_suffix}"
			echo -e " 비번           : ${Green_font_prefix}${password}${Font_color_suffix}"
			echo -e "${ss_link}"
			echo -e "${ssr_link}"
		done
		echo -e " ${Green_font_prefix} 참고: ${Font_color_suffix}
 브라우저에서 QR코드 링크에 접속하면 QR코드 이미지가 표시됩니다.
 프로토콜 및 난독화 명칭 뒤의 [ _compatible ]은 원본 프로토콜/난독화의 겸용 버전임을 표시합니다."
		echo && echo "==================================================="
	fi
}
# 설정 정보 설정
Set_config_port(){
	while true
	do
	echo -e "ShadowsocksR계정이 사용할 포트를 입력해주세요"
	read -e -p "(기본값: 2333):" ssr_port
	[[ -z "$ssr_port" ]] && ssr_port="2333"
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	포트 : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 정확한 숫자를 입력해주세요.(1-65535)"
		fi
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-65535)"
	fi
	done
}
Set_config_password(){
	echo "ShadowsocksR계정이 사용할 비번을 입력해주세요."
	read -e -p "(기본값: doub.io):" ssr_password
	[[ -z "${ssr_password}" ]] && ssr_password="doub.io"
	echo && echo ${Separator_1} && echo -e "	 : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "ShadowsocksR계정이 사용할 암호화 방식을 선택해주세요
	
 ${Green_font_prefix} 1.${Font_color_suffix} none
 ${Tip} 만약 auth_chain_a 프로토콜을 사용하는 경우，암호화 방식은 none을 선택해주시고，난독화는 임의로 설정하세요(plain 사용 추천)
 
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 ${Tip} salsa20/chacha20-*형식의 암호화는 별도로 libsodium 라이브러리를 설치해야 합니다. 설치하지 않으면 ShadowsocksR이 작동하지 않습니다." && echo
	read -e -p "(기본값: 5. aes-128-ctr):" ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="5"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="aes-128-ctr"
	fi
	echo && echo ${Separator_1} && echo -e "	암호화 : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	echo -e "ShadowsocksR사용할 프로토콜을 선택하세요
	
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b
 ${Tip} 만약 auth_chain_a 프로토콜을 사용하는 경우，암호화 방식은 none을 선택해주시고，난독화는 임의로 설정하세요(plain 사용 추천)" && echo
	read -e -p "(기본값: 2. auth_sha1_v4):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="2"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="auth_sha1_v4"
	fi
	echo && echo ${Separator_1} && echo -e "	프로토콜 : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "프로토콜의 원본겸용(_compatible)버전으로 설정하겠시겠습니까?？[Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
	echo -e "ShadowsocksR계정이 사용할 난독화를 선택하세요.
	
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
 ${Tip} ShadowsocksR을 사용하여 게임을 가속하는 경우，원본겸용난독화 또는 plain 난독화를 선택하고. 클라이언트에서 plain을 선택하세요. 그렇지 않으면 지연률이 높습니다.
 이와 별개로, tls1.2_ticket_auth를 선택한 경우 클라이언트에서 tls1.2_ticket_fastauth를 선택하세요. 이렇게 설정하시면 트래픽 위장도 되고 지연율도 낮습니다.
 만약 일본, 미국 등 인기있는 지역에 서버를 구축한 경우 plain 난독화를 선택하면 탐지될 가능성이 더 낮습니다." && echo
	read -e -p "(기본값: 1. plain):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo ${Separator_1} && echo -e "	난독화 : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "난독화의 원본겸용(_compatible) 버전으로 설정하겠습니까？[Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	echo -e "ShadowsocksR계정이 동시 사용할 기기 제한 수량을 입력하세요. (${Green_font_prefix} auth_* 종류의 프로토콜은 원본겸용 버전을 사용하지 않아야 설정이 유효합니다. ${Font_color_suffix})"
	echo -e "${Tip} 기기제한수량 : 매 포트마다 동시에 연결할 수 있는 클라이언트의 수량을 의미 (다중포트 모드는 매 포트를 각각 계산함)，최소 2개 이상으로 설정하는 것을 추천하합니ㅣ다."
	read -e -p "(기본값: 무제한):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "	기기수제한 : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 정확한 숫자를 넣어주세요.(1-9999)"
		fi
	else
		echo -e "${Error} 정확한 숫자를 넣어주세요.(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "매 포트별 단일 연결의 속도 제한 값을 입력해주세요.(단위：KB/S)"
	echo -e "${Tip} 기기별속도제한 : 매 포트마다 단일 연결이 사용하는 속도 제한 값을 의미하며, 다중 연결인 경우 무효합니다."
	read -e -p "(설정: 무제한):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	기기별속도제한 : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 정확한 숫자를 입력해주세요.(1-131072)"
		fi
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "매 포트의 총 속도 제한 값을 입력해주세요.(단위：KB/S)"
	echo -e "${Tip} 포트총속도제한：매 포트의 총 속도 제한 값을 의미합니다. 한개 포트의 최대 속도를 제한합니다."
	read -e -p "(기본값: 무제한):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	포트총속도제한 : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 정확한 숫자를 입력해주세요.(1-131072)"
		fi
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-131072)"
	fi
	done
}
Set_config_all(){
	Set_config_port
	Set_config_password
	Set_config_method
	Set_config_protocol
	Set_config_obfs
	Set_config_protocol_param
	Set_config_speed_limit_per_con
	Set_config_speed_limit_per_user
}
# 설정 정보 수정
Modify_config_port(){
	sed -i 's/"server_port": '"$(echo ${port})"'/"server_port": '"$(echo ${ssr_port})"'/g' ${config_user_file}
}
Modify_config_password(){
	sed -i 's/"password": "'"$(echo ${password})"'"/"password": "'"$(echo ${ssr_password})"'"/g' ${config_user_file}
}
Modify_config_method(){
	sed -i 's/"method": "'"$(echo ${method})"'"/"method": "'"$(echo ${ssr_method})"'"/g' ${config_user_file}
}
Modify_config_protocol(){
	sed -i 's/"protocol": "'"$(echo ${protocol})"'"/"protocol": "'"$(echo ${ssr_protocol})"'"/g' ${config_user_file}
}
Modify_config_obfs(){
	sed -i 's/"obfs": "'"$(echo ${obfs})"'"/"obfs": "'"$(echo ${ssr_obfs})"'"/g' ${config_user_file}
}
Modify_config_protocol_param(){
	sed -i 's/"protocol_param": "'"$(echo ${protocol_param})"'"/"protocol_param": "'"$(echo ${ssr_protocol_param})"'"/g' ${config_user_file}
}
Modify_config_speed_limit_per_con(){
	sed -i 's/"speed_limit_per_con": '"$(echo ${speed_limit_per_con})"'/"speed_limit_per_con": '"$(echo ${ssr_speed_limit_per_con})"'/g' ${config_user_file}
}
Modify_config_speed_limit_per_user(){
	sed -i 's/"speed_limit_per_user": '"$(echo ${speed_limit_per_user})"'/"speed_limit_per_user": '"$(echo ${ssr_speed_limit_per_user})"'/g' ${config_user_file}
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"'/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"'/g' ${config_user_file}
}
Modify_config_all(){
	Modify_config_port
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
}
Modify_config_port_many(){
	sed -i 's/"'"$(echo ${port})"'":/"'"$(echo ${ssr_port})"'":/g' ${config_user_file}
}
Modify_config_password_many(){
	sed -i 's/"'"$(echo ${password})"'"/"'"$(echo ${ssr_password})"'"/g' ${config_user_file}
}
# 설정 정보 파일 저장
Write_configuration(){
	cat > ${config_user_file}<<-EOF
{
    "server": "0.0.0.0",
    "server_ipv6": "::",
    "server_port": ${ssr_port},
    "local_address": "127.0.0.1",
    "local_port": 1080,

    "password": "${ssr_password}",
    "method": "${ssr_method}",
    "protocol": "${ssr_protocol}",
    "protocol_param": "${ssr_protocol_param}",
    "obfs": "${ssr_obfs}",
    "obfs_param": "",
    "speed_limit_per_con": ${ssr_speed_limit_per_con},
    "speed_limit_per_user": ${ssr_speed_limit_per_user},

    "additional_ports" : {},
    "timeout": 120,
    "udp_timeout": 60,
    "dns_ipv6": false,
    "connect_verbose_info": 0,
    "redirect": "",
    "fast_open": false
}
EOF
}
Write_configuration_many(){
	cat > ${config_user_file}<<-EOF
{
    "server": "0.0.0.0",
    "server_ipv6": "::",
    "local_address": "127.0.0.1",
    "local_port": 1080,

    "port_password":{
        "${ssr_port}":"${ssr_password}"
    },
    "method": "${ssr_method}",
    "protocol": "${ssr_protocol}",
    "protocol_param": "${ssr_protocol_param}",
    "obfs": "${ssr_obfs}",
    "obfs_param": "",
    "speed_limit_per_con": ${ssr_speed_limit_per_con},
    "speed_limit_per_user": ${ssr_speed_limit_per_user},

    "additional_ports" : {},
    "timeout": 120,
    "udp_timeout": 60,
    "dns_ipv6": false,
    "connect_verbose_info": 0,
    "redirect": "",
    "fast_open": false
}
EOF
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python이 설치되지 않았습니다. 설치를 시작합니다..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip net-tools
	else
		yum install -y vim unzip
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip net-tools
	else
		apt-get install -y vim unzip
	fi
}
# ShadowsocksR 다운로드
Download_SSR(){
	cd "/usr/local/"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR서버 다운로드 실패 !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} ShadowsocksR서버 압축파일 다운로드 실패 !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} ShadowsocksR서버 압축풀기 실패 !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} ShadowsocksR서버 이름변경 실패 !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	[[ -e ${config_folder} ]] && rm -rf ${config_folder}
	mkdir ${config_folder}
	[[ ! -e ${config_folder} ]] && echo -e "${Error} ShadowsocksR 설정 파일 서정할 디렉토리 생성 실패 !" && exit 1
	echo -e "${Info} ShadowsocksR서버 다운로드 완료 !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/kikunae77/doubi/master/service/ssr_centos -O /etc/init.d/ssr; then
			echo -e "${Error} ShadowsocksR서버 관리 스크립트 다운로드 실패 !" && exit 1
		fi
		chmod +x /etc/init.d/ssr
		chkconfig --add ssr
		chkconfig ssr on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/kikunae77/doubi/master/service/ssr_debian -O /etc/init.d/ssr; then
			echo -e "${Error} ShadowsocksR서버 관리 스크립트 다운로드 실패 !" && exit 1
		fi
		chmod +x /etc/init.d/ssr
		update-rc.d -f ssr defaults
	fi
	echo -e "${Info} ShadowsocksR서버 관리 스크립트 다운로드 완료 !"
}
# JQ해석기 설치
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ해석기 이름 변경실패，확인해주세요 !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} JQ해석기 설치 완료.계속합니다..." 
	else
		echo -e "${Info} JQ해석기가 이미 설치되어 있습니다. 계속합니다..."
	fi
}
# 라이브러리 설치
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} unzip(압축해제) 라이브러리 설치 실패，설치 저장소 문제일 확률이 높습니다. 확인해주세요 !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}
Install_SSR(){
	check_root
	[[ -e ${config_user_file} ]] && echo -e "${Error} ShadowsocksR 설정 파일이 이미 존재합니다. 확인해주세요. (만약 설치실패한 기존 파일 또는 구버전 파일이 있으면 우선 삭제해 주세요.)" && exit 1
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR 디렉토리가 이미 존재합니다. 확인해주세요. (만약 설치실패한 기존 파일 또는 구버전 파일이 있으면 우선 삭제해 주세요.)" && exit 1
	echo -e "${Info} ShadowsocksR계정을 설정합니다..."
	Set_config_all
	echo -e "${Info} ShadowsocksR 관련 라이브러리를 설치/설정합니다..."
	Installation_dependency
	echo -e "${Info} ShadowsocksR 문서를 다운로드/설치합니다..."
	Download_SSR
	echo -e "${Info} ShadowsocksR서버 스크립트를 다운로드/설치합니다. (init)..."
	Service_SSR
	echo -e "${Info} JSNO해석기 JQ를 다운로드/설치합니다..."
	JQ_install
	echo -e "${Info} ShadowsocksR 설정 파일을 기록합니다..."
	Write_configuration
	echo -e "${Info} iptables 방화벽을 설정합니다..."
	Set_iptables
	echo -e "${Info} iptables 방화벽 규칙을 설정합니다..."
	Add_iptables
	echo -e "${Info} iptables 방화벽 규칙을 저장합니다..."
	Save_iptables
	echo -e "${Info} 모든 설치 단계과 완료되었습니다.ShadowsocksR 서버를 실행합니다..."
	Start_SSR
}
Update_SSR(){
	SSR_installation_status
	echo -e "ShadowsocksR 서버 개발이 중단 중이므로，이 기능은 잠시 사용불가합니다."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${config_user_file} ]] && [[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR이 설치되어 있지 않습니다. 확인해주세요." && exit 1
	echo "ShadowsocksR을 제거하시겠습니까？[y/N]" && echo
	read -e -p "(默认: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		if [[ -z "${now_mode}" ]]; then
			port=`${jq_file} '.server_port' ${config_user_file}`
			Del_iptables
			Save_iptables
		else
			user_total=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | wc -l`
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $1}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssr
		else
			update-rc.d -f ssr remove
		fi
		rm -rf ${ssr_folder} && rm -rf ${config_folder} && rm -rf /etc/init.d/ssr
		echo && echo " ShadowsocksR 제거 완료 !" && echo
	else
		echo && echo " 제거가 취소되었습니다..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} libsodium 최신버전 확인 중..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} libsodium 최신버전은 ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix}입니다."
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium 이 이미 설치되어 있습니다. 재설치(업데이트)하시겠습니까？[y/N]"
		read -e -p "(기본값: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "취소되었습니다..." && exit 1
		fi
	else
		echo -e "${Info} libsodium 이 설치되어 있지 않습니다. 설치를 시작합니다..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} 라이브러리 설치..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} 다운로드..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 압축해제..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 컴파일, 설치..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} 라이브러리 설치..."
		apt-get install -y build-essential
		echo -e "${Info} 다운로드..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 압축해제..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 컴파일, 설치..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium 설치 실패 !" && exit 1
	echo && echo -e "${Info} libsodium 설치 성공 !" && echo
}
# 연결 정보 표시
debian_View_user_connection_info(){
	format_1=$1
	if [[ -z "${now_mode}" ]]; then
		now_mode="단일 포트" && user_total="1"
		IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
		user_port=`${jq_file} '.server_port' ${config_user_file}`
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" `
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_list_all="포트: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 연결 IP 총 수: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 현재 연결 IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
		echo -e "현재 모드: ${Green_background_prefix} "${now_mode}" ${Font_color_suffix} 연결 IP 총 수: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix}"
		echo -e "${user_list_all}"
	else
		now_mode="다중포트" && user_total=`${jq_file} '.port_password' ${config_user_file} |sed '$d;1d' | wc -l`
		IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
		user_list_all=""
		for((integer = ${user_total}; integer >= 1; integer--))
		do
			user_port=`${jq_file} '.port_password' ${config_user_file} |sed '$d;1d' |awk -F ":" '{print $1}' |sed -n "${integer}p" |sed -r 's/.*\"(.+)\".*/\1/'`
			user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep "${user_port}" |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
			if [[ -z ${user_IP_1} ]]; then
				user_IP_total="0"
			else
				user_IP_total=`echo -e "${user_IP_1}"|wc -l`
				if [[ ${format_1} == "IP_address" ]]; then
					get_IP_address
				else
					user_IP=`echo -e "\n${user_IP_1}"`
				fi
			fi
			user_list_all=${user_list_all}"포트: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 연결 IP 총 수: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 현재 연결 IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
			user_IP=""
		done
		echo -e "현재 모드: ${Green_background_prefix} "${now_mode}" ${Font_color_suffix} 사용자 총 수: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} 연결 IP 총 수: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
		echo -e "${user_list_all}"
	fi
}
centos_View_user_connection_info(){
	format_1=$1
	if [[ -z "${now_mode}" ]]; then
		now_mode="단일포트" && user_total="1"
		IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
		user_port=`${jq_file} '.server_port' ${config_user_file}`
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} " | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_list_all="포트: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 연결 IP 총 수: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 현재 연결 IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
		echo -e "현재 모드: ${Green_background_prefix} "${now_mode}" ${Font_color_suffix} 연결 IP 총 수: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix}"
		echo -e "${user_list_all}"
	else
		now_mode="다중포트" && user_total=`${jq_file} '.port_password' ${config_user_file} |sed '$d;1d' | wc -l`
		IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
		user_list_all=""
		for((integer = 1; integer <= ${user_total}; integer++))
		do
			user_port=`${jq_file} '.port_password' ${config_user_file} |sed '$d;1d' |awk -F ":" '{print $1}' |sed -n "${integer}p" |sed -r 's/.*\"(.+)\".*/\1/'`
			user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep "${user_port}"|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" `
			if [[ -z ${user_IP_1} ]]; then
				user_IP_total="0"
			else
				user_IP_total=`echo -e "${user_IP_1}"|wc -l`
				if [[ ${format_1} == "IP_address" ]]; then
					get_IP_address
				else
					user_IP=`echo -e "\n${user_IP_1}"`
				fi
			fi
			user_list_all=${user_list_all}"포트: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 연결 IP 총 수: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 현재 연결 IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
			user_IP=""
		done
		echo -e "현재모드: ${Green_background_prefix} "${now_mode}" ${Font_color_suffix} 用户总数: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} 연결 IP 총 수: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
		echo -e "${user_list_all}"
	fi
}
View_user_connection_info(){
	SSR_installation_status
	echo && echo -e "표시방식 선택：
 ${Green_font_prefix}1.${Font_color_suffix} IP 표시 방식
 ${Green_font_prefix}2.${Font_color_suffix} IP+IP위치 표시 방식" && echo
	read -e -p "(기본값: 1):" ssr_connection_info
	[[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} IP위치(ipip.net)테스트 중. IP가 많은 경우, 시간이 길어질 수 있습니다..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# 修改 用户配置
Modify_Config(){
	SSR_installation_status
	if [[ -z "${now_mode}" ]]; then
		echo && echo -e "현재 모드: 단일포트，무엇을 원하세요?
 ${Green_font_prefix}1.${Font_color_suffix} 포트 변경
 ${Green_font_prefix}2.${Font_color_suffix} 비번 변경
 ${Green_font_prefix}3.${Font_color_suffix} 암호화 방식 변경
 ${Green_font_prefix}4.${Font_color_suffix} 프로토콜 변경
 ${Green_font_prefix}5.${Font_color_suffix} 난독화 변경
 ${Green_font_prefix}6.${Font_color_suffix} 기기수제한 변경
 ${Green_font_prefix}7.${Font_color_suffix} 기기별속도제한 변경
 ${Green_font_prefix}8.${Font_color_suffix} 포트총속도제한 변경
 ${Green_font_prefix}9.${Font_color_suffix} 전체 설정 변경" && echo
		read -e -p "(기본값: 취소):" ssr_modify
		[[ -z "${ssr_modify}" ]] && echo "취소되었습니다..." && exit 1
		Get_User
		if [[ ${ssr_modify} == "1" ]]; then
			Set_config_port
			Modify_config_port
			Add_iptables
			Del_iptables
			Save_iptables
		elif [[ ${ssr_modify} == "2" ]]; then
			Set_config_password
			Modify_config_password
		elif [[ ${ssr_modify} == "3" ]]; then
			Set_config_method
			Modify_config_method
		elif [[ ${ssr_modify} == "4" ]]; then
			Set_config_protocol
			Modify_config_protocol
		elif [[ ${ssr_modify} == "5" ]]; then
			Set_config_obfs
			Modify_config_obfs
		elif [[ ${ssr_modify} == "6" ]]; then
			Set_config_protocol_param
			Modify_config_protocol_param
		elif [[ ${ssr_modify} == "7" ]]; then
			Set_config_speed_limit_per_con
			Modify_config_speed_limit_per_con
		elif [[ ${ssr_modify} == "8" ]]; then
			Set_config_speed_limit_per_user
			Modify_config_speed_limit_per_user
		elif [[ ${ssr_modify} == "9" ]]; then
			Set_config_all
			Modify_config_all
		else
			echo -e "${Error} 정확한 숫자를 입력해주세요.(1-9)" && exit 1
		fi
	else
		echo && echo -e "현재 모드: 다중포트，무엇을 원하세요?
 ${Green_font_prefix}1.${Font_color_suffix}  사용자 설정 추가
 ${Green_font_prefix}2.${Font_color_suffix}  사용자 설정 삭제
 ${Green_font_prefix}3.${Font_color_suffix}  사용자 설정 변경
——————————
 ${Green_font_prefix}4.${Font_color_suffix}  암호화 방식 변경
 ${Green_font_prefix}5.${Font_color_suffix}  프로토콜 변경
 ${Green_font_prefix}6.${Font_color_suffix}  난독화 변경
 ${Green_font_prefix}7.${Font_color_suffix}  기기총수량 변경
 ${Green_font_prefix}8.${Font_color_suffix}  기기별속도제한 변경
 ${Green_font_prefix}9.${Font_color_suffix}  포트총속도제한 변경
 ${Green_font_prefix}10.${Font_color_suffix} 전체 설정 변경" && echo
		read -e -p "(기본값: 취소):" ssr_modify
		[[ -z "${ssr_modify}" ]] && echo "취소되었습니다..." && exit 1
		Get_User
		if [[ ${ssr_modify} == "1" ]]; then
			Add_multi_port_user
		elif [[ ${ssr_modify} == "2" ]]; then
			Del_multi_port_user
		elif [[ ${ssr_modify} == "3" ]]; then
			Modify_multi_port_user
		elif [[ ${ssr_modify} == "4" ]]; then
			Set_config_method
			Modify_config_method
		elif [[ ${ssr_modify} == "5" ]]; then
			Set_config_protocol
			Modify_config_protocol
		elif [[ ${ssr_modify} == "6" ]]; then
			Set_config_obfs
			Modify_config_obfs
		elif [[ ${ssr_modify} == "7" ]]; then
			Set_config_protocol_param
			Modify_config_protocol_param
		elif [[ ${ssr_modify} == "8" ]]; then
			Set_config_speed_limit_per_con
			Modify_config_speed_limit_per_con
		elif [[ ${ssr_modify} == "9" ]]; then
			Set_config_speed_limit_per_user
			Modify_config_speed_limit_per_user
		elif [[ ${ssr_modify} == "10" ]]; then
			Set_config_method
			Set_config_protocol
			Set_config_obfs
			Set_config_protocol_param
			Set_config_speed_limit_per_con
			Set_config_speed_limit_per_user
			Modify_config_method
			Modify_config_protocol
			Modify_config_obfs
			Modify_config_protocol_param
			Modify_config_speed_limit_per_con
			Modify_config_speed_limit_per_user
		else
			echo -e "${Error} 정확한 숫자를 입력해주세요.(1-9)" && exit 1
		fi
	fi
	Restart_SSR
}
# 다중포트 사용자 정보 표시
List_multi_port_user(){
	user_total=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | wc -l`
	[[ ${user_total} = "0" ]] && echo -e "${Error} 다중포트 사용자를 찾을 수 없습니다. 확인해주세요 !" && exit 1
	user_list_all=""
	for((integer = ${user_total}; integer >= 1; integer--))
	do
		user_port=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $1}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
		user_password=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $2}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
		user_list_all=${user_list_all}"포트: "${user_port}" 비번: "${user_password}"\n"
	done
	echo && echo -e "사용자 총 수 ${Green_font_prefix}"${user_total}"${Font_color_suffix}"
	echo -e ${user_list_all}
}
# 다중포트 사용자 추가
Add_multi_port_user(){
	Set_config_port
	Set_config_password
	sed -i "8 i \"        \"${ssr_port}\":\"${ssr_password}\"," ${config_user_file}
	sed -i "8s/^\"//" ${config_user_file}
	Add_iptables
	Save_iptables
	echo -e "${Info} 다중포트 사용자 추가 방식 ${Green_font_prefix}[포트: ${ssr_port} , 비번: ${ssr_password}]${Font_color_suffix} "
}
# 다중포트 사용자 변경
Modify_multi_port_user(){
	List_multi_port_user
	echo && echo -e "변경할 사용자 포트를 입력하세요."
	read -e -p "(기본값: 취소):" modify_user_port
	[[ -z "${modify_user_port}" ]] && echo -e "취소되었습니다..." && exit 1
	del_user=`cat ${config_user_file}|grep '"'"${modify_user_port}"'"'`
	if [[ ! -z "${del_user}" ]]; then
		port="${modify_user_port}"
		password=`echo -e ${del_user}|awk -F ":" '{print $NF}'|sed -r 's/.*\"(.+)\".*/\1/'`
		Set_config_port
		Set_config_password
		sed -i 's/"'$(echo ${port})'":"'$(echo ${password})'"/"'$(echo ${ssr_port})'":"'$(echo ${ssr_password})'"/g' ${config_user_file}
		Del_iptables
		Add_iptables
		Save_iptables
		echo -e "${Inof} 다중포트 사용자 변경 완료 ${Green_font_prefix}[旧: ${modify_user_port}  ${password} , 변경 정보: ${ssr_port}  ${ssr_password}]${Font_color_suffix} "
	else
		echo -e "${Error} 정확한 포트 번호를 입력해주세요 !" && exit 1
	fi
}
# 다중포트 사용자 삭제
Del_multi_port_user(){
	List_multi_port_user
	user_total=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | wc -l`
	[[ "${user_total}" = "1" ]] && echo -e "${Error} 다중포트 사용자가 1명 남았습니다. 삭제할 수 없습니다 !" && exit 1
	echo -e "삭제할 사용자 포트를 입력하세요"
	read -e -p "(기본값: 취소):" del_user_port
	[[ -z "${del_user_port}" ]] && echo -e "취소되었습니다..." && exit 1
	del_user=`cat ${config_user_file}|grep '"'"${del_user_port}"'"'`
	if [[ ! -z ${del_user} ]]; then
		port=${del_user_port}
		Del_iptables
		Save_iptables
		del_user_determine=`echo ${del_user:((${#del_user} - 1))}`
		if [[ ${del_user_determine} != "," ]]; then
			del_user_num=$(sed -n -e "/${port}/=" ${config_user_file})
			echo $((${ssr_protocol_param}+0)) &>/dev/null
			del_user_num=$(echo $((${del_user_num}-1)))
			sed -i "${del_user_num}s/,//g" ${config_user_file}
		fi
		sed -i "/${port}/d" ${config_user_file}
		echo -e "${Info} 다중포트 사용자 삭제 성공 ${Green_font_prefix} ${del_user_port} ${Font_color_suffix} "
	else
		echo "${Error} 정확한 포트 번호를 입력해주세요 !" && exit 1
	fi
}
# 사용자 설정 수동 변경
Manually_Modify_Config(){
	SSR_installation_status
	port=`${jq_file} '.server_port' ${config_user_file}`
	vi ${config_user_file}
	if [[ -z "${now_mode}" ]]; then
		ssr_port=`${jq_file} '.server_port' ${config_user_file}`
		Del_iptables
		Add_iptables
	fi
	Restart_SSR
}
# 포트 모드 변경
Port_mode_switching(){
	SSR_installation_status
	if [[ -z "${now_mode}" ]]; then
		echo && echo -e "	현재 모드: ${Green_font_prefix}단일 포트${Font_color_suffix}" && echo
		echo -e "다중 포트 모드로 변경하겠습니까?[y/N]"
		read -e -p "(기본값: n):" mode_yn
		[[ -z ${mode_yn} ]] && mode_yn="n"
		if [[ ${mode_yn} == [Yy] ]]; then
			port=`${jq_file} '.server_port' ${config_user_file}`
			Set_config_all
			Write_configuration_many
			Del_iptables
			Add_iptables
			Save_iptables
			Restart_SSR
		else
			echo && echo "	취소되었습니다..." && echo
		fi
	else
		echo && echo -e "	현재모드: ${Green_font_prefix}다중포트${Font_color_suffix}" && echo
		echo -e "단일 포트 모드로 변경하겠습니까?[y/N]"
		read -e -p "(기본값: n):" mode_yn
		[[ -z ${mode_yn} ]] && mode_yn="n"
		if [[ ${mode_yn} == [Yy] ]]; then
			user_total=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | wc -l`
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=`${jq_file} '.port_password' ${config_user_file} | sed '$d' | sed "1d" | awk -F ":" '{print $1}' | sed -n "${integer}p" | sed -r 's/.*\"(.+)\".*/\1/'`
				Del_iptables
			done
			Set_config_all
			Write_configuration
			Add_iptables
			Restart_SSR
		else
			echo && echo "	취소되었습니다..." && echo
		fi
	fi
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR 실행됨 !" && exit 1
	/etc/init.d/ssr start
	check_pid
	[[ ! -z ${PID} ]] && View_User
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR 정지됨 !" && exit 1
	/etc/init.d/ssr stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssr stop
	/etc/init.d/ssr start
	check_pid
	[[ ! -z ${PID} ]] && View_User
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} ShadowsocksR 이력(Log)파일이 존재하지 않습니다 !" && exit 1
	echo && echo -e "${Tip} ${Red_font_prefix}Ctrl+C${Font_color_suffix}를 눌러 이력(Log)보기를 종료하세요." && echo -e "만약 이력(Log)내용 전체를 보고자 하는 경우 ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix} 명령을 사용하세요." && echo
	tail -f ${ssr_log_file}
}
# 가속
Configure_Server_Speeder(){
	echo && echo -e "어떤 작업을 원하세요?
 ${Green_font_prefix}1.${Font_color_suffix} 가속기 설치
 ${Green_font_prefix}2.${Font_color_suffix} 가속기 제거
————————
 ${Green_font_prefix}3.${Font_color_suffix} 가속기 시작
 ${Green_font_prefix}4.${Font_color_suffix} 가속기 정지
 ${Green_font_prefix}5.${Font_color_suffix} 가속기 재시작
 ${Green_font_prefix}6.${Font_color_suffix} 가속기 상태 확인
 
 주의： 가속기 및 LotServer는 동시에 설치/사용이 불가능합니다!" && echo
	read -e -p "(기본값: 취소):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "취소되었습니다..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} 가속기(Server Speeder)가 이미 설치되었습니다 !" && exit 1
	cd /root
	#借用91yun.rog的开心版锐速
	wget -N --no-check-certificate https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "serverspeeder.sh" ]] && echo -e "${Error} 가속기 설치 스크립트 다운로드 실패 !" && exit 1
	bash serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /root/serverspeeder.sh
		rm -rf /root/91yunserverspeeder
		rm -rf /root/91yunserverspeeder.tar.gz
		echo -e "${Info} 가속기(Server Speeder) 설치 완료 !" && exit 1
	else
		echo -e "${Error} 가속기(Server Speeder) 설치 실패 !" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "가속기(Server Speeder)를 제거하시겠습니까?[y/N]" && echo
	read -e -p "(기본값: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "취소되었습니다..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "가속기(Server Speeder) 제거 완료 !" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "어떤 작업을 원하세요?
 ${Green_font_prefix}1.${Font_color_suffix} LotServer 설치
 ${Green_font_prefix}2.${Font_color_suffix} LotServer 제거
————————
 ${Green_font_prefix}3.${Font_color_suffix} LotServer 시작
 ${Green_font_prefix}4.${Font_color_suffix} LotServer 중지
 ${Green_font_prefix}5.${Font_color_suffix} LotServer 재시작
 ${Green_font_prefix}6.${Font_color_suffix} LotServer 상태 확인
 
 주의： 가속기와 LotServer는 동시에 설치/사용이 불가능합니다!" && echo
	read -e -p "(기본값: 취소):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "취소되었습니다..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer가 이미 설치되어 있습니다 !" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} LotServer 설치 스크립트 다운로드 실패 !" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer 설치 완료 !" && exit 1
	else
		echo -e "${Error} LotServer 설치 실패 !" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "LotServer를 제거하시겠습니까?[y/N]" && echo
	read -e -p "(기본값: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "취소되었습니다..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer 제거 완료 !" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "  어떤 작업을 원하십니까?
	
 ${Green_font_prefix}1.${Font_color_suffix} BBR 설치
————————
 ${Green_font_prefix}2.${Font_color_suffix} BBR 시작
 ${Green_font_prefix}3.${Font_color_suffix} BBR 중지
 ${Green_font_prefix}4.${Font_color_suffix} BBR 상태 확인" && echo
echo -e "${Green_font_prefix} [설치전 주의사항] ${Font_color_suffix}
1. BBR을 설치하여 시작하면, 커널 변경이 필요하며, 변경 실패 등의 위험성이 있습니다. (서버 재시동 불가)
2. 본 스크립트는 Debian / Ubuntu 시스템의 커널을 변경하며, OpenVZ 및 Docker 는 커널 변경을 지원하지 않습니다.
3. Debian 커널 변경 과정 중 [ 커널을 중지하고 변경하시겠습니까? ]라는 프롬프트가 뜨면, ${Green_font_prefix} NO ${Font_color_suffix}를 선택하세요" && echo
	read -e -p "(기본: 취소):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "취소되었습니다..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} 본 스크립트는 CentOS 시스템의 BBR 설치를 지원하지 않습니다 !" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# 기타 기능
Other_functions(){
	echo && echo -e "  어떤 작업을 원하세요?
	
  ${Green_font_prefix}1.${Font_color_suffix} BBR 설정
  ${Green_font_prefix}2.${Font_color_suffix} 가속기(ServerSpeeder) 설정
  ${Green_font_prefix}3.${Font_color_suffix} LotServer 설정
  주의： 가속기/LotServer/BBR은 OpenVZ를 지원하지 않습니다!
  주의： 가속기/LotServer/BBR은 동시에 사용이 불가능합니다!
————————————
  ${Green_font_prefix}4.${Font_color_suffix} BT/PT/SPAM (iptables) 원클릭 금지
  ${Green_font_prefix}5.${Font_color_suffix} BT/PT/SPAM (iptables) 원클릭 금지해제
  ${Green_font_prefix}6.${Font_color_suffix} ShadowsocksR 이력(Log) 표시 모드 변경
  ——설명：SSR은 기본적으로 에러 이력만 내보내기합니다. 이 항목은 상세한 방문이력을 표시하는 것으로 변경가능합니다." && echo
	read -e -p "(기본값: 취소):" other_num
	[[ -z "${other_num}" ]] && echo "취소되었습니다..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	else
		echo -e "${Error} 정확한 숫자를 입력해주세요.[1-6]" && exit 1
	fi
}
# BT PT SPAM 금지
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# BT PT SPAM 금지해제
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	Get_User
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "현재 이력 표시 모드: ${Green_font_prefix}간단모드(에러 이력만 표시)${Font_color_suffix}" && echo
		echo -e "${Green_font_prefix}상세모드(상세 연결 이력 + 에러 이력)${Font_color_suffix}로 변경하시겠습니까?[y/N]"
		read -e -p "(기본값: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	취소되었습니다..." && echo
		fi
	else
		echo && echo -e "현재 이력 표시 모드: ${Green_font_prefix}상세모드(상세 연결 이력 + 에러 이력)${Font_color_suffix}" && echo
		echo -e "${Green_font_prefix}간단모드(에러 이력만 표시)${Font_color_suffix}로 변경하시겠습니까?[y/N]"
		read -e -p "(기본값: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	취소되었습니다..." && echo
		fi
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/kikunae77/doubi/master/ssr.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Github에 연결할 수 없습니다 !" && exit 0
	if [[ -e "/etc/init.d/ssr" ]]; then
		rm -rf /etc/init.d/ssr
		Service_SSR
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/kikunae77/doubi/master/ssr.sh" && chmod +x ssr.sh
	echo -e "스크립트가 새버전[ ${sh_new_ver} ]으로 업데이트 되었습니다!(주의：기존의 스크립트를 덮어쓰는 방식으로 업데이트 되므로, 아래 오류정보등이 표시될 수 있습니다. 아무 표시 없으면 문제가 없는 겁니다.)" && exit 0
}
# 显示 菜单状态
menu_status(){
	if [[ -e ${config_user_file} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " 현재 상태: ${Green_font_prefix}설치되어있음${Font_color_suffix} / ${Green_font_prefix}시작됨${Font_color_suffix}"
		else
			echo -e " 현재 상태: ${Green_font_prefix}설치되어있음${Font_color_suffix} / ${Red_font_prefix}중지됨${Font_color_suffix}"
		fi
		now_mode=$(cat "${config_user_file}"|grep '"port_password"')
		if [[ -z "${now_mode}" ]]; then
			echo -e " 현재 모드: ${Green_font_prefix}단일포트${Font_color_suffix}"
		else
			echo -e " 현재 모드: ${Green_font_prefix}다중포트${Font_color_suffix}"
		fi
	else
		echo -e " 현재상태: ${Red_font_prefix}설치되어있지 않음${Font_color_suffix}"
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 본 스크립트는 현재 시스템을 지원하지 않습니다. ${release} !" && exit 1
echo -e "  ShadowsocksR 원클릭 관리 스크립트 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- Toyo | doub.io/ss-jc42, Translate kikuna | blog.szkorean.net ----

  ${Green_font_prefix}1.${Font_color_suffix} ShadowsocksR 설치
  ${Green_font_prefix}2.${Font_color_suffix} ShadowsocksR 업데이트
  ${Green_font_prefix}3.${Font_color_suffix} ShadowsocksR 제거
  ${Green_font_prefix}4.${Font_color_suffix} libsodium(chacha20) 설치
————————————
  ${Green_font_prefix}5.${Font_color_suffix} 계정 정보 보기
  ${Green_font_prefix}6.${Font_color_suffix} 연결 정보 보기
  ${Green_font_prefix}7.${Font_color_suffix} 계정 설정 변경
  ${Green_font_prefix}8.${Font_color_suffix} 설정 수동 변경
  ${Green_font_prefix}9.${Font_color_suffix} 포트 모드 변경
————————————
 ${Green_font_prefix}10.${Font_color_suffix} ShadowsocksR 시작
 ${Green_font_prefix}11.${Font_color_suffix} ShadowsocksR 정지
 ${Green_font_prefix}12.${Font_color_suffix} ShadowsocksR 재시작
 ${Green_font_prefix}13.${Font_color_suffix} ShadowsocksR 이력 보기
————————————
 ${Green_font_prefix}14.${Font_color_suffix} 기타 기능
 ${Green_font_prefix}15.${Font_color_suffix} 스크립트 업데이트
 "
menu_status
echo && read -e -p "숫자를 입력하세요 [1-15]：" num
case "$num" in
	1)
	Install_SSR
	;;
	2)
	Update_SSR
	;;
	3)
	Uninstall_SSR
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Port_mode_switching
	;;
	10)
	Start_SSR
	;;
	11)
	Stop_SSR
	;;
	12)
	Restart_SSR
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Update_Shell
	;;
	*)
	echo -e "${Error} 정확한 숫자를 입력하세요 [1-15]"
	;;
esac
