#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================
#       System Required: CentOS/Debian/Ubuntu
#       Description: iptables 封禁 BT、PT、SPAM（垃圾邮件）和自定义端口、关键词
#       Version: 1.0.10
#       Blog: https://doub.io/shell-jc2/
#=================================================

sh_ver="1.0.10"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[정보]${Font_color_suffix}"
Error="${Red_font_prefix}[오류]${Font_color_suffix}"

smtp_port="25,26,465,587"
pop3_port="109,110,995"
imap_port="143,218,220,993"
other_port="24,50,57,105,106,158,209,1109,24554,60177,60179"
bt_key_word="torrent
.torrent
peer_id=
announce
info_hash
get_peers
find_node
BitTorrent
announce_peer
BitTorrent protocol
announce.php?passkey=
magnet:
xunlei
sandai
Thunder
XLLiveUD"

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
check_BT(){
	Cat_KEY_WORDS
	BT_KEY_WORDS=$(echo -e "$Ban_KEY_WORDS_list"|grep "torrent")
}
check_SPAM(){
	Cat_PORT
	SPAM_PORT=$(echo -e "$Ban_PORT_list"|grep "${smtp_port}")
}
Cat_PORT(){
	Ban_PORT_list=$(iptables -t filter -L OUTPUT -nvx --line-numbers|grep "REJECT"|awk '{print $13}')
}
Cat_KEY_WORDS(){
	Ban_KEY_WORDS_list=""
	Ban_KEY_WORDS_v6_list=""
	if [[ ! -z ${v6iptables} ]]; then
		Ban_KEY_WORDS_v6_text=$(${v6iptables} -t mangle -L OUTPUT -nvx --line-numbers|grep "DROP")
		Ban_KEY_WORDS_v6_list=$(echo -e "${Ban_KEY_WORDS_v6_text}"|sed -r 's/.*\"(.+)\".*/\1/')
	fi
	Ban_KEY_WORDS_text=$(${v4iptables} -t mangle -L OUTPUT -nvx --line-numbers|grep "DROP")
	Ban_KEY_WORDS_list=$(echo -e "${Ban_KEY_WORDS_text}"|sed -r 's/.*\"(.+)\".*/\1/')
}
View_PORT(){
	Cat_PORT
	echo -e "===============${Red_background_prefix} 현재 사용 금지된 포트 ${Font_color_suffix}==============="
	echo -e "$Ban_PORT_list" && echo && echo -e "==============================================="
}
View_KEY_WORDS(){
	Cat_KEY_WORDS
	echo -e "==============${Red_background_prefix} 현재 사용 금지된 키워드 ${Font_color_suffix}=============="
	echo -e "$Ban_KEY_WORDS_list" && echo -e "==============================================="
}
View_ALL(){
	echo
	View_PORT
	View_KEY_WORDS
	echo
}
Save_iptables_v4_v6(){
	if [[ ${release} == "centos" ]]; then
		if [[ ! -z "$v6iptables" ]]; then
			service ip6tables save
			chkconfig --level 2345 ip6tables on
		fi
		service iptables save
		chkconfig --level 2345 iptables on
	else
		if [[ ! -z "$v6iptables" ]]; then
			ip6tables-save > /etc/ip6tables.up.rules
			echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules" > /etc/network/if-pre-up.d/iptables
		else
			echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules" > /etc/network/if-pre-up.d/iptables
		fi
		iptables-save > /etc/iptables.up.rules
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
Set_key_word() { $1 -t mangle -$3 OUTPUT -m string --string "$2" --algo bm --to 65535 -j DROP; }
Set_tcp_port() {
	[[ "$1" = "$v4iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable
	[[ "$1" = "$v6iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with tcp-reset
}
Set_udp_port() { $1 -t filter -$3 OUTPUT -p udp -m multiport --dports "$2" -j DROP; }
Set_SPAM_Code_v4(){
	for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}
		do
		Set_tcp_port $v4iptables "$i" $s
		Set_udp_port $v4iptables "$i" $s
	done
}
Set_SPAM_Code_v4_v6(){
	for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}
	do
		for j in $v4iptables $v6iptables
		do
			Set_tcp_port $j "$i" $s
			Set_udp_port $j "$i" $s
		done
	done
}
Set_PORT(){
	if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
		Set_tcp_port $v4iptables $PORT $s
		Set_udp_port $v4iptables $PORT $s
		Set_tcp_port $v6iptables $PORT $s
		Set_udp_port $v6iptables $PORT $s
	elif [[ -n "$v4iptables" ]]; then
		Set_tcp_port $v4iptables $PORT $s
		Set_udp_port $v4iptables $PORT $s
	fi
	Save_iptables_v4_v6
}
Set_KEY_WORDS(){
	key_word_num=$(echo -e "${key_word}"|wc -l)
	for((integer = 1; integer <= ${key_word_num}; integer++))
		do
			i=$(echo -e "${key_word}"|sed -n "${integer}p")
			Set_key_word $v4iptables "$i" $s
			[[ ! -z "$v6iptables" ]] && Set_key_word $v6iptables "$i" $s
	done
	Save_iptables_v4_v6
}
Set_BT(){
	key_word=${bt_key_word}
	Set_KEY_WORDS
	Save_iptables_v4_v6
}
Set_SPAM(){
	if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
		Set_SPAM_Code_v4_v6
	elif [[ -n "$v4iptables" ]]; then
		Set_SPAM_Code_v4
	fi
	Save_iptables_v4_v6
}
Set_ALL(){
	Set_BT
	Set_SPAM
}
Ban_BT(){
	check_BT
	[[ ! -z ${BT_KEY_WORDS} ]] && echo -e "${Error} BT, PT 키워드 사용이 이미 금지되어 있습니다. 다시 금지할 필요가 없습니다 !" && exit 0
	s="A"
	Set_BT
	View_ALL
	echo -e "${Info} BT,PT 키워드 사용을 금지하였습니다 !"
}
Ban_SPAM(){
	check_SPAM
	[[ ! -z ${SPAM_PORT} ]] && echo -e "${Error} SPAM(정크메일) 포트가 이미 사용 금지되어 있습니다. 다시 금지할 필요가 없습니다 !" && exit 0
	s="A"
	Set_SPAM
	View_ALL
	echo -e "${Info} SPAM(정크메일) 포트를 사용 금지하였습니다 !"
}
Ban_ALL(){
	check_BT
	check_SPAM
	s="A"
	if [[ -z ${BT_KEY_WORDS} ]]; then
		if [[ -z ${SPAM_PORT} ]]; then
			Set_ALL
			View_ALL
			echo -e "${Info} BT, PT 키워드 및 SPAM(정크메일) 포트 사용을 금지하였습니다 !"
		else
			Set_BT
			View_ALL
			echo -e "${Info} BT, PT 키워드 사용을 금지하였습니다 !"
		fi
	else
		if [[ -z ${SPAM_PORT} ]]; then
			Set_SPAM
			View_ALL
			echo -e "${Info} SPAM(정크메일) 포트 사용을 금지하였습니다 !"
		else
			echo -e "${Error} BT, PT 키워드 및 SPAM(정크메일) 포트 사용이 이미 금지되어 있습니다. 다시 금지할 필요가 없습니다 !" && exit 0
		fi
	fi
}
UnBan_BT(){
	check_BT
	[[ -z ${BT_KEY_WORDS} ]] && echo -e "${Error} BT, PT 키워드 사용이 금지되어 있지 않습니다. 확인해주세요 !" && exit 0
	s="D"
	Set_BT
	View_ALL
	echo -e "${Info} BT, PT 키워드 사용 금지를 해제하였습니다 !"
}
UnBan_SPAM(){
	check_SPAM
	[[ -z ${SPAM_PORT} ]] && echo -e "${Error} SPAM(정크메일) 포트 사용이 금지되어 있지 않습니다. 확인해주세요 !" && exit 0
	s="D"
	Set_SPAM
	View_ALL
	echo -e "${Info} SPAM(정크메일) 포트 사용 금지를 해제하였습니다 !"
}
UnBan_ALL(){
	check_BT
	check_SPAM
	s="D"
	if [[ ! -z ${BT_KEY_WORDS} ]]; then
		if [[ ! -z ${SPAM_PORT} ]]; then
			Set_ALL
			View_ALL
			echo -e "${Info} BT, PT 키워드 및 SPAM(정크메일) 포트 사용 금지를 해제하였습니다 !"
		else
			Set_BT
			View_ALL
			echo -e "${Info} BT, PT 키워드 사용 금지를 해제하였습니다 !"
		fi
	else
		if [[ ! -z ${SPAM_PORT} ]]; then
			Set_SPAM
			View_ALL
			echo -e "${Info} SPAM(정크메일) 포트 사용 금지를 해제하였습니다 !"
		else
			echo -e "${Error} BT, PT 키워드 및 SPAM(정크메일) 포트 사용 금지가 이미 해제되어 있습니다. 확인해주세요 !" && exit 0
		fi
	fi
}
ENTER_Ban_KEY_WORDS_type(){
	Type=$1
	Type_1=$2
	if [[ $Type_1 != "ban_1" ]]; then
		echo -e "입력형식을 선택해주세요 :
 1. 수동입력 (한개의 키워드 입력만 지원)
 2. 로컬 파일 불러오기 (다수의 키워드 불러오기 지원, 매 행마다 1개의 키워드)
 3. 인터넷 주소에서 불러오기 (다수의 키워드 불러오기 지원, 매 행마다 1개의 키워드)" && echo
		read -e -p "(기본값: 1. 수동입력):" key_word_type
	fi
	[[ -z "${key_word_type}" ]] && key_word_type="1"
	if [[ ${key_word_type} == "1" ]]; then
		if [[ $Type == "ban" ]]; then
			ENTER_Ban_KEY_WORDS
		else
			ENTER_UnBan_KEY_WORDS
		fi
	elif [[ ${key_word_type} == "2" ]]; then
		ENTER_Ban_KEY_WORDS_file
	elif [[ ${key_word_type} == "3" ]]; then
		ENTER_Ban_KEY_WORDS_url
	else
		if [[ $Type == "ban" ]]; then
			ENTER_Ban_KEY_WORDS
		else
			ENTER_UnBan_KEY_WORDS
		fi
	fi
}
ENTER_Ban_PORT(){
	echo -e "사용 금지할 포트를 입력하세요（단일포트/다중포트/연속된 포트범위）"
	if [[ ${Ban_PORT_Type_1} != "1" ]]; then
	echo -e "${Green_font_prefix}========입력방법========${Font_color_suffix}
 단일포트 : 25（포트 한개 입력）
 다중포트 : 25,26,465,587（여러개의 포트를 영문키보드의 ,로 분리하여 입력）
 연속된 포트범위 : 25:587（25-587사이의 모든 포트）" && echo
	fi
	read -e -p "(엔터만 입력하면 취소됩니다):" PORT
	[[ -z "${PORT}" ]] && echo "취소되었습니다..." && View_ALL && exit 0
}
ENTER_Ban_KEY_WORDS(){
	echo -e "사용 금지할 키워드를 입력하세요（도메인 등.. 한개의 키워드만 지원합니다.）"
	if [[ ${Type_1} != "ban_1" ]]; then
	echo -e "${Green_font_prefix}========입력방법========${Font_color_suffix}
 키워드：youtube, youtube가 포함된 모든 도메인에 방문 금지.
 키워드：youtube.com, youtube.com이 포함된 모든 도메인에 방문 금지（최상위 도메인 제한）。
 키워드：www.youtube.com, www.youtube.com이 포함된 모든 도메인에 방문 금지（3차 도메인 제한）。
 다양한 키워드를 테스트해보세요. (키워드를 .zip 으로 설정하면 모든 .zip확장자를 가진 파일의 다운로드 금지)" && echo
	fi
	read -e -p "(엔터만 입력하면 취소됩니다):" key_word
	[[ -z "${key_word}" ]] && echo "취소되었습니다..." && View_ALL && exit 0
}
ENTER_Ban_KEY_WORDS_file(){
	echo -e "사용 금지/금지 해제할 키워드 로컬 파일을 입력하세요. (절대경로로 입력)" && echo
	read -e -p "(기본값은 스크립트와 동일한 디렉토리의 key_word.txt ):" key_word
	[[ -z "${key_word}" ]] && key_word="key_word.txt"
	if [[ -e "${key_word}" ]]; then
		key_word=$(cat "${key_word}")
		[[ -z ${key_word} ]] && echo -e "${Error} 파일 내용이 없습니다 !" && View_ALL && exit 0
	else
		echo -e "${Error} 다음 파일을 찾을 수 없습니다. ${key_word} !" && View_ALL && exit 0
	fi
}
ENTER_Ban_KEY_WORDS_url(){
	echo -e "사용 금지/금지 해제할 키워드 온라인 파일 주소를 입력하세요. (예. http://xxx.xx/key_word.txt)" && echo
	read -e -p "(엔터만 입력하면 취소됩니다):" key_word
	[[ -z "${key_word}" ]] && echo "취소되었습니다..." && View_ALL && exit 0
	key_word=$(wget --no-check-certificate -t3 -T5 -qO- "${key_word}")
	[[ -z ${key_word} ]] && echo -e "${Error} 온라인 파일의 내용이 없거나 연결시간이 초과되었습니다 !" && View_ALL && exit 0
}
ENTER_UnBan_KEY_WORDS(){
	View_KEY_WORDS
	echo -e "사용 금지를 해제할 키워드를 입력해주세요. (위 목록의 키워드와 완전히 동일한 키워드를 입력해주세요)" && echo
	read -e -p "(엔터만 입력하면 취소됩니다):" key_word
	[[ -z "${key_word}" ]] && echo "취소되었습니다..." && View_ALL && exit 0
}
ENTER_UnBan_PORT(){
	echo -e "사용 금지를 해제할 포트번호를 입력해주세요. (, 및 :를 포함하여 위 목록의 포트번호와 완전히 동일한 포트를 입력해주세요.)" && echo
	read -e -p "(엔터만 입력하면 취소됩니다):" PORT
	[[ -z "${PORT}" ]] && echo "취소되었습니다..." && View_ALL && exit 0
}
Ban_PORT(){
	s="A"
	ENTER_Ban_PORT
	Set_PORT
	echo -e "${Info} [ ${PORT} ] 포트를 사용 금지하였습니다 !\n"
	Ban_PORT_Type_1="1"
	while true
	do
		ENTER_Ban_PORT
		Set_PORT
		echo -e "${Info} [ ${PORT} ] 포트를 사용 금지하였습니다 !\n"
	done
	View_ALL
}
Ban_KEY_WORDS(){
	s="A"
	ENTER_Ban_KEY_WORDS_type "ban"
	Set_KEY_WORDS
	echo -e "${Info} [ ${key_word} ] 키워드를 사용 금지하였습니다 !\n"
	while true
	do
		ENTER_Ban_KEY_WORDS_type "ban" "ban_1"
		Set_KEY_WORDS
		echo -e "${Info} [ ${key_word} ] 키워드를 사용 금지하였습니다 !\n"
	done
	View_ALL
}
UnBan_PORT(){
	s="D"
	View_PORT
	[[ -z ${Ban_PORT_list} ]] && echo -e "${Error} 사용 금지된 포트가 없습니다 !" && exit 0
	ENTER_UnBan_PORT
	Set_PORT
	echo -e "${Info} [ ${PORT} ] 포트를 사용 금지 해제하였습니다 !\n"
	while true
	do
		View_PORT
		[[ -z ${Ban_PORT_list} ]] && echo -e "${Error} 사용 금지된 포트가 없습니다 !" && exit 0
		ENTER_UnBan_PORT
		Set_PORT
		echo -e "${Info} [ ${PORT} ] 포트를 사용 금지 해제하였습니다 !\n"
	done
	View_ALL
}
UnBan_KEY_WORDS(){
	s="D"
	Cat_KEY_WORDS
	[[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error} 사용 금지된 키워드가 없습니다 !" && exit 0
	ENTER_Ban_KEY_WORDS_type "unban"
	Set_KEY_WORDS
	echo -e "${Info} [ ${key_word} ] 키워드를 사용 금지 해제하였습니다 !\n"
	while true
	do
		Cat_KEY_WORDS
		[[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error} 사용 금지된 키워드가 없습니다 !" && exit 0
		ENTER_Ban_KEY_WORDS_type "unban" "ban_1"
		Set_KEY_WORDS
		echo -e "${Info} [ ${key_word} ] 키워드를 사용 금지 해제하였습니다 !\n"
	done
	View_ALL
}
UnBan_KEY_WORDS_ALL(){
	Cat_KEY_WORDS
	[[ -z ${Ban_KEY_WORDS_text} ]] && echo -e "${Error} 사용 금지된 키워드가 없습니다. 확인해주세요 !" && exit 0
	if [[ ! -z "${v6iptables}" ]]; then
		Ban_KEY_WORDS_v6_num=$(echo -e "${Ban_KEY_WORDS_v6_list}"|wc -l)
		for((integer = 1; integer <= ${Ban_KEY_WORDS_v6_num}; integer++))
			do
				${v6iptables} -t mangle -D OUTPUT 1
		done
	fi
	Ban_KEY_WORDS_num=$(echo -e "${Ban_KEY_WORDS_list}"|wc -l)
	for((integer = 1; integer <= ${Ban_KEY_WORDS_num}; integer++))
		do
			${v4iptables} -t mangle -D OUTPUT 1
	done
	Save_iptables_v4_v6
	View_ALL
	echo -e "${Info} 모든 키워드를 사용 금지 해제하였습니다 !"
}
check_iptables(){
	v4iptables=`iptables -V`
	v6iptables=`ip6tables -V`
	if [[ ! -z ${v4iptables} ]]; then
		v4iptables="iptables"
		if [[ ! -z ${v6iptables} ]]; then
			v6iptables="ip6tables"
		fi
	else
		echo -e "${Error} iptables 방화벽이 설치되어 있지 않습니다 !
iptables 방화벽을 설치해주세요：
CentOS 시스템：yum install iptables -y
Debian / Ubuntu 시스템：apt-get install iptables -y"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/kikunae77/doubi/master/ban_iptables.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Github에 연결할 수 없습니다 !" && exit 0
	wget -N --no-check-certificate "https://raw.githubusercontent.com/kikunae77/doubi/master/ban_iptables.sh" && chmod +x ban_iptables.sh
	echo -e "스크립트가 최신 버전[ ${sh_new_ver} ]으로 업데이트 되었습니다!(주의：덮어씌우는 방식으로 업데이트 하므로, 아래에 오류 메시지가 표시될 수 있습니다. 아무것도 표시되지 않으면 정상입니다.)" && exit 0
}
check_sys
check_iptables
action=$1
if [[ ! -z $action ]]; then
	[[ $action = "banbt" ]] && Ban_BT && exit 0
	[[ $action = "banspam" ]] && Ban_SPAM && exit 0
	[[ $action = "banall" ]] && Ban_ALL && exit 0
	[[ $action = "unbanbt" ]] && UnBan_BT && exit 0
	[[ $action = "unbanspam" ]] && UnBan_SPAM && exit 0
	[[ $action = "unbanall" ]] && UnBan_ALL && exit 0
fi
echo && echo -e " iptables 방화벽 사용 금지 스크립트 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- Toyo | doub.io/shell-jc2 --

  ${Green_font_prefix}0.${Font_color_suffix} 현재 금지 목록 확인
————————————
  ${Green_font_prefix}1.${Font_color_suffix} BT, PT 키워드 사용 금지
  ${Green_font_prefix}2.${Font_color_suffix} SPAM(정크메일) 사용 금지
  ${Green_font_prefix}3.${Font_color_suffix} BT, PT+SPAM 사용 금지
  ${Green_font_prefix}4.${Font_color_suffix} 사용자 지정 포트 사용 금지
  ${Green_font_prefix}5.${Font_color_suffix} 사용자 지정 키워드 사용 금지
————————————
  ${Green_font_prefix}6.${Font_color_suffix} BT, PT 사용 금지 해제
  ${Green_font_prefix}7.${Font_color_suffix} SPAM(정크메일) 사용 금지 해제
  ${Green_font_prefix}8.${Font_color_suffix} BT, PT+SPAM 사용 금지 해제
  ${Green_font_prefix}9.${Font_color_suffix} 사용자 지정 포트 사용 금지 해제
 ${Green_font_prefix}10.${Font_color_suffix} 사용자 지정 키워드 사용 금지 해제
 ${Green_font_prefix}11.${Font_color_suffix} 모든 키워드 사용 금지 해제
————————————
 ${Green_font_prefix}12.${Font_color_suffix} 스크립트 업데이트
" && echo
read -e -p " 숫자를 입력하세요. [0-12]:" num
case "$num" in
	0)
	View_ALL
	;;
	1)
	Ban_BT
	;;
	2)
	Ban_SPAM
	;;
	3)
	Ban_ALL
	;;
	4)
	Ban_PORT
	;;
	5)
	Ban_KEY_WORDS
	;;
	6)
	UnBan_BT
	;;
	7)
	UnBan_SPAM
	;;
	8)
	UnBan_ALL
	;;
	9)
	UnBan_PORT
	;;
	10)
	UnBan_KEY_WORDS
	;;
	11)
	UnBan_KEY_WORDS_ALL
	;;
	12)
	Update_Shell
	;;
	*)
	echo "정확한 숫자를 입력해주세요. [0-12]"
	;;
esac
