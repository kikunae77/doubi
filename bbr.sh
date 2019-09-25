#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: Debian/Ubuntu
#	Description: TCP-BBR
#	Version: 1.0.22
#	Author: Toyo
#	Blog: https://doub.io/wlzy-16/
#	Tranlate: kikunae
#	Blog: https://blog.szkorean.net
#=================================================

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[정보]${Font_color_suffix}"
Error="${Red_font_prefix}[오류]${Font_color_suffix}"
Tip="${Green_font_prefix}[주의]${Font_color_suffix}"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 현재 사용자는 ROOT계정(또는ROOT권한을 가진 계정)이 아니어서，계속 진행할 수 없습니다.${Green_background_prefix} sudo su ${Font_color_suffix}명령어로 ROOT 권한을 임시로 획득한 후 다시 스크립트를 시작하세요." && exit 1
}
#检查系统
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
}
Set_latest_new_version(){
	echo -e "다운로드하여 설치할 리눅스 커널 버전(BBR)을 입력하세요.${Green_font_prefix}[ 형식: x.xx.xx ，예: 4.9.96 ]${Font_color_suffix}
${Tip} 커널버젼목록은 다음 사이트에서 확인할 수 있습니다.：${Green_font_prefix}[ http://kernel.ubuntu.com/~kernel-ppa/mainline/ ]${Font_color_suffix}
${Green_font_prefix}안정 버전인：4.9.XX ${Font_color_suffix}사용을 추천합니다. 4.9이상 버전은 테스트 버전입니다. 안정 버전과 테스트 버전은 동시에 업데이트 되므로 BBR 가속효과는 동일합니다."
	read -e -p "(엔터를 누르면 자동으로 최신 안정 버전을 확인합니다.):" latest_version
	[[ -z "${latest_version}" ]] && get_latest_new_version
	echo
}
# 여기서 최신 안정 버전 확인: https://teddysun.com/489.html
get_latest_new_version(){
	echo -e "${Info} 안정판 최신 커널 버전 확인 중..."
	latest_version=$(wget -qO- -t1 -T2 "http://kernel.ubuntu.com/~kernel-ppa/mainline/" | awk -F'\"v' '/v4.9.*/{print $2}' |grep -v '\-rc'| cut -d/ -f1 | sort -V | tail -1)
	[[ -z ${latest_version} ]] && echo -e "${Error} 최신 커널 버전 확인 실패 !" && exit 1
	echo -e "${Info} 안정판 최신 커널 버전 : ${latest_version}"
}
get_latest_version(){
	Set_latest_new_version
	bit=`uname -m`
	if [[ ${bit} == "x86_64" ]]; then
		deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1 )
		deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
		deb_kernel_name="linux-image-${latest_version}-amd64.deb"
	else
		deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
		deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
		deb_kernel_name="linux-image-${latest_version}-i386.deb"
	fi
}
#커널버전 적합여부 확인
check_deb_off(){
	get_latest_new_version
	deb_ver=`dpkg -l|grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep '[4-9].[0-9]*.'`
	latest_version_2=$(echo "${latest_version}"|grep -o '\.'|wc -l)
	if [[ "${latest_version_2}" == "1" ]]; then
		latest_version="${latest_version}.0"
	fi
	if [[ "${deb_ver}" != "" ]]; then
		if [[ "${deb_ver}" == "${latest_version}" ]]; then
			echo -e "${Info} 현재 커널 버전[${deb_ver}]이 요구사항을 만족합니다. 계속합니다..."
		else
			echo -e "${Tip} 현재 커널 버전[${deb_ver}]이 BBR 사용을 지원하지만 최신 버전은 아닙니다. ${Green_font_prefix} bash ${file}/bbr.sh ${Font_color_suffix}명령어로 커널을 업데이트 할 수 있습니다! (주의：새 버전이 반드시 좋은 것은 아니며, 4.9 이상 버전의 커널은 테스트 버전으로 안정성을 보증하지 못합니다. 구 버전이 사용에 문제가 없으면，업데이트 하지 않기를 권장합니다!)"
		fi
	else
		echo -e "${Error} 현재 커널 버전[${deb_ver}]이 BBR 사용을 지원하지 않습니다. ${Green_font_prefix} bash ${file}/bbr.sh ${Font_color_suffix}명령어로 커널을 업데이트 하세요 !" && exit 1
	fi
}
# 여분 커널 삭제
del_deb(){
	deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | wc -l`
	if [[ "${deb_total}" -ge "1" ]]; then
		echo -e "${Info} ${deb_total} 개의 여분 커널이 발견되었습니다. 삭제를 시작합니다..."
		for((integer = 1; integer <= ${deb_total}; integer++))
		do
			deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | head -${integer}`
			echo -e "${Info} ${deb_del} 커널을 삭제합니다..."
			apt-get purge -y ${deb_del}
			echo -e "${Info} ${deb_del} 커널 삭제가 완료되었습니다. 계속합니다..."
		done
		deb_total=`dpkg -l|grep linux-image | awk '{print $2}' | wc -l`
		if [[ "${deb_total}" = "1" ]]; then
			echo -e "${Info} 커널 삭제가 완료되었습니다. 계속합니다..."
		else
			echo -e "${Error} 커널 삭제 오류. 확인해주세요 !" && exit 1
		fi
	else
		echo -e "${Info} 방금 설치한 커널 이외에 여분 커널이 없는 것으로 확인됩니다. 여유분 커널 삭제 과정을 건너뜁니다 !"
	fi
}
del_deb_over(){
	del_deb
	update-grub
	addsysctl
	echo -e "${Tip} VPS 재시동 후，스크립트를 실행해 BBR이 정상 실행중인지 확인하세요. 명령어： ${Green_background_prefix} bash ${file}/bbr.sh status ${Font_color_suffix}"
	read -e -p "VPS를 재시동해야 BBR이 시작됩니다. 지금 다시 시작하겠습니까? [Y/n] :" yn
	[[ -z "${yn}" ]] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 재시작 중..."
		reboot
	fi
}
# BBR 설치
installbbr(){
	check_root
	get_latest_version
	deb_ver=`dpkg -l|grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep '[4-9].[0-9]*.'`
	latest_version_2=$(echo "${latest_version}"|grep -o '\.'|wc -l)
	if [[ "${latest_version_2}" == "1" ]]; then
		latest_version="${latest_version}.0"
	fi
	if [[ "${deb_ver}" != "" ]]; then	
		if [[ "${deb_ver}" == "${latest_version}" ]]; then
			echo -e "${Info} 현재 커널 버전[${deb_ver}]이 이미 최신 버전입니다. 설치할 필요가 없습니다 !"
			deb_total=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | wc -l`
			if [[ "${deb_total}" != "0" ]]; then
				echo -e "${Info} 커널 수량에 이상이 발견되었습니다. 커널 수량이 많습니다. 제거를 시작합니다..."
				del_deb_over
			else
				exit 1
			fi
		else
			echo -e "${Info} 현재 커널 버전이 BBR사용을 지원하지만 최신 버전은 아닙니다. 커널을 업그레이드(또는 다운그레이드)합니다..."
		fi
	else
		echo -e "${Info} 커널 버전이 BBR사용을 지원하지 않습니다..."
		virt=`virt-what`
		if [[ -z ${virt} ]]; then
			apt-get update && apt-get install virt-what -y
			virt=`virt-what`
		fi
		if [[ ${virt} == "openvz" ]]; then
			echo -e "${Error} BBR이 OpenVZ 가상화를 지원하지 않습니다(커널 변경 미지원) !" && exit 1
		fi
	fi
	echo "nameserver 8.8.8.8" > /etc/resolv.conf
	echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	
	wget -O "${deb_kernel_name}" "${deb_kernel_url}"
	if [[ -s ${deb_kernel_name} ]]; then
		echo -e "${Info} 커널 설치 파일 다운로드 성공，커널을 설치합니다..."
		dpkg -i ${deb_kernel_name}
		rm -rf ${deb_kernel_name}
	else
		echo -e "${Error} 커널 설치 파일 다운로드 실패，확인해주세요 !" && exit 1
	fi
	#判断内核是否安装成功
	deb_ver=`dpkg -l | grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep "${latest_version}"`
	if [[ "${deb_ver}" != "" ]]; then
		echo -e "${Info} 커널 설치 성공，여분의 커널 삭제를 시작합니다..."
		del_deb_over
	else
		echo -e "${Error} 커널 설치 실패，확인해주세요 !" && exit 1
	fi
}
bbrstatus(){
	check_bbr_status_on=`sysctl net.ipv4.tcp_congestion_control | awk '{print $3}'`
	if [[ "${check_bbr_status_on}" = "bbr" ]]; then
		echo -e "${Info} BBR이 이미 시작되었습니다 !"
		# BBR 시작되었는지 확인
		check_bbr_status_off=`lsmod | grep bbr`
		if [[ "${check_bbr_status_off}" = "" ]]; then
			echo -e "${Error} BBR이 시작되었느나 정상적으로 운용되지 않고 있습니다. 낮은 버전의 커널을 사용하여 테스트해주세요.(겸용성 문제일 수 있습니다. 커널이 BBR 실행은 가능하지만 사용은 불가능합니다.) !"
		else
			echo -e "${Info} BBR이 시작되어 정상 운용중입니다 !"
		fi
		exit 1
	fi
}
addsysctl(){
	sed -i '/net\.core\.default_qdisc=fq/d' /etc/sysctl.conf
	sed -i '/net\.ipv4\.tcp_congestion_control=bbr/d' /etc/sysctl.conf
	
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
}
startbbr(){
	check_deb_off
	bbrstatus
	addsysctl
	sleep 1s
	bbrstatus
}
# BBR 중지
stopbbr(){
	check_deb_off
	sed -i '/net\.core\.default_qdisc=fq/d' /etc/sysctl.conf
	sed -i '/net\.ipv4\.tcp_congestion_control=bbr/d' /etc/sysctl.conf
	sysctl -p
	sleep 1s
	
	read -e -p "VPS를 재시동해야，BBR이 중지 됩니다. 지금 다시 시작하겠습니까? [Y/n] :" yn
	[[ -z "${yn}" ]] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 재시작 중..."
		reboot
	fi
}
# BBR상태 확인
statusbbr(){
	check_deb_off
	bbrstatus
	echo -e "${Error} BBR 시작되지 않음 !"
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && echo -e "${Error} 본 스크립트는 현재 시스템을 지원하지 않습니다 ${release} !" && exit 1
action=$1
[[ -z $1 ]] && action=install
case "$action" in
	install|start|stop|status)
	${action}bbr
	;;
	*)
	echo "입력 에러 !"
	echo "사용법: { install | start | stop | status }"
	;;
esac
