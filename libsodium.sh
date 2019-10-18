#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: Libsodium Install
#	Version: 1.0.0
#	Author: Toyo
#	Blog: https://doub.io/shell-jc6/
#=================================================

Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[정보]${Font_color_suffix}" && Error="${Red_font_prefix}[오류]${Font_color_suffix}" && Tip="${Green_font_prefix}[주의]${Font_color_suffix}"

Check_Libsodium_ver(){
	echo -e "${Info} libsodium 최신 버전을 가져옵니다..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} libsodium 최신 버전 ${Green_font_prefix}[${Libsodiumr_ver}]${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium이 이미 설치되었습니다. 덮어씌워 설치하시겠습니까(또는 업데이트 하시겠습니까)? [y/N]"
		read -e -p "(기본값: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "취소되었습니다..." && exit 1
		fi
	else
		echo -e "${Info} libsodium이 설치되어 있지 않습니다. 설치를 시작합니다..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} 라이브러리 설치..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} 다운로드..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 압축해제..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz
		cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 컴파일러 설치..."
		./configure --disable-maintainer-mode
		make -j2
		make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} 라이브러리 설치..."
		apt-get install -y build-essential
		echo -e "${Info} 다운로드..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 압축해제..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz
		cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 컴파일러 설치..."
		./configure --disable-maintainer-mode
		make -j2
		make install
	fi
	ldconfig
	cd ..
	rm -rf libsodium-${Libsodiumr_ver}.tar.gz
	rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium 설치 실패 !" && exit 1
	echo && echo -e "${Info} libsodium 설치 완료 !" && echo
}
action=$1
[[ -z $1 ]] && action=install
case "$action" in
	install)
	Install_Libsodium
	;;
    *)
    echo "입력 오류 !"
    echo "사용법: [ install ]"
    ;;
esac
