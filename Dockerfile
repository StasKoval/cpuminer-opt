#
# Dockerfile for cpuminer
# usage: docker run creack/cpuminer --url xxxx --user xxxx --pass xxxx
# ex: docker run creack/cpuminer --url stratum+tcp://ltc.pool.com:80 --user creack.worker1 --pass abcdef
#
#

FROM		ubuntu:16.04
MAINTAINER	Guillaume J. Charmes <guillaume@charmes.net>

RUN		apt-get update -qq

RUN		apt-get install -qqy automake gcc
RUN		apt-get install -qqy libssl-dev libcurl4-openssl-dev libjansson-dev
RUN		apt-get install -qqy git git libboost-dev libboost-system-dev  libboost-thread-dev
RUN		apt-get install -qqy make

RUN		git clone https://github.com/pooler/cpuminer

RUN		cd cpuminer && ./autogen.sh
RUN		cd cpuminer && ./configure CFLAGS="-O3"
RUN		cd cpuminer && make

WORKDIR		/cpuminer
ENTRYPOINT	["./cpuminer"]
