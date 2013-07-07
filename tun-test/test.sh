#!/bin/sh

PATH=/usr/bin:/usr/sbin:$PATH

main() { 

    if [ "nobuild" = "$1" ]; then
        nobuild=1
        cd ../
    else 
        nobuld=0
    fi

    echo "##" | tee -a $TESTLOGFILE
    echo "## Initializing test env" | tee -a $TESTLOGFILE
    echo "##" | tee -a $TESTLOGFILE
    init

    if [ "$nobuild" -eq 0 ]; then
        echo "##"  | tee -a $TESTLOGFILE
        echo "## Building " | tee -a $TESTLOGFILE
        echo "##" | tee -a $TESTLOGFILE
        install
    fi

    echo "##" | tee -a $TESTLOGFILE
    echo "## Start Test" | tee -a $TESTLOGFILE
    echo "##" | tee -a $TESTLOGFILE

    loadcheck "tun"
    loadcheck "tap"

    plumb "tun"
    plumb "tap"

    unplumb "tun"
    unplumb "tap"

    echo "##" | tee -a $TESTLOGFILE
    echo "## Clean up test env" | tee -a $TESTLOGFILE
    echo "##" | tee -a $TESTLOGFILE
    fini $1
}

plumb(){
    dev=$1
    sudo tun-test/tunctl -t ${dev}0 -b
    if [ $? -ne 0 ]; then
	echo "Faild." | tee -a $TESTLOGFILE
    fi
}

unplumb(){
    dev=$1
    #sudo ifconfig ${dev}0 unplumb
    sudo tun-test/tunctl -d ${dev}0 -b
    if [ $? -ne 0 ]; then
	echo "Faild." | tee -a $TESTLOGFILE
    fi
}

unplumball(){
    unplumb tun0
    unplumb tap0
}


loadcheck(){
    loaded=`modinfo| grep "$1 (TUN/TAP"`
    if [ -z $loaded ]; then
        echo "$1 driver not loaded"  | tee -a $TESTLOGFILE
    else 
        echo "$1 driver loaded"  | tee -a $TESTLOGFILE 
    fi
}

clean(){
    make clean | tee -a $TESTLOGFILE
    make distclean | tee -a $TESTLOGFILE
}

build(){
    ./configure | tee -a $TESTLOGFILE
    make | tee -a $TESTLOGFILE
}

install(){
    build
    sudo make install | tee -a $TESTLOGFILE
}

uninstall(){
    sudo make uinstall | tee -a $TESTLOGFILE
    clean
}


init (){
    LOGDIR=$PWD/logs
    TESTLOGFILE=$LOGDIR/test-`date '+%Y%m%d-%H:%M:%S'`.log
    DAEMONLOGFILE=$LOGDIR/localfsd-`date '+%Y%m%d-%H:%M:%S'`.log

    # Create log directory 
    if [ ! -d "${LOGDIR}" ]; then
	mkdir ${LOGDIR}
        echo "$LOGDIR created" | tee -a $TESTLOGFILE
    fi	
    echo "log file name: $TESTLOGFILE"  | tee -a $TESTLOGFILE

    touch $TESTLOGFILE

    # Log start message
    echo "started" | tee -a $TESTLOGFILE

}

fini() {
    unplumball > /dev/null 2>&1
    if [ "$nobuild" -eq 0 ]; then
        clean > /dev/null 2>&1
    fi
    echo "finished" | tee -a $TESTLOGFILE 
}

main $1