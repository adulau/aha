command_not_found_handle() {
    echo $1
    ARGS=""
    if [ ! -z "$1" ]; then
        ARGS="$ARGS$1"
    fi

    if [ ! -z "$2" ]; then
        ARGS="$ARGS $2"
    fi

    if [ ! -z "$3" ]; then
        ARGS="$ARGS $3"
    fi

    if [ ! -z "$4" ]; then
        ARGS="$ARGS $4"
    fi


    if [ ! -z "$5" ]; then
        ARGS="$ARGS $5"
    fi

    if [ ! -z "$6" ]; then
        ARGS="$ARGS $6"
    fi

    if [ ! -z "$7" ]; then
        ARGS="$ARGS $7"
    fi

    if [ ! -z "$8" ]; then
        ARGS="$ARGS $8"
    fi

    if [ ! -z "$9" ]; then
        ARGS="$ARGS $9"
    fi



    /sbin/user_insult $ARGS
}
