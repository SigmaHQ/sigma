event = {
    1: ('childproc_count',"[1-*]"),
    # 2: Change time,
    3: ('netconn_count',"[1-*]]"),
    # 4: sysmon state change
    # 5: Process termincated
    6: ('modload',"*\System32\Drivers*]"),
    7: ('modload_count',"[1-*]]"),
    8: ('crossproc_type', 'remote_thread')
    # 9: Raw Access Read
    10: ('crossproc_type', 'process_open')
    11: ('filemod_count','[1-*]')
    12: ('regmod_count','[1-*]')
    14: ('regmod_count','[1-*]')
    # 15 File create stream hash
}