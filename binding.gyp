{
    'conditions': [
        ['OS=="mac" or OS=="freebsd"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-bpf.cc',
                        'arpcache-ctlnet.cc'
                    ],
                }
            ]
        }],
        ['OS=="linux"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-sockpacket.cc',
                        'arpcache-proc.cc'
                    ],
                }
            ]
        }],
        ['OS=="solaris"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-dlpi.cc',
                        'arpcache-dlpi.cc'
                    ],
                }
            ]
        }],
        ['OS=="windows"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-win32.cc',
                        'arpcache-none.cc'
                    ],
                }
            ]
        }],
        ['1==1', {
            'targets': [ 
                {
                    'target_name': 'IFEStub',
                    'type': 'none'
                }
            ]
        }]
    ]
}
