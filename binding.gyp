{
    'conditions': [
        ['OS=="mac" or OS=="freebsd"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-bpf.cc'
                    ],
                }
            ]
        },
        'OS=="linux"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-sockpacket.cc'
                    ],
                }
            ]
        },
        'OS=="solaris"', {
            'targets': [
                {
                    'target_name': 'IFEBinding',
                    'sources': [
                        'IFE.cc',
                        'ife-icmp-support.cc',
                        'ife-dlpi.cc'
                    ],
                }
            ]
        },
        {
            'targets': [ 
                {
                    'target_name': 'IFEStub',
                    'type': 'none'
                }
            ]
        }]
    ]
}
