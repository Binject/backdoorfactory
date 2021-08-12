module github.com/Binject/backdoorfactory

go 1.16

require (
	github.com/Binject/binjection v0.0.0-20191205221130-3927f970a61f
	github.com/Binject/debug v0.0.0-20190929072709-9846938ecdec // indirect
	github.com/Binject/shellcode v0.0.0-20191101084904-a8a90e7d4563
	github.com/akamensky/argparse v1.2.1
	github.com/fatih/color v1.9.0 // indirect
	github.com/h2non/filetype v1.1.0
	github.com/sassoftware/relic v7.2.1+incompatible
	golang.org/x/crypto v0.0.0-20210812204632-0ba0e8f03122 // indirect
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
)

replace github.com/sassoftware/relic => github.com/pqxct/relic v0.0.0-20210812162757-c7fe711ac8b9
