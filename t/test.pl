#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

use File::Basename;
use lib File::Basename::dirname(__FILE__) . "/../lib";
use POSIX;

use KSM::Daemon;
use KSM::Logger qw(debug verbose info warning error);

########################################

KSM::Logger::initialize({filename_template => sprintf("%s/log/%s.%%F.log", 
						      POSIX::getcwd,
						      File::Basename::basename($0)),
			 level => KSM::Logger::DEBUG});
			 
sub greeting {
    local $SIG{ALRM} = sub { info("received ALRM signal") };

    while(1) {
	foreach (@_) {
	    print sprintf("Hello, %s!\n", $_);
	}
	sleep 10;
    }
}

sub bar {
    local $SIG{ALRM} = sub { info("received ALRM signal") };

    while(1) {
	print STDERR "bar\n";
	# exit 1 if(int(rand(10)) < 5);
	sleep 20;
    }
}

KSM::Daemon::daemonize(
    [{name => "greeter",
      function => \&greeting,
      args => ["Abe", "Barry", "Charlie"],
      restart => 30,
      error => 60,
      signals => ['ALRM'],
     },
     {name => "bar writer",
      function => \&bar,
      restart => 30,
      error => 60,
     },
    ]);
