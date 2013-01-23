#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

########################################

use File::Basename;
use POSIX;
use KSM::Logger qw(:all);

use lib File::Basename::dirname(File::Basename::dirname(__FILE__)) . "/lib";
use KSM::Daemon;

########################################

KSM::Logger::initialize(
    {filename_template => sprintf("%s/log/%s.%%F.log", 
				  POSIX::getcwd,
				  File::Basename::basename($0)),
     level => KSM::Logger::DEBUG});
			 
sub greeting {
    foreach my $signal (qw(ALRM HUP USR1 USR2)) {
	$SIG{$signal} = sub { info("received %s signal", $signal) };
    }

    while(1) {
	foreach (@_) {
	    printf "Hello, %s, this is (uid %d) (gid %d)!\n", $_, $>, $);
	    sleep 2;
	}
    }
    sleep 5;
}

sub bar {
    foreach my $signal (qw(ALRM HUP USR1 USR2)) {
	$SIG{$signal} = sub { info("received %s signal", $signal) };
    }

    while(1) {
	print STDERR "bar\n";
	exit 1 if(int(rand(10)) < 5);
	sleep 20;
    }
}

KSM::Daemon::daemonize(
    [{name => "greeter as nobody",
      function => \&greeting,
      args => ["Abe", "Barry", "Charlie"],
      restart => 30,
      error => 60,
      signals => ['USR1'],
      user => 'nobody',
     },
     {name => "bar writer",
      function => \&bar,
      restart => 30,
      error => 60,
      signals => ['USR2'],
     },
    ]);
# not reached
exit 1;
