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

use KSM::Daemon;
use KSM::Logger qw(debug verbose info warning error);

########################################

KSM::Logger::filename_template(sprintf("log/%s.%%F.log", __FILE__));
KSM::Logger::level(KSM::Logger::DEBUG);
KSM::Logger::reformatter(sub {
    my ($level,$line) = @_;
    sprintf("%s %s: (pid %d) %s",
 	    POSIX::strftime("[%F %T %Z] %s", gmtime),
	    $level, $$, $line);
			 });
info("Starting up %s", __FILE__);

sub greeting {
    while(1) {
	foreach (@_) {
	    print sprintf("Hello, %s!\n", $_);
	}
	sleep 10;
    }
}

sub bar {
    while(1) {
	print STDERR "bar\n";
	exit 1 if(int(rand(10)) < 5);
	sleep 10;
    }
}

KSM::Daemon::daemonize(
    [{name => "greeter",
      function => \&greeting,
      args => ["Abe", "Barry", "Charlie"],
      restart => 30,
      error => 60,
     },
     {name => "bar writer",
      function => \&bar,
      restart => 30,
      error => 60,
     },
    ]);
die("my_daemon died");  # &daemonize should never return
