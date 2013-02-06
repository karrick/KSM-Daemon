#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

use KSM::Helper qw(:all);
use KSM::Daemon qw(:all);

########################################
# HELPERS

sub is_pid_still_alive {
    my ($pid) = @_;
    return kill(0, $pid);
}

sub is_command_line_running {
    my ($command_line) = @_;
    $command_line = shell_quote($command_line);
    my $result = `pgrep -f $command_line`;
    ($result =~ /\d+/ ? 1 : 0);
}

sub test_is_command_line_running {
    ok(is_command_line_running(__FILE__));
    ok(!is_command_line_running("foobarbaz"));
}

########################################

sub with_nothing_out(&) {
    my ($code) = @_;
    my ($stdout,$stderr,$result) = capture {
	$code->();
    };
    is($stdout, "");
    is($stderr, "");
    $result;
}

sub with_captured_log(&) {
    my ($function) = @_;
    with_temp {
	my (undef,$logfile) = @_;
	KSM::Logger::initialize({level => KSM::Logger::DEBUG,
				 filename_template => $logfile,
				 reformatter => sub {
				     my ($level,$msg) = @_;
				     sprintf("%s: %s", $level, $msg);
				 }});
	eval { $function->() };
	file_read($logfile);
    };
}

########################################

sub terminate_test_child : Test(teardown) {
    my ($self) = @_;
    if(defined($self->{child}) && defined($self->{child}->{pid})) {
	kill('TERM', $self->{child}->{pid});
    }
}

########################################
# maybe_relay_signal_to_child

sub test_maybe_relay_signal_to_child_does_not_relay_unrequested_signals : Tests {
    my ($self) = @_;

    $self->{child} = verify_child({name => 'test_child',
				   function => sub {1},
				   signals => ['USR1']});

    local $SIG{USR1} = sub { POSIX::_exit(1) };

    my $log = with_captured_log(
	sub {
	    if(my $pid = fork) {
		$self->{child}->{pid} = $pid;
		# not subscribed to USR2
		maybe_relay_signal_to_child('USR2', $self->{child});
		waitpid($pid, 0);
		is($?, 0);
	    } elsif(defined $pid) {
		sleep 2;
		POSIX::_exit(0);
	    } else {
		fail "cannot fork";
	    }
	});
    like($log, qr|not relaying USR2 signal to child|);
}

sub test_maybe_relay_signal_to_child_relays_requested_signals : Tests {
    my ($self) = @_;

    $self->{child} = verify_child({name => 'test_child',
				   function => sub {1},
				   signals => ['USR1']});

    local $SIG{USR1} = sub { POSIX::_exit(0) };

    if(my $pid = fork) {
	$self->{child}->{pid} = $pid;

	# subscribed to USR1
	maybe_relay_signal_to_child('USR1', $self->{child});
	waitpid($pid, 0);
	my $status = ($? >> 8);
	is($status, 0);
    } elsif(defined $pid) {
	sleep 2;
	POSIX::_exit(1);
    } else {
	fail "cannot fork";
    }
}
