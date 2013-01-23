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
    kill(0, $pid);
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

sub with_captured_log {
    my $function = shift;
    # remaining args for function

    with_temp(
	sub {
	    my (undef,$logfile) = @_;
	    # remaining args for function

	    KSM::Logger::filename_template($logfile);
	    KSM::Logger::reformatter(sub {
		my ($level,$msg) = @_; 
		croak("undefined level") unless defined($level);
		croak("undefined msg") unless defined($msg);
		sprintf("%s: %s", $level, $msg);
				     });
	    eval { &{$function}(@_) };
	    is($@, '', "should not have reported error");
	    file_read($logfile);
	});
}

########################################

sub terminate_test_child : Tests(teardown) {
    my ($self) = @_;
    if(defined($self->{child}) && defined($self->{child}->{pid})) {
	kill('TERM', $self->{child}->{pid});
    }
}

########################################
# maybe_relay_signal_to_child

sub test_maybe_relay_signal_to_child_does_not_relay_unrequested_signals : Tests {
    my ($self) = @_;

    $self->{child} = KSM::Daemon::verify_child({name => 'test_child', 
    						function => sub {1},
    						signals => ['USR1']});

    local $SIG{USR1} = sub { exit 1 };

    my $log = with_captured_log(
	sub {
	    if(my $pid = fork) {
		$self->{child}->{pid} = $pid;

		# not subscribed to USR2
		KSM::Daemon::maybe_relay_signal_to_child('USR2', $self->{child});
		waitpid($pid, 0);
		my $status = ($? >> 8);
		is($status, 0);
	    } elsif(defined $pid) {
		sleep 2;
		exit;
	    } else {
		fail "cannot fork";
	    }
	});
    like($log, qr|not relaying USR2 signal to child|);
}

sub test_maybe_relay_signal_to_child_relays_requested_signals : Tests {
    my ($self) = @_;

    $self->{child} = KSM::Daemon::verify_child({name => 'test_child', 
    						function => sub {1},
    						signals => ['USR1']});

    local $SIG{USR1} = sub { exit };

    if(my $pid = fork) {
	$self->{child}->{pid} = $pid;

	# subscribed to USR1
	KSM::Daemon::maybe_relay_signal_to_child('USR1', $self->{child});
	waitpid($pid, 0);
	my $status = ($? >> 8);
	is($status, 0);
    } elsif(defined $pid) {
	sleep 2;
	exit 1;
    } else {
	fail "cannot fork";
    }
}
