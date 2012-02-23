#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

use KSM::Daemon qw(:all);

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
	fail "unable to fork";
    }
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
	fail "unable to fork";
    }
}
