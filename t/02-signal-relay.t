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
# find

sub test_find_can_find_with_eq : Tests {
    is(KSM::Daemon::find('world', ['hello','world','!'], sub { shift eq shift }), 'world');
    ok(!KSM::Daemon::find('frobo', ['hello','world','!'], sub { shift eq shift }));
}

########################################
# relay_signal_to_child_p

sub test_relay_signal_to_child_p_always_true_for_int_and_term : Tests {
    is(KSM::Daemon::relay_signal_to_child_p('INT', {}), 1);
    is(KSM::Daemon::relay_signal_to_child_p('TERM', {}), 1);
    is(KSM::Daemon::relay_signal_to_child_p('INT', {signals => 'INT'}), 1);
    is(KSM::Daemon::relay_signal_to_child_p('TERM', {signals => 'TERM'}), 1);
}

sub test_relay_signal_to_child_p_true_iff_in_array : Tests {
    is(KSM::Daemon::relay_signal_to_child_p('USR1', {signals => []}), 0);
    is(KSM::Daemon::relay_signal_to_child_p('USR1', {signals => ['USR2']}), 0);

    is(KSM::Daemon::relay_signal_to_child_p('HUP', {signals => ['HUP','USR1','USR2']}), 1);
    is(KSM::Daemon::relay_signal_to_child_p('USR1', {signals => ['HUP','USR1','USR2']}), 1);
    is(KSM::Daemon::relay_signal_to_child_p('USR2', {signals => ['HUP','USR1','USR2']}), 1);
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
