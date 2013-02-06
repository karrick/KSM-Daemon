#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

use Time::HiRes qw(usleep);
use Capture::Tiny qw(capture);
use KSM::Helper qw(:all);

########################################

use KSM::Daemon qw(:all);

########################################
# HELPERS

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
				     sprintf("%s: (pid %d) %s", $level, $$, $msg);
				 }
				});
	eval { $function->() };
	file_read($logfile);
    };
}

########################################

sub reset_globals : Test(setup) {
    $KSM::Daemon::respawn = 0;

    $KSM::Daemon::retired = {};
    $KSM::Daemon::children = {};
    $KSM::Daemon::pipes = {};
}

sub close_pipes : Test(teardown) {
    my $pipes = $KSM::Daemon::pipes;
    foreach my $name (sort keys %$pipes) {
	if(defined($pipes->{$name}->{stdin})) {
	    close($pipes->{$name}->{stdin}->{read});
	    close($pipes->{$name}->{stdin}->{write});
	}
    }
}

sub terminate_children : Test(teardown) {
    my $children = $KSM::Daemon::children;
    foreach my $pid (keys %$children) {
	if(kill(0, $pid)) {
	    diag sprintf("TEARDOWN: sending TERM to %d", $pid);
	    kill('TERM', $pid);
	}
    }
}

########################################

sub wait_for_child {
    my ($child) = @_;
    while(alive_p($child)) {
	usleep(10000);
    }
}

########################################
# alive_p

sub test_alive_p : Tests {
    ok(alive_p({pid => $$}));
    ok(!alive_p({}));
}

########################################
# find_child_by_name

sub test_returns_undef_when_name_not_found : Tests {
    my ($self) = @_;
    is(find_child_by_name({}, "foo"), undef);
}

sub test_returns_child_hash_when_name_found : Tests {
    my ($self) = @_;
    is_deeply(find_child_by_name({
	13 => { name => "foo" },
	42 => { name => "bar" },
				 },
				 "foo"),
	      { name => "foo" });
}

########################################
# spawn_child

sub test_handles_fast_children : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "true",
	exec => ['bash','-c','true'],
	stdout => 'log',
	stderr => 'log',
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	$child = spawn_child($child);
	# VERIFY
	my $pid = $child->{pid};
	# VERIFY -- child gone
	diag sprintf("FAST: waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
    };
    like($log, qr|spawned child|);
}

sub test_handles_slow_children : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "sleep 1",
	exec => ['sleep','1'],
	stdout => 'log',
	stderr => 'log',
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	$child = spawn_child($child);
	# VERIFY
	my $pid = $child->{pid};
	# VERIFY -- child gone
	diag sprintf("SLOW: waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
    };
    like($log, qr|spawned child|);
}

sub test_does_not_delay_if_not_set : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "no delay",
	exec => ['bash','-c','true'],
	stdout => 'log',
	stderr => 'log',
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	$child = spawn_child($child);
	# VERIFY
	my $pid = $child->{pid};
	# VERIFY -- child gone
	diag sprintf("NO DELAY: waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
    };
    like($log, qr|spawned child|);
    unlike($log, qr|snooze|);
}

sub test_spawns_child_sleeps_if_delay : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "delay",
	exec => ['bash','-c','true'],
	stdout => 'log',
	stderr => 'log',
	delay => 1,
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	my $before = time();
	$child = spawn_child($child);
	# VERIFY
	my $pid = $child->{pid};
	# VERIFY -- child gone
	diag sprintf("DELAY: waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
	my $after = time();
	ok($after - $before >= 1);
    };
    like($log, qr|spawned child|);
    like($log, qr|snooze.*\b1\b.*seconds|);
}

sub test_sets_up_io_streams : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "true",
	exec => ['bash','-c','true'],
	stdout => 'log',
	stderr => 'log',
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	$child = spawn_child($child);

	# VERIFY
	my $pid = $child->{pid};

	# TODO: actually test io stream handling...

	# VERIFY -- child gone
	diag sprintf("waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
    };
    like($log, qr|spawned child|);
    like($log, qr|setting up io streams|);
    unlike($log, qr|redirecting stin|);
    like($log, qr|redirecting stdout|);
    like($log, qr|redirecting stderr|);
}

sub test_all_stuff{# : Tests {
    my ($self) = @_;
    # SETUP
    $SIG{CHLD} = \&REAPER;
    my $children = $KSM::Daemon::children;
    my $child = {
	name => "sleep 1",
	exec => ['sleep','1'],
	stdout => 'log',
	stderr => 'log',
    };
    create_pipes({$child->{name} => $child});
    # TEST
    my $log = with_captured_log {
	my $before = time();
	$child = spawn_child($child);
	my $after = time();

	# VERIFY
	is(ref($child), 'HASH');
	my $pid = $child->{pid};
	ok(defined($pid));
	ok(alive_p($child));

	ok(defined($child->{started}));
	ok($child->{started} >= $before);
	ok($child->{started} <= $after);

	ok(defined($children->{$child->{pid}}));
	ok(!defined($child->{ended}));
	ok(!defined($child->{status}));
	ok(!defined($child->{signal}));
	ok(!defined($child->{duration}));

	# VERIFY -- child gone
	diag sprintf("waiting for child pid %d to terminate...", $pid);
	wait_for_child($children->{$pid});
    };
    like($log, qr|spawned child .sleep|);
    like($log, qr|setting up io streams|);
    unlike($log, qr|redirecting stin|);
    like($log, qr|redirecting stdout|);
    like($log, qr|redirecting stderr|);
}
