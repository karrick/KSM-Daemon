#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

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
				     sprintf("%s: %s", $level, $msg);
				 }});
	eval { $function->() };
	file_read($logfile);
    };
}

########################################

sub reset_globals : Test(setup) {
    $KSM::Daemon::respawn = 1;

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

########################################
# create_pipes

sub test_sets_stdout_and_stderr_to_log : Tests {
    my ($self) = @_;
    # SETUP
    my $pipes = $KSM::Daemon::pipes;
    my $procs = {
	foo => { stdout => "log", stderr => "log" },
	bar => { stdout => "log", stderr => "log" },
    };
    # TEST
    with_nothing_out {
	my $log = with_captured_log {
	    create_pipes($procs);
	};
	# like($log, qr|creating pipe for log stdin|);
	# unlike($log, qr|creating pipe for foo stdin|);
	# unlike($log, qr|creating pipe for bar stdin|);
	# like($log, qr|setting bar stdout to log|);
	# like($log, qr|setting foo stdout to log|);
	# like($log, qr|setting bar stderr to log|);
	# like($log, qr|setting foo stderr to log|);
    };

    # VERIFY -- log no stdout, stderr
    ok(!defined($pipes->{log}->{stdout}), "log ought not have stdout");
    ok(!defined($pipes->{log}->{stderr}), "log ought not have stderr");
    # VERIFY -- log stdin
    my $log_read = $pipes->{log}->{stdin}->{read};
    my $log_write = $pipes->{log}->{stdin}->{write};
    ok(defined(fileno($log_read)));
    ok(defined(fileno($log_write)));
    # VERIFY -- foo to log
    is($pipes->{log}->{stdin}->{write}, $pipes->{foo}->{stdout}, "foo stdout log");
    is($pipes->{log}->{stdin}->{write}, $pipes->{foo}->{stderr}, "foo stderr log ");
    # VERIFY -- bar to log
    is($pipes->{log}->{stdin}->{write}, $pipes->{bar}->{stdout}, "bar stdout log");
    is($pipes->{log}->{stdin}->{write}, $pipes->{bar}->{stderr}, "bar stderr log ");
}

sub test_sets_read_pipes_to_appropriate_write_pipes : Tests {
    my ($self) = @_;
    # SETUP -- circular, alternating between stdout and stderr
    my $pipes = $KSM::Daemon::pipes;
    my $procs = {
	foo => { stdout => "bar", stderr => "log" },
	bar => { stdout => "log", stderr => "baz" },
	baz => { stdout => "foo", stderr => "log" },
    };
    # TEST
    with_nothing_out {
	my $log = with_captured_log {
	    create_pipes($procs);
	};
	# like($log, qr|creating pipe for log stdin|);
	# like($log, qr|creating pipe for foo stdin|);
	# like($log, qr|creating pipe for bar stdin|);

	# like($log, qr|setting bar stdout to log|);
	# like($log, qr|setting bar stderr to baz|);

	# like($log, qr|setting foo stdout to bar|);
	# like($log, qr|setting foo stderr to log|);

	# like($log, qr|setting baz stdout to foo|);
	# like($log, qr|setting baz stderr to log|);
    };
    # VERIFY -- log no stdout, stderr
    ok(!defined($pipes->{log}->{stdout}), "log ought not have stdout");
    ok(!defined($pipes->{log}->{stderr}), "log ought not have stderr");
    # VERIFY -- log stdin
    my $log_read = $pipes->{log}->{stdin}->{read};
    my $log_write = $pipes->{log}->{stdin}->{write};
    ok(defined(fileno($log_read)));
    ok(defined(fileno($log_write)));
    # VERIFY -- foo stdin
    my $foo_read = $pipes->{foo}->{stdin}->{read};
    my $foo_write = $pipes->{foo}->{stdin}->{write};
    ok(defined($foo_read));
    ok(defined(fileno($foo_read)));
    ok(defined($foo_write));
    ok(defined(fileno($foo_write)));
    # VERIFY -- bar stdin
    my $bar_read = $pipes->{bar}->{stdin}->{read};
    my $bar_write = $pipes->{bar}->{stdin}->{write};
    ok(defined($bar_read));
    ok(defined(fileno($bar_read)));
    ok(defined($bar_write));
    ok(defined(fileno($bar_write)));
    # VERIFY -- baz stdin
    my $baz_read = $pipes->{baz}->{stdin}->{read};
    my $baz_write = $pipes->{baz}->{stdin}->{write};
    ok(defined($baz_read));
    ok(defined(fileno($baz_read)));
    ok(defined($baz_write));
    ok(defined(fileno($baz_write)));
    # VERIFY -- foo output
    is($pipes->{bar}->{stdin}->{write}, $pipes->{foo}->{stdout}, "foo stdout bar");
    is($pipes->{log}->{stdin}->{write}, $pipes->{foo}->{stderr}, "foo stderr log");
    # VERIFY -- bar output
    is($pipes->{log}->{stdin}->{write}, $pipes->{bar}->{stdout}, "bar stdout log");
    is($pipes->{baz}->{stdin}->{write}, $pipes->{bar}->{stderr}, "bar stderr baz");
    # VERIFY -- baz output
    is($pipes->{foo}->{stdin}->{write}, $pipes->{baz}->{stdout}, "baz stdout foo");
    is($pipes->{log}->{stdin}->{write}, $pipes->{baz}->{stderr}, "baz stderr log");
}
