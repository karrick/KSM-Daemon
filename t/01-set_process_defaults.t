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
# set_process_defaults

sub test_sets_name_of_each_process : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $result = set_process_defaults(
	    {
		"foo" => {},
		"bar" => {},
	    });
	is($result->{foo}->{name}, "foo");
	is($result->{bar}->{name}, "bar");
    };
}

sub test_sets_stdout_to_log_if_not_defined : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $result = set_process_defaults(
	    {
		"foo" => { stdout => "bar" },
		"bar" => { stdout => "log" },
		"baz" => {},
	    });
	is($result->{foo}->{stdout}, "bar");
	is($result->{bar}->{stdout}, "log");
	is($result->{baz}->{stdout}, "log");
    };
}

sub test_sets_stderr_to_log_if_not_defined : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $result = set_process_defaults(
	    {
		"foo" => { stderr => "bar" },
		"bar" => { stderr => "log" },
		"baz" => {},
	    });
	is($result->{foo}->{stderr}, "bar");
	is($result->{bar}->{stderr}, "log");
	is($result->{baz}->{stderr}, "log");
    };
}
