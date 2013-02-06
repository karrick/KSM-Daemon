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
# verify_child

sub test_verify_child_croaks_when_child_bad : Tests {
    eval {KSM::Daemon::verify_child()};
    like($@, qr/\bchild should be reference to a hash\b/);

    eval {KSM::Daemon::verify_child([])};
    like($@, qr/\bchild should be reference to a hash\b/);
}

####################
# name

sub test_verify_child_checks_name : Tests {
    eval {KSM::Daemon::verify_child({})};
    like($@, qr/\bchild name should be string\b/);

    eval {KSM::Daemon::verify_child({name => {}})};
    like($@, qr/\bchild name should be string\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}}));
}

####################
# user

sub test_verify_child_checks_user : Tests {
    KSM::Daemon::verify_child({name => 'text', function => sub {1}});
    KSM::Daemon::verify_child({name => 'text', function => sub {1}, user => 'nobody'});

    eval {KSM::Daemon::verify_child({name => 'text', function => sub {1}, user => []})};
    like($@, qr/\bchild user should be string\b/);
}

####################
# function

sub test_verify_child_checks_function : Tests {
    eval {KSM::Daemon::verify_child({name => 'test'})};
    like($@, qr/\bchild function should be a function\b/);

    eval {KSM::Daemon::verify_child({name => 'test', function => 'foo'})};
    like($@, qr/\bchild function should be a function\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}}));
}

####################
# signals

sub test_verify_child_checks_signals : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => '1'})};
    like($@, qr|child signals should be reference to array|);

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','ALRM']})->{signals},
	      ['TERM','INT','HUP','ALRM'], "should add TERM and INT when neither found");

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','ALRM','TERM']})->{signals},
	      ['INT','HUP','ALRM','TERM'], "should add INT when not found");

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','INT','ALRM']})->{signals},
	      ['TERM','HUP','INT','ALRM'], "should add TERM when not found");
}

sub test_verify_child_signals_default : Tests {
    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{signals},
	      ['TERM','INT'], "should add TERM and INT when no signals requested");
}

####################
# args

sub test_verify_child_checks_function_checks_args : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, args => '1'})};
    like($@, qr/\bchild args should be reference to array\b/);

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, args => ["one",2]})->{args},
	      ["one",2]);
}

sub test_verify_child_checks_function_args_default : Tests {
    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{args}, []);
}

####################
# restart, error

sub test_verify_child_checks_function_checks_restart : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, restart => []})};
    like($@, qr/\bchild restart should be a scalar\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}, restart => 1}));;
}

sub test_verify_child_checks_function_checks_error : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, error => []})};
    like($@, qr/\bchild error should be a scalar\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}, error => 1}));;
}

sub test_verify_child_checks_function_restart_default : Tests {
    is(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{restart}, 0);
}

sub test_verify_child_checks_function_error_default : Tests {
    is(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{error}, 0);
}

########################################
# verify_children

sub test_verify_children_checks_children : Tests {
    eval {KSM::Daemon::verify_children()};
    like($@, qr/\bchildren ought be array reference\b/);
    eval {KSM::Daemon::verify_children({})};
    like($@, qr/\bchildren ought be array reference\b/);
    eval {KSM::Daemon::verify_children([])};
    like($@, qr/\bchildren ought have at least one child\b/);
}

sub test_verify_children_checks_each_child : Tests {
    # first child
    eval {KSM::Daemon::verify_children([{name => 'foo'},
					{name => 'bar', function => sub {1}},
					{name => 'baz', function => sub {1}}])};
    like($@, qr/\bcannot verify children\b/);
    like($@, qr/\bchild function should be\b/);

    # middle child
    eval {KSM::Daemon::verify_children([{name => 'foo', function => sub {1}},
					{function => sub {1}},
					{name => 'baz', function => sub {1}}])};
    like($@, qr/\bcannot verify children\b/);
    like($@, qr/\bchild name should be\b/);

    # last child
    eval {KSM::Daemon::verify_children([{name => 'foo', function => sub {1}},
					{name => 'bar', function => sub {1}},
					{name => 'baz', function => sub {1}, args => 1}])};
    like($@, qr/\bcannot verify children\b/);
    like($@, qr/\bchild args should be\b/);
}

########################################
# validate_process

sub test_proc_ought_be_hash : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process();
	    };
	    like($@, qr|ought to be hash|);

	    eval {
		validate_process("foo");
	    };
	    like($@, qr|ought to be hash|);
	};
	is($log, "");
    };
}

####################
# name

sub test_proc_ought_have_name : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({});
	    };
	    like($@, qr|ought to have name|);
	};
	is($log, "");
    };
}

sub test_name_ought_be_scalar : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({name => ['ignore']});
	    };
	    like($@, qr|name ought to be scalar|);
	};
	is($log, "");
    };
}

sub test_name_ought_not_be_log : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({ name => "log" });
	    };
	    like($@, qr|name ought not be log|);
	};
	is($log, "");
    };
}

####################
# exec

sub test_proc_ought_have_exec : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({name => "foo"});
	    };
	    like($@, qr|ought to have exec|);
	};
	is($log, "");
    };
}

sub test_exec_ought_be_array : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({name => "foo", exec => "not array"});
	    };
	    like($@, qr|exec ought to be non-empty array|);
	};
	is($log, "");
    };
}

sub test_exec_ought_not_be_empty : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process({name => "foo", exec => []});
	    };
	    like($@, qr|exec ought to be non-empty array|);
	};
    };
}

########################################
# stdout

sub test_does_not_die_if_stdout_matches_log : Tests {
    my ($self) = @_;

    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stdout => "log",
			stderr => "log",
		    },
		    ['foo','baz']);
	    };
	    unlike($@, qr|stdout must match a process name|);
	};
    };
}

sub test_die_if_stdout_matches_own_name : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stdout => "foo",
			stderr => "log",
		    },
		    ['foo']);
	    };
	    like($@, qr|stdout ought not match own process name|);
	};
    };
}

sub test_die_if_stdout_does_not_match_any_name : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stdout => "bar",
			stderr => "log",
		    },
		    ['foo','baz']);
	    };
	    like($@, qr|stdout must match a process name|);
	};
    };
}

########################################
# stderr

sub test_does_not_die_if_stderr_matches_log : Tests {
    my ($self) = @_;

    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stderr => "log",
			stdout => 'log',
		    },
		    ['foo','baz']);
	    };
	    unlike($@, qr|stderr must match a process name|);
	};
    };
}

sub test_die_if_stderr_matches_own_name : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stderr => "foo",
			stdout => 'log',
		    },
		    ['foo']);
	    };
	    like($@, qr|stderr ought not match own process name|);
	};
    };
}

sub test_die_if_stderr_does_not_match_any_name : Tests {
    my ($self) = @_;
    with_nothing_out {
	my $log = with_captured_log {
	    eval {
		validate_process(
		    {
			name => "foo",
			exec => ['ignore'],
			stderr => "bar",
			stdout => 'log',
		    },
		    ['foo','baz']);
	    };
	    like($@, qr|stderr must match a process name|);
	};
    };
}
